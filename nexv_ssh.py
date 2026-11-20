#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nexv-ssh — SSH credential finder for your OWN servers.

Reads a list of IPs and a list of candidate passwords, then finds which
password opens which server over SSH. Intended for recovering access to
servers you own or are explicitly authorized to test. Do not use it on
systems you do not own or have written permission to access.
"""

import os
import sys
import json
import time
import shutil
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Where scan progress is saved so an interrupted run can be resumed with
# `nexv-ssh continue`.
STATE_PATH = os.path.join(os.path.expanduser("~"), ".nexv-ssh", "state.json")

# ---- connection engines ----------------------------------------------------
# Preferred: the system OpenSSH client + sshpass. It is far more compatible
# with real-world servers (old or hardened crypto) than paramiko.
# Fallback: paramiko (pure-python), used only if ssh/sshpass are missing.
SSH_BIN = shutil.which("ssh")
SSHPASS_BIN = shutil.which("sshpass")
USE_SSHPASS = bool(SSH_BIN and SSHPASS_BIN)

paramiko = None
if not USE_SSHPASS:
    try:
        import paramiko  # noqa
        import logging
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    except ImportError:
        sys.stderr.write(
            "\n[!] Neither 'sshpass' nor 'paramiko' is available.\n"
            "    Re-run the nexv installer, or install one of:\n"
            "      - sshpass + openssh-client   (recommended)\n"
            "      - pip3 install paramiko\n\n"
        )
        sys.exit(1)

# ----------------------------- colors --------------------------------------
class C:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    CY = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"

    @classmethod
    def off(cls):
        for k in ("R", "G", "Y", "B", "CY", "BOLD", "DIM", "END"):
            setattr(cls, k, "")


if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C.off()

# Default connection tuning (override with env vars)
#   NEXV_TIMEOUT  - per-attempt connect/auth timeout, seconds (default 4)
#   NEXV_PROBE    - fast TCP port-probe timeout, seconds   (default min(timeout,2))
#   NEXV_WORKERS  - max servers scanned in parallel        (default 100)
CONNECT_TIMEOUT = int(os.environ.get("NEXV_TIMEOUT", "4"))
AUTH_TIMEOUT = CONNECT_TIMEOUT
PROBE_TIMEOUT = float(os.environ.get("NEXV_PROBE", str(min(CONNECT_TIMEOUT, 2))))
MAX_WORKERS = int(os.environ.get("NEXV_WORKERS", "100"))
RETRY_UNREACHABLE = 1      # retry count when the host times out / resets

_print_lock = threading.Lock()


def log(msg=""):
    with _print_lock:
        print(msg, flush=True)


def _term_width():
    try:
        return max(40, shutil.get_terminal_size((100, 20)).columns)
    except Exception:
        return 100


class Progress:
    """Thread-safe live status line + permanent result lines."""

    def __init__(self, total_ips, total_pw):
        self.total_ips = total_ips
        self.total_pw = total_pw
        self.ips_done = 0
        self.found = 0
        self.last_ip = "-"
        self.last_pw_idx = 0
        self.last_pw = "-"
        self.lock = threading.Lock()
        self.active = sys.stdout.isatty()
        self.start_time = None
        self._ticker = None
        self._stop = False

    def start_timer(self):
        """Begin the elapsed clock and a background thread that refreshes the
        timer every second even while no attempt has finished."""
        self.start_time = time.time()
        if self.active:
            self._stop = False
            self._ticker = threading.Thread(target=self._tick, daemon=True)
            self._ticker.start()

    def _tick(self):
        while not self._stop:
            time.sleep(1.0)
            with self.lock:
                if self._stop:
                    break
                self._render_nolock()

    def _elapsed_str(self):
        if not self.start_time:
            return "00:00"
        s = int(time.time() - self.start_time)
        return "{:02d}:{:02d}".format(s // 60, s % 60)

    def _render_nolock(self):
        if not self.active:
            return
        pw = self.last_pw
        if len(pw) > 32:
            pw = pw[:29] + "..."
        line = (
            "{d}[{t}]{e} "
            "{b}passwords[{pi}/{pt}]{e} "
            "{b}ips[{ii}/{it}]{e} | "
            "{cy}{ip}{e} → {y}{pw}{e} | "
            "{g}matched {f}{e}"
        ).format(
            d=C.DIM, t=self._elapsed_str(), b=C.BOLD, e=C.END,
            cy=C.CY, y=C.Y, g=C.G,
            pi=self.last_pw_idx, pt=self.total_pw,
            ii=self.ips_done, it=self.total_ips,
            ip=self.last_ip, pw=pw, f=self.found,
        )
        sys.stdout.write("\r\033[K" + line)
        sys.stdout.flush()

    def trying(self, ip, pw_idx, pw):
        with self.lock:
            self.last_ip = ip
            self.last_pw_idx = pw_idx
            self.last_pw = pw
            self._render_nolock()

    def host_done(self, found=False):
        with self.lock:
            self.ips_done += 1
            if found:
                self.found += 1
            self._render_nolock()

    def emit(self, msg):
        """Print a permanent line above the live status line."""
        with self.lock:
            if self.active:
                sys.stdout.write("\r\033[K")
            print(msg, flush=True)
            self._render_nolock()

    def finish(self):
        with self.lock:
            self._stop = True
            if self.active:
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()


class State:
    """Persists scan progress to disk so `nexv-ssh continue` can resume.

    Per-IP record is one of:
      {"status": "found", "password": "..."}
      {"status": "notfound"}
      {"status": "unreachable", "error": "..."}
      {"status": "inprogress", "idx": <0-based password index being tried>}
    """

    def __init__(self, path=STATE_PATH):
        self.path = path
        self.lock = threading.Lock()
        self.data = {"version": 1, "config": {}, "ips": {}}
        self._last_save = 0.0

    def init_fresh(self, config):
        with self.lock:
            self.data = {"version": 1, "config": config, "ips": {}}
            self._save_nolock(force=True)

    def load(self):
        with open(self.path, "r", encoding="utf-8") as fh:
            self.data = json.load(fh)
        return self.data

    def exists(self):
        return os.path.isfile(self.path)

    def config(self):
        return self.data.get("config", {})

    def get(self, ip):
        return self.data.get("ips", {}).get(ip)

    def set_inprogress(self, ip, idx):
        with self.lock:
            self.data["ips"][ip] = {"status": "inprogress", "idx": idx}
            self._save_nolock()

    def set_done(self, ip, status, **extra):
        with self.lock:
            rec = {"status": status}
            rec.update(extra)
            self.data["ips"][ip] = rec
            self._save_nolock(force=True)

    def _save_nolock(self, force=False):
        now = time.time()
        if not force and (now - self._last_save) < 1.0:
            return
        self._last_save = now
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh)
            os.replace(tmp, self.path)
        except Exception:
            pass


def banner():
    log(C.CY + C.BOLD + r"""
   _ __   _____  ____   __    ___ ___ _  _
  | '_ \ / _ \ \/ /\ \ / /   / __/ __| || |
  | | | |  __/>  <  \ V /    \__ \__ \ __ |
  |_| |_|\___/_/\_\  \_/     |___/___/_||_|
""" + C.END)
    log(C.DIM + "        nexv  ·  SSH credential finder" + C.END)
    log(C.DIM + "        Use only on servers you own or are authorized to test." + C.END)
    log("")


def ask(prompt, default=None):
    if default is not None:
        shown = "{}{} [{}]{}: ".format(C.BOLD, prompt, default, C.END)
    else:
        shown = "{}{}{}: ".format(C.BOLD, prompt, C.END)
    try:
        val = input(shown).strip()
    except (EOFError, KeyboardInterrupt):
        log("\n" + C.Y + "Aborted." + C.END)
        sys.exit(1)
    if not val and default is not None:
        return str(default)
    return val


def load_lines(path):
    """Load non-empty, de-duplicated lines preserving order."""
    if not os.path.isfile(path):
        log(C.R + "[!] File not found: {}".format(path) + C.END)
        sys.exit(1)
    seen = set()
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line in seen:
                continue
            seen.add(line)
            out.append(line)
    return out


def host_is_open(host, port, timeout):
    """Fast TCP probe: is the SSH port reachable at all? Skips dead hosts
    instantly instead of waiting out a full SSH/auth timeout on each password."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def _try_password_sshpass(host, port, username, password):
    """Authenticate using the OpenSSH client driven by sshpass."""
    cmd = [
        SSHPASS_BIN, "-p", password,
        SSH_BIN,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout={}".format(CONNECT_TIMEOUT),
        "-o", "NumberOfPasswordPrompts=1",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        "-o", "PubkeyAuthentication=no",
        "-o", "GSSAPIAuthentication=no",
        "-o", "LogLevel=ERROR",
        "-p", str(port),
        "{}@{}".format(username, host),
        "exit",
    ]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=CONNECT_TIMEOUT + 3,
        )
    except subprocess.TimeoutExpired:
        return "ERR:timeout"
    except Exception as e:  # noqa
        return "ERR:" + type(e).__name__

    if proc.returncode == 0:
        return True

    err = (proc.stderr or b"").decode("utf-8", "replace").lower()
    if "permission denied" in err or "authentication failed" in err:
        return False
    if proc.returncode == 5:            # sshpass: incorrect password
        return False
    if "connection refused" in err:
        return "ERR:refused"
    if "timed out" in err or "timeout" in err:
        return "ERR:timeout"
    if "no route to host" in err:
        return "ERR:no-route"
    if "could not resolve" in err or "name or service not known" in err:
        return "ERR:dns"
    last = err.strip().splitlines()[-1][:40] if err.strip() else "rc{}".format(proc.returncode)
    return "ERR:" + last


def _try_password_paramiko(host, port, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=CONNECT_TIMEOUT,
            banner_timeout=CONNECT_TIMEOUT,
            auth_timeout=AUTH_TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
        )
        return True
    except paramiko.AuthenticationException:
        return False
    except (socket.timeout, socket.error, paramiko.SSHException, EOFError) as e:
        return "ERR:" + type(e).__name__
    except Exception as e:  # noqa
        return "ERR:" + type(e).__name__
    finally:
        try:
            client.close()
        except Exception:
            pass


def try_password(host, port, username, password):
    """Return True if this password authenticates, False if rejected.

    Returns a string marker starting with 'ERR:' if the host could not be
    reached at all, so the caller can tell 'wrong password' from 'host down'.
    """
    if USE_SSHPASS:
        return _try_password_sshpass(host, port, username, password)
    return _try_password_paramiko(host, port, username, password)


def scan_host(host, port, username, passwords, progress, state, start_idx=0):
    """Try each password against one host; stop at the first that works.

    start_idx lets a resumed run continue from the password it was on.
    """
    # Fast pre-check: if the port isn't even open, don't waste any attempts.
    if not host_is_open(host, port, PROBE_TIMEOUT):
        progress.emit("{}[x] UNREACH{} {}{:<16}{}  (port closed / no response)".format(
            C.R, C.END, C.DIM, host, C.END))
        state.set_done(host, "unreachable", error="port closed/timeout")
        progress.host_done()
        return {"host": host, "status": "unreachable", "error": "port closed/timeout"}

    unreachable_streak = 0
    if start_idx < 0:
        start_idx = 0
    for idx in range(start_idx, len(passwords)):
        pw = passwords[idx]
        progress.trying(host, idx + 1, pw)
        state.set_inprogress(host, idx)
        result = try_password(host, port, username, pw)
        if result is True:
            progress.emit("{}[+] MATCH{}  {}{:<16}{}  ->  password: {}{}{}".format(
                C.G + C.BOLD, C.END, C.CY, host, C.END, C.G + C.BOLD, pw, C.END))
            state.set_done(host, "found", password=pw)
            progress.host_done(found=True)
            return {"host": host, "status": "found", "password": pw}
        if isinstance(result, str) and result.startswith("ERR:"):
            unreachable_streak += 1
            # If the very first attempts can't even connect, the host is down.
            if unreachable_streak > RETRY_UNREACHABLE and unreachable_streak >= 2:
                progress.emit("{}[x] UNREACH{} {}{:<16}{}  ({})".format(
                    C.R, C.END, C.DIM, host, C.END, result[4:]))
                state.set_done(host, "unreachable", error=result[4:])
                progress.host_done()
                return {"host": host, "status": "unreachable", "error": result[4:]}
        else:
            unreachable_streak = 0
    progress.emit("{}[-] NONE{}   {}{:<16}{}  (no password matched)".format(
        C.Y, C.END, C.DIM, host, C.END))
    state.set_done(host, "notfound")
    progress.host_done()
    return {"host": host, "status": "notfound"}


def _rec_to_result(host, rec):
    """Convert a saved state record back into a result dict for the report."""
    status = rec.get("status")
    if status == "found":
        return {"host": host, "status": "found", "password": rec.get("password", "")}
    if status == "unreachable":
        return {"host": host, "status": "unreachable", "error": rec.get("error", "unknown")}
    return {"host": host, "status": "notfound"}


def do_scan(port, username, ips, passwords, state, resume=False, workers=None):
    """Scan the pending hosts (optionally resuming), return all results."""
    results = []
    pending = []                 # list of (host, start_idx)
    done_count = 0
    found_count = 0

    for host in ips:
        rec = state.get(host) if resume else None
        if rec and rec.get("status") in ("found", "notfound", "unreachable"):
            results.append(_rec_to_result(host, rec))
            done_count += 1
            if rec["status"] == "found":
                found_count += 1
        else:
            start_idx = 0
            if rec and rec.get("status") == "inprogress":
                start_idx = int(rec.get("idx", 0))
            pending.append((host, start_idx))

    total = len(ips) * len(passwords)
    requested = workers if workers else MAX_WORKERS
    workers = max(1, min(requested, len(pending) or 1))
    log("")
    log("{}Summary{}".format(C.BOLD, C.END))
    log("  Port       : {}".format(port))
    log("  Username   : {}".format(username))
    log("  Servers    : {}".format(len(ips)))
    log("  Passwords  : {}".format(len(passwords)))
    if resume:
        log("  {}Resuming{}   : {} already done, {} left to scan".format(
            C.G, C.END, done_count, len(pending)))
    log("  Max checks : {} (stops at first match per server)".format(total))
    log("  Parallel   : {} servers at once".format(workers))
    log("  Timeout    : {}s per attempt  (TCP probe {}s)".format(CONNECT_TIMEOUT, PROBE_TIMEOUT))
    log("  Engine     : {}".format("openssh+sshpass" if USE_SSHPASS else "paramiko"))
    log("")

    if not pending:
        log(C.G + "Everything is already done — nothing left to scan." + C.END)
        return results, 0.0

    confirm = ask("Start scanning? (y/n)", "y").lower()
    if confirm not in ("y", "yes"):
        log(C.Y + "Cancelled. Progress is saved; run 'nexv continue' to resume." + C.END)
        sys.exit(0)

    log("")
    log(C.DIM + "Scanning... (progress is saved; you can resume with 'nexv continue')" + C.END)
    log("")

    started = datetime.now()
    progress = Progress(len(ips), len(passwords))
    progress.ips_done = done_count
    progress.found = found_count
    progress.start_timer()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan_host, host, port, username, passwords, progress, state, sidx): host
            for host, sidx in pending
        }
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:  # noqa
                host = futures[fut]
                progress.emit(C.R + "[!] Error scanning {}: {}".format(host, e) + C.END)
                results.append({"host": host, "status": "error", "error": str(e)})

    progress.finish()
    elapsed = (datetime.now() - started).total_seconds()
    return results, elapsed


def report(port, username, ips, results, elapsed):
    # Keep the report in the same order as the input IP file
    order = {ip: i for i, ip in enumerate(ips)}
    results.sort(key=lambda r: order.get(r["host"], 1e9))

    found = [r for r in results if r["status"] == "found"]
    notfound = [r for r in results if r["status"] == "notfound"]
    unreachable = [r for r in results if r["status"] in ("unreachable", "error")]

    # ------------------------- final report ------------------------------
    log("")
    log(C.BOLD + "=" * 60 + C.END)
    log(C.BOLD + " RESULTS" + C.END)
    log(C.BOLD + "=" * 60 + C.END)
    log("")

    if found:
        log(C.G + C.BOLD + "MATCHED SERVERS ({}):".format(len(found)) + C.END)
        log("")
        log("  {:<18} {:<6} {}".format("IP", "PORT", "PASSWORD"))
        log("  {:<18} {:<6} {}".format("-" * 16, "-" * 4, "-" * 20))
        for r in found:
            log("  {}{:<18}{} {:<6} {}{}{}".format(
                C.CY, r["host"], C.END, port, C.G, r["password"], C.END))
        log("")

    if notfound:
        log(C.Y + "NO PASSWORD MATCHED ({}):".format(len(notfound)) + C.END)
        for r in notfound:
            log("  {}".format(r["host"]))
        log("")

    if unreachable:
        log(C.R + "UNREACHABLE / ERROR ({}):".format(len(unreachable)) + C.END)
        for r in unreachable:
            log("  {:<18} ({})".format(r["host"], r.get("error", "unknown")))
        log("")

    log(C.DIM + "Done in {:.1f}s  ·  {} matched / {} none / {} unreachable".format(
        elapsed, len(found), len(notfound), len(unreachable)) + C.END)

    # ------------------------- save results ------------------------------
    now = datetime.now()
    out_path = "nexv_results_{}.txt".format(now.strftime("%Y%m%d_%H%M%S"))
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("nexv-ssh results  -  {}\n".format(now.isoformat()))
            fh.write("port={}  username={}\n\n".format(port, username))
            fh.write("# MATCHED (ip | port | password)\n")
            for r in found:
                fh.write("{} | {} | {}\n".format(r["host"], port, r["password"]))
            fh.write("\n# NO MATCH\n")
            for r in notfound:
                fh.write("{}\n".format(r["host"]))
            fh.write("\n# UNREACHABLE / ERROR\n")
            for r in unreachable:
                fh.write("{} | {}\n".format(r["host"], r.get("error", "unknown")))
        log(C.DIM + "Saved: {}".format(os.path.abspath(out_path)) + C.END)
    except Exception as e:  # noqa
        log(C.R + "[!] Could not save results file: {}".format(e) + C.END)


def ask_port(default="22"):
    port_raw = ask("SSH port to test", default)
    try:
        port = int(port_raw)
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        log(C.R + "[!] Invalid port: {}".format(port_raw) + C.END)
        sys.exit(1)
    return port


def ask_int(prompt, default, lo=1, hi=None):
    raw = ask(prompt, default)
    try:
        val = int(raw)
    except ValueError:
        log(C.Y + "[!] '{}' is not a number; using {}.".format(raw, default) + C.END)
        val = int(default)
    if val < lo:
        val = lo
    if hi is not None and val > hi:
        val = hi
    return val


def run_fresh():
    """Start a brand-new scan (asks for everything), saving progress as it goes."""
    port = ask_port()
    username = ask("SSH username", "root")
    ip_file = ask("IP list file (one IP per line)", "ip.txt")
    pw_file = ask("Password list file (one password per line)", "password.txt")

    ips = load_lines(ip_file)
    passwords = load_lines(pw_file)
    if not ips:
        log(C.R + "[!] No IPs found in {}".format(ip_file) + C.END)
        sys.exit(1)
    if not passwords:
        log(C.R + "[!] No passwords found in {}".format(pw_file) + C.END)
        sys.exit(1)

    # How many servers to check at the same time. More = faster (as each server
    # finishes, the next one starts automatically). Default: all of them at once.
    default_workers = min(MAX_WORKERS, len(ips))
    workers = ask_int(
        "How many servers to check at the same time", default_workers,
        lo=1, hi=len(ips))

    state = State()
    state.init_fresh({
        "port": port,
        "username": username,
        "ip_file": os.path.abspath(ip_file),
        "pw_file": os.path.abspath(pw_file),
        "workers": workers,
    })

    results, elapsed = do_scan(port, username, ips, passwords, state,
                              resume=False, workers=workers)
    report(port, username, ips, results, elapsed)


def run_resume():
    """Resume an interrupted scan from the saved progress file."""
    state = State()
    if not state.exists():
        log(C.Y + "[!] No saved progress found." + C.END)
        log("    Start a new scan first with:  " + C.BOLD + "nexv start" + C.END)
        sys.exit(1)
    try:
        state.load()
    except Exception as e:  # noqa
        log(C.R + "[!] Could not read saved progress: {}".format(e) + C.END)
        sys.exit(1)

    cfg = state.config()
    port = cfg.get("port", 22)
    username = cfg.get("username", "root")
    ip_file = cfg.get("ip_file", "ip.txt")
    pw_file = cfg.get("pw_file", "password.txt")
    workers = cfg.get("workers")

    log(C.DIM + "Resuming previous scan:" + C.END)
    log("  IP file       : {}".format(ip_file))
    log("  Password file : {}".format(pw_file))

    for label, path in (("IP", ip_file), ("Password", pw_file)):
        if not os.path.isfile(path):
            log(C.R + "[!] {} file no longer exists: {}".format(label, path) + C.END)
            log("    Put it back, or start a fresh scan with: " + C.BOLD + "nexv start" + C.END)
            sys.exit(1)

    ips = load_lines(ip_file)
    passwords = load_lines(pw_file)
    if not ips or not passwords:
        log(C.R + "[!] IP or password file is now empty." + C.END)
        sys.exit(1)

    results, elapsed = do_scan(port, username, ips, passwords, state,
                              resume=True, workers=workers)
    report(port, username, ips, results, elapsed)


def main():
    banner()
    arg = sys.argv[1].lower() if len(sys.argv) > 1 else ""
    if arg in ("continue", "--continue", "-c", "resume", "--resume"):
        run_resume()
    else:
        run_fresh()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\n" + C.Y + "Interrupted by user." + C.END)
        sys.exit(130)
