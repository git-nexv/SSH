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
import re
import sys
import json
import time
import atexit
import shutil
import signal
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime

# Where scan progress is saved so an interrupted run can be resumed with
# `nexv-ssh continue`.
STATE_PATH = os.path.join(os.path.expanduser("~"), ".nexv-ssh", "state.json")
# PID of the currently running scan, so `nexv stop` can stop it precisely.
PID_PATH = os.path.join(os.path.expanduser("~"), ".nexv-ssh", "nexv.pid")


def _write_pid():
    try:
        os.makedirs(os.path.dirname(PID_PATH), exist_ok=True)
        with open(PID_PATH, "w") as fh:
            fh.write(str(os.getpid()))
    except Exception:
        pass


def _clear_pid():
    try:
        os.remove(PID_PATH)
    except Exception:
        pass


# Set when `nexv retry` sends SIGUSR1 to a running scan: triggers an extra round
# that re-tries the servers that errored.
_RETRY_REQUEST = threading.Event()


def _on_retry_signal(signum, frame):  # noqa
    _RETRY_REQUEST.set()


# Stop requested by typing 'stop' in the live input line.
_QUIT_REQUEST = threading.Event()

# Log file a background scan writes its output to.
SCAN_LOG = os.path.join(os.path.expanduser("~"), ".nexv-ssh", "scan.log")


# ---- raw terminal handling for the live input line -------------------------
_TTY_FD = None
_TTY_OLD = None


def _enter_cbreak():
    global _TTY_FD, _TTY_OLD
    import termios
    import tty
    _TTY_FD = sys.stdin.fileno()
    _TTY_OLD = termios.tcgetattr(_TTY_FD)
    tty.setcbreak(_TTY_FD)        # keeps Ctrl-C working (ISIG), disables echo


def _restore_tty():
    global _TTY_OLD, _TTY_FD
    if _TTY_OLD is not None and _TTY_FD is not None:
        try:
            import termios
            termios.tcsetattr(_TTY_FD, termios.TCSADRAIN, _TTY_OLD)
        except Exception:  # noqa
            pass
    _TTY_OLD = None


atexit.register(_restore_tty)


def _input_reader(progress, handle_cmd, stop_event):
    """Read a typed command line at the bottom of the live display, so the user
    can watch the scan AND type commands in the same terminal."""
    try:
        import select
    except Exception:  # noqa
        return
    if not sys.stdin.isatty():
        return
    try:
        _enter_cbreak()
    except Exception:  # noqa
        return
    buf = ""
    progress.set_input("")
    fd = sys.stdin.fileno()
    try:
        while not stop_event.is_set():
            try:
                r, _, _ = select.select([fd], [], [], 0.3)
            except Exception:  # noqa
                break
            if not r:
                continue
            try:
                data = os.read(fd, 1)
            except Exception:  # noqa
                break
            if not data:
                break
            o = data[0]
            if o in (10, 13):               # Enter
                cmd = buf.strip()
                buf = ""
                progress.set_input("")
                handle_cmd(cmd)
            elif o in (127, 8):             # Backspace
                buf = buf[:-1]
                progress.set_input(buf)
            elif 32 <= o < 127:            # printable
                buf += chr(o)
                progress.set_input(buf)
            # other keys (arrows, etc.) are ignored
    finally:
        _restore_tty()

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
#   NEXV_WORKERS  - default parallel servers (default: all of them, no cap)
#   NEXV_RETRIES  - retries on a transient error (reset/timeout) (default 3)
#   NEXV_DELAY    - seconds to wait between attempts on one host (default 0)
CONNECT_TIMEOUT = int(os.environ.get("NEXV_TIMEOUT", "3"))
AUTH_TIMEOUT = CONNECT_TIMEOUT
PROBE_TIMEOUT = float(os.environ.get("NEXV_PROBE", str(min(CONNECT_TIMEOUT, 1.5))))
# No artificial cap: default to as many parallel workers as there are servers.
# (More workers than servers is pointless, so the effective max is the IP count.)
MAX_WORKERS = int(os.environ.get("NEXV_WORKERS", "1000000"))
RETRIES = int(os.environ.get("NEXV_RETRIES", "3"))
INTER_DELAY = float(os.environ.get("NEXV_DELAY", "0"))
RETRY_UNREACHABLE = 1      # consecutive hard failures before marking a host down

# Error markers treated as transient (server is up but throttling/overloading
# us): retried with backoff instead of giving up. These are all connection-phase
# failures that typically mean rate-limiting under heavy parallel load, not a
# truly dead host (the TCP port probe already passed before we got here).
TRANSIENT_ERRORS = ("reset", "timeout", "closed", "refused")

_print_lock = threading.Lock()


def log(msg=""):
    with _print_lock:
        print(msg, flush=True)


def _term_width():
    try:
        return max(40, shutil.get_terminal_size((100, 20)).columns)
    except Exception:
        return 100


MAX_LIVE_ROWS = 20   # cap how many per-IP live rows are shown at once


class Progress:
    """Thread-safe live display: one status row per concurrently-scanned IP,
    stacked vertically, plus a summary row. Finished servers print a permanent
    result line above the live block."""

    def __init__(self, total_ips, total_pw, workers=1):
        self.total_ips = total_ips
        self.total_pw = total_pw
        self.ips_done = 0
        self.found = 0
        self.failed = 0
        self.lock = threading.Lock()
        self.active_tty = sys.stdout.isatty()
        self.start_time = None
        self._ticker = None
        self._stop = False
        self._drawn = 0                      # live rows currently on screen
        self.input_enabled = False
        self.input_buffer = ""
        # one visible row per parallel worker, capped for sanity
        self.slots_count = max(1, min(workers, total_ips, MAX_LIVE_ROWS))
        self.slots = [None] * self.slots_count   # slot index -> host
        self.slot_of = {}                        # host -> slot index
        self.active = {}                         # host -> (pw_idx, pw)

    # ---- timer / background refresh ----
    def start_timer(self):
        self.start_time = time.time()
        if self.active_tty:
            self._stop = False
            self._ticker = threading.Thread(target=self._tick, daemon=True)
            self._ticker.start()

    def _tick(self):
        while not self._stop:
            time.sleep(1.0)
            with self.lock:
                if self._stop:
                    break
                self._repaint_nolock()

    def _elapsed_str(self):
        if not self.start_time:
            return "00:00"
        s = int(time.time() - self.start_time)
        return "{:02d}:{:02d}".format(s // 60, s % 60)

    # ---- slot bookkeeping ----
    def _assign_slot(self, host):
        if host in self.slot_of:
            return
        for i in range(self.slots_count):
            if self.slots[i] is None:
                self.slots[i] = host
                self.slot_of[host] = i
                return

    def _free_slot(self, host):
        i = self.slot_of.pop(host, None)
        if i is None:
            return
        self.slots[i] = None
        # promote another active host that has no visible row yet
        for h in self.active:
            if h not in self.slot_of:
                self.slots[i] = h
                self.slot_of[h] = i
                break

    # ---- rendering ----
    def _build_block(self):
        t = self._elapsed_str()
        rows = []
        for i in range(self.slots_count):
            host = self.slots[i]
            if host is not None and host in self.active:
                idx, pw = self.active[host]
                if len(pw) > 24:
                    pw = pw[:21] + "..."
                rows.append(
                    "{d}[{t}]{e} {cy}{host:<15}{e} {b}passwords[{i}/{n}]{e} → {y}{pw}{e}".format(
                        d=C.DIM, t=t, e=C.END, cy=C.CY, host=host,
                        b=C.BOLD, i=idx, n=self.total_pw, y=C.Y, pw=pw))
            else:
                rows.append("{d}[{t}] ...{e}".format(d=C.DIM, t=t, e=C.END))
        rows.append(
            ("{d}── total {b}  ·  {cy}{k} scanning{d}  ·  "
             "done {a}/{b}  ·  {g}{f} matched{d}  ·  {r}{u} failed{d}  ·  "
             "{q} queued ──{e}").format(
                d=C.DIM, b=self.total_ips, cy=C.CY, k=len(self.active),
                a=self.ips_done, g=C.G, f=self.found, r=C.R, u=self.failed,
                q=max(0, self.total_ips - self.ips_done - len(self.active)),
                e=C.END))
        if self.input_enabled:
            rows.append(
                "{b}>{e} {buf}{d}▁   (type: {e}{b}retry{e}{d} | {e}{b}status{e}{d} | {e}{b}stop{e}{d}){e}".format(
                    b=C.BOLD, e=C.END, d=C.DIM, buf=self.input_buffer))
        return rows

    def status_text(self):
        return ("total {b}  ·  {k} scanning  ·  done {a}  ·  "
                "{f} matched  ·  {u} failed  ·  {q} queued").format(
            b=self.total_ips, k=len(self.active), a=self.ips_done,
            f=self.found, u=self.failed,
            q=max(0, self.total_ips - self.ips_done - len(self.active)))

    def set_input(self, buf):
        with self.lock:
            self.input_enabled = True
            self.input_buffer = buf
            self._repaint_nolock()

    def _repaint_nolock(self, permanent=None):
        if not self.active_tty:
            if permanent is not None:
                print(permanent, flush=True)
            return
        out = []
        if self._drawn:
            out.append("\033[{}F".format(self._drawn))   # cursor up to block top
        if permanent is not None:
            out.append("\033[2K" + permanent + "\n")
        block = self._build_block()
        for row in block:
            out.append("\033[2K" + row + "\n")
        self._drawn = len(block)
        sys.stdout.write("".join(out))
        sys.stdout.flush()

    # ---- public API ----
    def trying(self, host, pw_idx, pw):
        with self.lock:
            self.active[host] = (pw_idx, pw)
            self._assign_slot(host)
            self._repaint_nolock()

    def host_done(self, host, msg=None, found=False, failed=False):
        with self.lock:
            self.active.pop(host, None)
            self._free_slot(host)
            self.ips_done += 1
            if found:
                self.found += 1
            if failed:
                self.failed += 1
            self._repaint_nolock(permanent=msg)

    def emit(self, msg):
        """Print a permanent line above the live block."""
        with self.lock:
            self._repaint_nolock(permanent=msg)

    def finish(self):
        with self.lock:
            self._stop = True
            if self.active_tty and self._drawn:
                out = ["\033[{}F".format(self._drawn)]
                for _ in range(self._drawn):
                    out.append("\033[2K\n")
                out.append("\033[{}F".format(self._drawn))
                self._drawn = 0
                sys.stdout.write("".join(out))
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
    """Load non-empty, de-duplicated lines preserving order.

    Returns (items, duplicates_skipped).
    """
    if not os.path.isfile(path):
        log(C.R + "[!] File not found: {}".format(path) + C.END)
        sys.exit(1)
    seen = set()
    out = []
    dups = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line in seen:
                dups += 1
                continue
            seen.add(line)
            out.append(line)
    return out, dups


def parse_endpoint(token):
    """Split an 'IP:PORT' token into (ip, port). Returns (ip, None) when no
    valid port is given, so the global/default port is used for that IP.
    Lines with several colons (e.g. IPv6) are left as-is with the default port.
    """
    token = token.strip()
    if token.count(":") == 1:
        host, _, p = token.partition(":")
        if host and p.isdigit() and 1 <= int(p) <= 65535:
            return host, int(p)
    return token, None


def build_targets(raw_ips, default_ports):
    """From raw IP lines (each optionally 'ip:port'), build the unique IP list
    and a per-IP list of candidate ports. A line's own ':port' overrides the
    default list. Returns (ips, portlists, extra_duplicates)."""
    ips = []
    portlists = {}
    seen = set()
    dups = 0
    for tok in raw_ips:
        ip, p = parse_endpoint(tok)
        if ip in seen:
            dups += 1
            continue
        seen.add(ip)
        ips.append(ip)
        portlists[ip] = [p] if p is not None else list(default_ports)
    return ips, portlists, dups


def load_usernames(value):
    """Resolve the username input into a list of usernames.

    - If `value` is a path to an existing file, read one username per line.
    - Otherwise treat `value` as a single literal username (e.g. 'root').
    Always returns at least ['root'].
    """
    value = (value or "").strip()
    if value and os.path.isfile(value):
        items, _ = load_lines(value)
        return items or ["root"]
    return [value or "root"]


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
    if "too many authentication failures" in err:
        return "ERR:too-many-auth"
    # Server up but closed/reset us mid-handshake -> rate-limiting / MaxStartups
    # / fail2ban. Transient: worth retrying with backoff.
    if ("kex_exchange_identification" in err or "reset by peer" in err
            or "connection reset" in err):
        return "ERR:reset"
    if "closed by remote host" in err or "connection closed" in err:
        return "ERR:closed"
    if "connection refused" in err:
        return "ERR:refused"
    if "timed out" in err or "timeout" in err:
        return "ERR:timeout"
    if "no route to host" in err or "network is unreachable" in err:
        return "ERR:no-route"
    if "could not resolve" in err or "name or service not known" in err:
        return "ERR:dns"
    # Fallback: surface the REAL ssh reason instead of a useless 'rc255'.
    # ssh prints: "ssh: connect to host H port P: <reason>".
    m = re.search(r"port \d+:\s*(.+)", err)
    if m:
        return "ERR:" + m.group(1).strip()[:48]
    first = next((ln.strip() for ln in err.splitlines() if ln.strip()), "")
    return "ERR:" + (first[:48] if first else "rc{}".format(proc.returncode))


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


def _try_once(host, port, username, password):
    if USE_SSHPASS:
        return _try_password_sshpass(host, port, username, password)
    return _try_password_paramiko(host, port, username, password)


def try_password(host, port, username, password):
    """Return (result, attempts).

    result is True (auth ok), False (wrong password) or an 'ERR:...' marker.
    attempts is how many connection attempts were made (1 + retries). Transient
    errors (reset / timeout = server up but rate-limiting us) are retried with
    increasing backoff before giving up.
    """
    attempt = 0
    while True:
        attempt += 1
        result = _try_once(host, port, username, password)
        if result is True or result is False:
            return result, attempt
        kind = result[4:] if isinstance(result, str) else ""
        transient = any(k in kind for k in TRANSIENT_ERRORS)
        if transient and attempt <= RETRIES:
            time.sleep(min(1.5, 0.3 * attempt))   # short backoff: 0.3s, 0.6s ...
            continue
        return result, attempt


def reason_text(err):
    """Human-readable explanation for an error marker."""
    return {
        "reset": "connection reset (rate-limited?)",
        "closed": "connection closed (rate-limited?)",
        "refused": "refused (rate-limited? / port closed)",
        "timeout": "timeout (slow or filtered)",
        "no-route": "no route to host",
        "dns": "cannot resolve hostname",
        "too-many-auth": "too many auth failures (server limit)",
    }.get(err, err)


def fmt_result_line(r):
    """Build the permanent one-line result for a host (MATCH / NONE / UNREACH)."""
    host = r["host"]
    st = r["status"]
    if st == "found":
        cred = "{}:{}".format(r.get("username", "root"), r.get("password", ""))
        return "{}[+] MATCH{}  {}{:<16}{}  ->  {}{}{}".format(
            C.G + C.BOLD, C.END, C.CY, host, C.END, C.G + C.BOLD, cred, C.END)
    if st in ("unreachable", "error"):
        return "{}[x] UNREACH{} {}{:<16}{}  ({})".format(
            C.R, C.END, C.DIM, host, C.END, r.get("error", "unknown"))
    return "{}[-] NONE{}   {}{:<16}{}  (no password matched)".format(
        C.Y, C.END, C.DIM, host, C.END)


def scan_host(host, portlist, creds, progress, state, start_idx=0, show_user=False):
    """Try each (username, password) credential against one host; stop at the
    first that works. `portlist` is the candidate ports to try (the first one
    that is open is used). `creds` is a flat list of (username, password) tuples.

    start_idx lets a resumed run continue from the credential it was on.
    """
    # Find the first open port among the candidates (fast TCP probe).
    port = None
    for p in portlist:
        if host_is_open(host, p, PROBE_TIMEOUT):
            port = p
            break
    if port is None:
        tried = ",".join(str(p) for p in portlist)
        err = "port closed / no response (ports {})".format(tried)
        r = {"host": host, "status": "unreachable", "error": err}
        state.set_done(host, "unreachable", error=err)
        progress.host_done(host, fmt_result_line(r), failed=True)
        return r

    unreachable_streak = 0
    tries = 0                     # total connection attempts made for this host
    if start_idx < 0:
        start_idx = 0
    for idx in range(start_idx, len(creds)):
        user, pw = creds[idx]
        shown = "{}:{}".format(user, pw) if show_user else pw
        progress.trying(host, idx + 1, shown)
        state.set_inprogress(host, idx)
        result, attempts = try_password(host, port, user, pw)
        tries += attempts
        if result is True:
            r = {"host": host, "status": "found", "port": port,
                 "username": user, "password": pw}
            state.set_done(host, "found", port=port, username=user, password=pw)
            progress.host_done(host, fmt_result_line(r), found=True)
            return r
        if isinstance(result, str) and result.startswith("ERR:"):
            unreachable_streak += 1
            # If the very first attempts can't even connect, the host is down.
            if unreachable_streak > RETRY_UNREACHABLE and unreachable_streak >= 2:
                note = "{}, {} tries".format(reason_text(result[4:]), tries)
                r = {"host": host, "status": "unreachable", "error": note}
                state.set_done(host, "unreachable", error=note)
                progress.host_done(host, fmt_result_line(r), failed=True)
                return r
        else:
            unreachable_streak = 0
        if INTER_DELAY > 0:
            time.sleep(INTER_DELAY)
    r = {"host": host, "status": "notfound", "port": port}
    state.set_done(host, "notfound", port=port)
    progress.host_done(host, fmt_result_line(r))
    return r


def _rec_to_result(host, rec):
    """Convert a saved state record back into a result dict for the report."""
    status = rec.get("status")
    if status == "found":
        return {"host": host, "status": "found", "port": rec.get("port"),
                "username": rec.get("username", "root"),
                "password": rec.get("password", "")}
    if status == "unreachable":
        return {"host": host, "status": "unreachable", "error": rec.get("error", "unknown")}
    return {"host": host, "status": "notfound", "port": rec.get("port")}


def do_scan(default_ports, portlists, usernames, ips, passwords, state,
            resume=False, workers=None, retry_failed=False, ask_background=True):
    """Scan the pending hosts (optionally resuming), return all results.

    `portlists` maps each IP to its candidate ports. `usernames` is the list of
    usernames to try; each host is tried against every (username, password) pair.
    retry_failed also re-scans hosts previously marked unreachable.
    """
    # Flat credential list: every username against every password.
    creds = [(u, p) for u in usernames for p in passwords]
    show_user = len(usernames) > 1
    results_by_host = {}
    pending = []                 # list of (host, start_idx)
    done_count = 0
    found_count = 0
    fail_count = 0

    for host in ips:
        rec = state.get(host)
        status = rec.get("status") if rec else None
        if status == "unreachable" and retry_failed:
            pending.append((host, 0))        # re-try the failed ones
        elif status in ("found", "notfound", "unreachable"):
            results_by_host[host] = _rec_to_result(host, rec)
            done_count += 1
            if status == "found":
                found_count += 1
            elif status == "unreachable":
                fail_count += 1
        else:
            start_idx = int(rec.get("idx", 0)) if status == "inprogress" else 0
            pending.append((host, start_idx))

    total = len(ips) * len(creds)
    requested = workers if workers else MAX_WORKERS
    workers = max(1, min(requested, len(pending) or 1))
    custom_ports = any(portlists.get(h) != default_ports for h in ips)
    ports_str = " ".join(str(p) for p in default_ports)
    log("")
    log("{}Summary{}".format(C.BOLD, C.END))
    log("  Port(s)    : {}{}".format(
        ports_str, "  (+ per-IP ports from file)" if custom_ports else ""))
    if len(usernames) == 1:
        log("  Username   : {}".format(usernames[0]))
    else:
        log("  Usernames  : {} ({})".format(
            len(usernames), ", ".join(usernames[:5]) + ("..." if len(usernames) > 5 else "")))
    log("  Servers    : {}".format(len(ips)))
    log("  Passwords  : {}".format(len(passwords)))
    if done_count:
        label = "Resuming" if resume else "Skipping  "
        log("  {}{}{} : {} already tested, {} left to scan".format(
            C.G, label, C.END, done_count, len(pending)))
    log("  Max checks : {} (stops at first match per server)".format(total))
    log("  Parallel   : {} servers at once".format(workers))
    log("  Timeout    : {}s per attempt  (TCP probe {}s)".format(CONNECT_TIMEOUT, PROBE_TIMEOUT))
    log("  Retries    : {} on reset/timeout{}".format(
        RETRIES, "  ·  delay {}s".format(INTER_DELAY) if INTER_DELAY > 0 else ""))
    log("  Engine     : {}".format("openssh+sshpass" if USE_SSHPASS else "paramiko"))
    log("")

    # On resume, show everything already found/tested before so the picture is
    # complete, not just the servers about to be scanned now.
    if resume and results_by_host:
        prev_order = {ip: i for i, ip in enumerate(ips)}
        shown = sorted(results_by_host.values(), key=lambda r: prev_order.get(r["host"], 1e9))
        log(C.BOLD + "Results so far from the previous run ({}):".format(len(shown)) + C.END)
        for r in shown:
            log("  " + fmt_result_line(r))
        log("")

    if not pending:
        log(C.G + "Everything is already done — nothing left to scan." + C.END)
        return list(results_by_host.values()), 0.0

    confirm = ask("Start scanning? (y/n)", "y").lower()
    if confirm not in ("y", "yes"):
        log(C.Y + "Cancelled. Progress is saved; run 'nexv continue' to resume." + C.END)
        sys.exit(0)

    # Offer to run in the background so the terminal stays free for other
    # commands (nexv status / retry / stop) while the scan runs.
    background = False
    if ask_background and hasattr(os, "fork") and sys.stdout.isatty():
        ans = ask("Run in background so you can keep typing commands? (y/n)", "n").lower()
        background = ans in ("y", "yes")

    if background:
        sys.stdout.flush()
        sys.stderr.flush()
        pid = os.fork()
        if pid > 0:
            # Parent: tell the user how to drive the background scan, then exit.
            log("")
            log(C.G + C.BOLD + "Scan started in the background (pid {}).".format(pid) + C.END)
            log("  " + C.BOLD + "nexv status" + C.END + "   see progress and matches so far")
            log("  " + C.BOLD + "nexv retry" + C.END + "    re-try the servers that errored")
            log("  " + C.BOLD + "nexv stop" + C.END + "     stop it (progress is saved)")
            log(C.DIM + "  log: {}".format(SCAN_LOG) + C.END)
            log("")
            return None, None
        # Child: detach from the terminal and send output to the log file.
        try:
            os.setsid()
        except Exception:  # noqa
            pass
        try:
            os.makedirs(os.path.dirname(SCAN_LOG), exist_ok=True)
            _logf = open(SCAN_LOG, "a", buffering=1)
            os.dup2(_logf.fileno(), sys.stdout.fileno())
            os.dup2(_logf.fileno(), sys.stderr.fileno())
            _devnull = open(os.devnull, "r")
            os.dup2(_devnull.fileno(), sys.stdin.fileno())
        except Exception:  # noqa
            pass
        log("")
        log("=== background scan started {} ===".format(datetime.now().isoformat()))

    interactive = (not background) and sys.stdin.isatty() and sys.stdout.isatty()
    if not background:
        log("")
        if interactive:
            log(C.DIM + "Scanning... type a command below and press Enter: "
                + C.BOLD + "retry" + C.END + C.DIM + " (re-try failed) · "
                + C.BOLD + "status" + C.END + C.DIM + " · "
                + C.BOLD + "stop" + C.END + C.DIM + "   (progress is saved)" + C.END)
        else:
            log(C.DIM + "Scanning... (progress saved; resume with 'nexv continue')" + C.END)
        log("")

    started = datetime.now()
    progress = Progress(len(ips), len(creds), workers)
    progress.ips_done = done_count
    progress.found = found_count
    progress.failed = fail_count
    progress.start_timer()

    # `nexv retry` / `nexv stop` (from any terminal) reach this scan via signals.
    _RETRY_REQUEST.clear()
    _QUIT_REQUEST.clear()
    try:
        signal.signal(signal.SIGUSR1, _on_retry_signal)      # nexv retry
        signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))  # nexv stop -> clean exit
    except Exception:  # noqa (not main thread / unsupported)
        pass

    def handle_cmd(cmd):
        c = cmd.lower().strip()
        if c.startswith("nexv "):
            c = c[5:].strip()
        if c in ("retry", "r"):
            _RETRY_REQUEST.set()
        elif c in ("stop", "quit", "q"):
            _QUIT_REQUEST.set()
        elif c in ("status", "s"):
            progress.emit(C.CY + progress.status_text() + C.END)
        elif c in ("help", "h", "?"):
            progress.emit(C.DIM + "commands: retry (re-try failed) · status · stop" + C.END)
        elif c == "":
            pass
        else:
            progress.emit(C.Y + "unknown command: {}  (retry | status | stop)".format(cmd) + C.END)

    _in_stop = threading.Event()
    _in_thread = None
    if interactive:
        _in_thread = threading.Thread(
            target=_input_reader, args=(progress, handle_cmd, _in_stop), daemon=True)
        _in_thread.start()

    _write_pid()

    def requeue_failed(queue):
        """Pull hosts that have errored back into the work queue (triggered by
        `nexv retry`). Returns how many were re-queued."""
        failed_hosts = [h for h, r in results_by_host.items()
                        if r["status"] in ("unreachable", "error")]
        # Don't re-queue a host that is already queued or in flight.
        queued = {h for h, _ in queue}
        failed_hosts = [h for h in failed_hosts if h not in queued]
        if not failed_hosts:
            return 0
        with progress.lock:
            progress.ips_done = max(0, progress.ips_done - len(failed_hosts))
            progress.failed = max(0, progress.failed - len(failed_hosts))
        for h in failed_hosts:
            results_by_host.pop(h, None)
            queue.append((h, 0))
        return len(failed_hosts)

    try:
        # Dynamic scheduler: keep up to `workers` scans in flight, and whenever
        # `nexv retry` is received, re-queue the failed servers immediately so
        # they are retried alongside the ongoing work (not after it).
        queue = list(pending)
        in_flight = {}

        with ThreadPoolExecutor(max_workers=workers) as pool:
            def fill():
                while queue and len(in_flight) < workers:
                    host, sidx = queue.pop(0)
                    fut = pool.submit(scan_host, host, portlists.get(host, default_ports),
                                      creds, progress, state, sidx, show_user)
                    in_flight[fut] = host

            fill()
            while in_flight:
                done, _ = wait(list(in_flight), timeout=1.0, return_when=FIRST_COMPLETED)
                for fut in done:
                    host = in_flight.pop(fut)
                    try:
                        results_by_host[host] = fut.result()
                    except Exception as e:  # noqa
                        progress.host_done(host, C.R + "[!] Error scanning {}: {}".format(host, e) + C.END,
                                           failed=True)
                        results_by_host[host] = {"host": host, "status": "error", "error": str(e)}
                # A retry was requested ('r' key or `nexv retry`): re-queue the
                # failed servers right away.
                if _RETRY_REQUEST.is_set():
                    _RETRY_REQUEST.clear()
                    n = requeue_failed(queue)
                    if n:
                        progress.emit(C.Y + "↻ Retry: re-trying {} failed server(s)...".format(n) + C.END)
                    else:
                        progress.emit(C.DIM + "↻ Retry: no failed servers to re-try right now." + C.END)
                # Stop requested (typed 'stop' or `nexv stop`): drain and exit.
                if _QUIT_REQUEST.is_set() and queue:
                    progress.emit(C.Y + "■ Stopping... (progress saved; resume with 'nexv continue')" + C.END)
                    queue.clear()
                fill()
    finally:
        _in_stop.set()
        progress.finish()
        _clear_pid()
    elapsed = (datetime.now() - started).total_seconds()
    return list(results_by_host.values()), elapsed


def report(default_ports, portlists, usernames, ips, results, elapsed):
    def pof(r):
        # Actual matched port if known, else the host's first candidate port.
        return r.get("port") or (portlists.get(r["host"]) or default_ports)[0]

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
        log("  {:<18} {:<6} {:<14} {}".format("IP", "PORT", "USERNAME", "PASSWORD"))
        log("  {:<18} {:<6} {:<14} {}".format("-" * 16, "-" * 4, "-" * 12, "-" * 20))
        for r in found:
            log("  {}{:<18}{} {:<6} {:<14} {}{}{}".format(
                C.CY, r["host"], C.END, pof(r),
                r.get("username", "root"), C.G, r["password"], C.END))
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
            fh.write("ports={}  usernames={}\n\n".format(
                " ".join(str(p) for p in default_ports), ",".join(usernames)))
            fh.write("# MATCHED (ip | port | username | password)\n")
            for r in found:
                fh.write("{} | {} | {} | {}\n".format(
                    r["host"], pof(r), r.get("username", "root"), r["password"]))
            fh.write("\n# NO MATCH\n")
            for r in notfound:
                fh.write("{}\n".format(r["host"]))
            fh.write("\n# UNREACHABLE / ERROR\n")
            for r in unreachable:
                fh.write("{} | {}\n".format(r["host"], r.get("error", "unknown")))
        log(C.DIM + "Saved: {}".format(os.path.abspath(out_path)) + C.END)
    except Exception as e:  # noqa
        log(C.R + "[!] Could not save results file: {}".format(e) + C.END)


def ask_ports(default="22"):
    """Ask for one or more ports, space- (or comma-) separated, e.g. '22 35 65'.
    Returns a list of ints."""
    raw = ask("SSH port(s) to test, space-separated (e.g. 22 2222)", default)
    ports = []
    for tok in raw.replace(",", " ").split():
        try:
            p = int(tok)
        except ValueError:
            log(C.Y + "[!] Ignoring invalid port '{}'".format(tok) + C.END)
            continue
        if 1 <= p <= 65535 and p not in ports:
            ports.append(p)
    if not ports:
        log(C.R + "[!] No valid port given." + C.END)
        sys.exit(1)
    return ports


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
    default_ports = ask_ports()
    user_in = ask("SSH username, or a usernames file", "root")
    usernames = load_usernames(user_in)
    if len(usernames) > 1:
        log(C.DIM + "Loaded {} usernames from {}.".format(len(usernames), user_in) + C.END)
    ip_file = ask("IP list file (one IP per line)", "ip.txt")
    pw_file = ask("Password list file (one password per line)", "password.txt")

    raw_ips, ip_dups = load_lines(ip_file)
    passwords, pw_dups = load_lines(pw_file)
    # Parse optional 'ip:port' suffixes; each IP keeps its own port list.
    ips, portlists, extra = build_targets(raw_ips, default_ports)
    ip_dups += extra
    if not ips:
        log(C.R + "[!] No IPs found in {}".format(ip_file) + C.END)
        sys.exit(1)
    if not passwords:
        log(C.R + "[!] No passwords found in {}".format(pw_file) + C.END)
        sys.exit(1)
    if ip_dups:
        log(C.DIM + "Skipped {} duplicate IP(s) in {}.".format(ip_dups, ip_file) + C.END)
    if pw_dups:
        log(C.DIM + "Skipped {} duplicate password(s) in {}.".format(pw_dups, pw_file) + C.END)

    # How many servers to check at the same time. More = faster (as each server
    # finishes, the next one starts automatically). No cap: the default is all of
    # them at once (equal to the number of servers).
    default_workers = min(MAX_WORKERS, len(ips))
    workers = ask_int(
        "How many servers to check at the same time (max {} = all)".format(len(ips)),
        default_workers, lo=1, hi=len(ips))

    # How many times to retry a server that times out / won't connect before
    # giving up on it.
    global RETRIES
    RETRIES = ask_int(
        "How many retries when a server times out / won't connect", RETRIES,
        lo=0, hi=20)

    # If a previous scan tested some of these IPs (with passwords), offer to skip
    # them. 'tested' means we reached a verdict (found / no match); servers that
    # were only unreachable are NOT counted as tested and will be tried again.
    history = {}
    prev = State()
    if prev.exists():
        try:
            prev.load()
            history = prev.data.get("ips", {})
        except Exception:  # noqa
            history = {}
    tested = [ip for ip in ips
              if history.get(ip, {}).get("status") in ("found", "notfound")]
    skip = set()
    if tested:
        ans = ask("Re-test the {} IP(s) already tested in a previous scan? (y/n)".format(
            len(tested)), "n").lower()
        if ans not in ("y", "yes"):
            skip = set(tested)

    state = State()
    state.init_fresh({
        "ports": default_ports,
        "usernames": usernames,
        "ip_file": os.path.abspath(ip_file),
        "pw_file": os.path.abspath(pw_file),
        "workers": workers,
        "retries": RETRIES,
    })
    # Carry forward results for the IPs we're skipping, so they appear in the
    # report and are not scanned again.
    for ip in skip:
        rec = history[ip]
        if rec.get("status") == "found":
            state.set_done(ip, "found", port=rec.get("port"),
                           username=rec.get("username", "root"),
                           password=rec.get("password", ""))
        else:
            state.set_done(ip, "notfound", port=rec.get("port"))

    results, elapsed = do_scan(default_ports, portlists, usernames, ips, passwords, state,
                              resume=False, workers=workers)
    if results is None:
        return                       # detached to background; parent is done
    report(default_ports, portlists, usernames, ips, results, elapsed)


def _load_saved_scan():
    """Load the saved state + config and rebuild the scan inputs. Used by both
    `continue` and `retry`. Returns (state, default_ports, portlists, usernames,
    ips, passwords, workers)."""
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
    default_ports = cfg.get("ports") or [cfg.get("port", 22)]
    usernames = cfg.get("usernames") or [cfg.get("username", "root")]
    ip_file = cfg.get("ip_file", "ip.txt")
    pw_file = cfg.get("pw_file", "password.txt")
    workers = cfg.get("workers")
    global RETRIES
    if cfg.get("retries") is not None:
        RETRIES = int(cfg.get("retries"))

    for label, path in (("IP", ip_file), ("Password", pw_file)):
        if not os.path.isfile(path):
            log(C.R + "[!] {} file no longer exists: {}".format(label, path) + C.END)
            log("    Put it back, or start a fresh scan with: " + C.BOLD + "nexv start" + C.END)
            sys.exit(1)

    raw_ips, _ = load_lines(ip_file)
    passwords, _ = load_lines(pw_file)
    ips, portlists, _ = build_targets(raw_ips, default_ports)
    if not ips or not passwords:
        log(C.R + "[!] IP or password file is now empty." + C.END)
        sys.exit(1)
    return state, default_ports, portlists, usernames, ips, passwords, workers


def run_resume():
    """Resume an interrupted scan from the saved progress file."""
    state, default_ports, portlists, usernames, ips, passwords, workers = _load_saved_scan()
    log(C.DIM + "Resuming previous scan..." + C.END)
    results, elapsed = do_scan(default_ports, portlists, usernames, ips, passwords, state,
                              resume=True, workers=workers)
    if results is None:
        return
    report(default_ports, portlists, usernames, ips, results, elapsed)


def run_retry():
    """Re-try the servers that errored.

    If a scan is currently running, ask it (via signal) to add a retry round for
    its failed servers, without stopping its work. Otherwise, run a standalone
    retry of the failed servers from the saved progress.
    """
    # Is a scan already running? Ask it to retry its failures.
    pid = None
    try:
        if os.path.isfile(PID_PATH):
            with open(PID_PATH) as fh:
                pid = int((fh.read() or "0").strip())
    except Exception:  # noqa
        pid = None
    if pid and pid != os.getpid():
        try:
            os.kill(pid, signal.SIGUSR1)
            log(C.G + "Asked the running scan (pid {}) to re-try its failed servers.".format(pid) + C.END)
            log(C.DIM + "The running scan keeps going; failed servers get an extra round." + C.END)
            return
        except ProcessLookupError:
            pass            # stale pid file; fall through to standalone retry
        except Exception as e:  # noqa
            log(C.Y + "[!] Could not signal the running scan: {}".format(e) + C.END)

    # No scan running: standalone retry of the failed servers.
    state, default_ports, portlists, usernames, ips, passwords, workers = _load_saved_scan()
    failed = [h for h in ips if (state.get(h) or {}).get("status") in ("unreachable",)]
    if not failed:
        log(C.G + "No failed servers to re-try." + C.END)
        return
    log(C.DIM + "Re-trying {} failed server(s)...".format(len(failed)) + C.END)
    results, elapsed = do_scan(default_ports, portlists, usernames, ips, passwords, state,
                              resume=True, workers=workers, retry_failed=True,
                              ask_background=False)
    if results is None:
        return
    report(default_ports, portlists, usernames, ips, results, elapsed)


def _scan_running():
    """Return the running scan's pid, or None."""
    try:
        if os.path.isfile(PID_PATH):
            with open(PID_PATH) as fh:
                pid = int((fh.read() or "0").strip())
            if pid:
                os.kill(pid, 0)   # raises if not alive
                return pid
    except Exception:  # noqa
        pass
    return None


def run_status():
    """Show a snapshot of the current/last scan from the saved state."""
    state = State()
    if not state.exists():
        log(C.Y + "No scan found yet. Start one with: " + C.BOLD + "nexv start" + C.END)
        return
    try:
        state.load()
    except Exception as e:  # noqa
        log(C.R + "[!] Could not read scan state: {}".format(e) + C.END)
        return

    cfg = state.config()
    ip_file = cfg.get("ip_file", "ip.txt")
    default_ports = cfg.get("ports") or [cfg.get("port", 22)]
    total = None
    if os.path.isfile(ip_file):
        ips, _, _ = build_targets(load_lines(ip_file)[0], default_ports)
        total = len(ips)

    recs = state.data.get("ips", {})
    found = [h for h, r in recs.items() if r.get("status") == "found"]
    none_ = [h for h, r in recs.items() if r.get("status") == "notfound"]
    failed = [h for h, r in recs.items() if r.get("status") == "unreachable"]
    inprog = [h for h, r in recs.items() if r.get("status") == "inprogress"]
    done = len(found) + len(none_) + len(failed)
    if total is None:
        total = done + len(inprog)
    queued = max(0, total - done - len(inprog))

    pid = _scan_running()
    log("")
    if pid:
        log(C.G + C.BOLD + "● Scan running (pid {})".format(pid) + C.END)
    else:
        log(C.DIM + "○ No scan running (showing last results)" + C.END)
    log("  total {}  ·  {}scanning {}{}  ·  done {}  ·  {}matched {}{}  ·  {}failed {}{}  ·  queued {}".format(
        total, C.CY, len(inprog), C.END, done,
        C.G, len(found), C.END, C.R, len(failed), C.END, queued))
    log("")
    if found:
        log(C.G + C.BOLD + "MATCHED ({}):".format(len(found)) + C.END)
        order = {}
        for h in found:
            r = recs[h]
            log("  {}{:<18}{} {:<6} {:<14} {}{}{}".format(
                C.CY, h, C.END, r.get("port") or default_ports[0],
                r.get("username", "root"), C.G, r.get("password", ""), C.END))
        log("")
    if pid:
        log(C.DIM + "Commands: nexv retry (re-try failed) · nexv stop · nexv status" + C.END)
    else:
        log(C.DIM + "Commands: nexv continue (finish) · nexv retry (re-try failed)" + C.END)


def main():
    banner()
    arg = sys.argv[1].lower() if len(sys.argv) > 1 else ""
    if arg in ("continue", "--continue", "-c", "resume", "--resume"):
        run_resume()
    elif arg in ("retry", "--retry", "-r"):
        run_retry()
    elif arg in ("status", "--status", "-s"):
        run_status()
    else:
        run_fresh()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\n" + C.Y + "Interrupted by user." + C.END)
        sys.exit(130)
