# nexv

A small Linux terminal tool that finds **which password opens which of your SSH servers**.

You give it a list of server IPs and a list of candidate passwords. It tries
every password against every server (in parallel) and, at the end, prints a
clean report mapping each server to the password that worked — plus the port.

Perfect for the "I own ~50 servers but forgot which of my usual passwords I set
on each one" situation.

> ⚠️ **Authorized use only.** Use this only on servers you own or have explicit
> written permission to access. Testing passwords against systems you don't own
> is illegal in most places.

---

## Install (one line)

```bash
curl -fsSL https://raw.githubusercontent.com/git-nexv/SSH/main/install.sh | bash
```

This installs the engine and registers the command `nexv`.

---

## Usage

1. In the folder where you want to work, create two files:

   **`ip.txt`** — one server IP (or hostname) per line. Optionally add a port
   as `IP:PORT` to override the default port for that one server:
   ```
   192.168.1.10
   203.0.113.5:2222
   server1.example.com:22
   ```
   Lines without a port use the port you pick when the scan starts.

   **`password.txt`** — one candidate password per line:
   ```
   MyOldPassword1
   Summer2023!
   changeme
   ```

2. Start a scan:

   ```bash
   nexv start
   ```

3. It will ask you:
   - **SSH port(s)** (press Enter for `22`). You can list several ports
     separated by spaces, e.g. `22 2222 65`; for each server the first open
     one is used. A server line can still override with its own `IP:PORT`.
   - **SSH username, or a usernames file** (press Enter for `root`). Type a
     single username, or the name of a file (e.g. `users.txt`) with one username
     per line — then every username is tried against every password.
   - **IP list file** (e.g. `ip.txt`)
   - **Password list file** (e.g. `password.txt`)
   - **How many servers to check at the same time** — higher = faster, no cap.
     The default is *all* of them at once (even hundreds); as each server
     finishes, the next one starts. Lower it only if you hit rate-limiting.
   - **How many retries when a server times out / won't connect** (default `3`)
     — a server that resets or times out is retried this many times (with
     backoff) before being marked unreachable.
   - **Re-test IPs already tested before?** (only asked if a previous scan
     tested some of these IPs; default `n`). Answer `n` to skip servers that
     already got a verdict (matched / no match) in an earlier scan — their old
     result is carried into the new report. Servers that were only *unreachable*
     before are **not** counted as tested and are tried again either way.
   - Then press `y` to start.

4. When it finishes, you get a report like:

   ```
   MATCHED SERVERS (3):

     IP                 PORT   PASSWORD
     ----------------   ----   --------------------
     192.168.1.10       22     MyOldPassword1
     203.0.113.5        22     Summer2023!
     45.33.12.8         22     changeme

   NO PASSWORD MATCHED (1):
     10.0.0.9

   UNREACHABLE / ERROR (1):
     8.8.8.8 (timeout)
   ```

   The results are also saved to a file named `nexv_results_<date>.txt`.

---

## Resume an interrupted scan

Progress is saved continuously while scanning (to `~/.nexv-ssh/state.json`).
If your SSH session drops, the server reboots, or you close the terminal in the
middle of a scan, just reopen the terminal and run:

```bash
nexv continue
```

It first reprints everything from the previous run (matches, no-matches and
unreachable servers), then picks up where it left off — finished servers are
skipped, and the server that was in progress resumes from the exact password it
was on, so you never have to start over. Unreachable servers show how many
connection attempts were made, e.g. `(rate-limited? ..., 6 tries)`.

## Commands

```bash
nexv start       # start a new scan
nexv status      # show progress + matches of the running/last scan
nexv continue    # resume an interrupted scan
nexv retry       # re-try the servers that errored
nexv stop        # stop a scan that is currently running
nexv update      # pull the latest version from GitHub
nexv uninstall   # remove nexv from this machine
nexv help        # show the full menu
```

### Watch live AND type commands at the same time

While a scan runs in the foreground you still see the live display, and there is
a command line at the bottom:

```
[01:23] 94.72.104.95     passwords[4/1000]  → raspberry
...
── total 100 · 3 scanning · done 10/100 · 3 matched · 2 failed · 87 queued ──
> retry▁   (type: retry | status | stop)
```

Type a command there and press Enter — it does **not** erase your typing:

- `retry`  — re-try the servers that errored (right now, alongside the scan)
- `status` — print a one-line summary
- `stop`   — stop the scan (progress is saved; resume with `nexv continue`)

### Or run it in the background

When you start a scan it also asks **"Run in background?"**. Answer `y` and the
scan detaches so the whole terminal is free; then use `nexv status`, `nexv retry`
and `nexv stop` as normal commands. Background output goes to `~/.nexv-ssh/scan.log`.

**`nexv retry`** re-tries the servers that failed (connection reset / timeout /
refused) without disturbing the ones already done. It also works against a scan
still running (foreground in another terminal, or a background scan).

## How it works

- For each server it tries the passwords one by one and **stops at the first
  match** (so once it finds the right password for a server, it moves on).
- It tests up to **15 servers at the same time** to stay fast.
- It separates three outcomes: a password matched, no password matched, or the
  server couldn't be reached (down / firewalled / wrong port).

## Notes & tuning

While scanning, each server being checked gets its own live row (one per
parallel worker), updating independently, with a summary line underneath:

```
[01:23] 94.72.104.95     passwords[4/1000]  → raspberry
[01:23] 85.214.203.149   passwords[12/1000] → Summer2023
[01:23] 203.0.113.5      passwords[7/1000]  → changeme
── total 100 · 3 scanning · done 10/100 · 3 matched · 2 failed · 87 queued ──
```

The summary line shows the whole picture: total servers, how many are being
checked right now, how many are done, how many matched, how many failed
(unreachable), and how many are still queued.

When a server finishes it prints a permanent MATCH / NONE / UNREACH line above
the live rows, and the freed row moves on to the next server. The `[MM:SS]`
timer updates every second; the total time is also printed at the end.

**Speed:** before trying any password, each server gets a fast TCP port probe.
Dead or filtered servers are skipped instantly instead of waiting out a timeout
on every password, and live servers usually answer each password in well under a
second.

The number of servers scanned in parallel is asked as the last question when
you run `nexv start` (higher = faster; as each server finishes, the next starts).

Other settings via environment variables:

- `NEXV_RETRIES` — retries on a transient error (connection reset / timeout)
  with backoff, before marking a server unreachable (default `3`).
- `NEXV_DELAY` — seconds to wait between attempts on one server (default `0`).
  Raise it (e.g. `1`) if servers rate-limit or ban you.
- `NEXV_TIMEOUT` — per-attempt connect/auth timeout in seconds (default `4`).
- `NEXV_PROBE` — TCP port-probe timeout in seconds (default `min(timeout, 2)`).
- `NO_COLOR=1` — disable colored output.

Example (very fast, aggressive timeouts):

```bash
NEXV_TIMEOUT=3 NEXV_PROBE=1 nexv start
```

> Lower timeouts are faster but, on distant/high-latency servers, can miss a
> valid password if the handshake doesn't finish in time. `3`–`4`s is a good
> balance; drop to `1`–`2`s only for nearby/fast servers.

> Passwords are tried **one at a time per server** (not in parallel on the same
> server) on purpose, to avoid triggering account lockouts or IP bans.

## Troubleshooting

**Lots of `UNREACH ... (rate-limited? ...)` or `connection reset` errors.**
This means the server *is* up, but it reset the connection during the SSH
handshake — the classic sign of rate-limiting (`MaxStartups`, `fail2ban`, or a
firewall) because too many connections came too fast. Fixes:

- **Lower the parallel count** when it asks (try `5`–`10` instead of all at once).
- **Add a delay** between attempts: `NEXV_DELAY=1 nexv start`.
- The tool already retries these errors a few times with backoff (`NEXV_RETRIES`).

Some VPS providers also throttle outbound SSH from *your* server when it opens
many connections at once — lowering the parallel count helps there too.

**`refused` / `port closed`** — nothing is listening on that port: the server is
down, or its SSH port is not the one you entered.

## Requirements

- Linux (works on most distros: Debian/Ubuntu, RHEL/CentOS/Fedora, Arch, Alpine, openSUSE)
- Python 3 (installed automatically by the installer)
- `paramiko` (installed automatically)

## Uninstall

```bash
sudo rm -f /usr/local/bin/nexv ~/.local/bin/nexv
rm -rf ~/.nexv-ssh
```
