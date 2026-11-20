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

   **`ip.txt`** — one server IP (or hostname) per line:
   ```
   192.168.1.10
   203.0.113.5
   server1.example.com
   ```

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
   - **SSH port** (press Enter for `22`, or type another port)
   - **SSH username** (press Enter for `root`)
   - **IP list file** (e.g. `ip.txt`)
   - **Password list file** (e.g. `password.txt`)
   - **How many servers to check at the same time** — higher = faster. Default
     is all of them at once; as each server finishes, the next one starts.
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

It picks up where it left off — servers that were already finished are skipped,
and the server that was in progress resumes from the exact password it was on,
so you never have to start over.

## Commands

```bash
nexv start       # start a new scan
nexv continue    # resume an interrupted scan
nexv update      # pull the latest version from GitHub
nexv uninstall   # remove nexv from this machine
nexv help        # show all commands
```

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
── ips[10/100]  ·  matched 3  ·  3 scanning ──
```

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
