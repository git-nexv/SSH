# nexv-ssh

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

This installs Python + paramiko and registers the command `nexv-ssh`.

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

2. Run the program:

   ```bash
   nexv-ssh
   ```

3. It will ask you:
   - **SSH port** (press Enter for `22`, or type another port)
   - **SSH username** (press Enter for `root`)
   - **IP list file** (e.g. `ip.txt`)
   - **Password list file** (e.g. `password.txt`)
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
nexv-ssh continue
```

It picks up where it left off — servers that were already finished are skipped,
and the server that was in progress resumes from the exact password it was on,
so you never have to start over.

## Update & Uninstall

```bash
nexv-ssh --update      # pull the latest version from GitHub
nexv-ssh --uninstall   # remove nexv-ssh from this machine
nexv-ssh --help        # show all commands
```

## How it works

- For each server it tries the passwords one by one and **stops at the first
  match** (so once it finds the right password for a server, it moves on).
- It tests up to **15 servers at the same time** to stay fast.
- It separates three outcomes: a password matched, no password matched, or the
  server couldn't be reached (down / firewalled / wrong port).

## Notes & tuning

A live status line shows progress while scanning:

```
passwords[11/50] ips[10/100] | 85.214.203.149 → Summer2023 | matched 3
```

**Speed:** before trying any password, each server gets a fast TCP port probe.
Dead or filtered servers are skipped instantly instead of waiting out a timeout
on every password, and live servers usually answer each password in well under a
second.

Tune with environment variables:

- `NEXV_WORKERS` — how many servers to scan in parallel (default `100`; actual
  is capped to the number of servers, so all of them run at once).
- `NEXV_TIMEOUT` — per-attempt connect/auth timeout in seconds (default `4`).
- `NEXV_PROBE` — TCP port-probe timeout in seconds (default `min(timeout, 2)`).
- `NO_COLOR=1` — disable colored output.

Example (very fast, aggressive timeouts):

```bash
NEXV_WORKERS=100 NEXV_TIMEOUT=3 NEXV_PROBE=1 nexv-ssh
```

> Lower timeouts are faster but, on distant/high-latency servers, can miss a
> valid password if the handshake doesn't finish in time. `3`–`4`s is a good
> balance; drop to `1`–`2`s only for nearby/fast servers.

> Passwords are tried **one at a time per server** (not in parallel on the same
> server) on purpose, to avoid triggering account lockouts or IP bans.

## Requirements

- Linux (works on most distros: Debian/Ubuntu, RHEL/CentOS/Fedora, Arch, Alpine, openSUSE)
- Python 3 (installed automatically by the installer)
- `paramiko` (installed automatically)

## Uninstall

```bash
sudo rm -f /usr/local/bin/nexv-ssh ~/.local/bin/nexv-ssh
rm -rf ~/.nexv-ssh
```
