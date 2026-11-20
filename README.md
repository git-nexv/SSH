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

## How it works

- For each server it tries the passwords one by one and **stops at the first
  match** (so once it finds the right password for a server, it moves on).
- It tests up to **15 servers at the same time** to stay fast.
- It separates three outcomes: a password matched, no password matched, or the
  server couldn't be reached (down / firewalled / wrong port).

## Notes & tuning

You can tweak behavior at the top of `nexv_ssh.py`:

- `CONNECT_TIMEOUT` / `AUTH_TIMEOUT` — connection and auth timeouts (seconds)
- `MAX_WORKERS` — how many servers to scan in parallel
- Set `NO_COLOR=1` to disable colored output.

## Requirements

- Linux (works on most distros: Debian/Ubuntu, RHEL/CentOS/Fedora, Arch, Alpine, openSUSE)
- Python 3 (installed automatically by the installer)
- `paramiko` (installed automatically)

## Uninstall

```bash
sudo rm -f /usr/local/bin/nexv-ssh ~/.local/bin/nexv-ssh
rm -rf ~/.nexv-ssh
```
