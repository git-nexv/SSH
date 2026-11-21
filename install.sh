#!/usr/bin/env bash
#
# nexv installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/git-nexv/SSH/main/install.sh | bash
#
set -euo pipefail

REPO_URL="https://github.com/git-nexv/SSH.git"
RAW_PY="https://raw.githubusercontent.com/git-nexv/SSH/main/nexv_ssh.py"
INSTALL_DIR="${HOME}/.nexv-ssh"
BIN_DIR="/usr/local/bin"
CMD_NAME="nexv"

GREEN='\033[92m'; YELLOW='\033[93m'; RED='\033[91m'; BOLD='\033[1m'; END='\033[0m'
say()  { echo -e "${GREEN}[*]${END} $*"; }
warn() { echo -e "${YELLOW}[!]${END} $*"; }
die()  { echo -e "${RED}[x]${END} $*" >&2; exit 1; }

# ---- sudo helper (works whether or not we are already root) ----------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        warn "Not root and sudo not found; system install steps may fail."
    fi
fi

say "Installing nexv ..."

# ---- install python3 + pip + git ------------------------------------------
install_deps() {
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get update -y
        $SUDO apt-get install -y python3 python3-pip python3-venv git sshpass openssh-client
    elif command -v dnf >/dev/null 2>&1; then
        $SUDO dnf install -y python3 python3-pip git sshpass openssh-clients
    elif command -v yum >/dev/null 2>&1; then
        $SUDO yum install -y python3 python3-pip git sshpass openssh-clients
    elif command -v pacman >/dev/null 2>&1; then
        $SUDO pacman -Sy --noconfirm python python-pip git sshpass openssh
    elif command -v apk >/dev/null 2>&1; then
        $SUDO apk add --no-cache python3 py3-pip git sshpass openssh-client
    elif command -v zypper >/dev/null 2>&1; then
        $SUDO zypper install -y python3 python3-pip git sshpass openssh
    else
        warn "Unknown package manager. Make sure python3, pip, git and sshpass are installed."
    fi
}
install_deps

command -v python3 >/dev/null 2>&1 || die "python3 is required but was not installed."

# ---- fetch the program -----------------------------------------------------
mkdir -p "$INSTALL_DIR"
if command -v git >/dev/null 2>&1; then
    if [ -d "$INSTALL_DIR/.git" ]; then
        say "Updating existing copy ..."
        git -C "$INSTALL_DIR" pull --ff-only || true
    else
        rm -rf "$INSTALL_DIR"
        git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
    fi
else
    say "git not available, downloading script directly ..."
    curl -fsSL "$RAW_PY" -o "$INSTALL_DIR/nexv_ssh.py"
fi

# ---- install paramiko (prefer an isolated venv) ----------------------------
VENV_DIR="$INSTALL_DIR/venv"
PYBIN=""
if python3 -m venv "$VENV_DIR" 2>/dev/null; then
    "$VENV_DIR/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
    if "$VENV_DIR/bin/pip" install paramiko; then
        PYBIN="$VENV_DIR/bin/python"
    fi
fi

if [ -z "$PYBIN" ]; then
    warn "venv install failed; trying a direct pip install (paramiko fallback) ..."
    python3 -m pip install --user paramiko --break-system-packages 2>/dev/null \
        || python3 -m pip install --user paramiko 2>/dev/null \
        || warn "paramiko not installed; will rely on sshpass + openssh (recommended anyway)."
    PYBIN="python3"
fi

# sshpass is the primary engine; make sure it is present.
if ! command -v sshpass >/dev/null 2>&1; then
    warn "sshpass not found. The tool works best with it; the installer tried to"
    warn "install it above. If missing, install manually (e.g. apt install sshpass)."
fi

# ---- create the launcher command ------------------------------------------
LAUNCHER="$INSTALL_DIR/launcher.sh"
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
# nexv launcher (auto-generated)
NEXV_DIR="$INSTALL_DIR"
PYBIN="$PYBIN"
INSTALL_URL="https://raw.githubusercontent.com/git-nexv/SSH/main/install.sh"
CMD_NAME="$CMD_NAME"
EOF
cat >> "$LAUNCHER" <<'EOF'

_sudo=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then _sudo="sudo"; fi

show_help() {
    local C B D R    # cyan, bold, dim, reset
    if [ -t 1 ]; then C=$'\033[96m'; B=$'\033[1m'; D=$'\033[2m'; R=$'\033[0m';
    else C=''; B=''; D=''; R=''; fi
    local line="────────────────────────────────────────────────────────"

    printf '\n'
    printf '  %s%snexv%s  ·  SSH credential finder\n' "$C" "$B" "$R"
    printf '  %sFind which password opens which of your SSH servers.%s\n\n' "$D" "$R"

    printf '  %s%sCOMMANDS%s\n' "$C" "$B" "$R"
    printf '  %s%s%s\n' "$D" "$line" "$R"
    printf '    %s%-15s%s %s\n' "$B" "nexv start"     "$R" "Start a new scan (asks the questions below)"
    printf '    %s%-15s%s %s\n' "$B" "nexv continue"  "$R" "Resume an interrupted scan where it stopped"
    printf '    %s%-15s%s %s\n' "$B" "nexv status"    "$R" "Watch the running scan live (full screen)"
    printf '    %s%-15s%s %s\n' "$B" "nexv retry"     "$R" "Re-try the servers that errored (works mid-scan)"
    printf '    %s%-15s%s %s\n' "$B" "nexv stop"      "$R" "Stop a scan that is currently running"
    printf '    %s%-15s%s %s\n' "$B" "nexv update"    "$R" "Update to the latest version from GitHub"
    printf '    %s%-15s%s %s\n' "$B" "nexv uninstall" "$R" "Remove nexv from this machine"
    printf '    %s%-15s%s %s\n' "$B" "nexv help"      "$R" "Show this menu"
    printf '\n'
    printf '    %sThe scan keeps running even if you close the terminal. On the live%s\n' "$D" "$R"
    printf '    %sscreen you can type %sretry%s%s / %sstop%s%s / %squit%s%s and press Enter, or%s\n' "$D" "$B" "$R" "$D" "$B" "$R" "$D" "$B" "$R" "$D" "$R"
    printf '    %sreattach any time with %snexv status%s%s.%s\n' "$D" "$B" "$R" "$D" "$R"
    printf '\n'

    printf '  %s%sWHAT "nexv start" ASKS%s\n' "$C" "$B" "$R"
    printf '  %s%s%s\n' "$D" "$line" "$R"
    printf '    %-22s %s\n' "SSH port(s)"        "one or more, e.g. 22 or 22 2222   (default 22)"
    printf '    %-22s %s\n' "username / file"    "a name, or a usernames file       (default root)"
    printf '    %-22s %s\n' "IP list file"       "one IP per line                   (ip.txt)"
    printf '    %-22s %s\n' "password list file" "one password per line             (password.txt)"
    printf '    %-22s %s\n' "parallel servers"   "how many to check at once         (no limit)"
    printf '    %-22s %s\n' "retries"            "attempts on timeout / reset       (default 3)"
    printf '\n'

    printf '  %s%sFILES%s   %s(in the folder you run nexv from)%s\n' "$C" "$B" "$R" "$D" "$R"
    printf '  %s%s%s\n' "$D" "$line" "$R"
    printf '    %s%-16s%s %s\n' "$B" "ip.txt"        "$R" "one IP per line; optional IP:PORT per line"
    printf '    %s%-16s%s %s\n' "$B" "password.txt"  "$R" "one password per line"
    printf '    %s%-16s%s %s\n' "$B" "users.txt"     "$R" "(optional) one username per line"
    printf '    %s%-16s%s %s\n' "$B" "nexv_results_*" "$R" "saved report, written after each scan"
    printf '\n'

    printf '  %s%sSPEED%s   %s(optional environment variables)%s\n' "$C" "$B" "$R" "$D" "$R"
    printf '  %s%s%s\n' "$D" "$line" "$R"
    printf '    %s%-16s%s %s\n' "$B" "NEXV_TIMEOUT"  "$R" "per-attempt timeout in seconds   (default 3)"
    printf '    %s%-16s%s %s\n' "$B" "NEXV_PROBE"    "$R" "TCP port-probe timeout in seconds"
    printf '    %s%-16s%s %s\n' "$B" "NEXV_DELAY"    "$R" "pause between attempts (if rate-limited)"
    printf '    %sexample:%s NEXV_TIMEOUT=2 nexv start\n' "$D" "$R"
    printf '\n'
    printf '  %sUse only on servers you own or are authorized to test.%s\n\n' "$D" "$R"
}

case "${1:-}" in
    start|run|scan)
        exec "$PYBIN" "$NEXV_DIR/nexv_ssh.py" start
        ;;
    continue|resume|-c|--continue)
        exec "$PYBIN" "$NEXV_DIR/nexv_ssh.py" continue
        ;;
    retry|--retry|-r)
        exec "$PYBIN" "$NEXV_DIR/nexv_ssh.py" retry
        ;;
    status|--status|-s)
        exec "$PYBIN" "$NEXV_DIR/nexv_ssh.py" status
        ;;
    stop|kill)
        # Stop the running nexv scan (progress is saved; resume with 'nexv continue').
        pidf="$NEXV_DIR/nexv.pid"
        if [ -f "$pidf" ] && kill "$(cat "$pidf" 2>/dev/null)" 2>/dev/null; then
            rm -f "$pidf"
            echo "[*] Stopped the running nexv scan. Resume later with: nexv continue"
        else
            rm -f "$pidf" 2>/dev/null
            echo "[*] No running nexv scan was found."
        fi
        exit 0
        ;;
    update|--update|-u)
        echo "[*] Updating nexv ..."
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$INSTALL_URL" | bash
        else
            wget -qO- "$INSTALL_URL" | bash
        fi
        exit $?
        ;;
    uninstall|remove|--uninstall|--remove)
        echo "[*] Uninstalling nexv ..."
        $_sudo rm -f /usr/local/bin/nexv /usr/local/bin/nexv-ssh 2>/dev/null \
            || rm -f /usr/local/bin/nexv /usr/local/bin/nexv-ssh 2>/dev/null
        rm -f "$HOME/.local/bin/nexv" "$HOME/.local/bin/nexv-ssh" 2>/dev/null
        rm -rf "$NEXV_DIR"
        echo "[*] Done. nexv has been removed."
        exit 0
        ;;
    help|--help|-h|"")
        show_help
        exit 0
        ;;
    *)
        echo "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
EOF
chmod +x "$LAUNCHER"

# Remove any old 'nexv-ssh' command from the previous naming.
$SUDO rm -f "$BIN_DIR/nexv-ssh" 2>/dev/null || true
rm -f "$HOME/.local/bin/nexv-ssh" 2>/dev/null || true

if [ -w "$BIN_DIR" ] || [ -n "$SUDO" ]; then
    $SUDO ln -sf "$LAUNCHER" "$BIN_DIR/$CMD_NAME"
    TARGET="$BIN_DIR/$CMD_NAME"
else
    mkdir -p "$HOME/.local/bin"
    ln -sf "$LAUNCHER" "$HOME/.local/bin/$CMD_NAME"
    TARGET="$HOME/.local/bin/$CMD_NAME"
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) warn "Add ~/.local/bin to your PATH to run '$CMD_NAME' from anywhere." ;;
    esac
fi

echo ""
say "${BOLD}Done!${END} Installed as: ${BOLD}${CMD_NAME}${END}  (${TARGET})"
echo ""
echo -e "Start a scan:   ${BOLD}nexv start${END}"
echo "It will ask for: SSH port, username, IP file, password file, parallel count."
echo ""
echo "Other commands:"
echo -e "  ${BOLD}nexv continue${END}    resume an interrupted scan"
echo -e "  ${BOLD}nexv update${END}      update to the latest version"
echo -e "  ${BOLD}nexv uninstall${END}   remove nexv"
echo ""
