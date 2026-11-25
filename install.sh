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
CMD_NAME="sv"

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

say "Installing sv ..."

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
    local G R W bar
    if [ -t 1 ]; then G=$'\033[92m'; R=$'\033[0m'; else G=''; R=''; fi
    W=62
    printf -v bar '%*s' $((W + 2)) ''
    bar=${bar// /═}
    _r() { printf '%s║%s %-'"$W"'s %s║%s\n' "$G" "$R" "$1" "$G" "$R"; }

    printf '\n'
    printf '%s╔%s╗%s\n' "$G" "$bar" "$R"
    _r "sv  -  SSH credential finder"
    _r "find which password opens which of your SSH servers"
    printf '%s╠%s╣%s\n' "$G" "$bar" "$R"
    _r "COMMANDS"
    _r "  sv start        start a new scan"
    _r "  sv status       watch the running scan live (full screen)"
    _r "  sv continue     resume an interrupted scan"
    _r "  sv retry        re-try the servers that errored"
    _r "  sv stop         stop the running scan"
    _r "  sv update       update to the latest version"
    _r "  sv uninstall    remove sv from this machine"
    _r "  sv help         show this menu"
    printf '%s╠%s╣%s\n' "$G" "$bar" "$R"
    _r "RESULT LISTS   (just list them)"
    _r "  sv match        found servers (shows the password)"
    _r "  sv none         searched fully, no password matched"
    _r "  sv timeout      could not connect (timeout / reset)"
    _r "  sv notdone      still running / not finished yet"
    _r "  sv <list> start   re-scan that group"
    _r "  sv <list> stop    set that group aside (ignore it)"
    printf '%s╠%s╣%s\n' "$G" "$bar" "$R"
    _r "PER-FILE MEMORY"
    _r "  fully-tested IPs are remembered per file and skipped"
    _r "  next time you scan that same file"
    _r "  sv reset <file>   forget them, test that file again"
    printf '%s╠%s╣%s\n' "$G" "$bar" "$R"
    _r "sv start asks:"
    _r "  port(s), username or file, IP file, password file,"
    _r "  how many IPs this run, how many at once, retries"
    _r "  done IPs are remembered per file (sv reset clears)"
    printf '%s╠%s╣%s\n' "$G" "$bar" "$R"
    _r "FILES   ip.txt   password.txt   users.txt (optional)"
    _r "SPEED   NEXV_TIMEOUT   NEXV_PROBE   NEXV_DELAY"
    _r "        e.g.  NEXV_TIMEOUT=2 sv start"
    printf '%s╠%s╣%s\n' "$G" "$bar" "$R"
    _r "the scan keeps running even if you close the terminal"
    _r "use only on servers you own or are authorized to test"
    printf '%s╚%s╝%s\n' "$G" "$bar" "$R"
    printf '\n'
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
    match|matched|none|nomatch|notfound|timeout|timedout|unreachable|failed|notdone|more|pending|running|reset)
        exec "$PYBIN" "$NEXV_DIR/nexv_ssh.py" "$@"
        ;;
    stop|kill)
        # Stop the running nexv scan (progress is saved; resume with 'nexv continue').
        pidf="$NEXV_DIR/nexv.pid"
        if [ -f "$pidf" ] && kill "$(cat "$pidf" 2>/dev/null)" 2>/dev/null; then
            rm -f "$pidf"
            echo "[*] Stopped the running sv scan. Resume later with: sv continue"
        else
            rm -f "$pidf" 2>/dev/null
            echo "[*] No running sv scan was found."
        fi
        exit 0
        ;;
    update|--update|-u)
        echo "[*] Updating sv ..."
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$INSTALL_URL" | bash
        else
            wget -qO- "$INSTALL_URL" | bash
        fi
        exit $?
        ;;
    uninstall|remove|--uninstall|--remove)
        echo "[*] Uninstalling sv ..."
        $_sudo rm -f /usr/local/bin/sv /usr/local/bin/nexv /usr/local/bin/nexv-ssh 2>/dev/null \
            || rm -f /usr/local/bin/sv /usr/local/bin/nexv /usr/local/bin/nexv-ssh 2>/dev/null
        rm -f "$HOME/.local/bin/sv" "$HOME/.local/bin/nexv" "$HOME/.local/bin/nexv-ssh" 2>/dev/null
        rm -rf "$NEXV_DIR"
        echo "[*] Done. sv has been removed."
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

# Remove old command names from previous naming (nexv, nexv-ssh).
$SUDO rm -f "$BIN_DIR/nexv" "$BIN_DIR/nexv-ssh" 2>/dev/null || true
rm -f "$HOME/.local/bin/nexv" "$HOME/.local/bin/nexv-ssh" 2>/dev/null || true

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
echo -e "Start a scan:   ${BOLD}sv start${END}"
echo "It will ask for: SSH port, username, IP file, password file, parallel count."
echo ""
echo "Other commands:"
echo -e "  ${BOLD}sv continue${END}    resume an interrupted scan"
echo -e "  ${BOLD}sv update${END}      update to the latest version"
echo -e "  ${BOLD}sv uninstall${END}   remove sv"
echo ""
