#!/usr/bin/env bash
#
# nexv-ssh installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/git-nexv/SSH/main/install.sh | bash
#
set -euo pipefail

REPO_URL="https://github.com/git-nexv/SSH.git"
RAW_PY="https://raw.githubusercontent.com/git-nexv/SSH/main/nexv_ssh.py"
INSTALL_DIR="${HOME}/.nexv-ssh"
BIN_DIR="/usr/local/bin"
CMD_NAME="nexv-ssh"

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

say "Installing nexv-ssh ..."

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
# nexv-ssh launcher (auto-generated)
NEXV_DIR="$INSTALL_DIR"
PYBIN="$PYBIN"
INSTALL_URL="https://raw.githubusercontent.com/git-nexv/SSH/main/install.sh"
CMD_NAME="$CMD_NAME"
EOF
cat >> "$LAUNCHER" <<'EOF'

_sudo=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then _sudo="sudo"; fi

case "${1:-}" in
    --update|-u|update)
        echo "[*] Updating nexv-ssh ..."
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$INSTALL_URL" | bash
        else
            wget -qO- "$INSTALL_URL" | bash
        fi
        exit $?
        ;;
    --uninstall|--remove|uninstall|remove)
        echo "[*] Uninstalling nexv-ssh ..."
        $_sudo rm -f /usr/local/bin/"$CMD_NAME" 2>/dev/null || rm -f /usr/local/bin/"$CMD_NAME" 2>/dev/null
        rm -f "$HOME/.local/bin/$CMD_NAME" 2>/dev/null
        rm -rf "$NEXV_DIR"
        echo "[*] Done. nexv-ssh has been removed."
        exit 0
        ;;
    --help|-h|help)
        echo "nexv-ssh - SSH credential finder"
        echo ""
        echo "Usage:"
        echo "  nexv-ssh              Start scanning (asks: port, username, IP file, password file)"
        echo "  nexv-ssh --update     Update to the latest version from GitHub"
        echo "  nexv-ssh --uninstall  Remove nexv-ssh from this machine"
        echo "  nexv-ssh --help       Show this help"
        exit 0
        ;;
    *)
        exec "$PYBIN" "$NEXV_DIR/nexv_ssh.py" "$@"
        ;;
esac
EOF
chmod +x "$LAUNCHER"

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
echo -e "Run it with:   ${BOLD}${CMD_NAME}${END}"
echo "It will ask for: SSH port, username, IP file, password file."
echo ""
echo "Other commands:"
echo -e "  ${BOLD}${CMD_NAME} --update${END}     update to the latest version"
echo -e "  ${BOLD}${CMD_NAME} --uninstall${END}  remove nexv-ssh"
echo ""
