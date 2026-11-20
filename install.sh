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
        $SUDO apt-get install -y python3 python3-pip python3-venv git
    elif command -v dnf >/dev/null 2>&1; then
        $SUDO dnf install -y python3 python3-pip git
    elif command -v yum >/dev/null 2>&1; then
        $SUDO yum install -y python3 python3-pip git
    elif command -v pacman >/dev/null 2>&1; then
        $SUDO pacman -Sy --noconfirm python python-pip git
    elif command -v apk >/dev/null 2>&1; then
        $SUDO apk add --no-cache python3 py3-pip git
    elif command -v zypper >/dev/null 2>&1; then
        $SUDO zypper install -y python3 python3-pip git
    else
        warn "Unknown package manager. Make sure python3, pip and git are installed."
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
    warn "venv install failed, trying a direct pip install ..."
    python3 -m pip install --user paramiko --break-system-packages 2>/dev/null \
        || python3 -m pip install --user paramiko \
        || die "Could not install paramiko. Install it manually: pip3 install paramiko"
    PYBIN="python3"
fi

# ---- create the launcher command ------------------------------------------
LAUNCHER="$INSTALL_DIR/launcher.sh"
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
exec "$PYBIN" "$INSTALL_DIR/nexv_ssh.py" "\$@"
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
