#!/usr/bin/env bash
# ================================================================
#                    G R U D A R I N
#          Installer for Linux / macOS / WSL
# ================================================================

set -euo pipefail

GRUDARIN_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$GRUDARIN_DIR/gruenv"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "  ${GREEN}[ok]${NC}    $1"; }
warn()  { echo -e "  ${YELLOW}[warn]${NC}  $1"; }
fail()  { echo -e "  ${RED}[fail]${NC}  $1"; }
step()  { echo ""; echo -e "  ${CYAN}${BOLD}>> $1${NC}"; }

echo ""
echo -e "${CYAN}${BOLD}"
echo "    ================================================================"
echo "                          G R U D A R I N"
echo "                        Installer v1.8.1"
echo "    ================================================================"
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    warn "Not running as root. Root privileges are required for installation."
    warn "Please run: sudo ./install.sh"
    exit 1
fi

# Detect OS
step "Detecting system"
OS="unknown"; PKG="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release; OS="$ID"
elif [ "$(uname)" = "Darwin" ]; then
    OS="macos"
fi

case "$OS" in
    ubuntu|debian|kali|parrot|pop|linuxmint|raspbian) PKG="apt" ;;
    fedora|rhel|centos|rocky|alma) PKG="dnf" ;;
    arch|manjaro|endeavouros|cachyos) PKG="pacman" ;;
    opensuse*|sles) PKG="zypper" ;;
    alpine) PKG="apk" ;;
    macos) PKG="brew" ;;
esac
info "OS: $OS (pkg: $PKG)"

# Install system deps
step "Installing system dependencies"
case "$PKG" in
    apt)
        apt-get update -qq 2>/dev/null
        apt-get install -y -qq python3 python3-pip python3-venv python3-tk net-tools wireless-tools iw tcpdump 2>/dev/null || true
        info "APT packages installed" ;;
    dnf)
        dnf install -y -q python3 python3-pip python3-tkinter net-tools wireless-tools iw tcpdump 2>/dev/null || true
        info "DNF packages installed" ;;
    pacman)
        pacman -Sy --noconfirm --needed python python-pip tk net-tools iw tcpdump 2>/dev/null || true
        info "Pacman packages installed" ;;
    brew)
        brew install python3 net-tools iw tcpdump 2>/dev/null || true
        info "Homebrew packages installed" ;;
    *)
        warn "Unknown package manager. Please ensure python3, pip, tk, and iw are installed." ;;
esac

# Python env
step "Setting up Python environment"
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR" || { fail "Failed to create virtual environment"; exit 1; }
fi

PIP="$VENV_DIR/bin/pip"
PY="$VENV_DIR/bin/python"

$PIP install --upgrade pip --quiet
if [ -f "$GRUDARIN_DIR/requirements.txt" ]; then
    $PIP install -r "$GRUDARIN_DIR/requirements.txt" --quiet
    info "Python requirements installed"
fi

# Launcher
step "Creating launcher"
LAUNCHER_PATH="/usr/local/bin/grudarin"
cat > "$GRUDARIN_DIR/grudarin_launcher.sh" << LAUNCHER
#!/usr/bin/env bash
export VIRTUAL_ENV="$VENV_DIR"
export PATH="$VENV_DIR/bin:\$PATH"
export GDK_BACKEND=x11
export QT_QPA_PLATFORM=xcb
RUN_CODE="import runpy, sys; sys.path.insert(0, '$GRUDARIN_DIR'); sys.argv[0] = 'grudarin'; runpy.run_module('grudarin', run_name='__main__')"
if [ "\$EUID" -ne 0 ]; then
    exec sudo "$PY" -c "\$RUN_CODE" "\$@"
else
    exec "$PY" -c "\$RUN_CODE" "\$@"
fi
LAUNCHER
chmod +x "$GRUDARIN_DIR/grudarin_launcher.sh"

ln -sf "$GRUDARIN_DIR/grudarin_launcher.sh" "$LAUNCHER_PATH"
info "Symlink created: $LAUNCHER_PATH"

# Verify
step "Verifying installation"
if command -v grudarin &>/dev/null; then
    info "Grudarin is now available as a system command."
else
    fail "Installation failed to register command."
    exit 1
fi

echo ""
echo -e "  ${GREEN}${BOLD}Installation complete.${NC}"
echo ""
echo "  Usage:"
echo "    sudo grudarin --list"
echo "    sudo grudarin --scan wlan0"
echo "    grudarin -s google.com"
echo ""
