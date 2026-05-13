#!/bin/bash
# Grudarin - Installer
# Sets up the spy tool with C engine compilation and PATH integration

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "Installing Grudarin from $PROJECT_DIR"

# Install Python dependencies
echo "[1/4] Installing Python dependencies..."
pip install --break-system-packages scapy rich 2>/dev/null || pip install scapy rich

# Compile C engine
echo "[2/4] Compiling C capture engine..."
cd "$PROJECT_DIR/bin"
if command -v gcc &>/dev/null; then
    gcc -O3 -o grudarin_capture grudarin_capture.c -lpcap -lpthread 2>/dev/null && \
        echo "  C engine compiled" || echo "  C engine skipped (install libpcap-dev)"
else
    echo "  gcc not found, skipping C engine (Scapy fallback used)"
fi

# Install launcher to PATH
echo "[3/4] Installing grudarin command..."
LAUNCHER_SRC="$PROJECT_DIR/grudarin_launcher.sh"
LAUNCHER_DST="/usr/local/bin/grudarin"
if [ -L "$LAUNCHER_DST" ] || [ -f "$LAUNCHER_DST" ]; then
    if [ -w "$LAUNCHER_DST" ]; then
        rm -f "$LAUNCHER_DST"
    else
        echo "  Need root to update $LAUNCHER_DST"
        sudo rm -f "$LAUNCHER_DST" 2>/dev/null || true
    fi
fi
cat > "$LAUNCHER_DST" << LAUNCHER 2>/dev/null || sudo tee "$LAUNCHER_DST" > /dev/null << LAUNCHER
#!/bin/bash
PROJECT_DIR="$PROJECT_DIR"
PYTHON=""
for candidate in python3 python3.14 python3.13 python3.12 python3.11 python3.10; do
    if \$candidate -c "import scapy" 2>/dev/null; then
        PYTHON="\$candidate"
        break
    fi
done
if [ -z "\$PYTHON" ]; then PYTHON="python3"; fi
exec "\$PYTHON" -c "
import sys
sys.path.insert(0, '$PROJECT_DIR')
sys.argv[0] = 'grudarin'
import runpy
runpy.run_module('grudarin', run_name='__main__')
" "\$@"
LAUNCHER
chmod +x "$LAUNCHER_DST" 2>/dev/null || sudo chmod +x "$LAUNCHER_DST"
echo "  Installed to $LAUNCHER_DST"

# Verify
echo "[4/4] Verifying installation..."
"$LAUNCHER_DST" --list 2>&1 | head -5
echo ""
echo "Installation complete! Run: sudo grudarin --scan <interface>"
echo "Examples:"
echo "  sudo grudarin --list"
echo "  sudo grudarin --scan wlan0 --monitor Pixel"
echo "  sudo grudarin --scan eth0 --stealth"
