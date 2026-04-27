#!/bin/bash
# grudarin installation helper
# Run once to install Python dependencies.

set -e

echo ""
echo "grudarin - Network Intelligence Monitor"
echo "Installation script"
echo "---------------------------------------"

# Check Python version
PYTHON=$(command -v python3 || command -v python)
if [ -z "$PYTHON" ]; then
    echo "ERROR: Python 3.10+ is required but not found."
    exit 1
fi

PY_VERSION=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Python: $PY_VERSION at $PYTHON"

# Install deps
echo ""
echo "Installing Python dependencies..."
$PYTHON -m pip install --upgrade pip --quiet
$PYTHON -m pip install -r requirements.txt

echo ""
echo "Installation complete."
echo ""
echo "Usage:"
echo "  sudo python3 grudarin.py --list-interfaces"
echo "  sudo python3 grudarin.py -i eth0 -o ~/grudarin_sessions"
echo ""
echo "NOTE: Packet capture requires root/sudo on Linux and macOS."
echo "      On Windows, install Npcap and run as Administrator."
echo ""
