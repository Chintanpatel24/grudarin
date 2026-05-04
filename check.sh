#!/usr/bin/env bash
# ================================================================
#                    G R U D A R I N
#                    Health Check Script
# ================================================================
# Verifies environment, dependencies, binaries, and runtime startup.
#
# Usage:
#   ./check.sh
#   ./check.sh --fix
# ================================================================

set -euo pipefail

GRUDARIN_DIR="$(cd "$(dirname "$0")" && pwd)"
GRUENV_DIR="$GRUDARIN_DIR/gruenv"
LEGACY_VENV_DIR="$GRUDARIN_DIR/.venv"
BIN_DIR="$GRUDARIN_DIR/bin"
FIX_MODE=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}[ok]${NC}    $1"; }
warn() { echo -e "  ${YELLOW}[warn]${NC}  $1"; }
fail() { echo -e "  ${RED}[fail]${NC}  $1"; }
step() { echo ""; echo -e "  ${CYAN}${BOLD}>> $1${NC}"; }

if [ "${1:-}" = "--fix" ]; then
    FIX_MODE=true
fi

echo ""
echo -e "${CYAN}${BOLD}"
echo "    ================================================================"
echo "                          G R U D A R I N"
echo "                          Health Check"
echo "    ================================================================"
echo -e "${NC}"

FAIL_COUNT=0
WARN_COUNT=0

# ----------------------------------------------------------------
# Detect Python environment
# ----------------------------------------------------------------
step "Detecting Python environment"
if [ -x "$GRUENV_DIR/bin/python" ]; then
    ACTIVE_ENV="$GRUENV_DIR"
    ok "Using default environment: gruenv"
elif [ -x "$LEGACY_VENV_DIR/bin/python" ]; then
    ACTIVE_ENV="$LEGACY_VENV_DIR"
    warn "Using legacy environment: .venv (consider reinstall for gruenv)"
    WARN_COUNT=$((WARN_COUNT + 1))
else
    ACTIVE_ENV=""
    warn "No virtual environment found (gruenv/.venv)"
    WARN_COUNT=$((WARN_COUNT + 1))
fi

if [ -n "$ACTIVE_ENV" ]; then
    PY="$ACTIVE_ENV/bin/python"
    PIP="$ACTIVE_ENV/bin/pip"
else
    PY="python3"
    PIP="pip3"
fi

# ----------------------------------------------------------------
# Required command checks
# ----------------------------------------------------------------
step "Checking required commands"
for cmd in python3 pip3; do
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "$cmd found"
    else
        fail "$cmd not found"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
done

# Optional but recommended tools
for cmd in g++ go cargo lua5.4 lua iw nmcli; do
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "$cmd found"
    else
        warn "$cmd not found (optional depending on feature use)"
        WARN_COUNT=$((WARN_COUNT + 1))
    fi
done

# ----------------------------------------------------------------
# Python dependency checks
# ----------------------------------------------------------------
step "Checking Python dependencies"
if "$PY" -c "import scapy, pygame" >/dev/null 2>&1; then
    ok "Python packages import successfully (scapy, pygame)"
else
    fail "Missing Python packages (scapy/pygame) in selected environment"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    if [ "$FIX_MODE" = true ]; then
        if "$PIP" install --upgrade pip >/dev/null 2>&1 && "$PIP" install -r "$GRUDARIN_DIR/requirements.txt" >/dev/null 2>&1; then
            ok "Installed missing Python dependencies"
            FAIL_COUNT=$((FAIL_COUNT - 1))
        else
            fail "Automatic Python dependency install failed"
        fi
    fi
fi

# ----------------------------------------------------------------
# Binary checks
# ----------------------------------------------------------------
step "Checking compiled components"
if [ -x "$BIN_DIR/grudarin_scanner" ]; then
    ok "C++ scanner binary present"
else
    warn "Missing C++ scanner binary: $BIN_DIR/grudarin_scanner"
    WARN_COUNT=$((WARN_COUNT + 1))
fi

if [ -x "$BIN_DIR/grudarin_netprobe" ]; then
    ok "Go netprobe binary present"
else
    warn "Missing Go netprobe binary: $BIN_DIR/grudarin_netprobe"
    WARN_COUNT=$((WARN_COUNT + 1))
fi

if [ -x "$BIN_DIR/grudarin_probe" ]; then
    ok "Rust probe helper binary present"
else
    warn "Missing Rust probe helper binary: $BIN_DIR/grudarin_probe"
    WARN_COUNT=$((WARN_COUNT + 1))
fi

# ----------------------------------------------------------------
# Launcher checks
# ----------------------------------------------------------------
step "Checking launcher"
if [ -x "$GRUDARIN_DIR/grudarin.sh" ]; then
    ok "Launcher script present"
else
    fail "Launcher missing: grudarin.sh"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

if [ -L "/usr/local/bin/grudarin" ]; then
    TARGET="$(readlink /usr/local/bin/grudarin || true)"
    ok "System command symlink present -> $TARGET"
else
    warn "System symlink missing: /usr/local/bin/grudarin"
    WARN_COUNT=$((WARN_COUNT + 1))
fi

# ----------------------------------------------------------------
# Startup smoke test
# ----------------------------------------------------------------
step "Running startup smoke test"
if "$PY" -m grudarin --help >/dev/null 2>&1; then
    ok "CLI startup works"
else
    fail "CLI startup failed"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# ----------------------------------------------------------------
# Outdated package check
# ----------------------------------------------------------------
step "Checking outdated Python packages"
if OUTDATED_JSON="$($PIP list --outdated --format=json 2>/dev/null)"; then
    OUTDATED_LINES="$(
        "$PY" - <<'PY'
import json
import sys

raw = sys.stdin.read().strip()
if not raw:
    print("")
    raise SystemExit(0)

items = json.loads(raw)
for pkg in items:
    name = pkg.get("name", "?")
    cur = pkg.get("version", "?")
    latest = pkg.get("latest_version", "?")
    print(f"{name}: {cur} -> {latest}")
PY
    <<< "$OUTDATED_JSON"
    )"

    if [ -n "$OUTDATED_LINES" ]; then
        warn "Some Python packages are outdated"
        echo "$OUTDATED_LINES" | sed 's/^/          - /'
        WARN_COUNT=$((WARN_COUNT + 1))
    else
        ok "Python packages are up to date"
    fi
else
    warn "Could not determine outdated Python packages"
    WARN_COUNT=$((WARN_COUNT + 1))
fi

# ----------------------------------------------------------------
# Summary
# ----------------------------------------------------------------
echo ""
echo -e "  ${CYAN}${BOLD}Summary${NC}"
echo "  Failures: $FAIL_COUNT"
echo "  Warnings: $WARN_COUNT"

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "\n  ${GREEN}${BOLD}Health check passed.${NC}"
    exit 0
fi

echo -e "\n  ${RED}${BOLD}Health check failed.${NC}"
echo "  Suggested fix: sudo ./install.sh"
exit 1
