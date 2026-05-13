#!/bin/bash
# Grudarin launcher - uses the correct Python with dependencies
PROJECT_DIR="/home/cachy/zips/gru-jul/grudarin-main"

# Try to find Python with scapy installed
PYTHON=""
for candidate in python3 python3.14 python3.13 python3.12 python3.11 python3.10; do
    if $candidate -c "import scapy" 2>/dev/null; then
        PYTHON="$candidate"
        break
    fi
done

# Fallback to any python3
if [ -z "$PYTHON" ]; then
    PYTHON="python3"
fi

exec "$PYTHON" -c "
import sys
sys.path.insert(0, '$PROJECT_DIR')
sys.argv[0] = 'grudarin'
import runpy
runpy.run_module('grudarin', run_name='__main__')
" "$@"
