#!/usr/bin/env sh
set -eu

printf '[1/5] Creating virtual environment\n'
python3 -m venv .venv

printf '[2/5] Activating environment\n'
. .venv/bin/activate

printf '[3/5] Upgrading pip\n'
python -m pip install --upgrade pip

printf '[4/5] Installing Grudarin in editable mode\n'
python -m pip install -e .

printf '[5/5] Creating launcher helper\n'
cat > grudarin <<'EOF'
#!/usr/bin/env sh
set -eu
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/.venv/bin/activate"
exec python -m grudarin_app.cli "$@"
EOF
chmod +x grudarin

printf 'Installation complete\n'
printf 'Run one of the following commands:\n'
printf '  ./.venv/bin/grudarin --help\n'
printf '  ./grudarin interfaces\n'
printf '  ./grudarin scan\n'
