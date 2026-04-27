#!/usr/bin/env bash
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
	DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
	TARGET="$(readlink "$SOURCE")"
	if [ "${TARGET#/}" = "$TARGET" ]; then
		SOURCE="$DIR/$TARGET"
	else
		SOURCE="$TARGET"
	fi
done
DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"

if [ -f "$DIR/gruenv/bin/python" ]; then
	GRUENV="$DIR/gruenv"
elif [ -f "$DIR/.venv/bin/python" ]; then
	GRUENV="$DIR/.venv"
else
	GRUENV=""
fi

if [ -n "$GRUENV" ]; then
	# Process-scoped activation: auto-cleans when command exits.
	export VIRTUAL_ENV="$GRUENV"
	export PATH="$GRUENV/bin:$PATH"
	export PYTHONNOUSERSITE=1
	PY="$GRUENV/bin/python"
else
	PY="python3"
fi

ENTRY="$DIR/grudarin/__main__.py"

if [ "$EUID" -ne 0 ]; then
	if [ -f "$ENTRY" ]; then
		exec sudo "$PY" "$ENTRY" "$@"
	else
		exec sudo "$PY" -m grudarin "$@"
	fi
else
	if [ -f "$ENTRY" ]; then
		exec "$PY" "$ENTRY" "$@"
	else
		exec "$PY" -m grudarin "$@"
	fi
fi
