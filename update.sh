#!/usr/bin/env sh
set -eu

printf '[1/4] Verifying Git repository\n'
if [ ! -d .git ]; then
    printf 'This directory is not a Git repository. Clone the project with Git first.\n' >&2
    exit 1
fi

printf '[2/4] Pulling latest changes\n'
git pull --ff-only

printf '[3/4] Activating environment\n'
. .venv/bin/activate

printf '[4/4] Reinstalling Grudarin\n'
python -m pip install --upgrade pip
python -m pip install -e .

printf 'Update complete\n'
