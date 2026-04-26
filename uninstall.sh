#!/usr/bin/env sh
set -eu

printf 'This will remove the local Grudarin virtual environment and launcher helpers from the current directory.\n'
printf 'Continue? [y/N] '
read -r answer
case "$answer" in
    y|Y|yes|YES)
        ;;
    *)
        printf 'Aborted\n'
        exit 0
        ;;
esac

printf '[1/3] Removing virtual environment\n'
rm -rf .venv

printf '[2/3] Removing launcher helpers\n'
rm -f grudarin grudarin.bat

printf '[3/3] Removing local build artifacts\n'
rm -rf build dist *.egg-info

printf 'Uninstall complete. Source files were kept intact.\n'
