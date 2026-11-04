#!/bin/sh

set -eu

install_dir=${LATRA_INSTALL_DIR:-"$HOME/.local/bin"}
destination="$install_dir/latra"

if [ ! -e "$destination" ] && [ ! -L "$destination" ]; then
    printf 'Latra is not installed at %s\n' "$destination"
    exit 0
fi

rm -- "$destination"
printf 'Removed Latra from %s\n' "$destination"
