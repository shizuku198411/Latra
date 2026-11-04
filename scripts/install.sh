#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(dirname -- "$script_dir")
source_path="$project_dir/build/latra"
install_dir=${LATRA_INSTALL_DIR:-"$HOME/.local/bin"}
destination="$install_dir/latra"

printf 'Building Latra in the Workshop environment...\n'
(cd "$project_dir" && workshop run -- build)

if [ ! -f "$source_path" ]; then
    printf 'Workshop build did not produce the expected binary: %s\n' "$source_path" >&2
    exit 1
fi

mkdir -p -- "$install_dir"
install -m 0755 -- "$source_path" "$destination"

printf 'Installed Latra to %s\n' "$destination"

case ":${PATH:-}:" in
    *:"$install_dir":*) ;;
    *)
        printf 'Add %s to PATH to run latra from any directory.\n' "$install_dir"
        ;;
esac
