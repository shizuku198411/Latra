#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(dirname -- "$script_dir")
source_path="$project_dir/build/latra"
install_dir=${LATRA_INSTALL_DIR:-"$HOME/.local/bin"}
destination="$install_dir/latra"

if ! command -v workshop >/dev/null 2>&1; then
    printf 'Canonical Workshop is required but was not found in PATH.\n' >&2
    exit 1
fi

printf 'Checking the development Workshop status...\n'
launched_workshop=false
workshop_status=$(
    cd "$project_dir"
    workshop list --no-headers | awk '$1 == "dev" { print $2; exit }'
)

case "$workshop_status" in
    Ready)
        ;;
    Off)
        printf 'Launching the development Workshop...\n'
        (cd "$project_dir" && workshop launch dev --verbose)
        launched_workshop=true
        ;;
    '')
        printf 'Development Workshop "dev" was not found.\n' >&2
        exit 1
        ;;
    *)
        printf 'Development Workshop "dev" is not ready (status: %s).\n' "$workshop_status" >&2
        printf 'Resolve its current state before running the installer again.\n' >&2
        exit 1
        ;;
esac

printf 'Building Latra in the Workshop environment...\n'
if ! (cd "$project_dir" && workshop run -- build); then
    if [ "$launched_workshop" = true ]; then
        printf 'Removing the development Workshop after the failed build...\n'
        (cd "$project_dir" && workshop remove dev) || true
    fi
    exit 1
fi

if [ "$launched_workshop" = true ]; then
    printf 'Removing the development Workshop...\n'
    (cd "$project_dir" && workshop remove dev)
fi

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
