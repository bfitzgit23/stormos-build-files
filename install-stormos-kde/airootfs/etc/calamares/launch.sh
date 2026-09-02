#!/usr/bin/env bash
set -euo pipefail

CALAMARES_DIR="/etc/calamares"
UNPACKFS_CONFIG="${CALAMARES_DIR}/modules/unpackfs.conf"

run_as_root() {
    if [[ "$(id -u)" -eq 0 ]]; then
        "$@"
    else
        pkexec "$@"
    fi
}

if [[ -d /run/archiso/copytoram ]]; then
    run_as_root sed -i \
        -e 's|/run/archiso/bootmnt/arch/x86_64/airootfs.sfs|/run/archiso/copytoram/airootfs.sfs|g' \
        "$UNPACKFS_CONFIG"
fi

run_as_root /usr/bin/calamares "$@"
