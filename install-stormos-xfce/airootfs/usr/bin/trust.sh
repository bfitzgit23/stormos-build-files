#!/bin/bash


DESKTOP="$HOME/Desktop"
shopt -s nullglob
for f in "$DESKTOP"/*.desktop; do
    [ -f "$f" ] || continue
    chmod 755 "$f"
    hash=$(sha256sum "$f" | awk '{print $1}')
    gio set -t string "$f" metadata::xfce-exe-checksum "$hash"
done

# remove itself so it runs only once
rm -- "$0"
