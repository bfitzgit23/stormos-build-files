#!/bin/bash
for f in ~/Desktop/*.desktop; do
    [ -f "$f" ] || continue  # Skip if no .desktop files exist
    chmod +x "$f"
    gio set -t string "$f" metadata::xfce-exe-checksum "$(sha256sum "$f" | awk '{print $1}')"
done

# Remove any stale /usr/local/bin/xfce4-terminal wrapper left behind by older
# builds. Only do this when the real terminal is actually installed.
if [ -x /usr/bin/xfce4-terminal ] && [ -f /usr/local/bin/xfce4-terminal ] && grep -qs '^#!' /usr/local/bin/xfce4-terminal; then
    rm -f /usr/local/bin/xfce4-terminal
fi

