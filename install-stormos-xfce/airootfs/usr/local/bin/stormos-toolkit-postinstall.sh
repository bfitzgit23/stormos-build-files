#!/bin/bash
#
# StormOS Toolkit — Calamares post-install builder
# Runs inside the target chroot after user creation. Clones the toolkit
# from GitHub, compiles it, and installs it to /opt/stormos-toolkit.
#
# Originally created by DarkXero / XeroLinux (CyberXero Toolkit).
# Adapted for StormOS by Ben Fitzpatrick.
# https://github.com/MurderFromMars/CyberXero-Toolkit
#
set -u

LOG=/var/log/stormos-toolkit-postinstall.log
exec > >(tee -a "$LOG") 2>&1

REPO_URL="https://github.com/MurderFromMars/CyberXero-Toolkit"
SRC_DIR="/opt/stormos-toolkit-src"
INSTALL_DIR="/opt/stormos-toolkit"

echo "=================================================="
echo "StormOS Toolkit post-install — $(date)"
echo "Originally by DarkXero / XeroLinux"
echo "=================================================="

if ! command -v cargo >/dev/null 2>&1; then
    echo "rust/cargo not present in target; skipping toolkit build" >&2
    exit 0
fi

if ! command -v git >/dev/null 2>&1; then
    echo "git not present in target; skipping toolkit build" >&2
    exit 0
fi

rm -rf "$SRC_DIR"
git clone --depth 1 "$REPO_URL" "$SRC_DIR" || {
    echo "git clone failed (no network in chroot?); skipping toolkit build" >&2
    exit 0
}

cd "$SRC_DIR" || exit 0

export CARGO_HOME="${CARGO_HOME:-/root/.cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$SRC_DIR/target}"

echo "Running cargo build --release (this can take 5-15 min)…"
if ! cargo build --release; then
    echo "cargo build failed; leaving source at $SRC_DIR for later manual build" >&2
    exit 0
fi

install -d "$INSTALL_DIR" "$INSTALL_DIR/sources/scripts" "$INSTALL_DIR/sources/systemd"

for bin in cyberxero-toolkit cyberxero-authd cyberxero-auth; do
    if [ -f "target/release/$bin" ]; then
        # Rename binaries to stormos-toolkit
        newname="${bin/cyberxero-/stormos-toolkit-}"
        install -Dm755 "target/release/$bin" "$INSTALL_DIR/$newname"
    fi
done

if [ -d sources/scripts ]; then
    find sources/scripts -maxdepth 1 -type f -exec install -Dm755 {} "$INSTALL_DIR/sources/scripts/" \;
fi
if [ -d sources/systemd ]; then
    find sources/systemd -maxdepth 1 -type f -exec install -Dm644 {} "$INSTALL_DIR/sources/systemd/" \;
fi

# Create symlinks with stormos names
ln -sf "$INSTALL_DIR/stormos-toolkit-toolkit" /usr/bin/stormos-toolkit 2>/dev/null || true
# Also keep the original name for compatibility
ln -sf "$INSTALL_DIR/stormos-toolkit-toolkit" /usr/bin/cyberxero-toolkit 2>/dev/null || true

if [ -f packaging/cyberxero-toolkit.desktop ]; then
    # Create a StormOS-branded desktop entry
    cat > /usr/share/applications/stormos-toolkit.desktop << 'DESKTOP'
[Desktop Entry]
Type=Application
Name=StormOS Toolkit
Comment=System toolkit (based on CyberXero by DarkXero/XeroLinux)
Exec=/opt/stormos-toolkit/stormos-toolkit-toolkit
Icon=stormos-toolkit
Terminal=true
Categories=System;
DESKTOP
fi
if [ -f gui/resources/icons/scalable/apps/cyberxero-toolkit.png ]; then
    install -Dm644 gui/resources/icons/scalable/apps/cyberxero-toolkit.png /usr/share/icons/hicolor/scalable/apps/stormos-toolkit.png
fi

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor 2>/dev/null || true
fi

if [ -d extra-scripts/usr/local/bin ]; then
    find extra-scripts/usr/local/bin -maxdepth 1 -type f -exec install -Dm755 {} /usr/local/bin/ \;
fi

if git rev-parse HEAD >/dev/null 2>&1; then
    git rev-parse HEAD > "$INSTALL_DIR/.commit"
fi

echo "StormOS Toolkit installed to $INSTALL_DIR"
echo "Originally created by DarkXero / XeroLinux (CyberXero Toolkit)"
exit 0
