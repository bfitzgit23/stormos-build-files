#!/bin/bash
#
# CyberXero Toolkit — Calamares post-install builder
# Runs inside the target chroot after user creation. Clones the toolkit
# from GitHub, compiles it, and installs it to /opt/cyberxero-toolkit.
#
set -u

LOG=/var/log/cyberxero-postinstall.log
exec > >(tee -a "$LOG") 2>&1

REPO_URL="https://github.com/MurderFromMars/CyberXero-Toolkit"
SRC_DIR="/opt/cyberxero-toolkit-src"
INSTALL_DIR="/opt/cyberxero-toolkit"

echo "=================================================="
echo "CyberXero Toolkit post-install — $(date)"
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
        install -Dm755 "target/release/$bin" "$INSTALL_DIR/$bin"
    fi
done

if [ -d sources/scripts ]; then
    find sources/scripts -maxdepth 1 -type f -exec install -Dm755 {} "$INSTALL_DIR/sources/scripts/" \;
fi
if [ -d sources/systemd ]; then
    find sources/systemd -maxdepth 1 -type f -exec install -Dm644 {} "$INSTALL_DIR/sources/systemd/" \;
fi

ln -sf "$INSTALL_DIR/cyberxero-toolkit" /usr/bin/cyberxero-toolkit

if [ -f packaging/cyberxero-toolkit.desktop ]; then
    install -Dm644 packaging/cyberxero-toolkit.desktop /usr/share/applications/cyberxero-toolkit.desktop
fi
if [ -f gui/resources/icons/scalable/apps/cyberxero-toolkit.png ]; then
    install -Dm644 gui/resources/icons/scalable/apps/cyberxero-toolkit.png /usr/share/icons/hicolor/scalable/apps/cyberxero-toolkit.png
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

echo "CyberXero Toolkit installed to $INSTALL_DIR"
exit 0
