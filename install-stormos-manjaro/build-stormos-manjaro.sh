#!/usr/bin/env bash
#
# build-stormos-manjaro.sh — Build StormOS Manjaro ISO
#
# Prerequisites:
#   sudo pacman -S manjaro-tools-iso-git
#
# Usage:
#   ./build-stormos-manjaro.sh          # build ISO
#   ./build-stormos-manjaro.sh -c       # clean build
#   ./build-stormos-manjaro.sh -v       # verbose
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_DIR="$SCRIPT_DIR/manjaro-tools-profile/xfce"

# ─── Preflight ───────────────────────────────────────────────────────────────
if ! command -v buildiso &>/dev/null; then
    echo "ERROR: manjaro-tools-iso-git not installed"
    echo "  sudo pacman -S manjaro-tools-iso-git"
    exit 1
fi

# ─── Link our theme/icon files into the overlay ─────────────────────────────
OVL="$PROFILE_DIR/overlay"
THEMES="$SCRIPT_DIR/airootfs/usr/share/themes"
ICONS="$SCRIPT_DIR/airootfs/usr/share/icons"

echo "→ Linking StormOS themes into overlay..."
mkdir -p "$OVL/usr/share/themes" "$OVL/usr/share/icons"
cp -r "$THEMES/Arc-BLACK-ICE" "$OVL/usr/share/themes/" 2>/dev/null || true
cp -r "$THEMES/StormOS-Green" "$OVL/usr/share/themes/" 2>/dev/null || true
cp -r "$THEMES/StormOS-LightBlue" "$OVL/usr/share/themes/" 2>/dev/null || true

# Copy Qogir icons (large - use symlink or minimal subset)
for size in 16 16@2x 22 scalable; do
    if [ -d "$ICONS/Qogir-dark/$size" ]; then
        mkdir -p "$OVL/usr/share/icons/Qogir-dark/$size"
        cp -r "$ICONS/Qogir-dark/$size"/* "$OVL/usr/share/icons/Qogir-dark/$size/" 2>/dev/null || true
    fi
done
# Copy the Qogir-dark index.theme
cp "$ICONS/Qogir-dark/index.theme" "$OVL/usr/share/icons/Qogir-dark/" 2>/dev/null || true

# StormOS icon variants
cp -r "$ICONS/stormos-green" "$OVL/usr/share/icons/" 2>/dev/null || true
cp -r "$ICONS/stormos-lightblue" "$OVL/usr/share/icons/" 2>/dev/null || true

# StormOS-icons
mkdir -p "$OVL/usr/share/icons/StormOS-icons"
for size in 16 22 128 scalable; do
    if [ -d "$ICONS/StormOS-icons/$size" ]; then
        mkdir -p "$OVL/usr/share/icons/StormOS-icons/$size"
        cp -r "$ICONS/StormOS-icons/$size"/* "$OVL/usr/share/icons/StormOS-icons/$size/" 2>/dev/null || true
    fi
done
cp "$ICONS/StormOS-icons/index.theme" "$OVL/usr/share/icons/StormOS-icons/" 2>/dev/null || true

# Fastfetch logo
mkdir -p "$OVL/usr/share/fastfetch/logo"
cp "$SCRIPT_DIR/airootfs/usr/share/fastfetch/logo/StormOS.txt" "$OVL/usr/share/fastfetch/logo/" 2>/dev/null || true

# ─── Build ISO ───────────────────────────────────────────────────────────────
echo "→ Building StormOS Manjaro ISO..."
cd "$SCRIPT_DIR/manjaro-tools-profile"

EXTRA_ARGS=""
for arg in "$@"; do
    EXTRA_ARGS="$EXTRA_ARGS $arg"
done

buildiso -p xfce -k linux612 -b stable $EXTRA_ARGS

echo ""
echo "✓ ISO built. Check /var/cache/manjaro-tools/iso/"
