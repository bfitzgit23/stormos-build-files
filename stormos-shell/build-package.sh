#!/usr/bin/env bash
# build-package.sh — Build the stormos-react-desktop Arch package.
#
# Creates a source tarball with the correct directory name, then runs makepkg.
#
# Usage:
#   ./build-package.sh            # build + install
#   ./build-package.sh --src-only # just create the tarball
#   ./build-package.sh -i         # build + install with pacman

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Read version from PKGBUILD
PKGVER=$(grep '^pkgver=' PKGBUILD | cut -d= -f2)
PKGNAME=$(grep '^pkgname=' PKGBUILD | cut -d= -f2)
TARBALL="${PKGNAME}-${PKGVER}.tar.gz"

echo "==> Building ${PKGNAME} v${PKGVER}"

# --- Step 1: Ensure dist/ exists ---
if [ ! -f dist/index.html ]; then
    echo "==> dist/ not found; building React frontend..."
    if [ ! -d node_modules ]; then
        echo "==> Installing npm dependencies..."
        npm install --no-audit --no-fund
    fi
    echo "==> Running vite build..."
    npm run build
fi

if [ ! -f dist/index.html ]; then
    echo "ERROR: dist/index.html still missing after build" >&2
    exit 1
fi

echo "==> dist/ ready ($(du -sh dist/ | cut -f1))"

# --- Step 2: Create source tarball ---
# makepkg expects the tarball to contain a directory named $PKGNAME-$PKGVER/
# We create a temp dir with that name and copy everything in.
TMPTAR=$(mktemp -d)
TMPSRC="${TMPTAR}/${PKGNAME}-${PKGVER}"
mkdir -p "$TMPSRC"

# Copy all source files (excluding node_modules, .git, dist is included)
rsync -a --exclude='node_modules' --exclude='.git' --exclude='*.tar.gz' \
    --exclude='__pycache__' --exclude='*.pyc' \
    ./ "$TMPSRC/"

echo "==> Creating source tarball..."
tar -czf "$TARBALL" -C "$TMPTAR" "${PKGNAME}-${PKGVER}"
rm -rf "$TMPTAR"

echo "==> Tarball: $(ls -lh "$TARBALL" | awk '{print $5}') — $TARBALL"
echo "==> Contents:"
tar -tzf "$TARBALL" | head -20
echo "    ... ($(tar -tzf "$TARBALL" | wc -l) total files)"

# --- Step 3: Run makepkg ---
if [ "${1:-}" = "--src-only" ]; then
    echo "==> --src-only: tarball created, skipping makepkg"
    exit 0
fi

echo "==> Running makepkg..."
MAKEPKG_FLAGS="-scf"
if [ "${1:-}" = "-i" ] || [ "${1:-}" = "--install" ]; then
    MAKEPKG_FLAGS="-sci"
fi

makepkg $MAKEPKG_FLAGS
