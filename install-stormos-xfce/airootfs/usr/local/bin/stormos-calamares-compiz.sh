#!/usr/bin/env bash
#
# stormos-calamares-compiz.sh — Calamares post-install step (XFCE ISO only).
# Runs INSIDE the installed (target) system via Calamares' shellprocess,
# with the target mounted at / (dontChroot: false).
#
# Installs compiz-easy-patch from the AUR and deploys the StormOS compiz
# autostart entry + wrapper so the session can restore Compiz when the
# user toggles it on.
#
set -uo pipefail

log() { echo "[stormos-compiz] $*"; }

# --- 1. Build prerequisites --------------------------------------------------
log "Installing build prerequisites..."
pacman -S --noconfirm --needed git base-devel >/dev/null 2>&1 || true

# A temp build user (makepkg refuses to run as root)
BUILD_USER=stormos-build
if ! id "$BUILD_USER" &>/dev/null; then
    useradd -m -G wheel "$BUILD_USER" 2>/dev/null
    echo "$BUILD_USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/$BUILD_USER
fi

# --- 2. Fetch and build compiz-easy-patch from the repo copy -----------------
BUILD_DIR=$(mktemp -d)
cp -r /usr/share/stormos/pkg/compiz-easy-patch "$BUILD_DIR/" 2>/dev/null \
    || cp -r /run/archiso/bootmnt/usr/share/stormos/pkg/compiz-easy-patch "$BUILD_DIR/" 2>/dev/null

if [ ! -d "$BUILD_DIR/compiz-easy-patch" ]; then
    # Fall back to fetching from GitHub build-files repo
    git clone --depth 1 https://github.com/bfitzgit23/stormos-build-files "$BUILD_DIR/sbf" 2>/dev/null
    [ -d "$BUILD_DIR/sbf/compiz-easy-patch" ] && mv "$BUILD_DIR/sbf/compiz-easy-patch" "$BUILD_DIR/"
fi

if [ ! -f "$BUILD_DIR/compiz-easy-patch/PKGBUILD" ]; then
    log "ERROR: compiz-easy-patch PKGBUILD not found — skipping compiz install"
    exit 0
fi

chown -R "$BUILD_USER:" "$BUILD_DIR"
sudo -u "$BUILD_USER" bash -c "cd $BUILD_DIR/compiz-easy-patch && makepkg -sf --noconfirm" >> /var/log/stormos-compiz-build.log 2>&1
if pacman -U --noconfirm "$BUILD_DIR"/compiz-easy-patch/*.pkg.tar.zst >> /var/log/stormos-compiz-build.log 2>&1; then
    log "compiz-easy-patch installed"
else
    log "ERROR: compiz-easy-patch build/install failed (see /var/log/stormos-compiz-build.log)"
fi

# --- 3. Deploy autostart wrapper + entry for every real user home ------------
install -Dm755 /usr/local/bin/stormos-compiz-autostart /usr/local/bin/stormos-compiz-autostart 2>/dev/null || true

for skel_home in /root /home/*; do
    [ -d "$skel_home" ] || continue
    mkdir -p "$skel_home/.config/autostart"
    cp /usr/share/stormos/compiz/stormos-compiz.desktop "$skel_home/.config/autostart/" 2>/dev/null || true
    chown -R "$(stat -c %U:$G "$skel_home")" "$skel_home/.config/autostart" 2>/dev/null || true
done

# --- 4. Clean up the build user ----------------------------------------------
rm -f /etc/sudoers.d/$BUILD_USER
userdel -r "$BUILD_USER" 2>/dev/null || true
rm -rf "$BUILD_DIR"

log "Compiz setup complete"
exit 0
