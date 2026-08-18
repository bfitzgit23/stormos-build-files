#!/bin/bash -e
#
##############################################################################
#  PostInstall - StormOS setup script
##############################################################################

USER_NAME=$(logname)

rm -f "/home/$USER_NAME/Desktop/calamares.desktop" || true

reflector --protocol https --latest 20 --sort rate --save /etc/pacman.d/mirrorlist && pacman -Syu --noconfirm

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root" >&2
    exit 1
fi

LOG_FILE="/var/log/stormos-postinstall.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=================================================="
echo "StormOS Post-Installation Setup - $(date)"
echo "=================================================="

show_progress() {
    echo "→ $1"
}

# Detect Calamares
show_progress "Detecting installation context..."
if mount | grep -q "on /tmp/calamares-root" && [ -d "/tmp/calamares-root" ]; then
    TARGET_ROOT="/tmp/calamares-root"
    IS_CALAMARES=true
else
    TARGET_ROOT=""
    IS_CALAMARES=false
fi

# Find user
if [ "$IS_CALAMARES" = true ]; then
    show_progress "Finding target system user..."

    USER_NAME=$(awk -F: '$3 >= 1000 && $3 < 65000 && $1 != "nobody" {print $1; exit}' "$TARGET_ROOT/etc/passwd")

    [ -z "$USER_NAME" ] && USER_NAME=$(ls "$TARGET_ROOT/home" | head -n1)
    [ -z "$USER_NAME" ] && USER_NAME="user"

    USER_HOME="$TARGET_ROOT/home/$USER_NAME"
    mkdir -p "$USER_HOME"
fi

# === USER SETUP ===
if [ "$IS_CALAMARES" = true ]; then
    show_progress "Creating user dirs..."
    mkdir -p "$USER_HOME"/{Desktop,Documents,Downloads,Music,Pictures,Public,Templates,Videos}

    mkdir -p "$USER_HOME/.config"

    rsync -a /etc/skel/ "$USER_HOME/" 2>/dev/null || true

    USER_UID=$(awk -F: -v user="$USER_NAME" '$1 == user {print $3}' "$TARGET_ROOT/etc/passwd")
    USER_GID=$(awk -F: -v user="$USER_NAME" '$1 == user {print $4}' "$TARGET_ROOT/etc/passwd")

    chown -R "${USER_UID:-1000}:${USER_GID:-1000}" "$USER_HOME"

    # LightDM autologin fix
    sed -i '/^autologin-user=/d' "$TARGET_ROOT/etc/lightdm/lightdm.conf"
    sed -i "/^autologin-guest=/a autologin-user=$USER_NAME" "$TARGET_ROOT/etc/lightdm/lightdm.conf"
fi

# === PLYMOUTH SETUP ===
show_progress "Ensuring plymouth is configured for installed system..."
if [ -f "$TARGET_ROOT/etc/mkinitcpio.conf" ]; then
    if ! grep -q 'plymouth' "$TARGET_ROOT/etc/mkinitcpio.conf"; then
        sed -i 's/^HOOKS=(base systemd/HOOKS=(base systemd plymouth/' "$TARGET_ROOT/etc/mkinitcpio.conf"
        echo "✓ Added plymouth hook to mkinitcpio.conf"
    fi
fi

# Ensure splash is in GRUB defaults
if [ -f "$TARGET_ROOT/etc/default/grub" ]; then
    if ! grep -q 'splash' "$TARGET_ROOT/etc/default/grub"; then
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"/' "$TARGET_ROOT/etc/default/grub"
        echo "✓ Added splash to GRUB defaults"
    fi
fi

# DNS
show_progress "Configuring DNS..."
cat > "$TARGET_ROOT/etc/resolv.conf" << 'EOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF

# Permissions
show_progress "Fixing binaries..."
find "$TARGET_ROOT/usr/local/bin" -type f -exec chmod +x {} \; 2>/dev/null || true

echo ""
echo "=================================================="
echo "StormOS setup COMPLETE"
echo "=================================================="

exit 0
