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

    # =========================================================
    # ✅ FIRST-RUN WELCOME SETUP (SHOW ONCE ONLY)
    # =========================================================
    show_progress "Configuring StormOS Welcome first-run..."

    AUTOSTART_DIR="$USER_HOME/.config/autostart"
    mkdir -p "$AUTOSTART_DIR"

    if [ -f "$TARGET_ROOT/etc/skel/.config/autostart/stormos-welcome.desktop" ]; then
        cp "$TARGET_ROOT/etc/skel/.config/autostart/stormos-welcome.desktop" \
           "$AUTOSTART_DIR/stormos-welcome.desktop"
    fi

    touch "$USER_HOME/.storm-welcome-first-run"

    chown -R "${USER_UID:-1000}:${USER_GID:-1000}" "$AUTOSTART_DIR"
    chown "${USER_UID:-1000}:${USER_GID:-1000}" "$USER_HOME/.storm-welcome-first-run"

    echo "✓ Welcome will run once after install"

    # LightDM autologin fix
    sed -i '/^autologin-user=/d' "$TARGET_ROOT/etc/lightdm/lightdm.conf"
    sed -i "/^autologin-guest=/a autologin-user=$USER_NAME" "$TARGET_ROOT/etc/lightdm/lightdm.conf"
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
