#!/bin/bash -e
#
##############################################################################
#  PostInstall - StormOS setup script
##############################################################################

# === PRE-FLIGHT CHECKS ===
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

# Calamares expands ${ROOT} before running this command. In a normal
# target chroot, ROOT is simply "/"; the mount-point fallback supports
# older launch paths and the existing non-Calamares chroot caller.
show_progress "Detecting installation context..."
if [ -n "${CALAMARES_TARGET_ROOT:-}" ]; then
    TARGET_ROOT="$CALAMARES_TARGET_ROOT"
    IS_CALAMARES=true
elif mount | grep -q "on /tmp/calamares-root" && [ -d "/tmp/calamares-root" ]; then
    TARGET_ROOT="/tmp/calamares-root"
    IS_CALAMARES=true
else
    TARGET_ROOT="/"
    IS_CALAMARES=true
fi

# Find user
if [ "$IS_CALAMARES" = true ]; then
    show_progress "Finding target system user..."

    USER_NAME=$(awk -F: '$3 >= 1000 && $3 < 65000 && $1 != "nobody" {print $1; exit}' "$TARGET_ROOT/etc/passwd")

    [ -z "$USER_NAME" ] && USER_NAME=$(ls "$TARGET_ROOT/home" | head -n1)
    [ -z "$USER_NAME" ] && USER_NAME="user"

    USER_HOME="$TARGET_ROOT/home/$USER_NAME"
    mkdir -p "$USER_HOME"

    # Remove Calamares desktop shortcut from target user
    rm -f "$USER_HOME/Desktop/calamares.desktop" 2>/dev/null || true
else
    # Outside chroot — get caller name safely
    USER_NAME=$(logname 2>/dev/null || whoami 2>/dev/null || echo "root")
    rm -f "/home/$USER_NAME/Desktop/calamares.desktop" 2>/dev/null || true
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

# === STORMOS GRUB THEME SETUP ===
show_progress "Configuring StormOS GRUB theme..."
if [ -f "$TARGET_ROOT/etc/default/grub" ]; then
    if ! grep -q 'GRUB_THEME=' "$TARGET_ROOT/etc/default/grub"; then
        echo 'GRUB_THEME="/usr/share/grub/themes/stormos/theme.txt"' >> "$TARGET_ROOT/etc/default/grub"
        echo "✓ Added StormOS GRUB theme to GRUB defaults"
    fi
fi

# Ensure grub theme files are available in installed system
if [ -d "/usr/share/grub/themes/stormos" ] && [ ! -d "$TARGET_ROOT/usr/share/grub/themes/stormos" ]; then
    cp -r /usr/share/grub/themes/stormos "$TARGET_ROOT/usr/share/grub/themes/"
n# === PLYMOUTH THEME SETUP ===
show_progress "Setting StormOS plymouth theme..."
if [ -d "/usr/share/plymouth/themes/stormos" ]; then
    chroot "$TARGET_ROOT" plymouth-set-default-theme stormos 2>/dev/null || true
    echo "✓ Plymouth theme set to StormOS"
fi
    echo "✓ Copied StormOS GRUB theme to installed system"
fi

# DNS
if [ "$IS_CALAMARES" = true ]; then
    show_progress "Configuring DNS..."
    cat > "$TARGET_ROOT/etc/resolv.conf" << 'EOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF
fi

# Permissions
show_progress "Fixing binaries..."
find "$TARGET_ROOT/usr/local/bin" -type f -exec chmod +x {} \; 2>/dev/null || true

# NetworkManager
show_progress "Enabling NetworkManager..."
if [ -d "$TARGET_ROOT/etc/systemd/system/multi-user.target.wants" ] || [ -d "$TARGET_ROOT/usr/lib/systemd/system" ]; then
    ln -sf /usr/lib/systemd/system/NetworkManager.service "$TARGET_ROOT/etc/systemd/system/multi-user.target.wants/NetworkManager.service" 2>/dev/null || true
    echo "✓ NetworkManager enabled"
fi

# === STORMOS DESKTOP SHELL ===
show_progress "Installing StormOS Desktop shell..."
SHELL_SRC="/usr/share/stormos-shell"
SHELL_DST="$TARGET_ROOT/usr/share/stormos-shell"
if [ -d "$SHELL_SRC" ]; then
    mkdir -p "$SHELL_DST"
    cp -r "$SHELL_SRC"/* "$SHELL_DST/"
    chmod +x "$SHELL_DST/bin/stormos-desktop" 2>/dev/null || true
    echo "✓ StormOS Desktop shell installed to $SHELL_DST"

    # Install launcher binary
    mkdir -p "$TARGET_ROOT/usr/local/bin"
    cat > "$TARGET_ROOT/usr/bin/stormos-desktop" << LAUNCHER
#!/usr/bin/env bash
export STORMOS_DESKTOP_DIR="$SHELL_DST"
exec bash "$SHELL_DST/bin/stormos-desktop" "\$@"
LAUNCHER
    chmod +x "$TARGET_ROOT/usr/bin/stormos-desktop"
    echo "✓ Launcher installed to /usr/bin/stormos-desktop"

    # Install session entry
    mkdir -p "$TARGET_ROOT/usr/share/xsessions"
    cat > "$TARGET_ROOT/usr/share/xsessions/stormos-desktop.desktop" << 'XS'
[Desktop Entry]
Name=StormOS Desktop
Comment=StormOS React desktop shell (Electron + openbox)
Exec=/usr/bin/stormos-desktop
TryExec=/usr/bin/stormos-desktop
Type=Application
DesktopNames=StormOS
XS
    echo "✓ Session entry installed to /usr/share/xsessions/"

    # Install Node.js dependencies on target
    if [ -d "$SHELL_DST/node_modules" ] || [ -f "$SHELL_DST/package.json" ]; then
        show_progress "Installing Node.js dependencies for StormOS shell..."
        chroot "$TARGET_ROOT" /bin/bash -c "cd $SHELL_DST && npm install --production 2>/dev/null" || true
        echo "✓ Node.js dependencies installed"
    fi
else
    warn "  StormOS Desktop shell source not found at $SHELL_SRC — skipping"
fi

# === LIGHTDM SESSION CONFIGURATION ===
show_progress "Configuring LightDM session..."
LIGHTDM_CONF="$TARGET_ROOT/etc/lightdm/lightdm.conf"
if [ -f "$LIGHTDM_CONF" ]; then
    # Set StormOS Desktop as the default session
    sed -i 's/^user-session=.*/user-session=stormos-desktop/' "$LIGHTDM_CONF"
    sed -i 's/^autologin-session=.*/autologin-session=stormos-desktop/' "$LIGHTDM_CONF"

    # If no user-session line exists, add it under [Seat:*]
    if ! grep -q '^user-session=' "$LIGHTDM_CONF"; then
        sed -i '/\[Seat:\*\]/a user-session=stormos-desktop' "$LIGHTDM_CONF"
    fi
    if ! grep -q '^autologin-session=' "$LIGHTDM_CONF"; then
        sed -i '/\[Seat:\*\]/a autologin-session=stormos-desktop' "$LIGHTDM_CONF"
    fi

    # Set autologin to the user created by Calamares
    if [ -n "$USER_NAME" ] && [ "$USER_NAME" != "root" ]; then
        sed -i "s/^#*autologin-user=.*/autologin-user=$USER_NAME/" "$LIGHTDM_CONF"
        sed -i 's/^#*autologin-user-timeout=.*/autologin-user-timeout=0/' "$LIGHTDM_CONF"
        echo "✓ Autologin configured for $USER_NAME"
    fi

    echo "✓ LightDM session set to stormos-desktop"
fi

echo ""
echo "=================================================="
echo "StormOS setup COMPLETE"
echo "=================================================="

exit 0
