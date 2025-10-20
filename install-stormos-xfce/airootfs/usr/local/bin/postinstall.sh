#!/bin/bash -e
#
##############################################################################
#  PostInstall - StormOS setup script
#  Licensed under GPLv3 or later
##############################################################################

# Get the actual logged-in user, even if script runs as root
USER_NAME=$(logname)

# Remove unwanted launchers
rm -f "/home/$USER_NAME/Desktop/calamares.desktop" || true

# Trust all remaining .desktop files on Desktop (run as real user)
#if [ -d "/home/$USER_NAME/Desktop" ]; then
#    sudo -u "$USER_NAME" bash -c '
#        find "$HOME/Desktop" -type f -name "*.desktop" \
#            -exec chmod +x {} \; \
#            -exec gio set {} "metadata::trusted" true \;
#    '
#fi

# Create required directories
mkdir -p /home/$USER_NAME/.config
mkdir -p /home/$USER_NAME/.local
mkdir -p /home/$USER_NAME/Desktop
mkdir -p /home/$USER_NAME/Music
mkdir -p /home/$USER_NAME/.oh-my-bash
mkdir -p /home/$USER_NAME/.config/autostart

# Set ownership of created directories
chown -R $USER_NAME:$USER_NAME /home/$USER_NAME/.config
chown -R $USER_NAME:$USER_NAME /home/$USER_NAME/.local
chown -R $USER_NAME:$USER_NAME /home/$USER_NAME/Desktop
chown -R $USER_NAME:$USER_NAME /home/$USER_NAME/Music
chown -R $USER_NAME:$USER_NAME /home/$USER_NAME/.oh-my-bash

# Copy configurations and themes
cp -r /usr/share/oh-my-bash/* /home/$USER_NAME/.oh-my-bash/ || true
cp -r /etc/skel/.config/* /home/$USER_NAME/.config/ || true

# Set ownership of copied files
chown -R $USER_NAME:$USER_NAME /home/$USER_NAME/.oh-my-bash
chown -R $USER_NAME:$USER_NAME /home/$USER_NAME/.config

# Set Plymouth theme and sudo feedback
plymouth-set-default-theme stormos
echo "Defaults pwfeedback" | EDITOR='tee -a' visudo >/dev/null 2>&1

# Prepare XFCE backgrounds
mkdir -p /usr/share/backgrounds/xfce
cp /usr/share/backgrounds/*.png /usr/share/backgrounds/xfce/ || true

# CRITICAL: Ensure DNS works in installed system
echo "Configuring network DNS for installed system..."

# Detect if we're running in Calamares chroot context
# Calamares mounts the target at a temporary path - check if we can detect it
if mount | grep -q "on /tmp/calamares-root"; then
    # We're in Calamares context - find the actual mount point
    CALAMARES_ROOT=$(mount | grep "on /tmp/calamares-root" | awk '{print $3}' | head -1)
    if [ -n "$CALAMARES_ROOT" ] && [ -d "$CALAMARES_ROOT" ]; then
        echo "Detected Calamares installation context, target root: $CALAMARES_ROOT"
        TARGET_ROOT="$CALAMARES_ROOT"
    else
        TARGET_ROOT=""
    fi
else
    TARGET_ROOT=""
fi

# Create reliable DNS configuration in the correct location
echo "Creating robust DNS configuration..."
if [ -n "$TARGET_ROOT" ]; then
    # We're in Calamares installation - create resolv.conf in target system
    mkdir -p "$TARGET_ROOT/etc"
    cat > "$TARGET_ROOT/etc/resolv.conf" << 'EOF'
# StormOS - Reliable DNS Configuration
# Primary DNS servers
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 9.9.9.9
# Secondary fallbacks
nameserver 208.67.222.222
nameserver 8.8.4.4
nameserver 1.0.0.1
# Options for better performance
options timeout:1
options attempts:2
options rotate
EOF
    echo "✓ DNS configured in target system: $TARGET_ROOT/etc/resolv.conf"
else
    # We're in live system or manual context
    # Remove existing resolv.conf if it's a broken symlink or doesn't exist
    if [ ! -e /etc/resolv.conf ] || [ -L /etc/resolv.conf ]; then
        rm -f /etc/resolv.conf
        cat > /etc/resolv.conf << 'EOF'
# StormOS - Reliable DNS Configuration
# Primary DNS servers
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 9.9.9.9
# Secondary fallbacks
nameserver 208.67.222.222
nameserver 8.8.4.4
nameserver 1.0.0.1
# Options for better performance
options timeout:1
options attempts:2
options rotate
EOF
        echo "✓ DNS configured in live system: /etc/resolv.conf"
    else
        echo "✓ DNS already configured in live system"
    fi
fi


# Set execute permissions for scripts and AppImages
chmod +x /usr/local/bin/*.sh 2>/dev/null || true
chmod +x /usr/local/bin/*.AppImage 2>/dev/null || true




xdg-user-dirs-update --force
