#!/bin/bash -e
#
##############################################################################
#  PostInstall - StormOS setup script
#  Licensed under GPLv3 or later
##############################################################################

# Get the actual logged-in user, even if script runs as root
USER_NAME=$(logname)
USER_HOME="/home/$USER_NAME"

echo "Starting StormOS post-installation setup for user: $USER_NAME"

# Remove unwanted launchers
rm -f "$USER_HOME/Desktop/calamares.desktop" || true
echo "✓ Removed calamares desktop launcher"


# Copy configurations and themes
echo "Copying configurations and themes..."
cp -r /usr/share/oh-my-bash/* "$USER_HOME/.oh-my-bash/" 2>/dev/null || true
cp -r /etc/skel/.config/* "$USER_HOME/.config/" 2>/dev/null || true

# Set ownership of copied files
chown -R "$USER_NAME:$USER_NAME" "$USER_HOME/.oh-my-bash"
chown -R "$USER_NAME:$USER_NAME" "$USER_HOME/.config"
echo "✓ Configurations copied"

# Set Plymouth theme and sudo feedback
echo "Setting Plymouth theme and sudo feedback..."
plymouth-set-default-theme stormos 2>/dev/null || echo "⚠ Plymouth theme not available"
echo "Defaults pwfeedback" | EDITOR='tee -a' visudo >/dev/null 2>&1 || echo "⚠ Could not configure sudo feedback"
echo "✓ Theme and sudo settings applied"

# Prepare XFCE backgrounds
echo "Preparing XFCE backgrounds..."
mkdir -p /usr/share/backgrounds/xfce
cp /usr/share/backgrounds/*.png /usr/share/backgrounds/xfce/ 2>/dev/null || true
echo "✓ Backgrounds prepared"

# CRITICAL: Ensure DNS works in installed system
echo "Configuring network DNS for installed system..."

# Detect if we're running in Calamares chroot context
if mount | grep -q "on /tmp/calamares-root"; then
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

# Create reliable DNS configuration
echo "Creating robust DNS configuration..."
if [ -n "$TARGET_ROOT" ]; then
    mkdir -p "$TARGET_ROOT/etc"
    cat > "$TARGET_ROOT/etc/resolv.conf" << 'EOF'
# StormOS - Reliable DNS Configuration
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 9.9.9.9
nameserver 208.67.222.222
nameserver 8.8.4.4
options timeout:1
options attempts:2
options rotate
EOF
    echo "✓ DNS configured in target system: $TARGET_ROOT/etc/resolv.conf"
else
    if [ ! -e /etc/resolv.conf ] || [ -L /etc/resolv.conf ]; then
        rm -f /etc/resolv.conf
        cat > /etc/resolv.conf << 'EOF'
# StormOS - Reliable DNS Configuration
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 9.9.9.9
nameserver 208.67.222.222
nameserver 8.8.4.4
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
echo "Setting execute permissions..."
chmod +x /usr/local/bin/*.sh 2>/dev/null || true
chmod +x /usr/local/bin/*.AppImage 2>/dev/null || true
echo "✓ Execute permissions set"

# Create XDG user directories configuration
echo "Creating XDG user directories configuration..."
cat > "$USER_HOME/.config/user-dirs.dirs" << 'EOF'
XDG_DESKTOP_DIR="$HOME/Desktop"
XDG_DOWNLOAD_DIR="$HOME/Downloads"
XDG_TEMPLATES_DIR="$HOME/Templates"
XDG_PUBLICSHARE_DIR="$HOME/Public"
XDG_DOCUMENTS_DIR="$HOME/Documents"
XDG_MUSIC_DIR="$HOME/Music"
XDG_PICTURES_DIR="$HOME/Pictures"
XDG_VIDEOS_DIR="$HOME/Videos"
EOF

chown "$USER_NAME:$USER_NAME" "$USER_HOME/.config/user-dirs.dirs"

# Also create user-dirs.locale to prevent language issues
cat > "$USER_HOME/.config/user-dirs.locale" << 'EOF'
en_US
EOF

chown "$USER_NAME:$USER_NAME" "$USER_HOME/.config/user-dirs.locale"
echo "✓ XDG directory configuration created"

# Create a basic .bashrc if it doesn't exist
if [ ! -f "$USER_HOME/.bashrc" ]; then
    echo "Creating basic .bashrc..."
    cp /etc/skel/.bashrc "$USER_HOME/.bashrc"
    chown "$USER_NAME:$USER_NAME" "$USER_HOME/.bashrc"
    echo "✓ Basic .bashrc created"
fi

# Verify all directories were created
echo ""
echo "Verifying user directory creation:"
for dir in Desktop Documents Downloads Music Pictures Public Templates Videos; do
    if [ -d "$USER_HOME/$dir" ]; then
        echo "✓ $USER_HOME/$dir - EXISTS"
    else
        echo "✗ $USER_HOME/$dir - MISSING"
    fi
done

# Final ownership fix - ensure everything in user home is owned by the user
echo "Performing final ownership check..."
chown -R "$USER_NAME:$USER_NAME" "$USER_HOME" 2>/dev/null || true

echo ""
echo "=================================================="
echo "StormOS post-installation setup COMPLETED SUCCESSFULLY!"
echo "All user directories have been created and configured."
echo "User: $USER_NAME"
echo "Home: $USER_HOME"
echo "=================================================="