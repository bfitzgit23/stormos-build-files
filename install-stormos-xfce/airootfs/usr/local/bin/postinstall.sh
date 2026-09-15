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

echo ""
echo "=================================================="
echo "StormOS setup COMPLETE"
echo "=================================================="

# === STORMOS WELCOME AUTOSTART (idempotent, survives missing remote script) ===
# Ensure the autostart desktop entry exists on the installed system even if the
# remote target.script path did not create it. This keeps the welcome app launching
# in both XFCE and KDE regardless of how the installer ran.
WELCOME_DESKTOP="$TARGET_ROOT/etc/xdg/autostart/stormos-welcome.desktop"
if [ ! -s "$WELCOME_DESKTOP" ]; then
    show_progress "Creating stormos-welcome autostart entry..."
    mkdir -p "$TARGET_ROOT/etc/xdg/autostart"
    cat > "$WELCOME_DESKTOP" << 'EOF'
[Desktop Entry]
Type=Application
Name=StormOS Welcome
Comment=StormOS welcome screen (first boot helper)
Exec=/usr/local/bin/stormos-welcome
Icon=stormos-welcome
Terminal=false
Categories=System;
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Phase=Application
Hidden=false
NoDisplay=false
StartupNotify=false
EOF
    show_progress "Created $WELCOME_DESKTOP"
fi

# Ensure the welcome binary is executable on the installed system.
# Some install paths only place the file but do not chmod it.
if [ -f "$TARGET_ROOT/usr/local/bin/stormos-welcome" ]; then
    chmod 755 "$TARGET_ROOT/usr/local/bin/stormos-welcome" 2>/dev/null || true
fi

# Also seed the liveuser copy if a user home exists. This is defensive; the image
# already carries it under /etc/skel, but some install flows skip skel propagation.
if [ -d "$TARGET_ROOT/home" ] && [ -n "$USER_HOME" ]; then
    SKEL_WELCOME_DEST="$USER_HOME/.config/autostart/stormos-welcome.desktop"
    if [ ! -s "$SKEL_WELCOME_DEST" ]; then
        mkdir -p "$USER_HOME/.config/autostart"
        cp -f "$WELCOME_DESKTOP" "$SKEL_WELCOME_DEST" 2>/dev/null || true
        show_progress "Seeded stormos-welcome autostart for target user"
    fi
fi

# === STRAY INSTALLER AUTOSTART CLEANUP ==============================
# Ensure no installer/cli entry is unexpectedly set to launch on login.
# This protects against a prior image or a stray desktop file that may
# have set Hidden=false for the CLI installer autostart entry.
if [ -d "$TARGET_ROOT/etc/xdg/autostart" ]; then
    for candidate in \
        "$TARGET_ROOT/etc/xdg/autostart/abif.desktop" \
        "$TARGET_ROOT/etc/xdg/autostart/stormos-installer-cli.desktop" \
        "$TARGET_ROOT/etc/xdg/autostart/install-stormos-cli.desktop" \
        "$TARGET_ROOT/etc/xdg/autostart/install-stormos-desktop.desktop" \
        "$TARGET_ROOT/etc/xdg/autostart/install-stormos.desktop" \
        "$TARGET_ROOT/etc/xdg/autostart/install-stormos-cli-installer.desktop" \
        "$TARGET_ROOT/etc/xdg/autostart/install-stormos-installer.desktop" \
        "$TARGET_ROOT/etc/xdg/autostart/stormos-installer.desktop" \
        "$TARGET_ROOT/etc/xdg/autostart/calamares.desktop" \
        "$TARGET_ROOT/etc/xdg/autostart/calamares-settings-daemon.desktop" \
        "$TARGET_ROOT/etc/xdg/autostart/install-stormos.desktop" \
        "$TARGET_ROOT/etc/xdg/autostart/install-stormos-cli-installer.desktop" \
        "$TARGET_ROOT/etc/xdg/autostart/install-stormos-installer.desktop" \
        "$TARGET_ROOT/etc/xdg/autostart/stormos-installer.desktop"; do
        if [ -f "$candidate" ]; then
            # Disable installer autostart by setting Hidden=true.
            # Only touch desktop files that look like installer entries.
            if grep -qiE 'Install StormOS|abif|calamares' "$candidate" 2>/dev/null; then
                if grep -qE '^Hidden=false$' "$candidate" 2>/dev/null; then
                    show_progress "Disabling stray installer autostart: $candidate"
                    sed -i 's/^Hidden=false$/Hidden=true/' "$candidate"
                elif ! grep -qE '^Hidden=true$' "$candidate" 2>/dev/null; then
                    # If the file has no Hidden key at all, add one safely.
                    show_progress "Adding Hidden=true to stray installer autostart: $candidate"
                    printf '\nHidden=true\n' >> "$candidate"
                fi
            fi
        fi
    done
fi

# If the target user home exists, also disable any installer autostart
# the user may have enabled in their personal autostart folder.
if [ -d "$TARGET_ROOT/home" ] && [ -n "$USER_HOME" ]; then
    for candidate in \
        "$USER_HOME/.config/autostart/abif.desktop" \
        "$USER_HOME/.config/autostart/stormos-installer-cli.desktop" \
        "$USER_HOME/.config/autostart/install-stormos-cli.desktop" \
        "$USER_HOME/.config/autostart/install-stormos-desktop.desktop" \
        "$USER_HOME/.config/autostart/install-stormos.desktop"; do
        if [ -f "$candidate" ]; then
            if grep -qiE 'Install StormOS|abif' "$candidate" 2>/dev/null; then
                if grep -qE '^Hidden=false$' "$candidate" 2>/dev/null; then
                    show_progress "Disabling user installer autostart: $candidate"
                    sed -i 's/^Hidden=false$/Hidden=true/' "$candidate"
                fi
            fi
        fi
    done
    # If the user has disabled every known installer autostart entry, also keep
    # the matching menu-only installer entry hidden so the menu and autostart
    # state stay consistent.
    if [ -d "$TARGET_ROOT/usr/share/applications" ]; then
        appdir2="$TARGET_ROOT/usr/share/applications"
        all_hidden2=true
        for candidate2 in \
            "$appdir2/stormos-installer-cli.desktop" \
            "$appdir2/abif.desktop" \
            "$appdir2/install-stormos-cli.desktop" \
            "$appdir2/install-stormos-desktop.desktop" \
            "$appdir2/install-stormos.desktop"; do
            if [ -f "$candidate2" ]; then
                if grep -qiE 'Install StormOS|abif|stormos-installer|install-stormos' "$candidate2" 2>/dev/null; then
                    if grep -qE '^Hidden=true$' "$candidate2" 2>/dev/null; then
                        : # already hidden, keep scanning
                    else
                        all_hidden2=false
                        break
                    fi
                fi
            fi
        done
        if [ "$all_hidden2" = true ]; then
            for menu_candidate2 in \
                "$appdir2/stormos-installer-cli.desktop" \
                "$appdir2/abif.desktop"; do
                if [ -f "$menu_candidate2" ]; then
                    if grep -qE '^Hidden=false$' "$menu_candidate2" 2>/dev/null; then
                        show_progress "Hiding menu-only installer entry to match disabled autostart: $menu_candidate2"
                        sed -i 's/^Hidden=false$/Hidden=true/' "$menu_candidate2"
                    elif ! grep -qE '^Hidden=true$' "$menu_candidate2" 2>/dev/null; then
                        show_progress "Adding Hidden=true to menu-only installer entry: $menu_candidate2"
                        printf '\nHidden=true\n' >> "$menu_candidate2"
                    fi
                fi
            done
        fi
    fi
fi

# === OPTIONAL: remove installer desktop shortcut from installed system ===
# If the installer/setup chooses to remove the CLI installer menu entry
# from the installed system, set this flag before running postinstall.
# Example: CALAMARES_REMOVE_INSTALLER_DESKTOP=1
#
# This removal path is deliberately broad for /usr/share/applications/ so
# that any installer shortcut that may have been installed by a different
# package path is also covered, not just the exact filenames shipped in
# this tree.
if [ "${CALAMARES_REMOVE_INSTALLER_DESKTOP:-}" = "1" ]; then
    show_progress "User chose to remove installer desktop shortcut from installed system"
    appdir="$TARGET_ROOT/usr/share/applications"
    if [ -d "$appdir" ]; then
        # Remove exact known installer shortcut names first.
        rm -f "$appdir/stormos-installer-cli.desktop" \
              "$appdir/abif.desktop" \
              "$appdir/install-stormos-cli.desktop" \
              "$appdir/install-stormos-desktop.desktop" \
              "$appdir/welcome.desktop" \
              "$appdir/install-stormos.desktop" \
              "$appdir/install-stormos-cli-installer.desktop" \
              "$appdir/install-stormos-installer.desktop" \
              "$appdir/stormos-installer.desktop" 2>/dev/null || true
        # Broad catch: remove any remaining installer-themed installer desktop
        # entries under /usr/share/applications/ that reference abif or the
        # StormOS CLI installer, regardless of their filename.
        find "$appdir" -maxdepth 1 -type f -name '*.desktop' 2>/dev/null | while IFS= read -r desktop; do
            if grep -qiE 'Install StormOS|abif|stormos-installer|install-stormos' "$desktop" 2>/dev/null; then
                rm -f "$desktop" 2>/dev/null || true
            fi
        done
        show_progress "Removed installer-related desktop entries from /usr/share/applications"
    fi
fi

exit 0
