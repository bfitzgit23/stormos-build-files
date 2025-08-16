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
rm -f "/home/$USER_NAME/Desktop/abif.desktop" || true

# Trust all remaining .desktop files on Desktop (run as real user)
if [ -d "/home/$USER_NAME/Desktop" ]; then
    sudo -u "$USER_NAME" bash -c '
        find "$HOME/Desktop" -type f -name "*.desktop" \
            -exec chmod +x {} \; \
            -exec gio set {} "metadata::trusted" true \;
    '
fi

# Create required directories
mkdir -p /home/$USER_NAME/.config
mkdir -p /home/$USER_NAME/.local
mkdir -p /home/$USER_NAME/Desktop
mkdir -p /home/$USER_NAME/Music
mkdir -p /home/$USER_NAME/.oh-my-bash
mkdir -p /home/$USER_NAME/.config/autostart

# Copy configurations and themes
cp -r /usr/share/oh-my-bash/* /home/$USER_NAME/.oh-my-bash/ || true
cp -r /etc/skel/.config/* /home/$USER_NAME/.config/ || true
cp -r /etc/skel/.local/* /home/$USER_NAME/.local || true

# Set Plymouth theme and sudo feedback
plymouth-set-default-theme stormos
echo "Defaults pwfeedback" | sudo EDITOR='tee -a' visudo >/dev/null 2>&1

# Prepare XFCE backgrounds

mkdir -p /usr/share/backgrounds/xfce
cp /usr/share/backgrounds/*.png /usr/share/backgrounds/xfce/ || true

sudo chmod +x /usr/local/bin/trust.sh && sudo chmod +x /usr/local/bin/*.AppImage

