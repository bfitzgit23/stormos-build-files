#!/bin/bash -e
#
##############################################################################
#
#  PostInstall is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your discretion) any later version.
#
#  PostInstall is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
##############################################################################

# clean out archiso files from install
sudo rm -f /etc/sudoers.d/g_wheel
sudo rm -f /etc/polkit-1/rules.d/49-nopasswd_global.rules
sudo rm -r /etc/systemd/system/etc-pacman.d-gnupg.mount
sudo rm /root/{.automated_script.sh,.zlogin}
sudo rm /etc/mkinitcpio-archiso.conf
sudo rm -r /etc/initcpio

sudo echo "FONT=ter-p16n" >> /etc/vconsole.conf

sudo rm -rf /usr/share/calamares
sudo rm -rf $HOME/liveuser/Desktop/calamares.desktop
sudo rm -rf $HOME/.config/autostart/calamares.desktop
sudo rm -rf $HOME/.config/autostart/NetworkManager.desktop

sudo rm -r /etc/pacman.d/gnupg # This moves your old keyring to a backup
sudo pacman-key --init
sudo pacman-key --populate archlinux # Manjaro users may also add manjaro
sudo pacman -Syy archlinux-keyring # Manjaro users may also add manjaro-keyring
sudo pacman -Syu



# Continue cleanup
rm /usr/local/bin/postinstall.sh
