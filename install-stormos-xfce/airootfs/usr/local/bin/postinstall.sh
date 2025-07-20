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
rm -f /etc/sudoers.d/g_wheel
rm -f /etc/polkit-1/rules.d/49-nopasswd_global.rules
rm /root/{.automated_script.sh,.zlogin}

echo "FONT=ter-p16n" >> /etc/vconsole.conf

rm -rf /usr/share/calamares
rm -rf $HOME/liveuser/Desktop/calamares.desktop
rm -rf $HOME/.config/autostart/calamares.desktop
rm -rf $HOME/.config/autostart/NetworkManager.desktop

rm -r /etc/pacman.d/gnupg # This moves your old keyring to a backup
pacman-key --init
pacman-key --populate archlinux # Manjaro users may also add manjaro
pacman -Syy archlinux-keyring # Manjaro users may also add manjaro-keyring
pacman -Syu



# Continue cleanup
rm /usr/local/bin/postinstall.sh
