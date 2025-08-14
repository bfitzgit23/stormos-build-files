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

# Better way to get the username - assuming the script is run by the target user
name=$(whoami)
REAL_NAME=/home/$USER

# genfstab -U / > /etc/fstab/

mkdir -p /home/$USER/.config
mkdir -p /home/$USER/.local
mkdir -p /home/$USER/Desktop
mkdir -p /home/$USER/Music
mkdir -p /home/$USER/.oh-my-bash

#cp -r /cinnamon-configs/cinnamon-stuff/nemo/* /home/$USER/.config/nemo
cp -r /usr/share/oh-my-bash/* /home/$USER/.oh-my-bash/
mkdir -p /home/$USER/.config/autostart

#cp -r /root/stormos.png /home/$USER/stormos.png

# create python fix!
cp -r /etc/skel/.config/* /home/$USER/.config/
cp -r /etc/skel/.local/* /home/$USER/.local 
cp -r /usr/share/oh-my-bash/* /home/$USER/.oh-my-bash/

#mkdir -p /usr/lib/python3.13/site-packages/six
#touch /usr/lib/python3.13/site-packages/six/__init__.py
#cp /usr/lib/python3.12/site-packages/six.py /usr/lib/python3.13/site-packages/six/six.py

# mkdir /home/$USER/.local/share/cinnamon
# cp -r /cinnamon-configs/cinnamon-stuff/extensions /home/$USER/.local/share/cinnamon/

plymouth-set-default-theme stormos
echo "Defaults pwfeedback" | sudo EDITOR='tee -a' visudo >/dev/null 2>&1

USERNAME=$(whoami)
mkdir -p /usr/share/backgrounds/xfce
cp /usr/share/backgrounds/* /usr/share/backgrounds/xfce/ || true

# Changed from rm to mv to /dev/null
rm -f "/home/$USER/Desktop/calamares.desktop"
rm -f "/home/$USER/Desktop/abif.desktop"
