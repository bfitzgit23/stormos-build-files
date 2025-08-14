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

 name=$(ls -1 /home)
 REAL_NAME=/home/$name

# genfstab -U / > /etc/fstab

#cp /cinnamon-configs/cinnamon-stuff/bin/* /bin/
#cp /cinnamon-configs/cinnamon-stuff/usr/bin/* /usr/bin/
#cp -r /cinnamon-configs/cinnamon-stuff/usr/share/* /usr/share/

mkdir -p /home/$name/.config
mkdir -p /home/$name/.local
mkdir -p /home/$name/Desktop
mkdir -p /home/$name/Music
mkdir -p /home/$name/.oh-my-bash

#cp -r /cinnamon-configs/cinnamon-stuff/nemo/* /home/$name/.config/nemo
cp -r /usr/share/oh-my-bash/* /home/$name/.oh-my-bash/

mkdir -p /home/$name/.config/autostart

#cp -r /root/stormos.png /home/$name/stormos.png

#mv /middle.png /home/$USER

# create python fix!

cp -r /etc/skel/.config/* /home/$name/.config/
cp -r /etc/skel/.local/* /home/$name/.local 
cp -r /usr/share/oh-my-bash/* /home/$name/.oh-my-bash/

#mkdir -p /usr/lib/python3.13/site-packages/six
#touch /usr/lib/python3.13/site-packages/six/__init__.py
#cp /usr/lib/python3.12/site-packages/six.py /usr/lib/python3.13/site-packages/six/six.py

# mkdir /home/$name/.local/share/cinnamon

# cp -r /cinnamon-configs/cinnamon-stuff/extensions /home/$name/.local/share/cinnamon/

plymouth-set-default-theme stormos

echo "Defaults pwfeedback" | sudo EDITOR='tee -a' visudo >/dev/null 2>&1

USERNAME=$(ls /home)

mkdir -p /usr/share/backgrounds/xfce
cp /usr/share/backgrounds/* /usr/share/backgrounds/xfce/ || true

rm /home/$name/Desktop/calamares.desktop
rm /home/$name/Desktop/abif.desktop
