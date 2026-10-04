#!/bin/bash
 
set -e -u

umask 022

sed -i 's/#\(en_US\.UTF-8\)/\1/' /etc/locale.gen
locale-gen

ln -sf /usr/share/zoneinfo/UTC /etc/localtime

usermod -s /usr/bin/bash root
cp -aT /etc/skel/ /root/
chmod 750 /root
passwd -d root

#useradd -m liveuser -u 500 -g users -G "adm,audio,floppy,log,network,rfkill,scanner,storage,optical,power,wheel" -s /bin/bash
#useradd -m -p "" -G "adm,audio,floppy,log,network,rfkill,scanner,storage,optical,power,wheel" -s /bin/bash liveuser
chown -R liveuser:liveuser /home/liveuser

#enable autologin
#groupadd -r autologin
gpasswd -a liveuser autologin

#groupadd -r nopasswdlogin
gpasswd -a liveuser nopasswdlogin

if ! grep -q "liveuser" /etc/sudoers;  then
	echo "liveuser ALL=(ALL) ALL" >> /etc/sudoers
fi

systemctl enable thermald.service
systemctl enable haveged.service
systemctl enable NetworkManager.service
systemctl enable pacman-init.service choose-mirror.service
systemctl enable sshd.service
systemctl enable bluetooth.service
systemctl enable lightdm.service
systemctl set-default graphical.target
systemctl enable cups.service

## Fix permissions
chmod 750 /etc/sudoers.d
chmod 440 /etc/sudoers.d/g_wheel
#chmod 644 /etc/systemd/system/*.service
chown 0 /etc/sudoers.d
chown 0 /etc/sudoers.d/g_wheel
chown root:root /etc/sudoers.d
chown root:root /etc/sudoers.d/g_wheel
chmod 755 /

sed -i 's/#\(PermitRootLogin \).\+/\1yes/' /etc/ssh/sshd_config
sed -i "s/#Server/Server/g" /etc/pacman.d/mirrorlist
sed -i 's/#\(Storage=\)auto/\1volatile/' /etc/systemd/journald.conf

sed -i 's/#\(HandleSuspendKey=\)suspend/\1ignore/' /etc/systemd/logind.conf
sed -i 's/#\(HandleHibernateKey=\)hibernate/\1ignore/' /etc/systemd/logind.conf
sed -i 's/#\(HandleLidSwitch=\)suspend/\1ignore/' /etc/systemd/logind.conf

## Wifi not available with networkmanager (BugFix)
su -c 'echo "" >> /etc/NetworkManager/NetworkManager.conf'
su -c 'echo "[device]" >> /etc/NetworkManager/NetworkManager.conf'
su -c 'echo "wifi.scan-rand-mac-address=no" >> /etc/NetworkManager.conf'

pacman-key --init
pacman-key --populate

# Stop lightdm user from expiring
chage -E -1 lightdm

#pacman -Rs xfwm4-themes --noconfirm

xdg-user-dirs-update --force


mkdir -p /usr/share/backgrounds/xfce
cp -af /usr/share/backgrounds/*.* /usr/share/backgrounds/xfce

####

chown -R liveuser:liveuser /tmp

plymouth-set-default-theme stormos

# Create theme directory
mkdir -p /usr/share/themes/grub/fonts

# Copy StormOS theme
cp -r /usr/share/themes/grub/stormos /usr/share/grub/themes

# Ensure proper permissions
chown -R root:root /usr/share/themes/grub
chmod -R 755 /usr/share/themes/grub

systemctl disable --now systemd-userdb-load-credentials.service systemd-userdbd.service systemd-userdbd.socket
systemctl mask systemd-userdb-load-credentials.service systemd-userdbd.service systemd-userdbd.socket

# Apply theme to GRUB by default
echo "set theme=/usr/share/grub/themes/stormos/theme.txt" > /etc/default/grub

# Fix libyaml-cpp version mismatch
if [ -f /usr/lib/libyaml-cpp.so.0.8 ]; then
    echo "libyaml-cpp.so.0.8 already exists"
elif [ -f /usr/lib/libyaml-cpp.so.0.7 ]; then
    ln -sf /usr/lib/libyaml-cpp.so.0.7 /usr/lib/libyaml-cpp.so.0.8
    echo "Created symlink for libyaml-cpp.so.0.8"
elif [ -f /usr/lib/libyaml-cpp.so.0.6 ]; then
    ln -sf /usr/lib/libyaml-cpp.so.0.6 /usr/lib/libyaml-cpp.so.0.8
    echo "Created symlink for libyaml-cpp.so.0.8"
else
    # Find any version
    for lib in /usr/lib/libyaml-cpp.so*; do
        if [ -f "$lib" ] && [[ "$lib" != *".0.8"* ]]; then
            ln -sf "$lib" /usr/lib/libyaml-cpp.so.0.8
            echo "Created symlink from $lib to libyaml-cpp.so.0.8"
            break
        fi
    done
fi

# The real xfce4-terminal (from the xfce4 group) must remain the system terminal.
# Older builds replaced it with a dangling symlink to mate-terminal which caused
# xfce4-terminal to fail with a silent "input/output error". Remove any stale
# wrapper/symlink left behind and verify the real binary is in place.
if [ -L /usr/bin/xfce4-terminal ] || [ -f /usr/bin/xfce4-terminal ]; then
    file /usr/bin/xfce4-terminal | grep -q "symlink to" && rm -f /usr/bin/xfce4-terminal
fi
if [ -e /usr/local/bin/xfce4-terminal ] && [ ! -x /usr/local/bin/xfce4-terminal ]; then
    rm -f /usr/local/bin/xfce4-terminal
fi
if ! command -v xfce4-terminal >/dev/null 2>&1 || [ ! -x /usr/bin/xfce4-terminal ]; then
    echo "WARNING: xfce4-terminal is missing; installing it." >&2
    pacman -S --noconfirm --needed xfce4-terminal
fi

sudo systemctl start clamav-freshclam

sudo systemctl enable clamav-freshclam

sudo systemctl start clamav-daemon

sudo systemctl enable clamav-daemon
