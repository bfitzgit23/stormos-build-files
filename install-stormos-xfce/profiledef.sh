#!/usr/bin/env bash
# shellcheck disable=SC2034

iso_name="StormOS_Familia"
iso_label="StormOS_Familia_Release"
iso_publisher="StormOS"
iso_application="StormOS Install Media"
iso_version="October"
install_dir="arch"
buildmodes=('iso')
bootmodes=('bios.syslinux'
           'uefi.systemd-boot')
arch="x86_64"
pacman_conf="pacman.conf"
airootfs_image_type="squashfs"
airootfs_image_tool_options=('-comp' 'xz' '-Xbcj' 'x86' '-b' '1M' '-Xdict-size' '1M')
bootstrap_tarball_compression=('zstd' '-c' '-T0' '--auto-threads=logical' '--long' '-19')
file_permissions=(
  ["/etc/shadow"]="0:0:400"
  ["/root"]="0:0:750"
  ["/root/.automated_script.sh"]="0:0:755"
  ["/root/.gnupg"]="0:0:700"
  ["/usr/local/bin/choose-mirror"]="0:0:755"
  ["/usr/local/bin/Installation_guide"]="0:0:755"
  ["/usr/local/bin/livecd-sound"]="0:0:755"
  ["/usr/local/bin/postinstall.sh"]="0:0:755"
  ["/usr/local/bin/readme"]="0:0:755"
  ["/usr/bin/installer"]="0:0:755"
  {"/usr/local/bin/launcher"}="0:0:755"
  ["/etc/gshadow"]="0:0:400"
  ["/etc/shadow"]="0:0:400"
  ["/usr/local/bin/trust.sh"]="0:0:755"
  ["/etc/skel/.config/autostart/calamares.desktop"]="0:0:755"
  ["/etc/skel/.config/autostart/NetworkManager.desktop"]="0:0:755"
  ["/etc/skel/.config/autostart/readme"]="0:0:755"
  ["/etc/skel/.config/autostart/welcome"]="0:0:755"
  ["/etc/skel/Desktop/calamares.desktop"]="0:0:755"
  ["/etc/skel/Desktop/system-tool.desktop"]="0:0:755"
  ["/usr/bin/wifi-connection.sh"]="0:0:755"
  ["/usr/bin/stormos-installer"]="0:0:755"
)
