#!/usr/bin/env bash
# shellcheck disable=SC2034

iso_name="StormOS"
iso_label="StormOS"
iso_publisher="StormOS"
iso_application="StormOS Install Media"
iso_version="1.0"
install_dir="arch"
buildmodes=('iso')
bootmodes=('bios.syslinux.mbr' 'bios.syslinux.eltorito'
           'uefi-ia32.systemd-boot.esp' 'uefi-x64.systemd-boot.esp'
           'uefi-ia32.systemd-boot.eltorito' 'uefi-x64.systemd-boot.eltorito')
arch="x86_64"
pacman_conf="pacman.conf"
airootfs_image_type="squashfs"
airootfs_image_tool_options=('-comp' 'zstd' '-Xcompression-level' '15' '-b' '1M' )
file_permissions=(
  ["/root"]="0:0:750"
  ["/root/.automated_script.sh"]="0:0:755"
  ["/usr/local/bin/choose-mirror"]="0:0:755"
  ["/usr/local/bin/Installation_guide"]="0:0:755"
  ["/usr/local/bin/livecd-sound"]="0:0:755"
  ["/usr/local/bin/postinstall.sh"]="0:0:755"
  ["/usr/local/bin/readme"]="0:0:755"
  ["/etc/gshadow"]="0:0:400"
  ["/etc/shadow"]="0:0:400"
  ["/usr/local/bin/compiz-remove.sh"]="0:0:755"
  ["/usr/bin/icarusv13.1g1.py"]="0:0:755"
  ["/usr/bin/stormav3.py"]="0:0:755"
  ["/usr/bin/appcreator11.py"]="0:0:755"
  ["/usr/bin/calamares"]="0:0:755"
)
