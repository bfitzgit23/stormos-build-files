#!/usr/bin/env bash
# shellcheck disable=SC2034

iso_name="StormOS_XFCE"
iso_label="StormOS_XFCE_$(date +%Y%m)"
iso_publisher="StormOS <https://www.storm-os.godaddysites.com>"
iso_application="StormOS install medium"
iso_version="$(date +%Y.%m.%d)"
install_dir="arch"
bootmodes=('bios.syslinux.mbr' 'bios.syslinux.eltorito' 'uefi-x64.systemd-boot.esp' 'uefi-x64.systemd-boot.eltorito')
arch="x86_64"
pacman_conf="pacman.conf"
airootfs_image_tool_options=('-comp' 'zstd' '-Xcompression-level' '15' '-b' '1M' )
file_permissions=(
  ["/root"]="0:0:750"
  ["/usr/local/bin/choose-mirror"]="0:0:755"
  ["/usr/local/bin/Installation_guide"]="0:0:755"
  ["/usr/local/bin/livecd-sound"]="0:0:755"
  ["/usr/local/bin/postinstall.sh"]="0:0:755"
  ["/usr/local/bin/readme"]="0:0:755"
  ["/usr/bin/menuxstorm"]="0:0:777"
  ["/usr/bin/wgetm"]="0:0:777"
  ["/usr/bin/playmovie"]="0:0:777"
  ["/usr/bin/axelc8"]="0:0:777"
)
