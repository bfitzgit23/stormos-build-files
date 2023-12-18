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
'uefi-ia32.grub.esp' 'uefi-x64.grub.esp'
           'uefi-ia32.grub.eltorito' 'uefi-x64.grub.eltorito'
pacman_conf="pacman.conf"
airootfs_image_type="squashfs"
airootfs_image_tool_options=('-comp' 'zstd' '-Xcompression-level' '15' '-b' '1M' )
file_permissions=(
  ["/root"]="0:0:750"
  ["/root/.automated_script.sh"]="0:0:777"
  ["/usr/local/bin/"]="0:0:755"
  ["/usr/bin/wgetm"]="0:0:777"
  ["/etc/gshadow"]="0:0:400"
  ["/etc/shadow"]="0:0:400"
  ["/usr/local/share/wm.sh"]=":0:0:755"
)
