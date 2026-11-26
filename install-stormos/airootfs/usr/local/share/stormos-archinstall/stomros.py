#!/usr/bin/env python3
"""StomrOS Aurora — archinstall profile generator.

Writes stomros.json next to this file. The output is archinstall 4.5's config
format, i.e. the keys ArchConfig.from_config() actually reads:

    archinstall --config /usr/local/share/stormos-archinstall/stomros.json

Note for anyone reading older archinstall material: 4.5 has no `config_version`
key. It ignores any version in the file and stamps its own, so a `config_version`
field would be dead weight (the strings are absent from the 4.5 package source).
What 4.5 validates is `disk_config.config_type` and the per-partition keys.

The disk is deliberately not fixed here. `disk_config` carries a default device
that /usr/local/bin/stormos-archinstall replaces with the disk the user picks,
and the / partition is resized to fill it — the file stays valid JSON that can
be previewed, but the device that gets erased is never guessed.
"""

import json
from pathlib import Path

# ── System identity ─────────────────────────────────────────────────────────
USERNAME = "storm"
HOSTNAME = "stomros"
TIMEZONE = "UTC"
LOCALE = "en_US.UTF-8"
KEYMAP = "us"
BOOTLOADER = "Systemd-boot"  # or "Grub"

# Placeholders: stormos-archinstall rewrites both before calling archinstall.
DEFAULT_DISK = "/dev/sda"
DEFAULT_ROOT_MIB = 20480

# ── Packages ────────────────────────────────────────────────────────────────
# Storm is a shell over a minimal Xfce substrate: xfwm4 draws the windows,
# xfsettingsd supplies XSETTINGS, xfce4-notifyd answers org.freedesktop.
# Notifications. xfce4-session and xfce4-panel are intentionally absent.
# envycontrol is AUR-only and cannot be installed by archinstall from the
# official repos, so it is not listed here.
PACKAGES = [
    "base",
    "linux",
    "linux-firmware",
    "linux-headers",
    "sudo",
    "networkmanager",
    "polkit",
    "polkit-gnome",
    "vim",
    "git",
    "curl",
    "wget",
    "htop",
    "btop",
    "unzip",
    "zip",
    "pipewire",
    "pipewire-pulse",
    "pipewire-alsa",
    "wireplumber",
    "brightnessctl",
    "power-profiles-daemon",
    "cpupower",
    "pciutils",
    "lightdm",
    "lightdm-slick-greeter",
    "xorg-server",
    "plymouth",
    "xfwm4",
    "xfce4-settings",
    "xfconf",
    "xfce4-notifyd",
    "electron",
    "python",
    "firefox",
    "thunar",
    "gvfs",
    "gvfs-mtp",
    "gvfs-gphoto2",
    "file-roller",
    "xarchiver",
    "code",
    "noto-fonts",
    "noto-fonts-emoji",
    "noto-fonts-cjk",
    "ttf-jetbrains-mono",
    "ttf-firacode-nerd",
    "inter-font",
]

SERVICES = [
    "NetworkManager",
    "lightdm",
    "systemd-timesyncd",
]

# Each entry is written to /var/tmp/user-command.N.sh and run inside the new
# system by archinstall, so these are chroot commands and must stand alone.
POST_INSTALL = [
    "systemctl set-default graphical.target\n",
    # Autologin, but only for an account that exists: archinstall prompts for
    # the user account, so someone who picks another name keeps a normal
    # greeter login instead of a lightdm session that cannot start.
    (
        "if id -u storm >/dev/null 2>&1 && [ -f /etc/lightdm/lightdm.conf ]; then\n"
        "  sed -i 's/^#\\?autologin-user=.*/autologin-user=storm/' /etc/lightdm/lightdm.conf\n"
        "fi\n"
    ),
    # Only point lightdm at the Storm session if StormUI actually shipped a
    # session file to this system; xfce4-session is not installed either.
    (
        "if [ -f /usr/share/xsessions/storm.desktop ] && [ -f /etc/lightdm/lightdm.conf ]; then\n"
        "  sed -i 's/^#\\?autologin-session=.*/autologin-session=storm/' /etc/lightdm/lightdm.conf\n"
        "fi\n"
    ),
    (
        "if [ -d /etc/lightdm ]; then\n"
        "  printf '[Greeter]\\nshow-clock=true\\nclock-format=%%H:%%M\\nfont-name=Inter 10\\n'"
        " > /etc/lightdm/slick-greeter.conf\n"
        "fi\n"
    ),
]


def _size(value_mib: int) -> dict:
    return {
        "sector_size": {"unit": "B", "value": 512},
        "unit": "MiB",
        "value": value_mib,
    }


def _partition(
    obj_id: str,
    start_mib: int,
    size_mib: int,
    fs_type: str,
    mountpoint: str,
    flags: list[str] | None = None,
) -> dict:
    """One partition as DiskLayoutConfiguration.parse_arg() expects it.

    Every key is read with [] indexing, so none of them may be omitted.
    """
    return {
        "btrfs": [],
        "dev_path": None,
        "flags": flags or [],
        "fs_type": fs_type,
        "size": _size(size_mib),
        "mount_options": [],
        "mountpoint": mountpoint,
        "obj_id": obj_id,
        "start": _size(start_mib),
        "status": "create",
        "type": "primary",
    }


profile = {
    "version": "2.8.6",  # ignored by 4.5; kept so older archinstall accepts it
    "script": "guided",
    "archinstall-language": "English",
    "audio_config": {"audio": "pipewire"},
    "bootloader_config": {
        "bootloader": BOOTLOADER,
        "uki": False,
        "removable": False,
    },
    "debug": False,
    "disk_config": {
        "config_type": "default_layout",
        "device_modifications": [
            {
                "device": DEFAULT_DISK,
                "wipe": True,
                "partitions": [
                    _partition(
                        "a1c2b3d4-0001-4a5b-8c7d-1e2f3a4b5c01",
                        1,
                        512,
                        "fat32",
                        "/boot",
                        ["boot"],
                    ),
                    _partition(
                        "a1c2b3d4-0002-4a5b-8c7d-1e2f3a4b5c02",
                        513,
                        DEFAULT_ROOT_MIB,
                        "ext4",
                        "/",
                    ),
                ],
            }
        ],
    },
    "hostname": HOSTNAME,
    "kernels": ["linux"],
    "locale_config": {
        "kb_layout": KEYMAP,
        "sys_enc": "UTF-8",
        "sys_lang": LOCALE,
    },
    # NetworkManager, matching the networkmanager package and the service below.
    "network_config": {"type": "nm"},
    "ntp": True,
    "offline": False,
    "no_pkg_lookups": False,
    "pacman_config": {"color": False, "parallel_downloads": 5},
    # Minimal adds no desktop profile of its own: the substrate above is the
    # desktop. Setting it explicitly stops archinstall prompting for a profile.
    "profile_config": {
        "profile": {"main": "Minimal"},
        "gfx_driver": None,
        "greeter": None,
    },
    "packages": PACKAGES,
    "services": SERVICES,
    "silent": False,
    "swap": {"enabled": True, "algorithm": "zstd"},
    "timezone": TIMEZONE,
    "custom_commands": POST_INSTALL,
}

if __name__ == "__main__":
    output_path = Path(__file__).parent / "stomros.json"
    output_path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    print(f"Profile written to {output_path}")
    print("Run: archinstall --config " + str(output_path))
