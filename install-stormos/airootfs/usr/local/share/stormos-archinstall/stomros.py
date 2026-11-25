#!/usr/bin/env python3
"""
StomrOS Aurora — archinstall profile
Run: archinstall --config installer/stomros.py
"""

import json
from pathlib import Path

# ── User configuration ──────────────────────────────────────────────────────
USERNAME = "storm"
HOSTNAME = "stomros"
TIMEZONE = "UTC"
LOCALE = "en_US.UTF-8"
KEYMAP = "us"
ROOT_PASSWORD = ""  # empty = disabled (sudo only)
USER_PASSWORD = ""  # empty = disabled (sudo only)

# ── Disk / Boot ─────────────────────────────────────────────────────────────
DISK = "nvme0n1"           # target disk (adjust in config)
BOOTLOADER = "systemd-boot"  # or "grub"
ENCRYPT = False             # LUKS encryption
SWAP_SIZE = "4G"            # swap partition size

# ── Packages ────────────────────────────────────────────────────────────────
PACKAGES_BASE = [
    "base", "linux", "linux-firmware", "linux-headers",
    "sudo", "networkmanager", "polkit", "polkit-gnome",
    "vim", "git", "curl", "wget", "htop", "btop", "unzip", "zip",
    "pipewire", "pipewire-pulse", "pipewire-alsa", "wireplumber",
    "brightnessctl", "power-profiles-daemon", "cpupower", "pciutils",
    "envycontrol",  # AUR - will be handled separately
    "lightdm", "lightdm-slick-greeter",
    "plymouth",
    "xfwm4", "xfce4-settings", "xfconf", "xfce4-notifyd",
    "electron",
    "python",
]

PACKAGES_GUI = [
    "firefox", "thunar", "gvfs", "gvfs-mtp", "gvfs-gphoto2",
    "file-roller", "xarchiver",
    "code",  # VS Code
]

PACKAGES_FONTS = [
    "noto-fonts", "noto-fonts-emoji", "noto-fonts-cjk",
    "ttf-jetbrains-mono", "ttf-firacode-nerd",
    "inter-font",
]

PACKAGES_AUR = [
    "stormui-git",  # built locally, installed via pacman -U
    "envycontrol",
]

# ── Profile ─────────────────────────────────────────────────────────────────
profile = {
    "version": "2.6",
    "profile": "minimal",
    "script": "guided",
    "bootloader": BOOTLOADER,
    "target": f"/dev/{DISK}",
    "disk_encryption": ENCRYPT,
    "swap": True,
    "swap_size": SWAP_SIZE,
    "hostname": HOSTNAME,
    "locale": LOCALE,
    "keymap": KEYMAP,
    "timezone": TIMEZONE,
    "root_password": ROOT_PASSWORD if ROOT_PASSWORD else None,
    "users": [
        {
            "username": USERNAME,
            "password": USER_PASSWORD if USER_PASSWORD else None,
            "sudo": True,
            "groups": ["wheel", "video", "audio", "storage", "power", "network"],
        }
    ],
    "packages": PACKAGES_BASE + PACKAGES_GUI + PACKAGES_FONTS,
    "services": [
        "NetworkManager",
        "lightdm",
        "systemd-timesyncd",
        "pipewire",
        "pipewire-pulse",
    ],
    "kernels": ["linux"],
    "profile_def": {
        "name": "StomrOS Aurora",
        "description": "Vibe-coded desktop over minimal Xfce substrate",
        "packages": PACKAGES_BASE + PACKAGES_GUI + PACKAGES_FONTS,
    },
    "post_install": [
        # Enable lightdm with autologin
        f"sed -i 's/^#autologin-user=.*/autologin-user={USERNAME}/' /etc/lightdm/lightdm.conf",
        f"sed -i 's/^#autologin-session=.*/autologin-session=Storm/' /etc/lightdm/lightdm.conf",
        f"sed -i 's/^#greeter-session=.*/greeter-session=lightdm-slick-greeter/' /etc/lightdm/lightdm.conf",

        # Slick greeter theme
        "mkdir -p /etc/lightdm",
        "cat > /etc/lightdm/slick-greeter.conf <<'EOF'\n[Greeter]\nbackground=/usr/share/backgrounds/stormos-grub.png\ntheme-name=Storm-Dark\nicon-theme-name=Papirus-Dark\nfont-name=Inter 10\nshow-indicators=~session;~power\nshow-clock=true\nclock-format=%H:%M\nEOF",

        # Plymouth theme
        "mkdir -p /usr/share/plymouth/themes/stormos",
        "cat > /usr/share/plymouth/themes/stormos/stormos.plymouth <<'EOF'\n[Plymouth Theme]\nName=StomrOS Aurora\nDescription=Vibe-coded boot splash\nModuleName=script\n[script]\nImageDir=/usr/share/plymouth/themes/stormos\nScriptFile=/usr/share/plymouth/themes/stormos/stormos.script\nEOF",

        # Install stormui-git package (built locally)
        "pacman -U --noconfirm /tmp/stormui-git-*.pkg.tar.zst 2>/dev/null || true",

        # Run stage3 to strip Xfce to substrate
        "bash /usr/lib/stormui/arch/stage3-arch.sh --apply --install --autologin storm 2>/dev/null || true",

        # Set default session to Storm
        "systemctl set-default graphical.target",

        # Ensure stormd user unit is enabled for the user
        f"sudo -u {USERNAME} systemctl --user enable stormd.service 2>/dev/null || true",

        # Clean up
        "pacman -Sc --noconfirm",
        "rm -rf /tmp/* /var/tmp/*",
    ],
    "extra_repos": [],
    "extra_packages": [],
}

# ── Write profile ───────────────────────────────────────────────────────────
output_path = Path(__file__).parent / "stomros.json"
output_path.write_text(json.dumps(profile, indent=2))
print(f"Profile written to {output_path}")
print("Run: archinstall --config installer/stomros.json")