#!/usr/bin/env bash
#
# install-stormos-theme.sh — Apply StormOS theme to an existing Arch XFCE install.
#
# Run as your normal user (uses sudo only for package installs and system files).
# Usage:  bash install-stormos-theme.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKEL="$SCRIPT_DIR/install-stormos-xfce/airootfs/etc/skel"
PKGS="$SCRIPT_DIR/install-stormos-xfce/packages.x86_64"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "${GREEN}✓${NC} $*"; }
info() { echo -e "${CYAN}→${NC} $*"; }
err()  { echo -e "${RED}✗${NC} $*"; }

echo ""
echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       StormOS Theme Installer        ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
echo ""

# ─── 1. Install missing packages ─────────────────────────────────────────────
info "Checking packages..."

# Official repo packages (pacman)
OFFICIAL_PKGS=(picom xcursor-vanilla-dmz xfce4-terminal fastfetch
               xfce4-goodies xorg-server switcheroo-control)

# AUR packages (yay)
AUR_PKGS=(ttf-inter ttf-jetbrains-mono-nerd xfce4-docklike-plugin)

# Check and install official packages
NEED_OFFICIAL=()
for pkg in "${OFFICIAL_PKGS[@]}"; do
    if ! pacman -Qi "$pkg" &>/dev/null; then
        NEED_OFFICIAL+=("$pkg")
    fi
done

if [ ${#NEED_OFFICIAL[@]} -gt 0 ]; then
    info "Installing (pacman): ${NEED_OFFICIAL[*]}"
    sudo pacman -S --needed --noconfirm "${NEED_OFFICIAL[@]}"
    ok "Official packages installed"
fi

# Check and install AUR packages via yay
if ! command -v yay &>/dev/null; then
    err "yay not found — install it first: https://aur.archlinux.org/packages/yay-bin"
    err "Then re-run this script."
    exit 1
fi

NEED_AUR=()
for pkg in "${AUR_PKGS[@]}"; do
    if ! yay -Qi "$pkg" &>/dev/null; then
        NEED_AUR+=("$pkg")
    fi
done

if [ ${#NEED_AUR[@]} -gt 0 ]; then
    info "Installing (yay): ${NEED_AUR[*]}"
    yay -S --needed --noconfirm "${NEED_AUR[@]}"
    ok "AUR packages installed"
else
    ok "All AUR packages already installed"
fi

ok "All packages ready"

# ─── 1b. Install StormOS themes from build files ────────────────────────────
info "Installing StormOS themes..."

THEMES_SRC="$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/share/themes"
ICONS_SRC="$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/share/icons"

# Copy Arc-BLACK-ICE theme
if [ -d "$THEMES_SRC/Arc-BLACK-ICE" ]; then
    sudo cp -r "$THEMES_SRC/Arc-BLACK-ICE" /usr/share/themes/
    ok "Arc-BLACK-ICE theme installed"
else
    err "Arc-BLACK-ICE not found in build files"
fi

# Copy Qogir icons
if [ -d "$ICONS_SRC/StormOS-icons" ]; then
    sudo cp -r "$ICONS_SRC/StormOS-icons" /usr/share/icons/
    sudo cp -r "$ICONS_SRC/StormOS-icons" /usr/share/icons/ 2>/dev/null || true
    ok "Qogir icons installed"
else
    err "Qogir icons not found in build files"
fi

# Copy StormOS wallpaper
WALLPAPER_SRC="$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/share/backgrounds"
if [ -f "$WALLPAPER_SRC/stormos-wallpaper.png" ]; then
    sudo cp "$WALLPAPER_SRC/stormos-wallpaper.png" /usr/share/backgrounds/
    ok "StormOS wallpaper installed"
fi

ok "Themes installed"

# ─── 2. Backup existing configs ──────────────────────────────────────────────
BACKUP="$HOME/.stormos-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
info "Backing up existing configs to $BACKUP"

for f in .config/xfce4 .config/gtk-3.0 .config/gtk-4.0 .config/gtkrc-2.0 \
         .config/qt5ct .config/qt6ct .config/Kvantum .config/Thunar \
         .config/autostart .gtk-bookmarks; do
    [ -e "$HOME/$f" ] && cp -r "$HOME/$f" "$BACKUP/$(basename "$f")" 2>/dev/null || true
done
ok "Backup complete"

# ─── 3. Copy XFCE skel configs ───────────────────────────────────────────────
info "Installing StormOS XFCE configs..."

# XFCE panel + window manager + settings
mkdir -p "$HOME/.config/xfce4/xfconf/xfce-perchannel-xml"
cp "$SKEL/.config/xfce4/xfconf/xfce-perchannel-xml/"*.xml \
   "$HOME/.config/xfce4/xfconf/xfce-perchannel-xml/"

# Panel launchers and docklike
mkdir -p "$HOME/.config/xfce4/panel"
cp -r "$SKEL/.config/xfce4/panel/"* "$HOME/.config/xfce4/panel/" 2>/dev/null || true

# GTK themes
mkdir -p "$HOME/.config/gtk-3.0" "$HOME/.config/gtk-4.0"
cp "$SKEL/.config/gtk-3.0/settings.ini" "$HOME/.config/gtk-3.0/"
cp "$SKEL/.config/gtk-3.0/gtk.css" "$HOME/.config/gtk-3.0/"
cp "$SKEL/.config/gtk-4.0/gtk.css" "$HOME/.config/gtk-4.0/"
cp "$SKEL/.config/gtkrc-2.0" "$HOME/.config/"

# GTK2 Murrine overrides
cp "$SKEL/.config/gtk-2.0/main.rc" "$HOME/.config/gtk-2.0/" 2>/dev/null || true

# xfce4-terminal is the default terminal — no additional terminals installed

# Picom compositor
mkdir -p "$HOME/.config/picom"
cp "$SKEL/.config/picom/picom.conf" "$HOME/.config/picom/"

# Conky system monitor

# Qt themes
mkdir -p "$HOME/.config/qt5ct" "$HOME/.config/qt6ct" "$HOME/.config/Kvantum"
cp "$SKEL/.config/qt5ct/qt5ct.conf" "$HOME/.config/qt5ct/"
cp "$SKEL/.config/qt6ct/qt6ct.conf" "$HOME/.config/qt6ct/"
cp "$SKEL/.config/Kvantum/kvantum.kvconfig" "$HOME/.config/Kvantum/"

# Thunar file manager
mkdir -p "$HOME/.config/Thunar"
cp "$SKEL/.config/Thunar/uca.xml" "$HOME/.config/Thunar/"
cp "$SKEL/.config/Thunar/gtk.xml" "$HOME/.config/Thunar/" 2>/dev/null || true

# Autostart entries (picom, welcome, switcheroo)
mkdir -p "$HOME/.config/autostart"
cp "$SKEL/.config/autostart/picom.desktop" "$HOME/.config/autostart/"
[ -f "$SKEL/.config/autostart/stormos-welcome.desktop" ] && \
    cp "$SKEL/.config/autostart/stormos-welcome.desktop" "$HOME/.config/autostart/"
[ -f "$SKEL/.config/autostart/stormos-switcheroo-applet.desktop" ] && \
    cp "$SKEL/.config/autostart/stormos-switcheroo-applet.desktop" "$HOME/.config/autostart/"

# Bookmarks
cp "$SKEL/.gtk-bookmarks" "$HOME/" 2>/dev/null || true

# StormOS environment
sudo cp "$SCRIPT_DIR/install-stormos-xfce/airootfs/etc/environment" /etc/environment

# Switcheroo-control applet
if [ -f "$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/local/bin/stormos-switcheroo-applet" ]; then
    sudo cp "$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/local/bin/stormos-switcheroo-applet" /usr/local/bin/
    sudo chmod +x /usr/local/bin/stormos-switcheroo-applet
    ok "Switcheroo applet installed"
fi

ok "All configs installed"

# ─── 4. Set GTK theme via xfconf ─────────────────────────────────────────────
info "Setting XFCE theme via xfconf..."

# Kill xfconfd if running so it picks up new configs
killall xfconfd 2>/dev/null || true
sleep 1

# Set theme
xfconf-query -c xsettings -p /Net/ThemeName -s "Arc-BLACK-ICE" 2>/dev/null || true
xfconf-query -c xsettings -p /Net/IconThemeName -s "StormOS-icons" 2>/dev/null || true
xfconf-query -c xsettings -p /Gtk/FontName -s "Inter 10" 2>/dev/null || true
xfconf-query -c xsettings -p /Gtk/MonospaceFontName -s "JetBrains Mono 10" 2>/dev/null || true
xfconf-query -c xsettings -p /Gtk/CursorThemeName -s "DMZ-Black" 2>/dev/null || true

# WM theme
xfconf-query -c xfwm4 -p /general/theme -s "Arc-BLACK-ICE" 2>/dev/null || true
xfconf-query -c xfwm4 -p /general/title_font -s "Inter Bold 10" 2>/dev/null || true

ok "XFCE theme set"

# ─── 5. Terminal setup ────────────────────────
# xfce4-terminal is the default — no terminals to remove

# ─── 6. Enable services ──────────────────────────────────────────────────────
info "Enabling services..."

# LightDM
if systemctl is-enabled lightdm &>/dev/null 2>&1; then
    ok "LightDM already enabled"
else
    sudo systemctl enable lightdm 2>/dev/null && ok "LightDM enabled" || true
fi

# NetworkManager
if systemctl is-enabled NetworkManager &>/dev/null 2>&1; then
    ok "NetworkManager already enabled"
else
    sudo systemctl enable NetworkManager 2>/dev/null && ok "NetworkManager enabled" || true
fi

# ─── 6. Start picom now ──────────────────────────────────────────────────────
if [ -n "$DISPLAY" ] || [ -n "$WAYLAND_DISPLAY" ]; then
    info "Starting picom compositor..."
    killall picom 2>/dev/null || true
    sleep 0.5
    if picom --daemon 2>/dev/null; then
        ok "Picom running"
    else
        err "Picom failed to start (may need a display server)"
    fi
else
    info "No display server detected — picom will start on next login"
fi

