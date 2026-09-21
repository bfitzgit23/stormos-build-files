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
OFFICIAL_PKGS=(picom xcursor-vanilla-dmz xfce4-terminal fastfetch conky
               xfce4-goodies xorg-server switcheroo-control
               xfce4-notifyd xfce4-power-manager xfce4-screenshooter
               xfce4-pulseaudio-plugin)

# AUR packages (yay)
AUR_PKGS=(ttf-inter ttf-jetbrains-mono-nerd xfce4-docklike-plugin qt5-styleplugins)

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

# ─── 1c. Remove labwc and openbox (StormOS uses xfwm4 now) ────────────────
REMOVE_PKGS=(labwc openbox)
NEED_REMOVE=()
for pkg in "${REMOVE_PKGS[@]}"; do
    if pacman -Qi "$pkg" &>/dev/null 2>&1; then
        NEED_REMOVE+=("$pkg")
    fi
done
if [ ${#NEED_REMOVE[@]} -gt 0 ]; then
    info "Removing old packages: ${NEED_REMOVE[*]}"
    sudo pacman -Rns --noconfirm "${NEED_REMOVE[@]}" 2>/dev/null && ok "Removed ${NEED_REMOVE[*]}" || true
fi

# Remove openbox/labwc session files and configs
for sess_file in /usr/share/xsessions/openbox.desktop /usr/share/xsessions/labwc.desktop /usr/share/xsessions/labwc-wayland.desktop; do
    [ -f "$sess_file" ] && sudo rm -f "$sess_file" && info "Removed $(basename $sess_file)"
done
for cfg_dir in ~/.config/openbox ~/.config/labwc /etc/xdg/openbox /etc/xdg/labwc; do
    [ -d "$cfg_dir" ] && sudo rm -rf "$cfg_dir" && info "Removed $cfg_dir"
done

# ─── 1e. Rename CyberXero toolkit → StormOS toolkit ─────────────────────────
if [ -d /opt/cyberxero-toolkit ]; then
    info "Renaming CyberXero toolkit → StormOS toolkit..."
    sudo mv /opt/cyberxero-toolkit /opt/stormos-toolkit 2>/dev/null || true
    sudo rm -f /opt/cyberxero-toolkit-src 2>/dev/null || true
    sudo ln -sf /opt/stormos-toolkit/cyberxero-toolkit /usr/bin/stormos-toolkit 2>/dev/null || true
    [ -f /usr/share/applications/cyberxero-toolkit.desktop ] && \
        sudo mv /usr/share/applications/cyberxero-toolkit.desktop /usr/share/applications/stormos-toolkit.desktop 2>/dev/null || true
    sudo rm -f /usr/local/bin/cyberxero-postinstall.sh 2>/dev/null || true
    sudo rm -f /etc/calamares/modules/shellprocess-cyberxero.conf 2>/dev/null || true
    ok "CyberXero toolkit renamed to StormOS toolkit"
fi

# ─── 1b. Install StormOS themes from build files ────────────────────────────
info "Installing StormOS themes..."

THEMES_SRC="$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/share/themes"
ICONS_SRC="$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/share/icons"

# Copy Arc-StormOS theme (base WM theme)
if [ -d "$THEMES_SRC/Arc-StormOS" ]; then
    sudo cp -r "$THEMES_SRC/Arc-StormOS" /usr/share/themes/
    # Fix CRLF in text files (may come from Windows)
    sudo find /usr/share/themes/Arc-StormOS -type f \
        \( -name '*.rc' -o -name '*.css' -o -name '*.conf' -o -name '*.theme' -o -name 'gtkrc' \) \
        -exec sed -i 's/\r$//' {} + 2>/dev/null || true
    ok "Arc-StormOS theme installed"
else
    err "Arc-StormOS not found in build files"
fi

# Copy Arc-StormOS theme (Arc-StormOS colors + BleuFear window borders)
if [ -d "$THEMES_SRC/Arc-StormOS" ]; then
    sudo cp -r "$THEMES_SRC/Arc-StormOS" /usr/share/themes/
    sudo find /usr/share/themes/Arc-StormOS -type f \
        \( -name '*.rc' -o -name '*.css' -o -name '*.conf' -o -name '*.theme' -o -name 'gtkrc' \) \
        -exec sed -i 's/\r$//' {} + 2>/dev/null || true
    ok "Arc-StormOS theme installed"
fi

# Copy BleuFear theme (dark blue accent theme)
if [ -d "$THEMES_SRC/BleuFear" ]; then
    sudo cp -r "$THEMES_SRC/BleuFear" /usr/share/themes/
    sudo find /usr/share/themes/BleuFear -type f \
        \( -name '*.rc' -o -name '*.css' -o -name '*.conf' -o -name '*.theme' -o -name 'gtkrc' \) \
        -exec sed -i 's/\r$//' {} + 2>/dev/null || true
    ok "BleuFear theme installed"
fi

# Copy Xfce-Purp theme (dark purple accent theme)
if [ -d "$THEMES_SRC/Xfce-Purp" ]; then
    sudo cp -r "$THEMES_SRC/Xfce-Purp" /usr/share/themes/
    sudo find /usr/share/themes/Xfce-Purp -type f \
        \( -name '*.rc' -o -name '*.css' -o -name '*.conf' -o -name '*.theme' -o -name 'gtkrc' \) \
        -exec sed -i 's/\r$//' {} + 2>/dev/null || true
    ok "Xfce-Purp theme installed"
fi

# Copy Qogir icons (now pre-recolored to StormOS blue)
for qtheme in Qogir Qogir-dark Qogir-manjaro Qogir-manjaro-dark; do
    if [ -d "$ICONS_SRC/$qtheme" ]; then
        sudo rm -rf "/usr/share/icons/$qtheme"
        sudo cp -r "$ICONS_SRC/$qtheme" /usr/share/icons/
        ok "$qtheme icons installed (StormOS recolor)"
    fi
done
# Safety net: if a stock (non-recolored) Qogir slipped in via pacman, retint it
if [ -f "$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/local/bin/recolor-qogir.sh" ]; then
    sudo cp "$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/local/bin/recolor-qogir.sh" /usr/local/bin/
    sudo chmod +x /usr/local/bin/recolor-qogir.sh
    sudo sed -i 's/\r$//' /usr/local/bin/recolor-qogir.sh
    sudo bash /usr/local/bin/recolor-qogir.sh || true
fi

# Copy StormOS-icons (blue icon overrides)
if [ -d "$ICONS_SRC/StormOS-icons" ]; then
    sudo rm -rf /usr/share/icons/StormOS-icons
    sudo cp -r "$ICONS_SRC/StormOS-icons" /usr/share/icons/
    ok "StormOS-icons installed"
else
    err "StormOS-icons not found in build files"
fi

# Fastfetch config + StormOS logo
if [ -d "$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/share/fastfetch/logo" ]; then
    sudo mkdir -p /usr/share/fastfetch/logo
    sudo cp -r "$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/share/fastfetch/logo/." /usr/share/fastfetch/logo/
    ok "Fastfetch StormOS logo installed"
fi
if [ -f "$SCRIPT_DIR/install-stormos-xfce/airootfs/etc/fastfetch/config.jsonc" ]; then
    sudo mkdir -p /etc/fastfetch
    sudo cp "$SCRIPT_DIR/install-stormos-xfce/airootfs/etc/fastfetch/config.jsonc" /etc/fastfetch/
    ok "Fastfetch config installed"
fi

# Remove stock XFCE backgrounds
info "Removing stock XFCE backgrounds..."
sudo rm -f /usr/share/backgrounds/xfce/* 2>/dev/null || true
sudo rm -f /usr/share/backgrounds/xfce-*.svg 2>/dev/null || true
ok "Stock backgrounds removed"

# Copy StormOS wallpaper
WALLPAPER_SRC="$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/share/backgrounds"
if [ -f "$WALLPAPER_SRC/stormos-wallpaper.png" ]; then
    sudo cp "$WALLPAPER_SRC/stormos-wallpaper.png" /usr/share/backgrounds/
    ok "StormOS wallpaper installed"
fi

# Install wallpaper setter script
if [ -f "$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/local/bin/stormos-set-wallpaper" ]; then
    sudo cp "$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/local/bin/stormos-set-wallpaper" /usr/local/bin/
    sudo chmod +x /usr/local/bin/stormos-set-wallpaper
    sudo sed -i 's/\r$//' /usr/local/bin/stormos-set-wallpaper
    ok "Wallpaper setter installed"
fi

# Install StormOS Gallery (custom image viewer, replaces ristretto)
if [ -f "$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/local/bin/stormos-gallery" ]; then
    sudo cp "$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/local/bin/stormos-gallery" /usr/local/bin/
    sudo chmod +x /usr/local/bin/stormos-gallery
    sudo sed -i 's/\r$//' /usr/local/bin/stormos-gallery
    ok "StormOS Gallery installed"
fi
if [ -f "$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/share/applications/stormos-gallery.desktop" ]; then
    sudo cp "$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/share/applications/stormos-gallery.desktop" /usr/share/applications/
    ok "StormOS Gallery desktop entry installed"
fi
# Make StormOS Gallery the default image viewer
if command -v xdg-mime >/dev/null 2>&1; then
    for mime in image/png image/jpeg image/gif image/bmp image/webp image/tiff image/svg+xml; do
        xdg-mime default stormos-gallery.desktop "$mime" 2>/dev/null || true
    done
    ok "StormOS Gallery set as default image viewer"
fi

# Install wallpaper autostart
mkdir -p "$HOME/.config/autostart"
cp "$SKEL/.config/autostart/stormos-wallpaper.desktop" "$HOME/.config/autostart/" 2>/dev/null || true

# Force wallpaper via xfconf-query
WALLPAPER="/usr/share/backgrounds/stormos-wallpaper.png"
for ws in 0 1 2 3; do
    xfconf-query -c xfce4-desktop -p "/backdrop/screen0/monitor0/workspace${ws}/image-style" -s 5 2>/dev/null || true
    xfconf-query -c xfce4-desktop -p "/backdrop/screen0/monitor0/workspace${ws}/image-path" -s "$WALLPAPER" 2>/dev/null || true
    xfconf-query -c xfce4-desktop -p "/backdrop/screen0/monitor0/workspace${ws}/last-image" -s "$WALLPAPER" 2>/dev/null || true
    xfconf-query -c xfce4-desktop -p "/backdrop/screen0/workspace${ws}/image-style" -s 5 2>/dev/null || true
    xfconf-query -c xfce4-desktop -p "/backdrop/screen0/workspace${ws}/image-path" -s "$WALLPAPER" 2>/dev/null || true
    xfconf-query -c xfce4-desktop -p "/backdrop/screen0/workspace${ws}/last-image" -s "$WALLPAPER" 2>/dev/null || true
done
ok "Wallpaper set"

ok "Themes installed"

# ─── 1d. Install StormOS session files ──────────────────────────────────────
info "Installing StormOS session files..."

SESSION_SRC="$SCRIPT_DIR/install-stormos-xfce/airootfs"

# StormOS session script
if [ -f "$SESSION_SRC/usr/bin/stormos-desktop" ]; then
    sudo cp "$SESSION_SRC/usr/bin/stormos-desktop" /usr/bin/stormos-desktop
    # Fix line endings (may come from Windows)
    sudo sed -i 's/\r$//' /usr/bin/stormos-desktop
    sudo chmod +x /usr/bin/stormos-desktop
    ok "StormOS session script installed"
fi

# Session .desktop files
sudo mkdir -p /usr/share/xsessions
for sess in "$SESSION_SRC/usr/share/xsessions/"*.desktop; do
    if [ -f "$sess" ]; then
        sudo cp "$sess" /usr/share/xsessions/
        sudo sed -i 's/\r$//' "/usr/share/xsessions/$(basename "$sess")"
        ok "Session: $(basename "$sess")"
    fi
done

# LightDM configs
LIGHTDM_SRC="$SESSION_SRC/etc/lightdm"
if [ -d "$LIGHTDM_SRC" ]; then
    sudo mkdir -p /etc/lightdm
    for lconf in lightdm.conf slick-greeter.conf users.conf; do
        if [ -f "$LIGHTDM_SRC/$lconf" ]; then
            sudo cp "$LIGHTDM_SRC/$lconf" /etc/lightdm/
            sudo sed -i 's/\r$//' "/etc/lightdm/$lconf"
        fi
    done
    ok "LightDM configs installed"
fi

ok "Session files installed"

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

# ─── 2b. Clean stale XFCE state (prevents blank screen / login loop) ─────
info "Cleaning stale XFCE state..."

# Remove saved session state — forces fresh session start
rm -rf "$HOME/.cache/sessions" 2>/dev/null || true

# Remove stale panel RC files (leftover from old plugin IDs)
rm -f "$HOME/.config/xfce4/panel/"*.rc 2>/dev/null || true
rm -rf "$HOME/.config/xfce4/panel/launcher-"* 2>/dev/null || true

# Remove ristretto and block it from coming back (replaced by StormOS Gallery)
sudo sed -i 's/^#IgnorePkg.*$/#IgnorePkg =\nIgnorePkg = ristretto/' /etc/pacman.conf 2>/dev/null || true
if pacman -Qi ristretto &>/dev/null; then
    sudo pacman -Rns --noconfirm ristretto 2>/dev/null || true
    info "Ristretto removed (replaced by StormOS Gallery)"
fi

# Remove stale autostart entries that might block session startup
rm -f "$HOME/.config/autostart/autoi.desktop" 2>/dev/null || true
rm -f "$HOME/.config/autostart/trust-launch.desktop" 2>/dev/null || true
rm -f "$HOME/.config/autostart/picom.desktop" 2>/dev/null || true

ok "Stale state cleaned"

# ─── 3. Copy XFCE theme settings ONLY (do NOT overwrite panel config!) ───────
info "Installing StormOS theme settings..."

# XFCE configs — themes, icons, fonts, panel, session
mkdir -p "$HOME/.config/xfce4/xfconf/xfce-perchannel-xml"
for xfconf_xml in xsettings.xml xfwm4.xml xfce4-desktop.xml xfce4-panel.xml xfce4-session.xml; do
    [ -f "$SKEL/.config/xfce4/xfconf/xfce-perchannel-xml/$xfconf_xml" ] && \
        cp "$SKEL/.config/xfce4/xfconf/xfce-perchannel-xml/$xfconf_xml" \
           "$HOME/.config/xfce4/xfconf/xfce-perchannel-xml/" 2>/dev/null || true
done
# Copy panel plugin RC files (docklike pinned apps etc.)
mkdir -p "$HOME/.config/xfce4/panel"
for panel_rc in "$SKEL/.config/xfce4/panel/"*.rc; do
    [ -f "$panel_rc" ] && cp "$panel_rc" "$HOME/.config/xfce4/panel/" 2>/dev/null || true
done
# Clear any saved session state that might reference broken components
rm -rf "$HOME/.cache/sessions" 2>/dev/null || true
ok "XFCE session configs installed"

# Restart xfce4-panel to pick up new config (dock pins etc.)
if pgrep -x xfce4-panel >/dev/null 2>&1; then
    xfce4-panel -r 2>/dev/null || true
    info "Panel restarted to apply dock pins"
fi

# Terminal config
mkdir -p "$HOME/.config/xfce4/terminal"
cp "$SKEL/.config/xfce4/terminal/terminalrc" "$HOME/.config/xfce4/terminal/" 2>/dev/null || true
# Enforce terminal font size 14 (JetBrains Mono Nerd)
sed -i 's/^FontName=.*/FontName=JetBrains Mono Nerd Font 14/' "$HOME/.config/xfce4/terminal/terminalrc" 2>/dev/null || true

# GTK themes
mkdir -p "$HOME/.config/gtk-3.0" "$HOME/.config/gtk-4.0"
cp "$SKEL/.config/gtk-3.0/settings.ini" "$HOME/.config/gtk-3.0/"
[ -f "$SKEL/.config/gtk-3.0/gtk.css" ] && cp "$SKEL/.config/gtk-3.0/gtk.css" "$HOME/.config/gtk-3.0/"
[ -f "$SKEL/.config/gtk-4.0/gtk.css" ] && cp "$SKEL/.config/gtk-4.0/gtk.css" "$HOME/.config/gtk-4.0/"
cp "$SKEL/.config/gtkrc-2.0" "$HOME/"

# GTK2 Murrine overrides
[ -f "$SKEL/.config/gtk-2.0/main.rc" ] && mkdir -p "$HOME/.config/gtk-2.0" && cp "$SKEL/.config/gtk-2.0/main.rc" "$HOME/.config/gtk-2.0/" 2>/dev/null || true

# Qt themes
mkdir -p "$HOME/.config/qt5ct" "$HOME/.config/qt6ct" "$HOME/.config/Kvantum"
cp "$SKEL/.config/qt5ct/qt5ct.conf" "$HOME/.config/qt5ct/"
cp "$SKEL/.config/qt5ct/style-colors.conf" "$HOME/.config/qt5ct/" 2>/dev/null || true
cp "$SKEL/.config/qt6ct/qt6ct.conf" "$HOME/.config/qt6ct/"
cp "$SKEL/.config/qt6ct/style-colors.conf" "$HOME/.config/qt6ct/" 2>/dev/null || true
cp "$SKEL/.config/Kvantum/kvantum.kvconfig" "$HOME/.config/Kvantum/"

# System-wide Qt color schemes
sudo mkdir -p /etc/qt5ct/colors /etc/qt6ct/colors
sudo cp "$SCRIPT_DIR/install-stormos-xfce/airootfs/etc/qt5ct/colors/stormos.conf" /etc/qt5ct/colors/ 2>/dev/null || true
sudo cp "$SCRIPT_DIR/install-stormos-xfce/airootfs/etc/qt6ct/colors/stormos.conf" /etc/qt6ct/colors/ 2>/dev/null || true

# Pamac config (AUR, Flatpak, parallel downloads)
mkdir -p "$HOME/.config/pamac"
[ -f "$SKEL/.config/pamac/pamac.conf" ] && cp "$SKEL/.config/pamac/pamac.conf" "$HOME/.config/pamac/" 2>/dev/null || true

# Thunar file manager
mkdir -p "$HOME/.config/Thunar"
cp "$SKEL/.config/Thunar/uca.xml" "$HOME/.config/Thunar/"
cp "$SKEL/.config/Thunar/gtk.xml" "$HOME/.config/Thunar/" 2>/dev/null || true

# Autostart entries (welcome, switcheroo, conky)
mkdir -p "$HOME/.config/autostart"
for auto in stormos-welcome.desktop stormos-switcheroo-applet.desktop stormos-conky.desktop; do
    [ -f "$SKEL/.config/autostart/$auto" ] && cp "$SKEL/.config/autostart/$auto" "$HOME/.config/autostart/"
done

# Conky config (system overview panel)
mkdir -p "$HOME/.config/conky"
cp "$SKEL/.config/conky/conky.conf" "$HOME/.config/conky/" 2>/dev/null || true
cp "$SKEL/.config/conky/stormos-rings.lua" "$HOME/.config/conky/" 2>/dev/null || true

# Bookmarks
cp "$SKEL/.gtk-bookmarks" "$HOME/" 2>/dev/null || true

# StormOS environment
sudo cp "$SCRIPT_DIR/install-stormos-xfce/airootfs/etc/environment" /etc/environment

# Remove GTK_THEME from /etc/environment (LightDM reads it and crashes)
# XFCE reads theme from xfconf instead
sudo sed -i '/^GTK_THEME=/d' /etc/environment 2>/dev/null || true
sudo sed -i 's/^GTK_ICON_THEME=.*/GTK_ICON_THEME=Qogir-dark/' /etc/environment 2>/dev/null || true

# Ensure environment variables are set for Qt theming
if ! grep -q 'QT_QPA_PLATFORMTHEME=gtk2' /etc/environment 2>/dev/null; then
    echo 'QT_QPA_PLATFORMTHEME=gtk2' | sudo tee -a /etc/environment >/dev/null
    echo 'QT_STYLE_OVERRIDE=gtk3' | sudo tee -a /etc/environment >/dev/null
fi

# Switcheroo-control applet
if [ -f "$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/local/bin/stormos-switcheroo-applet" ]; then
    sudo cp "$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/local/bin/stormos-switcheroo-applet" /usr/local/bin/
    sudo chmod +x /usr/local/bin/stormos-switcheroo-applet
    ok "Switcheroo applet installed"
fi

ok "All configs installed"

# ─── 4. Set GTK theme via xfconf ─────────────────────────────────────────────
info "Setting XFCE theme via xfconf..."

# Set theme (don't kill xfconfd — it will pick up new XML configs on restart)
xfconf-query -c xsettings -p /Net/ThemeName -s "Arc-StormOS" 2>/dev/null || true
xfconf-query -c xsettings -p /Net/IconThemeName -s "StormOS-icons" 2>/dev/null || true
xfconf-query -c xsettings -p /Gtk/FontName -s "Inter 11" 2>/dev/null || true
xfconf-query -c xsettings -p /Gtk/MonospaceFontName -s "JetBrains Mono 14" 2>/dev/null || true

# WM theme
xfconf-query -c xfwm4 -p /general/theme -s "Arc-StormOS" 2>/dev/null || true
# Also copy the themerc directly as a fallback
if [ -f "$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/share/themes/Arc-StormOS/xfwm4/themerc" ]; then
    sudo cp "$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/share/themes/Arc-StormOS/xfwm4/themerc" \
        /usr/share/themes/Arc-StormOS/xfwm4/themerc 2>/dev/null || true
fi
# Refresh xfwm4 to apply the new theme
if pgrep -x xfwm4 >/dev/null 2>&1; then
    xfwm4 --replace >/dev/null 2>&1 &
    info "xfwm4 refreshed to apply Arc-StormOS theme"
fi

# Set wallpaper for all workspaces (XFCE 4.20 uses monitor0 nesting)
for ws in 0 1 2 3; do
    xfconf-query -c xfce4-desktop -p "/backdrop/screen0/monitor0/workspace${ws}/image-style" -s 5 2>/dev/null || true
    xfconf-query -c xfce4-desktop -p "/backdrop/screen0/monitor0/workspace${ws}/image-path" -s "/usr/share/backgrounds/stormos-wallpaper.png" 2>/dev/null || true
    xfconf-query -c xfce4-desktop -p "/backdrop/screen0/workspace${ws}/image-style" -s 5 2>/dev/null || true
    xfconf-query -c xfce4-desktop -p "/backdrop/screen0/workspace${ws}/image-path" -s "/usr/share/backgrounds/stormos-wallpaper.png" 2>/dev/null || true
done

# Force xfdesktop to reload wallpaper and disable desktop icons
if pgrep -x xfdesktop >/dev/null 2>&1; then
    xfdesktop --reload 2>/dev/null || true
    # Kill and restart xfdesktop to ensure icons are disabled
    killall xfdesktop 2>/dev/null || true
    sleep 1
    xfdesktop --disable-desktop 2>/dev/null &
    sleep 1
    xfdesktop --reload 2>/dev/null || true
fi

# Also set desktop icons via xfconf to be absolutely sure
xfconf-query -c xfce4-desktop -p /icons/default/show -s false 2>/dev/null || true
xfconf-query -c xfce4-desktop -p /icons/default/show-home -s false 2>/dev/null || true
xfconf-query -c xfce4-desktop -p /icons/default/show-filesystem -s false 2>/dev/null || true
xfconf-query -c xfce4-desktop -p /icons/default/show-removable -s false 2>/dev/null || true
xfconf-query -c xfce4-desktop -p /icons/default/show-trash -s false 2>/dev/null || true

ok "XFCE theme set"

# ─── 5. Enable services ──────────────────────────────────────────────────────
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

echo ""
echo -e "${GREEN}✓ StormOS theme installed!${NC}"
echo -e "  Log out and back in to see changes."
echo ""
