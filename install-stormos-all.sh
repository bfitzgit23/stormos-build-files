#!/usr/bin/env bash
#
# install-stormos-all.sh — Universal StormOS theme installer.
#
# Detects Arch/Manjaro/Debian and applies the correct theme, icons,
# configs, and services. Runs from the stormos-build-files repo root.
#
# Usage:
#   bash install-stormos-all.sh              # detect distro + install
#   bash install-stormos-all.sh --arch       # force Arch
#   bash install-stormos-all.sh --manjaro    # force Manjaro
#   bash install-stormos-all.sh --debian     # force Debian
#   bash install-stormos-all.sh --dry-run    # show what would be done
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

ok()   { echo -e "${GREEN}✓${NC} $*"; }
info() { echo -e "${CYAN}→${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC} $*"; }
err()  { echo -e "${RED}✗${NC} $*"; }
bold() { echo -e "${BOLD}$*${NC}"; }

DRY_RUN=false
FORCE_DISTRO=""

# ─── Parse args ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)     FORCE_DISTRO="arch";     shift ;;
        --manjaro)  FORCE_DISTRO="manjaro";  shift ;;
        --debian)   FORCE_DISTRO="debian";   shift ;;
        --dry-run)  DRY_RUN=true;            shift ;;
        -h|--help)
            echo "Usage: $0 [--arch|--manjaro|--debian] [--dry-run]"
            exit 0 ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

# ─── Distro detection ────────────────────────────────────────────────────────
detect_distro() {
    if [[ -n "$FORCE_DISTRO" ]]; then
        echo "$FORCE_DISTRO"
        return
    fi

    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            arch|endeavouros|garuda|artix)
                echo "arch" ;;
            manjaro|manjaro-arm)
                echo "manjaro" ;;
            debian|ubuntu|linuxmint|devuan)
                echo "debian" ;;
            *)
                # Check ID_LIKE for fallback
                case "$ID_LIKE" in
                    *arch*)  echo "arch" ;;
                    *debian*) echo "debian" ;;
                    *) echo "unknown" ;;
                esac ;;
        esac
    else
        # Fallback: check package manager
        if command -v pacman &>/dev/null; then
            echo "arch"
        elif command -v apt &>/dev/null; then
            echo "debian"
        else
            echo "unknown"
        fi
    fi
}

DISTRO=$(detect_distro)

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          StormOS Universal Theme Installer       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
bold "Detected distro: $DISTRO"
echo ""

if [[ "$DISTRO" == "unknown" ]]; then
    err "Cannot detect distro. Use --arch, --manjaro, or --debian."
    exit 1
fi

if $DRY_RUN; then
    warn "DRY RUN — no changes will be made"
    echo ""
fi

# ─── Helper: run or print ────────────────────────────────────────────────────
run() {
    if $DRY_RUN; then
        echo -e "  ${CYAN}[dry-run]${NC} $*"
    else
        "$@"
    fi
}

# ─── Helper: install packages ────────────────────────────────────────────────
install_pkgs_pacman() {
    local pkgs=("$@")
    local need=()
    for pkg in "${pkgs[@]}"; do
        if ! pacman -Qi "$pkg" &>/dev/null 2>&1; then
            need+=("$pkg")
        fi
    done
    if [[ ${#need[@]} -gt 0 ]]; then
        info "Installing (pacman): ${need[*]}"
        run sudo pacman -S --needed --noconfirm "${need[@]}"
        ok "Pacman packages installed"
    else
        ok "All pacman packages already installed"
    fi
}

install_pkgs_apt() {
    local pkgs=("$@")
    local need=()
    for pkg in "${pkgs[@]}"; do
        if ! dpkg -s "$pkg" &>/dev/null 2>&1; then
            need+=("$pkg")
        fi
    done
    if [[ ${#need[@]} -gt 0 ]]; then
        info "Installing (apt): ${need[*]}"
        run sudo apt-get install -y "${need[@]}"
        ok "APT packages installed"
    else
        ok "All APT packages already installed"
    fi
}

install_pkgs_yay() {
    local pkgs=("$@")
    if ! command -v yay &>/dev/null; then
        err "yay not found — install it first: https://aur.archlinux.org/packages/yay-bin"
        return 1
    fi
    local need=()
    for pkg in "${pkgs[@]}"; do
        if ! yay -Qi "$pkg" &>/dev/null 2>&1; then
            need+=("$pkg")
        fi
    done
    if [[ ${#need[@]} -gt 0 ]]; then
        info "Installing (yay): ${need[*]}"
        run yay -S --needed --noconfirm "${need[@]}"
        ok "AUR packages installed"
    else
        ok "All AUR packages already installed"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# ARCH
# ═══════════════════════════════════════════════════════════════════════════════
install_arch() {
    bold "═══ Installing StormOS theme for Arch Linux ═══"

    local SKEL="$SCRIPT_DIR/install-stormos-xfce/airootfs/etc/skel"

    # ── Packages ──
    info "Checking packages..."
    install_pkgs_pacman picom conky xcursor-vanilla-dmz foot alacritty fastfetch \
        xfce4-goodies xfce4-terminal xorg-server switcheroo-control noto-fonts
    install_pkgs_yay ttf-inter ttf-jetbrains-mono-nerd xfce4-docklike-plugin

    # ── Backup ──
    local BACKUP="$HOME/.stormos-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP"
    info "Backing up existing configs to $BACKUP"
    for f in .config/xfce4 .config/gtk-3.0 .config/gtk-4.0 .config/gtkrc-2.0 \
             .config/alacritty .config/foot .config/conky .config/picom \
             .config/qt5ct .config/qt6ct .config/Kvantum .config/Thunar \
             .config/autostart .gtk-bookmarks; do
        [ -e "$HOME/$f" ] && run cp -r "$HOME/$f" "$BACKUP/$(basename "$f")" 2>/dev/null || true
    done
    ok "Backup complete"

    # ── Copy configs ──
    info "Installing StormOS XFCE configs..."
    mkdir -p "$HOME/.config/xfce4/xfconf/xfce-perchannel-xml"
    run cp "$SKEL/.config/xfce4/xfconf/xfce-perchannel-xml/"*.xml \
        "$HOME/.config/xfce4/xfconf/xfce-perchannel-xml/"

    mkdir -p "$HOME/.config/xfce4/panel"
    run cp -r "$SKEL/.config/xfce4/panel/"* "$HOME/.config/xfce4/panel/" 2>/dev/null || true

    mkdir -p "$HOME/.config/gtk-3.0" "$HOME/.config/gtk-4.0"
    run cp "$SKEL/.config/gtk-3.0/settings.ini" "$HOME/.config/gtk-3.0/"
    run cp "$SKEL/.config/gtk-3.0/gtk.css" "$HOME/.config/gtk-3.0/"
    run cp "$SKEL/.config/gtk-4.0/gtk.css" "$HOME/.config/gtk-4.0/"
    run cp "$SKEL/.config/gtkrc-2.0" "$HOME/.config/"

    mkdir -p "$HOME/.config/alacritty" "$HOME/.config/foot"
    run cp "$SKEL/.config/alacritty/alacritty.toml" "$HOME/.config/alacritty/"
    run cp "$SKEL/.config/foot/foot.ini" "$HOME/.config/foot/"

    mkdir -p "$HOME/.config/picom"
    run cp "$SKEL/.config/picom/picom.conf" "$HOME/.config/picom/"

    mkdir -p "$HOME/.config/conky"
    run cp "$SKEL/.config/conky/conky.conf" "$HOME/.config/conky/"

    mkdir -p "$HOME/.config/qt5ct" "$HOME/.config/qt6ct" "$HOME/.config/Kvantum"
    run cp "$SKEL/.config/qt5ct/qt5ct.conf" "$HOME/.config/qt5ct/"
    run cp "$SKEL/.config/qt6ct/qt6ct.conf" "$HOME/.config/qt6ct/"
    run cp "$SKEL/.config/Kvantum/kvantum.kvconfig" "$HOME/.config/Kvantum/"

    mkdir -p "$HOME/.config/Thunar"
    run cp "$SKEL/.config/Thunar/uca.xml" "$HOME/.config/Thunar/"

    mkdir -p "$HOME/.config/autostart"
    for d in "$SKEL/.config/autostart/"*.desktop; do
        [ -f "$d" ] && run cp "$d" "$HOME/.config/autostart/"
    done

    # ── GTK theme (Arc-BLACK-ICE) ──
    info "Setting XFCE theme..."
    run killall xfconfd 2>/dev/null || true
    sleep 1
    run xfconf-query -c xsettings -p /Net/ThemeName -s "Arc-BLACK-ICE" 2>/dev/null || true
    run xfconf-query -c xsettings -p /Net/IconThemeName -s "Qogir" 2>/dev/null || true
    run xfconf-query -c xsettings -p /Gtk/FontName -s "Inter 10" 2>/dev/null || true
    run xfconf-query -c xsettings -p /Gtk/CursorThemeName -s "DMZ-Black" 2>/dev/null || true
    run xfconf-query -c xfwm4 -p /general/theme -s "Arc-BLACK-ICE" 2>/dev/null || true
    ok "Theme set"

    # ── Switcheroo applet ──
    local APPLET="$SCRIPT_DIR/install-stormos-xfce/airootfs/usr/local/bin/stormos-switcheroo-applet"
    if [[ -f "$APPLET" ]]; then
        run sudo cp "$APPLET" /usr/local/bin/
        run sudo chmod +x /usr/local/bin/stormos-switcheroo-applet
        ok "Switcheroo applet installed"
    fi

    # ── Services ──
    info "Enabling services..."
    if systemctl is-enabled lightdm &>/dev/null 2>&1; then
        ok "LightDM already enabled"
    else
        run sudo systemctl enable lightdm 2>/dev/null && ok "LightDM enabled" || true
    fi
    if systemctl is-enabled NetworkManager &>/dev/null 2>&1; then
        ok "NetworkManager already enabled"
    else
        run sudo systemctl enable NetworkManager 2>/dev/null && ok "NetworkManager enabled" || true
    fi

    # ── Start compositor + conky now ──
    if [[ -n "${DISPLAY:-}" ]] || [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
        info "Starting picom..."
        run killall picom 2>/dev/null || true
        sleep 0.5
        run picom --daemon 2>/dev/null && ok "Picom running" || warn "Picom failed to start"
        info "Starting conky..."
        run killall conky 2>/dev/null || true
        conky -c "$HOME/.config/conky/conky.conf" &>/dev/null &
        ok "Conky started"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# MANJARO
# ═══════════════════════════════════════════════════════════════════════════════
install_manjaro() {
    bold "═══ Installing StormOS theme for Manjaro ═══"

    local SKEL="$SCRIPT_DIR/install-stormos-manjaro/airootfs/etc/skel"

    # ── Packages ──
    info "Checking packages..."
    install_pkgs_pacman picom conky foot alacritty fastfetch \
        xfce4-goodies xfce4-terminal xorg-server switcheroo-control noto-fonts \
        pamac-all mhwd mhwd-db
    install_pkgs_yay ttf-inter ttf-jetbrains-mono-nerd xfce4-docklike-plugin

    # ── Backup ──
    local BACKUP="$HOME/.stormos-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP"
    info "Backing up existing configs to $BACKUP"
    for f in .config/xfce4 .config/gtk-3.0 .config/gtk-4.0 .config/gtkrc-2.0 \
             .config/alacritty .config/foot .config/conky .config/picom \
             .config/qt5ct .config/qt6ct .config/Kvantum .config/Thunar \
             .config/autostart .gtk-bookmarks; do
        [ -e "$HOME/$f" ] && run cp -r "$HOME/$f" "$BACKUP/$(basename "$f")" 2>/dev/null || true
    done
    ok "Backup complete"

    # ── Copy configs ──
    info "Installing StormOS XFCE configs..."
    mkdir -p "$HOME/.config/xfce4/xfconf/xfce-perchannel-xml"
    run cp "$SKEL/.config/xfce4/xfconf/xfce-perchannel-xml/"*.xml \
        "$HOME/.config/xfce4/xfconf/xfce-perchannel-xml/"

    mkdir -p "$HOME/.config/xfce4/panel"
    run cp -r "$SKEL/.config/xfce4/panel/"* "$HOME/.config/xfce4/panel/" 2>/dev/null || true

    mkdir -p "$HOME/.config/gtk-3.0" "$HOME/.config/gtk-4.0"
    run cp "$SKEL/.config/gtk-3.0/settings.ini" "$HOME/.config/gtk-3.0/"
    run cp "$SKEL/.config/gtk-3.0/gtk.css" "$HOME/.config/gtk-3.0/"
    run cp "$SKEL/.config/gtk-4.0/gtk.css" "$HOME/.config/gtk-4.0/"
    run cp "$SKEL/.config/gtkrc-2.0" "$HOME/.config/"

    mkdir -p "$HOME/.config/alacritty" "$HOME/.config/foot"
    run cp "$SKEL/.config/alacritty/alacritty.toml" "$HOME/.config/alacritty/"
    run cp "$SKEL/.config/foot/foot.ini" "$HOME/.config/foot/"

    mkdir -p "$HOME/.config/picom"
    run cp "$SKEL/.config/picom/picom.conf" "$HOME/.config/picom/"

    mkdir -p "$HOME/.config/conky"
    run cp "$SKEL/.config/conky/conky.conf" "$HOME/.config/conky/"

    mkdir -p "$HOME/.config/qt5ct" "$HOME/.config/qt6ct" "$HOME/.config/Kvantum"
    run cp "$SKEL/.config/qt5ct/qt5ct.conf" "$HOME/.config/qt5ct/"
    run cp "$SKEL/.config/qt6ct/qt6ct.conf" "$HOME/.config/qt6ct/"
    run cp "$SKEL/.config/Kvantum/kvantum.kvconfig" "$HOME/.config/Kvantum/"

    mkdir -p "$HOME/.config/Thunar"
    run cp "$SKEL/.config/Thunar/uca.xml" "$HOME/.config/Thunar/"

    mkdir -p "$HOME/.config/autostart"
    for d in "$SKEL/.config/autostart/"*.desktop; do
        [ -f "$d" ] && run cp "$d" "$HOME/.config/autostart/"
    done

    # ── Theme variants ──
    info "Installing StormOS theme variants..."
    local THEMES="$SCRIPT_DIR/install-stormos-manjaro/airootfs/usr/share/themes"
    for theme in StormOS-Green StormOS-LightBlue; do
        if [[ -d "$THEMES/$theme" ]]; then
            run sudo cp -r "$THEMES/$theme" /usr/share/themes/
            ok "$theme theme installed"
        fi
    done

    # ── GTK theme ──
    info "Setting XFCE theme..."
    run killall xfconfd 2>/dev/null || true
    sleep 1
    run xfconf-query -c xsettings -p /Net/ThemeName -s "Arc-BLACK-ICE" 2>/dev/null || true
    run xfconf-query -c xsettings -p /Net/IconThemeName -s "Qogir" 2>/dev/null || true
    run xfconf-query -c xsettings -p /Gtk/FontName -s "Inter 10" 2>/dev/null || true
    run xfconf-query -c xsettings -p /Gtk/CursorThemeName -s "DMZ-Black" 2>/dev/null || true
    run xfconf-query -c xfwm4 -p /general/theme -s "Arc-BLACK-ICE" 2>/dev/null || true
    ok "Theme set"

    # ── Switcheroo applet ──
    local APPLET="$SCRIPT_DIR/install-stormos-manjaro/airootfs/usr/local/bin/stormos-switcheroo-applet"
    if [[ -f "$APPLET" ]]; then
        run sudo cp "$APPLET" /usr/local/bin/
        run sudo chmod +x /usr/local/bin/stormos-switcheroo-applet
        ok "Switcheroo applet installed"
    fi

    # ── Services ──
    info "Enabling services..."
    for svc in lightdm NetworkManager; do
        if systemctl is-enabled "$svc" &>/dev/null 2>&1; then
            ok "$svc already enabled"
        else
            run sudo systemctl enable "$svc" 2>/dev/null && ok "$svc enabled" || true
        fi
    done

    # ── Start compositor + conky now ──
    if [[ -n "${DISPLAY:-}" ]] || [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
        info "Starting picom..."
        run killall picom 2>/dev/null || true
        sleep 0.5
        run picom --daemon 2>/dev/null && ok "Picom running" || warn "Picom failed to start"
        info "Starting conky..."
        run killall conky 2>/dev/null || true
        conky -c "$HOME/.config/conky/conky.conf" &>/dev/null &
        ok "Conky started"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# DEBIAN (StormD)
# ═══════════════════════════════════════════════════════════════════════════════
install_debian() {
    bold "═══ Installing StormOS theme for Debian ═══"

    local SKEL="$SCRIPT_DIR/install-stormos-xfce/airootfs/etc/skel"

    # ── Packages ──
    info "Checking packages..."
    install_pkgs_apt xfce4 xfce4-goodies thunar xfce4-terminal \
        picom conky alacritty fastfetch fonts-inter \
        switcheroo-control network-manager-gnome lightdm slick-greeter

    # ── Backup ──
    local BACKUP="$HOME/.stormos-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP"
    info "Backing up existing configs to $BACKUP"
    for f in .config/xfce4 .config/gtk-3.0 .config/gtk-4.0 .config/gtkrc-2.0 \
             .config/alacritty .config/foot .config/conky .config/picom \
             .config/Thunar .config/autostart .gtk-bookmarks; do
        [ -e "$HOME/$f" ] && run cp -r "$HOME/$f" "$BACKUP/$(basename "$f")" 2>/dev/null || true
    done
    ok "Backup complete"

    # ── Copy configs ──
    info "Installing StormOS XFCE configs..."
    mkdir -p "$HOME/.config/xfce4/xfconf/xfce-perchannel-xml"
    run cp "$SKEL/.config/xfce4/xfconf/xfce-perchannel-xml/"*.xml \
        "$HOME/.config/xfce4/xfconf/xfce-perchannel-xml/"

    mkdir -p "$HOME/.config/gtk-3.0" "$HOME/.config/gtk-4.0"
    run cp "$SKEL/.config/gtk-3.0/settings.ini" "$HOME/.config/gtk-3.0/"
    run cp "$SKEL/.config/gtk-3.0/gtk.css" "$HOME/.config/gtk-3.0/"
    run cp "$SKEL/.config/gtk-4.0/gtk.css" "$HOME/.config/gtk-4.0/"
    run cp "$SKEL/.config/gtkrc-2.0" "$HOME/.config/"

    mkdir -p "$HOME/.config/alacritty" "$HOME/.config/foot"
    run cp "$SKEL/.config/alacritty/alacritty.toml" "$HOME/.config/alacritty/"
    run cp "$SKEL/.config/foot/foot.ini" "$HOME/.config/foot/"

    mkdir -p "$HOME/.config/picom"
    run cp "$SKEL/.config/picom/picom.conf" "$HOME/.config/picom/"

    mkdir -p "$HOME/.config/conky"
    run cp "$SKEL/.config/conky/conky.conf" "$HOME/.config/conky/"

    mkdir -p "$HOME/.config/Thunar"
    run cp "$SKEL/.config/Thunar/uca.xml" "$HOME/.config/Thunar/"

    mkdir -p "$HOME/.config/autostart"
    for d in "$SKEL/.config/autostart/"*.desktop; do
        [ -f "$d" ] && run cp "$d" "$HOME/.config/autostart/"
    done

    # ── Theme ──
    info "Setting XFCE theme..."
    run xfconf-query -c xsettings -p /Net/ThemeName -s "Arc-BLACK-ICE" 2>/dev/null || true
    run xfconf-query -c xsettings -p /Net/IconThemeName -s "Qogir" 2>/dev/null || true
    run xfconf-query -c xsettings -p /Gtk/FontName -s "Inter 10" 2>/dev/null || true
    run xfconf-query -c xfwm4 -p /general/theme -s "Arc-BLACK-ICE" 2>/dev/null || true
    ok "Theme set"

    # ── Services ──
    info "Enabling services..."
    for svc in lightdm NetworkManager; do
        if systemctl is-enabled "$svc" &>/dev/null 2>&1; then
            ok "$svc already enabled"
        else
            run sudo systemctl enable "$svc" 2>/dev/null && ok "$svc enabled" || true
        fi
    done

    # ── Start compositor + conky now ──
    if [[ -n "${DISPLAY:-}" ]] || [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
        info "Starting picom..."
        run killall picom 2>/dev/null || true
        sleep 0.5
        run picom --daemon 2>/dev/null && ok "Picom running" || warn "Picom failed to start"
        info "Starting conky..."
        run killall conky 2>/dev/null || true
        conky -c "$HOME/.config/conky/conky.conf" &>/dev/null &
        ok "Conky started"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════
case "$DISTRO" in
    arch)   install_arch   ;;
    manjaro) install_manjaro ;;
    debian) install_debian ;;
    *)
        err "Unsupported distro: $DISTRO"
        err "Supported: arch, manjaro, debian"
        exit 1 ;;
esac

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        StormOS theme applied successfully!       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Distro:  $DISTRO"
echo "  Theme:   Arc-BLACK-ICE + StormOS blue accents"
echo "  Icons:   Qogir"
echo "  Cursor:  DMZ-Black"
echo "  Font:    Inter (UI), JetBrains Mono (terminal)"
echo "  Compositor: picom (GLX, blur, shadows)"
echo "  System:  Conky sidebar (CPU, GPU, RAM, Disk, Network)"
echo ""
echo "  To reload panel:  xfce4-panel -r"
echo "  To restart WM:    xfwm4 --replace"
echo "  To apply now:     Log out and back in"
echo ""
