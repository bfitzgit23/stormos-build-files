#!/usr/bin/env bash
# install-stormos-desktop.sh — Install the StormOS React desktop shell.
#
# Installs Node.js, Electron, openbox, Python bridge deps, builds the
# frontend, installs session files, configures LightDM + slick-greeter.
#
# Usage:
#   sudo ./install-stormos-desktop.sh            # full install
#   ./install-stormos-desktop.sh --user-only     # skip system packages

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr}"
SKIP_SYSTEM_PKGS=0

for arg in "$@"; do
    case "$arg" in
        --user-only) SKIP_SYSTEM_PKGS=1 ;;
        --help|-h)
            echo "Usage: $0 [--user-only]"
            echo ""
            echo "  --user-only   Skip system package installation (Node, openbox, etc.)"
            exit 0
            ;;
    esac
done

info()  { printf '\033[1;34m[stormos]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[stormos]\033[0m %s\n' "$*"; }
error() { printf '\033[1;31m[stormos]\033[0m %s\n' "$*" >&2; exit 1; }

# ---- System packages ----
if [ "$SKIP_SYSTEM_PKGS" -eq 0 ]; then
    if ! command -v pacman >/dev/null 2>&1; then
        error "This installer targets Arch Linux (pacman not found). Use --user-only for other distros."
    fi

    info "Installing system dependencies..."
    sudo pacman -S --needed --noconfirm \
        nodejs npm python python-requests openbox xorg-server xorg-xinit \
        foot thunar firefox polkit-gnome \
        lightdm lightdm-slick-greeter
fi

# ---- Python bridge dependencies ----
info "Installing Python bridge dependencies..."
pip3 install --user requests 2>/dev/null || python3 -m pip install --user requests 2>/dev/null || true

# ---- Build the React frontend ----
info "Building React frontend..."
cd "$SCRIPT_DIR"
npm install
npm run build

# ---- Install session files ----
info "Installing session files to $INSTALL_PREFIX/share/stormos-desktop/..."
sudo mkdir -p "$INSTALL_PREFIX/share/stormos-desktop"

# Copy source files
for f in main.js preload.js vite.config.js package.json package-lock.json index.html; do
    [ -f "$SCRIPT_DIR/$f" ] && sudo cp "$SCRIPT_DIR/$f" "$INSTALL_PREFIX/share/stormos-desktop/"
done

# Copy directories (skip if not present)
for d in session native bin dist src; do
    [ -d "$SCRIPT_DIR/$d" ] && sudo cp -r "$SCRIPT_DIR/$d" "$INSTALL_PREFIX/share/stormos-desktop/"
done

# Copy config if it exists (foot.ini, picom.conf, etc.)
if [ -d "$SCRIPT_DIR/config" ]; then
    sudo cp -r "$SCRIPT_DIR/config" "$INSTALL_PREFIX/share/stormos-desktop/"
fi

# ---- Install the launcher binary ----
info "Installing stormos-desktop launcher..."
sudo tee "$INSTALL_PREFIX/bin/stormos-desktop" >/dev/null <<LAUNCHER
#!/usr/bin/env bash
# StormOS desktop launcher — called by LightDM or .xinitrc
export STORMOS_DESKTOP_DIR="$INSTALL_PREFIX/share/stormos-desktop"
exec bash "$INSTALL_PREFIX/share/stormos-desktop/bin/stormos-desktop" "\$@"
LAUNCHER
sudo chmod +x "$INSTALL_PREFIX/bin/stormos-desktop"

# ---- Install the bridge binary ----
info "Installing stormos-bridge..."
sudo tee "$INSTALL_PREFIX/bin/stormos-bridge" >/dev/null <<BRIDGE
#!/usr/bin/env python3
import sys, os
sys.path.insert(0, '$INSTALL_PREFIX/share/stormos-desktop/native')
exec(open('$INSTALL_PREFIX/share/stormos-desktop/native/stormos-bridge.py').read())
BRIDGE
sudo chmod +x "$INSTALL_PREFIX/bin/stormos-bridge"

# ---- Session desktop entry for display managers ----
info "Installing session desktop entry..."
sudo tee /usr/share/xsessions/stormos-desktop.desktop >/dev/null <<'XS'
[Desktop Entry]
Name=StormOS Desktop
Comment=StormOS React desktop shell (Electron + openbox)
Exec=/usr/bin/stormos-desktop
TryExec=/usr/bin/stormos-desktop
Type=Application
DesktopNames=StormOS
XS

# ---- LightDM configuration ----
info "Configuring LightDM..."
if [ -f /etc/lightdm/lightdm.conf ]; then
    # Back up existing config
    sudo cp /etc/lightdm/lightdm.conf /etc/lightdm/lightdm.conf.bak 2>/dev/null || true

    # Set user-session and autologin-session to stormos-desktop
    sudo sed -i 's/^user-session=.*/user-session=stormos-desktop/' /etc/lightdm/lightdm.conf
    sudo sed -i 's/^autologin-session=.*/autologin-session=stormos-desktop/' /etc/lightdm/lightdm.conf

    # If no user-session line exists, add it under [Seat:*]
    if ! grep -q '^user-session=' /etc/lightdm/lightdm.conf; then
        sudo sed -i '/^\[Seat:\*\]/a user-session=stormos-desktop' /etc/lightdm/lightdm.conf
    fi
    if ! grep -q '^autologin-session=' /etc/lightdm/lightdm.conf; then
        sudo sed -i '/^\[Seat:\*\]/a autologin-session=stormos-desktop' /etc/lightdm/lightdm.conf
    fi

    info "  Updated /etc/lightdm/lightdm.conf"
else
    warn "  /etc/lightdm/lightdm.conf not found — skipping LightDM config"
fi

# ---- slick-greeter configuration ----
info "Configuring slick-greeter..."
sudo mkdir -p /etc/lightdm
sudo tee /etc/lightdm/slick-greeter.conf >/dev/null <<'GREETER'
[Greeter]
background=/usr/share/backgrounds/stormos-wallpaper.png
logo=/usr/share/pixmaps/stormos-logo.png
theme-name=StormOS-GTK
icon-theme-name=Qogir
font-name=Inter 11
enable-hidpi=auto
draw-user-background=false
draw-grid=false
blur-radius=10
blur-saturation=1.0
GREETER
info "  Created /etc/lightdm/slick-greeter.conf"

# ---- Install wallpaper and logo for greeter ----
if [ -f "$SCRIPT_DIR/session/lightdm/slick-greeter.conf" ]; then
    sudo cp "$SCRIPT_DIR/session/lightdm/slick-greeter.conf" /etc/lightdm/slick-greeter.conf
fi

# Ensure wallpaper is in place
if [ ! -f /usr/share/backgrounds/stormos-wallpaper.png ]; then
    if [ -f "$SCRIPT_DIR/session/stormos-wallpaper.png" ]; then
        sudo cp "$SCRIPT_DIR/session/stormos-wallpaper.png" /usr/share/backgrounds/
    fi
fi

# Ensure logo is in place
if [ ! -f /usr/share/pixmaps/stormos-logo.png ]; then
    # Try to use the existing StormOS menu button as logo
    if [ -f /usr/share/pixmaps/stormos/menubutton.png ]; then
        sudo cp /usr/share/pixmaps/stormos/menubutton.png /usr/share/pixmaps/stormos-logo.png
    fi
fi

# ---- Enable polkit agent in autostart ----
mkdir -p "$HOME/.config/autostart"
cat > "$HOME/.config/autostart/stormos-polkit.desktop" <<'POLKIT'
[Desktop Entry]
Type=Application
Name=PolicyKit Agent
Exec=/usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1
Hidden=true
NoDisplay=true
X-GNOME-Autostart-enabled=false
POLKIT

# ---- Enable LightDM (if not already enabled) ----
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-enabled lightdm.service >/dev/null 2>&1; then
        info "  LightDM service already enabled"
    else
        info "  Enabling LightDM service..."
        sudo systemctl enable lightdm.service 2>/dev/null || true
    fi
fi

info ""
info "Installation complete!"
info ""
info "To start StormOS Desktop:"
info "  Option 1: Reboot — LightDM will show StormOS Desktop in the session list"
info "  Option 2: Select 'StormOS Desktop' in slick-greeter's session chooser (gear icon)"
info "  Option 3: Add to ~/.xinitrc and run 'startx'"
info "  Option 4: Run 'stormos-desktop' from a terminal"
info ""
info "To set StormOS as the default session:"
info "  sudo sed -i 's/^user-session=.*/user-session=stormos-desktop/' /etc/lightdm/lightdm.conf"
info "  sudo sed -i 's/^autologin-session=.*/autologin-session=stormos-desktop/' /etc/lightdm/lightdm.conf"
info ""
info "The Python bridge runs automatically on port 47821."
info "System stats are served via Electron IPC (no network needed)."
