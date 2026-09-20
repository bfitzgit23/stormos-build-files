#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="/usr"
BUILD_DIR="$(mktemp -d /tmp/stormos-react-build.XXXXXX)"
cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

if [[ $EUID -eq 0 ]]; then
  echo "Run this installer as your normal user; it uses sudo when needed."
  exit 1
fi

command -v sudo >/dev/null || { echo "sudo is required."; exit 1; }
command -v npm >/dev/null || {
  echo "npm/nodejs are required. Install nodejs and npm first."
  exit 1
}

echo "Installing required Arch packages..."
sudo pacman -S --needed --noconfirm \
  labwc gtk4 webkitgtk-6.0 python python-gobject \
  dbus networkmanager bluez bluez-utils pipewire wireplumber \
  thunar gvfs gvfs-mtp gvfs-smb gvfs-gphoto2 gvfs-nfs gvfs-dnssd \
  udisks2 thunar-volman firefox libreoffice-fresh xdg-utils \
  polkit polkit-gnome upower pavucontrol blueman swaybg foot \
  grim wlr-randr || true

echo "Building React desktop..."
mkdir -p "$BUILD_DIR"
cp -a "$ROOT"/. "$BUILD_DIR"/
rm -rf "$BUILD_DIR/node_modules" "$BUILD_DIR/dist"
(
  cd "$BUILD_DIR"
  npm install --no-audit --no-fund --ignore-scripts
  npm run build
)

echo "Installing StormOS desktop files..."
sudo install -d \
  "$PREFIX/share/stormos-shell/dist" \
  "$PREFIX/share/stormos-shell/session" \
  "$PREFIX/share/backgrounds/stormos" \
  "$PREFIX/share/themes" \
  "$PREFIX/share/icons" \
  "$PREFIX/share/wayland-sessions" \
  "$PREFIX/share/foot" \
  "$PREFIX/share/picom" \
  "$PREFIX/bin" \
  "/etc/xdg/labwc"

sudo cp -a "$BUILD_DIR/dist/." "$PREFIX/share/stormos-shell/dist/"
sudo install -m 0755 "$ROOT/native/stormos-bridge.py" "$PREFIX/share/stormos-shell/stormos-bridge.py"
sudo install -m 0755 "$ROOT/native/stormos-bridge.py" "$PREFIX/bin/stormos-bridge"
sudo install -m 0755 "$ROOT/native/stormos-shell-host.py" "$PREFIX/share/stormos-shell/stormos-shell-host.py"
sudo install -m 0755 "$ROOT/session/stormos-shell-host" "$PREFIX/bin/stormos-shell-host"

# Session wiring: the display manager execs /usr/bin/stormos-session, which
# execs labwc; labwc then runs /etc/xdg/labwc/autostart which starts the
# bridge, wallpaper and the shell host. rc.xml pins the shell fullscreen.
sudo install -m 0755 "$ROOT/session/stormos-session" "$PREFIX/bin/stormos-session"
sudo install -m 0755 "$ROOT/session/stormos-session-action" "$PREFIX/bin/stormos-session-action"
sudo install -m 0755 "$ROOT/session/stormos-session.sh" "$PREFIX/share/stormos-shell/session/stormos-session.sh"
sudo install -m 0755 "$ROOT/session/autostart" "/etc/xdg/labwc/autostart"
sudo install -m 0644 "$ROOT/session/rc.xml" "/etc/xdg/labwc/rc.xml"
sudo install -m 0644 "$ROOT/session/menu.xml" "/etc/xdg/labwc/menu.xml"
sudo install -m 0644 "$ROOT/session/environment" "/etc/xdg/labwc/environment"
sudo install -m 0644 "$ROOT/session/stormos.desktop" "$PREFIX/share/wayland-sessions/stormos.desktop"

# Session assets kept on disk for the standalone runner and reference.
sudo install -m 0644 "$ROOT/session/rc.xml" "$PREFIX/share/stormos-shell/session/rc.xml"
sudo install -m 0644 "$ROOT/session/menu.xml" "$PREFIX/share/stormos-shell/session/menu.xml"
sudo install -m 0644 "$ROOT/session/environment" "$PREFIX/share/stormos-shell/session/environment"
sudo install -m 0755 "$ROOT/session/autostart" "$PREFIX/share/stormos-shell/session/autostart"

sudo install -m 0644 "$ROOT/public/stormos-wallpaper.svg" "$PREFIX/share/backgrounds/stormos/stormos-wallpaper.svg"
sudo cp -a "$ROOT/themes/StormOS-GTK" "$PREFIX/share/themes/StormOS-GTK"
sudo cp -a "$ROOT/themes/StormOS-icons" "$PREFIX/share/icons/StormOS-icons"
sudo install -m 0644 "$ROOT/config/foot/foot.ini" "$PREFIX/share/foot/foot.ini"
sudo install -m 0644 "$ROOT/config/picom/picom.conf" "$PREFIX/share/picom/picom.conf"
sudo install -m 0755 "$ROOT/bin/stormos-foot" "$PREFIX/bin/stormos-foot"

echo
echo "StormOS React desktop installed."
echo "Log out, select 'StormOS' in your display manager, and log back in."
echo "The shell now loads as the desktop itself, not as a window inside stock labwc."
echo "Logs: ~/.local/state/stormos/ and ~/.stormos-*.log"
