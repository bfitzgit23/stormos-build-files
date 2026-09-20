#!/usr/bin/env bash
# Install the StormOS session assets into $PREFIX (default /usr).
# Run from the project root:  sudo ./session/install-stormos-shell.sh /usr
set -euo pipefail
PREFIX="${1:-/usr}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

install -d "$PREFIX/share/stormos-shell" \
           "$PREFIX/share/stormos-shell/session" \
           "$PREFIX/share/stormos-shell/dist" \
           "$PREFIX/share/backgrounds/stormos" \
           "$PREFIX/share/wayland-sessions" \
           "$PREFIX/bin" \
           "/etc/xdg/labwc"

# Backend + host (only if not already present from a full install).
[ -f "$PREFIX/share/stormos-shell/stormos-bridge.py" ] || \
    install -m 0755 "$ROOT/native/stormos-bridge.py" "$PREFIX/share/stormos-shell/stormos-bridge.py"
[ -f "$PREFIX/bin/stormos-bridge" ] || \
    install -m 0755 "$ROOT/native/stormos-bridge.py" "$PREFIX/bin/stormos-bridge"
[ -f "$PREFIX/share/stormos-shell/stormos-shell-host.py" ] || \
    install -m 0755 "$ROOT/native/stormos-shell-host.py" "$PREFIX/share/stormos-shell/stormos-shell-host.py"
[ -f "$PREFIX/bin/stormos-shell-host" ] || \
    install -m 0755 "$ROOT/session/stormos-shell-host" "$PREFIX/bin/stormos-shell-host"

# Session wiring (always refreshed — this is the important part).
install -m 0755 "$ROOT/session/stormos-session" "$PREFIX/bin/stormos-session"
install -m 0755 "$ROOT/session/stormos-session-action" "$PREFIX/bin/stormos-session-action"
install -m 0755 "$ROOT/session/stormos-session.sh" "$PREFIX/share/stormos-shell/session/stormos-session.sh"
install -m 0755 "$ROOT/session/autostart" "/etc/xdg/labwc/autostart"
install -m 0644 "$ROOT/session/rc.xml" "/etc/xdg/labwc/rc.xml"
install -m 0644 "$ROOT/session/menu.xml" "/etc/xdg/labwc/menu.xml"
install -m 0644 "$ROOT/session/environment" "/etc/xdg/labwc/environment"
install -m 0644 "$ROOT/session/stormos.desktop" "$PREFIX/share/wayland-sessions/stormos.desktop"

[ -f "$PREFIX/share/backgrounds/stormos/stormos-wallpaper.svg" ] || \
    install -m 0644 "$ROOT/public/stormos-wallpaper.svg" "$PREFIX/share/backgrounds/stormos/stormos-wallpaper.svg"

printf 'Installed StormOS session into %s\n' "$PREFIX"
