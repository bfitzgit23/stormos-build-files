#!/usr/bin/env bash
# StormOS session runner (manual/test entry point).
#
# This is the standalone variant of session/stormos-session used for testing
# the shell from an existing session (or from a TTY) without a display
# manager. It does NOT replace the system labwc config: it builds a private
# labwc config directory from the installed session assets and points labwc
# at it, so /etc/xdg/labwc stays untouched.
#
# Startup model (identical to the real session):
#   stormos-session.sh -> labwc (foreground) -> /etc/xdg/labwc-style autostart
#   hook starts bridge, wallpaper and the shell host. Killing this script or
#   quitting labwc tears the whole session down.

set -Eeuo pipefail

SESSION_DIR="/usr/share/stormos-shell/session"
[ -d "$SESSION_DIR" ] || SESSION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export XDG_CURRENT_DESKTOP=StormOS
export XDG_SESSION_DESKTOP=stormos
export XDG_SESSION_TYPE=wayland
export DESKTOP_SESSION=stormos
export GDK_BACKEND=wayland,x11
export GTK_USE_PORTAL=1
export GTK_THEME=Arc-BLACK-ICE
export GTK4_THEME=Arc-BLACK-ICE
export XCURSOR_THEME=StormOS-icons
export XCURSOR_SIZE=24
export GIO_USE_VFS=gvfs
export GIO_USE_VOLUME_MONITOR=GProxyVolumeMonitorUDisks2
export XDG_DATA_DIRS="/usr/share:/usr/local/share:${HOME}/.local/share:${XDG_DATA_DIRS:-}"
export GTK2_RC_FILES="/usr/share/themes/Arc-BLACK-ICE/gtk-2.0/gtkrc"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/bus}"

if command -v dbus-update-activation-environment >/dev/null 2>&1; then
    dbus-update-activation-environment --systemd \
        DISPLAY WAYLAND_DISPLAY \
        XDG_CURRENT_DESKTOP XDG_SESSION_DESKTOP XDG_SESSION_TYPE DESKTOP_SESSION \
        GDK_BACKEND GTK_USE_PORTAL GTK_THEME GTK4_THEME \
        XCURSOR_THEME XCURSOR_SIZE XDG_DATA_DIRS GIO_USE_VFS >/dev/null 2>&1 || true
fi
if command -v systemctl >/dev/null 2>&1; then
    systemctl --user import-environment \
        DISPLAY WAYLAND_DISPLAY \
        XDG_CURRENT_DESKTOP XDG_SESSION_DESKTOP XDG_SESSION_TYPE DESKTOP_SESSION \
        GDK_BACKEND GTK_USE_PORTAL GTK_THEME GTK4_THEME \
        XCURSOR_THEME XCURSOR_SIZE XDG_DATA_DIRS GIO_USE_VFS >/dev/null 2>&1 || true
fi

runtime="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/stormos"
mkdir -p "$runtime"

# Build the private labwc config tree. User/system labwc config is not
# touched; labwc picks up rc.xml, menu.xml, environment and autostart from
# this directory because XDG_CONFIG_HOME points here for this session only.
session_labwc_dir="$runtime/labwc"
mkdir -p "$session_labwc_dir"
for f in rc.xml menu.xml environment autostart; do
    if [ -f "$SESSION_DIR/$f" ]; then
        cp -f "$SESSION_DIR/$f" "$session_labwc_dir/$f"
    fi
done
# Wayland needs a real compositor socket dir even when testing.
[ -d "$HOME/.config" ] || mkdir -p "$HOME/.config"
export XDG_CONFIG_HOME="$runtime"

PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

# Volume services (user units when available, raw daemons otherwise).
if command -v systemctl >/dev/null 2>&1; then
    systemctl --user start gvfs-daemon.service >/dev/null 2>&1 || true
    systemctl --user start gvfs-udisks2-volume-monitor.service >/dev/null 2>&1 || true
    systemctl --user start gvfs-metadata.service >/dev/null 2>&1 || true
fi
command -v gvfsd >/dev/null 2>&1 && gvfsd >/dev/null 2>&1 & PIDS+=($!)
command -v gvfs-udisks2-volume-monitor >/dev/null 2>&1 && gvfs-udisks2-volume-monitor >/dev/null 2>&1 & PIDS+=($!)

# Polkit agent.
if [ -x /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1 ]; then
    /usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1 >/dev/null 2>&1 & PIDS+=($!)
elif command -v lxqt-policykit-agent >/dev/null 2>&1; then
    lxqt-policykit-agent >/dev/null 2>&1 & PIDS+=($!)
fi

# Shell backend bridge.
if [ -x /usr/bin/stormos-bridge ]; then
    /usr/bin/stormos-bridge >"$HOME/.stormos-bridge.log" 2>&1 & PIDS+=($!)
    echo $! >"$runtime/bridge.pid"
fi

# labwc runs in the foreground; its autostart hook brings up the wallpaper
# and the shell host. XDG_CONFIG_HOME above makes labwc read our private
# config tree, which includes the autostart hook.
labwc >"$HOME/.stormos-labwc.log" 2>&1
