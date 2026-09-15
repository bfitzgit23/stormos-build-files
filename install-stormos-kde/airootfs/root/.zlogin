# fix for screen readers
if grep -Fqa 'accessibility=' /proc/cmdline &> /dev/null; then
    setopt SINGLE_LINE_ZLE
fi

# NOTE: Do not launch stormos-welcome from here.
# The welcome app is auto-started by the desktop environment via
# /etc/xdg/autostart/stormos-welcome.desktop (and the liveuser copy
# under /etc/skel/.config/autostart). Launching it from .zlogin would
# run it before X/Wayland is ready and on the wrong session context.

~/.automated_script.sh
