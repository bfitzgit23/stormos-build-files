#!/bin/bash

sudo chmod +x /usr/local/bin/*.sh && sudo chmod +x /usr/local/bin/*.AppImage &&
if [ "${XDG_SESSION_TYPE:-}" = "wayland" ]; then
    kwin_wayland --replace &
else
    kwin_x11 --replace &
fi
