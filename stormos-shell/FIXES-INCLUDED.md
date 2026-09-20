# StormOS shell fixes

This package keeps the existing working GTK4/WebKit6 `stormos-shell-host` and fixes the React/bridge layer.

Included fixes:
- StormOS Settings opens as the React Settings window.
- StormOS Gallery remains an internal shell window.
- Thunar launches the real `thunar` process.
- Foot launches the real `foot` process.
- Firefox/LibreOffice/Steam/etc. continue through the native bridge.
- Panel Display/Bluetooth/Network/Audio/Power controls are clickable.
- Clock/date come from the Linux system clock via `date`.
- Timezone comes from `timedatectl show --property=Timezone`.
- NTP state comes from `timedatectl show --property=NTPSynchronized`.
- System panel uses live bridge data instead of hard-coded sample hardware values.
- The installer deliberately does not overwrite the known-good GTK/WebKit host.
