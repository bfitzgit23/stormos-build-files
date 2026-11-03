# Replacing Xfce — component by component

StormOS keeps Xfce **only as a substrate**: a window manager, a settings daemon,
a config store and a notification server. Every surface a user interacts with is
Storm. This matrix is the contract for that: what is gone, what is interim, and
what still blocks a full replacement.

Status legend: **Replaced** = Storm owns it · **Interim** = Storm UI, Xfce binary
underneath · **Kept** = no replacement exists yet, and here's why.

| Xfce component | Job | Storm replacement | Status |
|---|---|---|---|
| `xfce4-panel` | panel, taskbar, tray, clock | Storm bar + dock (`frontend/`) | **Replaced** — panel masked in `xfce-minimize.sh` |
| `xfdesktop` | wallpaper, desktop icons, right-click menu | Storm wallpaper/desktop layer + Storm Files | **Replaced** — icons/menu disabled, process masked |
| `xfce4-appfinder` | app launcher / run dialog | Storm launcher (⛈, search, categories) | **Replaced** |
| `Thunar` | file manager, volumes, trash | Storm Files (`apps/files.html` + `fs/*` API) | **Replaced** for browse/search/move; Thunar optional for GVFS/mount dialogs |
| `xfce4-settings-manager` | settings hub | Storm Settings panel in the shell | **Interim** — reads/writes the same `xfconf` keys |
| `xfce4-power-manager` | brightness, lid, suspend, battery, power profiles | `systemd-logind` + Control Center + `stormd` | **Replaced** — battery health/draw/time-left from sysfs, `powerprofilesctl` or ACPI `platform_profile`, CPU governors via `cpufreq`, keyboard backlight LED, hybrid GPU switching via `envycontrol` |
| `xfce4-settings-helper` keys | XF86 brightness/volume/mute shortcuts | `session/storm-key` + `storm-session` xfconf bindings | **Replaced** — keys POST to stormd, same path as the Control Center |
| `xfce4-applet-pulseaudio` | volume tray | Control Center (pactl backend planned) | **Interim** — sliders currently UI-only |
| `nm-applet` | network tray | Control Center network card (nmcli planned) | **Interim** — masked, nmcli wiring pending |
| `blueman-applet` | bluetooth tray | Control Center toggle | **Interim** — masked, `bluetoothctl` wiring pending |
| `xfce4-clipman` | clipboard history | not built | **Kept** (maskable; no clipboard daemon yet) |
| `xfce4-notifyd` | notification server | Storm draws the popups, but apps talk to `org.freedesktop.Notifications` | **Kept** — running the server avoids breaking every app |
| `tumbler` | thumbnails | Storm Files renders previews on demand via `/api/fs/raw` | **Replaced** — tumbler not required |
| `xfce4-terminal` | terminal emulator | Storm Terminal (xterm.js + PTY endpoint) | **Interim** — not built yet, terminal stays |
| `xfce4-session` | session manager, logout dialog | `session/storm-session` + Storm session menu | **Replaced** — Storm session does not use `xfce4-session` |
| `xfwm4` | window manager, compositor, snapping, workspaces | none | **Kept** — writing a WM is out of scope; this is the one real dependency |
| `xfconf` | config store | none | **Kept** — `xfwm4`/`xfsettingsd` read it; Storm writes it too |
| `xfsettingsd` | XSETTINGS daemon | none | **Kept** — GTK apps would lose theme/font/cursor without it |
| `lightdm` + greeter | login | Storm greeter | **Kept** (later) — themeable today via `lightdm-slick-greeter` |
| `plymouth` | boot splash | Storm Plymouth theme | **Replaced** (branding only) |

## What the Storm session actually starts

`session/storm-session` launches exactly:

1. `xfsettingsd` — XSETTINGS for GTK theming
2. `xfwm4` — window manager + compositor
3. `xfce4-notifyd` — notification server (optional but recommended)
4. `stormd` — Python system bridge on `127.0.0.1:9876`
5. `stormui` — the shell; when it exits, the session ends

That is the whole list. No `xfce4-session`, no panel, no desktop, no Thunar, no
app finder, no power manager, no applets.

## Path to zero Xfce

| Blocker | Why it stays | What would remove it |
|---|---|---|
| `xfwm4` | WM + compositor + X11 integration | a Wayland compositor (wlroots/smithay) with Storm-drawn decorations |
| `xfconf` + `xfsettingsd` | GTK theming contract on X11 | a small XSETTINGS daemon in Python/GTK, or GTK4 + `gsettings` |
| `xfce4-notifyd` | D-Bus notification service | Storm notification daemon registering `org.freedesktop.Notifications` |
| `lightdm` | display manager | `greetd` + Storm greeter |

Those four are the realistic ceiling for an X11 StormOS. Everything above them in
the table is already Storm-owned.
