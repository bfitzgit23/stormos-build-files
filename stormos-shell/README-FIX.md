# StormOS shell fixes in this revision

## Session wiring (the "shell loads inside stock labwc" bug)

The session chain was broken in three places, so the display manager started
labwc bare and the shell appeared as an ordinary floating window inside it:

1. `session/stormos.desktop` pointed at `/usr/bin/stormos-session`, but
   neither the installers nor the PKGBUILD actually installed that file.
2. The labwc `autostart` hook was not part of the session story: without it
   nothing started the shell host after the compositor came up.
3. `session/stormos-session.sh` had a broken single-line
   `export A=x B=y C=z`, which only sets `A=x` and leaves the shell trying to
   execute `B=y` as a command.

Fixes:

- `stormos.desktop` -> `/usr/bin/stormos-session` -> `exec labwc` chain is
  now complete and installed by the installer, PKGBUILD and the minimal
  session installer.
- New `/etc/xdg/labwc/autostart` is the single startup path: it starts the
  bridge, wallpaper and the shell host (with a bounded restart guard for the
  host). It no longer starts waybar/picom duplicates of the shell UI.
- New `/etc/xdg/labwc/rc.xml` pins `org.stormos.DesktopShell` fullscreen,
  undecorated, skipped in taskbar/switcher, and always-on-bottom so real
  application windows sit above the shell surface.
- New `/etc/xdg/labwc/environment` ships the StormOS session defaults.
- `stormos-session` exports one variable per `export` and execs labwc.
- `stormos-session.sh` (manual/test runner) was rewritten: it builds a
  private labwc config dir from the installed session assets, so testing the
  session never clobbers `/etc/xdg/labwc`.

## Other fixes

- `stormos-bridge.py` now uses `ThreadingHTTPServer` (the UI polls
  `/api/system` every second and `/api/apps` every five seconds; the old
  single-threaded server serialized those behind any slow launch) and sets
  `allow_reuse_address` so the restart guard can rebind quickly.
- `session-action` (lock/logout/suspend/hibernate/reboot/shutdown) is now
  installed as `/usr/bin/stormos-session-action` and wired into the power
  menu, rc.xml keybinds and the labwc menu.
- PKGBUILD `package()` ran inside `$srcdir` instead of the extracted project
  directory, so builds failed; `prepare()` also ran npm in the wrong
  directory. Both fixed, plus duplicated install lines removed.
- `smoke-test.sh` rewritten to validate the actual session chain, labwc XML
  well-formedness, bridge threading and the installer/PKGBUILD wiring.
