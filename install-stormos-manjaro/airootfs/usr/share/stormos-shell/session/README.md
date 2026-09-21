# Native StormOS session

The React UI is hosted by the GTK/WebKit `stormos-shell-host` as THE desktop
surface: top bar, workspaces, launcher, dock, windows and system panel all
live inside one fullscreen window.

Session chain (this is what makes the shell load on its own, not inside a
stock labwc desktop):

1. Display manager runs the **StormOS** Wayland session
   (`/usr/share/wayland-sessions/stormos.desktop`).
2. `stormos.desktop` execs `/usr/bin/stormos-session`, which exports the
   session environment and **execs labwc** as the session leader.
3. labwc sources `/etc/xdg/labwc/environment` (StormOS defaults).
4. labwc runs `/etc/xdg/labwc/autostart`, which starts the system bridge,
   wallpaper and the shell host.
5. labwc applies `/etc/xdg/labwc/rc.xml`, whose window rule pins the
   `org.stormos.DesktopShell` surface fullscreen, undecorated, skipped in the
   task switcher and kept at the bottom of the stack so application windows
   draw above it.

Install the session assets from the project root:

```bash
sudo ./session/install-stormos-shell.sh /usr
```

Or do a full install (builds the React bundle, installs everything):

```bash
./install-stormos-react-desktop.sh
```

Manual/test run without a display manager (uses a private labwc config dir,
does not touch /etc/xdg/labwc):

```bash
/usr/share/stormos-shell/session/stormos-session.sh
```

The bridge listens only on `127.0.0.1:47821` and provides:

- `GET /api/health`
- `GET /api/system`
- `GET /api/apps`
- `GET /api/displays`
- `POST /api/displays/apply`
- `POST /api/launch` with `{ "app": "terminal" }` (session actions:
  `lock`, `logout`, `suspend`, `hibernate`, `restart`, `shutdown`)

Logs: `~/.local/state/stormos/` (per-component) and `~/.stormos-*.log`
(session runner).
