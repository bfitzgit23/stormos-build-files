# StormOS React Desktop

This is a React/Vite prototype extrapolated from the StormOS desktop reference image.
It implements the visual shell as a functional desktop-like interface:

- Top bar and workspaces
- StormOS launcher with search
- Bottom dock
- System overview panel
- Thunar-style file manager window
- Foot-style terminal window
- StormOS Gallery window
- StormOS Settings window
- Power menu
- Responsive layout for smaller screens

## Run it

```bash
npm install
npm run dev
```

Then open the Vite URL shown in the terminal.

## Build it

```bash
npm run build
```

## Turning it into a real StormOS session

React is the shell UI. It should be hosted in a native Linux window using Tauri or Electron, or in a GTK/WebKit wrapper. The native wrapper should expose commands for:

- Launching applications with `GAppInfo` or `exec`
- Reading NetworkManager state
- Reading BlueZ state
- Reading PipeWire/WirePlumber state
- Reading UPower battery state
- Reading `/proc`, `lspci`, `lsblk`, and `uname`
- Controlling systemd session actions
- Managing wallpapers and workspaces

For a production StormOS implementation, keep `labwc` as the compositor and use the React shell for the panel, launcher, widgets, settings, and desktop surfaces. Do not replace the compositor with a browser window.

## Suggested production structure

```text
stormos-shell/
├── frontend/       React UI from this prototype
├── src-tauri/      Native Linux bridge
├── assets/         StormOS icons, wallpaper, fonts
├── protocols/      JSON command/event contracts
└── session/        labwc session and autostart files
```


## StormOS themes

This package installs the StormOS-GTK theme and StormOS-icons theme under `/usr/share/themes` and `/usr/share/icons`. The session exports `GTK_THEME=StormOS-GTK` and `XCURSOR_THEME=StormOS-icons`.


## Foot and Picom

The package installs a native Foot configuration with Wayland alpha transparency and a `stormos-foot` launcher that adjusts font size based on detected display dimensions. Picom is included for X11 applications; it is not started for Wayland because labwc performs Wayland compositing.


## Session architecture fix

This release runs labwc as the actual foreground Wayland compositor. The labwc
startup hook launches the wallpaper, GVFS services, policy agent, native bridge,
Waybar, and React shell independently after the compositor is ready. Logs are
stored under `~/.local/state/stormos/`.


## Final session startup correction

The display-manager session entry point now directly execs labwc. The labwc
autostart script is installed at `/etc/xdg/labwc/autostart`, which is the
location labwc reads for system-wide startup commands. Each component starts
independently and logs to `~/.local/state/stormos/`.


## Correct installation

This archive contains the actual StormOS React desktop shell shown in the
reference interface. It does not replace the React UI with a mockup and does
not launch a duplicate Waybar panel.

Run:

```bash
chmod +x install-stormos-react-desktop.sh
./install-stormos-react-desktop.sh
```

The installer builds the React/Vite frontend, installs the GTK4/WebKit host,
installs the native bridge, and places the labwc autostart hook at:

```text
/etc/xdg/labwc/autostart
```

The SDDM session is:

```text
/usr/share/wayland-sessions/stormos.desktop
```
