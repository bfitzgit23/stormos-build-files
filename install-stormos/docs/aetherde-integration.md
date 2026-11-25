# AetherDE integration in the StormOS XFCE profile

AetherDE is a web desktop shell on the XFCE4/X11 backend. It ships in this ISO profile
in two forms:

| Path | Role |
| --- | --- |
| `aetherde/` | Canonical source tree and `PKGBUILD` for manual builds |
| `airootfs/usr/lib/aether-de/` | Installed runtime tree copied into the live root |
| `airootfs/usr/bin/aether-session` | Session executable used by LightDM |
| `airootfs/usr/share/xsessions/aether-de.desktop` | LightDM session entry |
| `airootfs/etc/calamares/modules/shellprocess-aetherde.conf` | Post-install hook |
| `airootfs/usr/local/bin/aetherde-postinstall.sh` | Post-install hook body |

## Pre-install (live environment)

1. `packages.x86_64` installs the runtime dependencies: `nodejs`, `npm`, `electron`,
   `picom`, `python-xlib`, `python-dbus-next`, `python-psutil`, `python-fastapi`,
   `uvicorn`, `xorg-xprop`, `xorg-xinit` and `hicolor-icon-theme`. XFCE, `xorg-server`,
   `polkit-gnome`, `zsh` and `bash` were already present.
2. The build-time pacman hook `20-stormos-npm.hook` runs
   `/usr/local/sbin/stormos-build-npm`, which performs `npm install --omit=dev` in
   the gateway directory. Ownership and executable bits come from `profiledef.sh`
   `file_permissions`, not from a customization script.
3. `airootfs/etc/lightdm/lightdm.conf` sets `user-session=aether-de` and
   `autologin-session=aether-de`, so `liveuser` lands directly in AetherDE. The
   regular XFCE session remains selectable from the greeter.

If the build-time npm step cannot reach the registry, the warning is logged and
`aether-session` retries the install at first login, logging to
`$XDG_CACHE_HOME/aether-de/npm.log`.

## After install (Calamares / LightDM)

`unpackfs` copies the live root into the target, so the runtime tree, launchers,
session file and LightDM config are already there. The sequence in
`airootfs/etc/calamares/settings.conf` then runs `shellprocess@aetherde` after the
main `postinstall.sh` and after `displaymanager`, which:

- re-applies the LightDM defaults in case `displaymanager` rewrote `lightdm.conf`;
- repairs file modes flattened by `unpackfs`;
- self-heals `node_modules` if the ISO build step failed;
- verifies the installed files and logs to `/var/log/aetherde-postinstall.log`.

## Switching the default back to XFCE

Change both values in `airootfs/etc/lightdm/lightdm.conf`:

```ini
user-session=xfce
autologin-session=xfce
```

AetherDE stays installed and selectable from the greeter. Edit the config in the
profile's `airootfs` — the post-install hook re-applies `aether-de` from the
config that `unpackfs` copies into the target.

## Editing the source

Edit files under `aetherde/`, then sync them into `airootfs/` before building:

```bash
cd install-stormos
./aetherde/sync-airootfs.sh
sudo rm -rf work
sudo ./build.sh -v
```

Removing `work` matters: mkarchiso caches `airootfs`, so changed files are not
picked up until it is removed.

## Verification

```bash
# After a build, mount the ISO root and check both session paths:
./tests/install-test.sh                       # mounts at /tmp/stormos-test
./tests/aetherde-test.sh /tmp/stormos-test    # checks live tree

# On an installed system:
sudo ./tests/aetherde-test.sh /
```

Expected: the AetherDE session file, both launchers, the Python/Node/shell runtime,
and both LightDM `*-session=aether-de` values are present. `node_modules` absent is a
warning, not a failure, because the launcher self-heals.

## Known constraints

- `electron`, `npm` and `uvicorn` come from the `extra` repository, which is enabled
  in this profile's `pacman.conf`.
- Building `node-pty` needs `base-devel` (already in `packages.x86_64`).
- AetherDE is X11-only. It starts its own `xfwm4 --compositor=off` and `picom`, so do
  not select it together with another compositor session.
- The shell window is pinned to `_NET_WM_WINDOW_TYPE_DESKTOP` and
  `_NET_WM_STATE_BELOW` with `xorg-xprop`; native windows keep focus above it.
- On a Windows checkout git may store the new scripts without the executable bit.
  Set it before committing from Linux:

  ```bash
  chmod +x aetherde/sync-airootfs.sh tests/aetherde-test.sh \
           airootfs/usr/local/bin/aetherde-postinstall.sh
  ```
