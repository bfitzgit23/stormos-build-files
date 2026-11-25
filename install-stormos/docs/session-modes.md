# Session modes: LightDM, xinit, and XFCE fallback

StormOS ships one session script, `/usr/bin/aether-session`, and two ways to start it.

## 1. LightDM (default in the ISO)

`airootfs/etc/lightdm/lightdm.conf`:

```ini
user-session=aether-de
autologin-session=aether-de
```

The greeter lists both **AetherDE** and **XFCE**. XFCE is installed from the `xfce4`
group, so selecting it at the greeter is a real fallback, not just a config entry.
The same values are re-applied after installation by
`aetherde-postinstall.sh`, so a Calamares or custom-installer install behaves the
same way.

## 2. No display manager (xinit)

`aether-session` is a normal X session command; it does not require LightDM.
Start it from a TTY:

```bash
aether-xinit
# equivalent to:
startx /usr/bin/aether-session -- -nolisten tcp
```

`startx` with no arguments uses `/etc/skel/.xinitrc`, which also execs
`/usr/bin/aether-session`. `xorg-xinit` is in `packages.x86_64`.

To make this the default with **no login manager at all**:

1. Disable the display manager:

   ```bash
   sudo systemctl disable --now lightdm.service
   sudo systemctl set-default multi-user.target
   ```

2. Enable getty autologin on tty1 by creating
   `/etc/systemd/system/getty@tty1.service.d/autologin.conf`:

   ```ini
   [Service]
   ExecStart=
   ExecStart=-/usr/bin/agetty --autologin YOURUSER --noclear %I $TERM
   ```

   Enable it with `sudo systemctl enable getty@tty1.service`.

3. In `YOURUSER`'s `~/.bash_profile` (or `~/.zprofile`), start X only on tty1:

   ```bash
   if [ -z "$DISPLAY" ] && [ "$(tty)" = "/dev/tty1" ]; then
       exec aether-xinit
   fi
   ```

This gives a direct boot into AetherDE with no greeter. Keep the `lightdm` package
installed if you want to switch back with `sudo systemctl enable lightdm` and
`sudo systemctl set-default graphical.target`.

## 3. XFCE fallback behaviour

- **At the greeter:** choose the XFCE session from the session menu.
- **From a TTY:** `startx /usr/bin/startxfce4 -- -nolisten tcp`.
- **Automatically:** if the Python daemon or the Node gateway fails to become
  ready, `aether-session` terminates its children and `exec startxfce4`. The
  reason is written to `$XDG_CACHE_HOME/aether-de/aether-session.log`.

The automatic fallback only triggers for a failed daemon, not for a deliberate
logout. That keeps a broken Python/Node deployment from leaving you with a blank
screen.
