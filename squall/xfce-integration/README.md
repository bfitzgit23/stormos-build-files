# Xfce integration

Two supported modes.

## 1. Squall as the session (recommended)

`session/squall-session` starts only `xfsettingsd`, `xfwm4`, `xfce4-notifyd`,
`squalld` and `squall`. `xfce4-session` and `xfce4-panel` are not used.

Install:

```bash
sudo install -Dm755 session/squall-session /usr/bin/squall-session
sudo install -Dm644 session/squall.desktop /usr/share/xsessions/squall.desktop
```

Log out, pick **Squall** in the greeter. To undo, pick *Xfce Session* — nothing
about the stock session was modified.

The authoritative list of what is replaced vs kept lives in
[`../docs/xfce-replacement-matrix.md`](../docs/xfce-replacement-matrix.md).

## 2. Squall inside an existing Xfce session

For testing on a normal Xfce install without switching sessions:

```bash
bash session/xfce-minimize.sh          # mask panel, desktop, applets...
# autostart the shell for this user only
cp xfce-integration/squall-shell.desktop ~/.config/autostart/
```

`xfce-minimize.sh --restore` removes the masks and returns stock behaviour.

## ISO wiring

Add `squall-git` and the packages in [`../arch/xfce-minimal.txt`](../arch/xfce-minimal.txt)
to `install-stormos-xfce/packages.x86_64`, and drop the rest of the `xfce4`
group. `squall.desktop` in `/usr/share/xsessions` is what makes the greeter list
Squall.
