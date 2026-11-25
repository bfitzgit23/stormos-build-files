# Xfce integration

Two supported modes.

## 1. Storm as the session (recommended)

`session/storm-session` starts only `xfsettingsd`, `xfwm4`, `xfce4-notifyd`,
`stormd` and `stormui`. `xfce4-session` and `xfce4-panel` are not used.

Install:

```bash
sudo install -Dm755 session/storm-session /usr/bin/storm-session
sudo install -Dm644 session/storm.desktop /usr/share/xsessions/storm.desktop
```

Log out, pick **Storm** in the greeter. To undo, pick *Xfce Session* — nothing
about the stock session was modified.

The authoritative list of what is replaced vs kept lives in
[`../docs/xfce-replacement-matrix.md`](../docs/xfce-replacement-matrix.md).

## 2. Storm inside an existing Xfce session

For testing on a normal Xfce install without switching sessions:

```bash
bash session/xfce-minimize.sh          # mask panel, desktop, applets...
# autostart the shell for this user only
cp xfce-integration/storm-shell.desktop ~/.config/autostart/
```

`xfce-minimize.sh --restore` removes the masks and returns stock behaviour.

## ISO wiring

Add `stormui-git` and the packages in [`../arch/xfce-minimal.txt`](../arch/xfce-minimal.txt)
to `install-stormos-xfce/packages.x86_64`, and drop the rest of the `xfce4`
group. `storm.desktop` in `/usr/share/xsessions` is what makes the greeter list
Storm.
