# Rollout stages — putting Storm on a machine

Storm goes on in three stages. Stage 1 is the static shell already running
(unpacked folder, stormd, browser) — the UI works, nothing is a desktop yet.
Stage 2 turns that into a real X session wired to real hardware. Stage 3 makes
Storm the OS itself instead of a layer. On the current Arch base `pacman` is
already there, so stages 2 and 3 are dependency lists plus packaging plus a
script each — the LFS port at the end reuses this exact shape later.

On Arch **today**, run:

```bash
bash arch/stage2-arch.sh     # substrate + package + session wiring
bash arch/stage3-arch.sh     # strip Xfce to the substrate (report-only by default)
```

## Stage 1 — static shell (done)

Exit criteria already met on the box where the folder was unpacked:

- `http://127.0.0.1:9876/api/health` answers,
- the shell opens from `frontend/index.html` and renders,
- `/api/apps` returns the expected shape (even if `total: 0` on a bare system),
- hardware reads back honest `{"supported": false}` until the tools exist.

Nothing else happens at this stage. The launcher being empty is expected —
there are no `.desktop` files yet.

## Stage 2 — Storm as a session

Goal: a real X session with the shell overlay, live system controls, hardware
keys, and a greeter entry — i.e. what the replacement matrix calls a session.

`stage2-arch.sh` does:

1. **Substrate packages**, in this order:
   - `python`, `xfwm4`, `xfce4-settings`, `xfconf`, `xfce4-notifyd`
     (the four substrate components from `xfce-minimal.txt`, plus `xfce4-terminal`
     as interim terminal),
   - `electron` (shell host; swap later for WebKitGTK on low-RAM targets),
   - hardware helpers: `brightnessctl`, `power-profiles-daemon`, `envycontrol`,
     `cpupower`, `pciutils`, `curl`,
   - `polkit-gnome` (or `lxpolkit`) for pkexec prompts and backlight
     permissions.
2. **Permissions**: user in `video` (backlight sysfs), polkit agent running
   inside the session (storm-session now starts `polkit-gnome`/`lxpolkit`
   automatically), `lvfs`-style GPU power switching available through pkexec.
3. **Session wiring**: `storm-session`, `storm-key`, `storm.desktop`
   installed via `arch/PKGBUILD`; hardware XF86 keys bound to `storm-key`
   through xfconf (script already does this).
4. **greeter**: lightdm or greetd, Storm appears as a session choice.

What turns on here, and what to verify:

- dock/bar render as their own borderless always-on-top window (not inside a
  browser canvas);
- hardware controls become live — brightness, profile, battery, GPU mode, CPU
  governor all read real sysfs/tools instead of `supported: false`;
- XF86 brightness, keyboard backlight and volume keys change actual hardware;
- the adaptive menu starts populating for real: pacman filling
  `/usr/share/applications` is exactly what `/api/apps` scans. Every
  installed package shows with categories, search and a `New` chip on first
  sight; a build should add something graphical and see it appear without
  restarting the shell.

## Stage 3 — Storm as the OS

Goal: image builds and sessions assume Storm; nothing else is user-facing.

`stage3-arch.sh` is a report-only preview by default. Behind `--apply` it
removes every `xfce4`-group member outside the substrate's dependency closure
(pacman is asked one package at a time and left alone if the substrate still
needs it). Behind `--install` it writes the `stormui` PKGBUILD's optional
`stormd` user unit; behind `--autologin USER` it sets the greeter to land
directly in Storm on boot.

Verification:

- `stage3-arch.sh` report is empty (only the substrate remains from the group);
- `/usr/share/xsessions/storm.desktop` is the greeter's default;
- after a clean reboot, Storm runs end-to-end with no LFS-unfriendly parts:
  Xfce pieces not needed anymore no longer exist;
- the hardware layer is the whole story — control center edits take effect
  under the running session, not just in a nested Xvnc;
- a fresh LFS/PKGBUILD build of the substrate + ui brings up the whole stack
  after boot with no manual fixes.

## Porting to LFS

Stage 1 is unchanged. Stage 2's dependency list becomes the first batch of
PKGBUILDs and the stage-2 script's `pacman -S` list. Stage 3 is the same
`stage3-arch.sh` with the group list pointed at LFS packages. stormd, the
session, the apps and the frontend do not change. Electron is the only heavy
runtime dep: WebKitGTK or a smaller wrapper replaces it on the LFS build
(the renderer uses none of Electron's Node APIs, so this is mostly boilerplate).
