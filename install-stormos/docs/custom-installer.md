# StormOS custom installer

The default installer is a small, root-only Python backend plus an Electron window
showing a vanilla-JS GUI served same-origin from `127.0.0.1:9877`. Calamares remains
installed and is offered as the **Advanced Installer (Calamares)** desktop entry.

## Files

| Path | Role |
| --- | --- |
| `airootfs/usr/lib/stormos-installer/backend/installerd.py` | Privileged backend, stdlib only |
| `airootfs/usr/lib/stormos-installer/frontend/` | `index.html`, `styles.css`, `renderer.js` |
| `airootfs/usr/lib/stormos-installer/electron-main.js` | Electron host (no node integration, same-origin load) |
| `airootfs/usr/lib/stormos-installer/package.json` | Electron app metadata |
| `airootfs/usr/bin/stormos-installer` | Root check, backend start, Electron launch |
| `airootfs/usr/share/applications/stormos-installer.desktop` | Main installer entry |
| `airootfs/usr/share/applications/stormos-installer-advanced.desktop` | Calamares fallback |
| `tests/installer-test.sh` | Static checks against a root tree |

## Why it is faster and more accurate

- **No installer framework tax.** The backend is one stdlib process; the GUI is three
  static files. No Qt/Python module graph is loaded to render a form.
- **One validation pass before any write.** `POST /api/validate` checks the disk,
  live-ISO protection, boot mode, filesystem, locale, keymap, timezone, username,
  password, hostname and the confirmation token. `POST /api/install` re-validates
  with confirmation enforced before it starts a thread.
- **Live-root refusal.** The disk backing `/`, `/run/archiso/bootmnt` and
  `/run/archiso/copytoram` is resolved with `findmnt` and `lsblk` and is never offered
  as a target.
- **Hardware-aware defaults.** Largest non-live disk is pre-selected, UEFI/BIOS is
  detected from `/sys/firmware/efi`, the live squashfs is located (including
  `copytoram`), and locale/keymap/timezone lists come from the running system.
- **Direct copy.** `rsync -aHAX --numeric-ids` from the loop-mounted squashfs; no
  intermediate unpack directory. Progress is streamed over SSE, not polled.
- **Idempotent post-install.** The chroot step calls the profile's existing
  `postinstall.sh` and `aetherde-postinstall.sh`, so the installed system gets the
  same GRUB theme, Plymouth, NetworkManager, LightDM and AetherDE setup as a
  Calamares install.

## Flow

1. **Environment** — display detected firmware, memory and disks; pick locale,
   keyboard and timezone.
2. **Destination** — `Erase & install` (sgdisk + mkfs) or `Manual partitions`
   (mount existing partitions without formatting). The live disk is disabled.
3. **Account** — hostname, username, password; account joins `wheel` and
   `autologin`.
4. **Review** — full plan plus a generated token that must be typed before install.
5. **Install** — nine streamed steps with a progress bar and live log; Cancel is
   available.
6. **Done** — reboot into the installed system.

## Safety notes

- The backend binds loopback only and requires root; the GUI never runs `sudo`.
- All external commands use argv arrays, never `shell=True`.
- The confirmation token changes every time the backend starts.
- Cancellation and errors unmount `/mnt` and the squashfs loop mount in `finally`.

## Verification

```bash
# Static checks against a mounted ISO root or an installed system:
./tests/installer-test.sh /tmp/stormos-test

# Manual smoke test on the live media:
stormos-installer          # opens the GUI via pkexec
curl -s http://127.0.0.1:9877/api/overview | python3 -m json.tool
```

No destructive step is exercised by the static test. Real partitioning is only
performed after the token confirmation in the GUI.
