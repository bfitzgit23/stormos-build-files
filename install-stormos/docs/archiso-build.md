# Current archiso build model

`airootfs/root/customize_airootfs.sh` has been removed. Current `mkarchiso`
(archiso 92) prints a deprecation warning for that file and will drop support for
it entirely. This profile uses only the supported mechanisms.

## What replaces the old script

| Old `customize_airootfs.sh` step | Current mechanism |
| --- | --- |
| Uncomment locale, generate locales | Static `airootfs/etc/locale.gen`; glibc's own install hook runs `locale-gen` |
| Set `/etc/localtime` | `stormos-build-setup` hook (`ln -sf /usr/share/zoneinfo/UTC`) |
| Root password/shell/skel, liveuser groups, sudoers, `chage` | `10-stormos-base-setup.hook` → `/usr/local/sbin/stormos-build-setup` |
| `systemctl enable ...`, `set-default graphical.target` | Same hook; `systemctl enable` inside the build chroot creates the wanted symlinks |
| sshd/journald/logind hardening, Plymouth theme, libyaml-cpp link | Same hook |
| `npm install` for the AetherDE gateway | `20-stormos-npm.hook` → `/usr/local/sbin/stormos-build-npm` |
| `chmod` on launchers and payload | `file_permissions` in `profiledef.sh` |
| Package selection | `packages.x86_64` |
| Live user home population | `mkarchiso` copies `/etc/skel` for every UID listed in `airootfs/etc/passwd` |
| AetherDE session default and post-install repair | Static `lightdm.conf` plus the Calamares `shellprocess@aetherde` hook |

Both custom hooks contain the `# remove from airootfs!` marker, so the profile's
existing `zzzz99-remove-custom-hooks-from-airootfs.hook` deletes them from the built
image. Their scripts remain under `/usr/local/sbin/` but exit immediately on a
running system because of their marker files.

## Hook order

1. `10-stormos-base-setup.hook` — base/liveuser/services/daemon configuration.
2. `20-stormos-npm.hook` — Node dependencies (needs network; failures are logged,
   and the AetherDE session retries at login).
3. `zzzz99-remove-custom-hooks-from-airootfs.hook` — removes all marked hooks.

All three use `Target = *`, so they run once after the whole package transaction,
when `lightdm`, `npm` and the payload files are already present.

## Rebuilding

Because `airootfs` is copied early in the build, remove the cached work directory
after any profile change:

```bash
cd install-stormos
sudo rm -rf work
sudo ./build.sh -v
```
