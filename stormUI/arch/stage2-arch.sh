#!/usr/bin/env bash
# stage2-arch.sh — Storm rollout stage 2 on Arch: install the substrate,
# build and install the stormui package, finish with a check list.
#
# Run it from an ordinary user shell (it sudo's pacman itself); the stormUI
# folder must already be unpacked so that arch/PKGBUILD exists.
# Stage list and exit criteria: docs/stages.md
set -euo pipefail

BASE="$(cd "$(dirname "$0")/.." && pwd)"        # the unpacked stormUI folder
REPO_PKGS=(python electron xfwm4 xfce4-settings xfconf xfce4-notifyd
           brightnessctl power-profiles-daemon cpupower pciutils curl polkit-gnome)

say() { printf '\n==> %s\n' "$*"; }
die() { printf '!! %s\n' "$*" >&2; exit 1; }
sroot() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }

[ -f "$BASE/arch/PKGBUILD" ] || die "expected $BASE/arch/PKGBUILD — run this from the unpacked stormUI folder"

say "Installing substrate packages"
sroot pacman -Syu --needed "${REPO_PKGS[@]}"

if ! command -v envycontrol >/dev/null 2>&1; then
    if command -v paru >/dev/null 2>&1; then
        say "envycontrol is AUR-only — installing with paru"
        paru -S --needed envycontrol
    else
        say "envycontrol missing (AUR-only, pure Python) — hybrid-graphics switching stays unavailable until you install it"
    fi
fi

say "Building stormui-git"
( cd "$BASE/arch" && makepkg -f ) || die "makepkg failed"

pkg="$(find "$BASE/arch" -maxdepth 1 -name 'stormui-git-*.pkg.tar.zst' -newer "$BASE/arch/PKGBUILD" 2>/dev/null | sort | tail -n1)"
[ -n "$pkg" ] || pkg="$(find "$BASE/arch" -maxdepth 1 -name 'stormui-git-*.pkg.tar.zst' | sort | tail -n1)"
[ -n "$pkg" ] || die "makepkg produced no package"
say "Installing $(basename "$pkg")"
sroot pacman -U --needed --noconfirm "$pkg"

say "Post-install check"
for f in stormui storm-session storm-key; do
    p="$(command -v "$f" 2>/dev/null)" || die "$f is not on PATH — install failed"
    printf '  %-14s %s\n' "$f" "$p"
done

if pacman -Qq lightdm >/dev/null 2>&1; then
    say "lightdm present — pick the Storm session in the greeter"
else
    say "No display manager installed yet (lightdm or greetd) — install one if you want graphical login"
fi

say "Stage 2 done. Log out and pick the Storm session."
cat <<'EOF'

Sanity check at the desktop:
  - dock/bar render as their own borderless, always-on-top window
  - launcher lists pacman-installed apps (the menu index starts filling here)
  - XF86 brightness / volume keys change real hardware
  - Control Center controls are live, not "unavailable"
Next stage: bash arch/stage3-arch.sh (report-only by default)
EOF
