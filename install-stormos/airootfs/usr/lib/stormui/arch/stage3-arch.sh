#!/usr/bin/env bash
# stage3-arch.sh — Storm rollout stage 3 on Arch: make Storm the OS, not a layer.
#
# Default run is REPORT-ONLY: it prints what would change. Nothing is
# removed or written without a flag:
#   --apply            remove xfce4 group members outside the substrate's
#                      dependency closure (asks one by one; pacman keeps
#                      anything the substrate still needs)
#   --install          install + enable the stormd systemd user unit
#   --autologin USER   point lightdm at the Storm session for that user
#
# Stage list and exit criteria: docs/stages.md
set -euo pipefail

APPLY=0
UNIT=0
AUTOUSER=""

while [ $# -gt 0 ]; do
    case "$1" in
        --apply)     APPLY=1 ;;
        --install)   UNIT=1 ;;
        --autologin) AUTOUSER="${2:?--autologin needs a user name}"; shift ;;
        *) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

die() { printf '!! %s\n' "$*" >&2; exit 1; }
sroot() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }

command -v pactree >/dev/null 2>&1 || die "pactree not found — install pacman-contrib"
command -v xfconf-query >/dev/null 2>&1 || die "xfconf-query not found — stage 2 must run before stage 3"

# Everything the substrate may pull in: the four kept components, interim
# terminal, plus their direct dependencies (pactree keeps it true even as
# dependencies change between Xfce releases).
keep="$( {
  printf '%s\n' xfwm4 xfce4-settings xfconf xfce4-notifyd xfce4-terminal
  for p in xfwm4 xfce4-settings xfconf xfce4-notifyd; do
      pactree -d1 -u "$p" 2>/dev/null || true
  done
} | sed '/^$/d' | sort -u)"

installed="$(pacman -Qqg xfce4 2>/dev/null | sed '/^$/d' | sort -u || true)"

if [ -z "$installed" ]; then
    echo "xfce4 group not installed at all — nothing to strip"
elif [ -z "$(comm -23 <(printf '%s\n' "$installed") <(printf '%s\n' "$keep"))" ]; then
    echo "xfce4 group: only the substrate is installed — OK"
else
    extra="$(comm -23 <(printf '%s\n' "$installed") <(printf '%s\n' "$keep"))"
    echo "Still installed from the xfce4 group (Storm replaces all of these):"
    printf '%s\n' "$extra" | sed 's/^/  /'
    if [ "$APPLY" -eq 1 ]; then
        while IFS= read -r p; do
            [ -n "$p" ] || continue
            printf 'remove %s? [y/N] ' "$p"
            read -r ans
            if [ "$ans" = "y" ]; then
                sroot pacman -Rns "$p" || printf '  kept %s: pacman says something still needs it\n' "$p"
            fi
        done <<< "$extra"
    else
        echo "(report-only — rerun with --apply to remove them)"
    fi
fi

if [ "$UNIT" -eq 1 ]; then
    [ -f /usr/lib/systemd/user/stormd.service ] || die "stormd.service not installed — rerun the stormui package build first"
    [ "$(systemctl --user is-enabled stormd.service 2>/dev/null || true)" = "enabled" ] || {
        systemctl --user daemon-reload
        systemctl --user enable --now stormd.service
    }
    echo "stormd user unit enabled (it fails quietly if the session already runs its own stormd)"
fi

if [ -n "$AUTOUSER" ]; then
    conf=/etc/lightdm/lightdm.conf
    [ -e "$conf" ] || die "no $conf — lightdm isn't installed"
    sess="$(grep -m1 '^Name=' /usr/share/xsessions/storm.desktop 2>/dev/null | cut -d= -f2- || true)"
    sess="${sess:-Storm}"
    grep -Eq '^#?autologin-user=' "$conf" || die "$conf has no autologin-user key — add the autologin lines under [Seat:*] first"
    echo "Setting lightdm autologin: user=$AUTOUSER session=$sess"
    sroot sed -E -i \
        -e "s|^#?autologin-user=.*|autologin-user=$AUTOUSER|" \
        -e "s|^#?autologin-session=.*|autologin-session=$sess|" \
        "$conf"
    echo "Reboot to land straight in Storm."
fi

echo
echo "Verification:"
for p in xfwm4 xfce4-settings xfconf xfce4-notifyd xfce4-terminal; do
    if pacman -Qq "$p" >/dev/null 2>&1; then
        printf '  substrate present: %s\n' "$p"
    else
        printf '  MISSING: %s <-- resurrect with: pacman -S %s\n' "$p" "$p"
    fi
done
printf '  stormui: %s\n' "$(pacman -Qq stormui-git 2>/dev/null || echo missing)"
