#!/usr/bin/env bash
#
# stormd-compiz-calamares.sh — Calamares post-install step (StormD).
# Runs INSIDE the installed (target) system via Calamares' shellprocess,
# with the target mounted at / (dontChroot: false).
#
# StormD ships Debian's compiz 0.8.18 straight from the repos (no AUR-style
# build needed), so this step only needs to deploy the session autostart
# entry into every user home.
#
set -uo pipefail

log() { echo "[stormd-compiz] $*"; }

# Safety net: install the compiz set if the package list missed it
apt-get install -y compiz compiz-gnome compiz-plugins \
    compizconfig-settings-manager compiz-plugins-extra 2>/dev/null || true

# Deploy autostart entry for every real user home
for skel_home in /root /home/*; do
    [ -d "$skel_home" ] || continue
    mkdir -p "$skel_home/.config/autostart"
    cp /usr/share/stormd13X/compiz/stormos-compiz.desktop \
       "$skel_home/.config/autostart/" 2>/dev/null || true
    chown -R "$(stat -c %U "$skel_home")":"$(stat -c %G "$skel_home")" \
        "$skel_home/.config/autostart" 2>/dev/null || true
done

log "Compiz setup complete"
exit 0
