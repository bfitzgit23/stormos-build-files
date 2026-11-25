#!/bin/bash
#
# AetherDE integration test for the StormOS XFCE profile.
#
# Usage:
#   ./tests/aetherde-test.sh                    # mounted ISO root at /tmp/stormos-test
#   ./tests/aetherde-test.sh /tmp/stormos-test  # explicit mounted root
#   ./tests/aetherde-test.sh /                  # an installed system
#
# No guestfs or network access is required: point this at any root tree.

set -e

ROOT="${1:-/tmp/stormos-test}"
PASS=0
FAIL=0
WARN=0

echo "========================================"
echo "AetherDE Integration Test"
echo "========================================"
echo "Root: $ROOT"

check_file() {
    if [ -f "$ROOT/$1" ]; then
        echo "  ok: /$1"
        PASS=$((PASS + 1))
    else
        echo "  MISSING: /$1"
        FAIL=$((FAIL + 1))
    fi
}

check_exec() {
    if [ -x "$ROOT/$1" ]; then
        echo "  ok (executable): /$1"
        PASS=$((PASS + 1))
    else
        echo "  MISSING or not executable: /$1"
        FAIL=$((FAIL + 1))
    fi
}

check_config() {
    if [ -f "$ROOT/etc/lightdm/lightdm.conf" ] && grep -q "$2" "$ROOT/etc/lightdm/lightdm.conf"; then
        echo "  ok: lightdm.conf contains $2"
        PASS=$((PASS + 1))
    else
        echo "  MISSING: lightdm.conf does not contain $2"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "Session and launchers"
check_file usr/share/xsessions/aether-de.desktop
check_exec usr/bin/aether-session
check_exec usr/bin/aether-de
check_file usr/lib/systemd/user/aether-de.service

echo ""
echo "Runtime tree"
check_file usr/lib/aether-de/aether_de/daemon.py
check_file usr/lib/aether-de/aether_de/x11.py
check_file usr/lib/aether-de/gateway/server.js
check_file usr/lib/aether-de/gateway/pty.js
check_file usr/lib/aether-de/shell/index.html
check_file usr/lib/aether-de/shell/electron-main.js
check_file usr/lib/aether-de/shell/js/main.js

echo ""
echo "LightDM"
check_config lightdm 'user-session=aether-de'
check_config lightdm 'autologin-session=aether-de'
check_file usr/share/xsessions/xfce.desktop || WARN=$((WARN + 1))

echo ""
echo "Node dependencies"
if [ -d "$ROOT/usr/lib/aether-de/gateway/node_modules" ]; then
    echo "  ok: gateway/node_modules present"
    PASS=$((PASS + 1))
else
    echo "  WARN: gateway/node_modules absent (session launcher will npm install at login)"
    WARN=$((WARN + 1))
fi

echo ""
echo "========================================"
echo "Passed: $PASS  Failed: $FAIL  Warnings: $WARN"
echo "========================================"

if [ "$FAIL" -eq 0 ]; then
    echo "AetherDE integration checks passed"
    exit 0
fi

echo "AetherDE integration checks failed" >&2
exit 1
