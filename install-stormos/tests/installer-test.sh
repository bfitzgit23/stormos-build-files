#!/bin/bash
#
# Static checks for the StormOS custom installer.
# Usage: ./tests/installer-test.sh [root-tree]   (default: /tmp/stormos-test)

set -e
ROOT="${1:-/tmp/stormos-test}"
PASS=0
FAIL=0

echo "========================================"
echo "StormOS Installer Test"
echo "========================================"
echo "Root: $ROOT"

check() {
    if [ -e "$ROOT/$1" ]; then
        echo "  ok: /$1"
        PASS=$((PASS + 1))
    else
        echo "  MISSING: /$1"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "Installer files"
check usr/bin/stormos-installer
check usr/lib/stormos-installer/backend/installerd.py
check usr/lib/stormos-installer/frontend/index.html
check usr/lib/stormos-installer/frontend/styles.css
check usr/lib/stormos-installer/frontend/renderer.js
check usr/lib/stormos-installer/electron-main.js
check usr/lib/stormos-installer/package.json
check usr/share/applications/stormos-installer.desktop
check usr/share/applications/stormos-installer-advanced.desktop

echo ""
echo "Calamares fallback"
check usr/bin/calamares
check etc/calamares/launch.sh

echo ""
echo "Syntax"
if [ -f "$ROOT/usr/lib/stormos-installer/backend/installerd.py" ] && command -v python3 >/dev/null 2>&1; then
    if python3 -m py_compile "$ROOT/usr/lib/stormos-installer/backend/installerd.py" 2>/dev/null; then
        echo "  ok: installerd.py compiles"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: installerd.py did not compile"
        FAIL=$((FAIL + 1))
    fi
fi
if [ -f "$ROOT/usr/lib/stormos-installer/frontend/renderer.js" ] && command -v node >/dev/null 2>&1; then
    if node --check "$ROOT/usr/lib/stormos-installer/frontend/renderer.js" 2>/dev/null; then
        echo "  ok: renderer.js parses"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: renderer.js did not parse"
        FAIL=$((FAIL + 1))
    fi
fi

echo ""
echo "========================================"
echo "Passed: $PASS  Failed: $FAIL"
echo "========================================"

if [ "$FAIL" -eq 0 ]; then
    echo "Installer integration checks passed"
    exit 0
fi

echo "Installer integration checks failed" >&2
exit 1
