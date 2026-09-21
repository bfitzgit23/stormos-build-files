#!/usr/bin/env bash
#
# recolor-qogir.sh — bake the StormOS blue accent into the bundled Qogir
# icon themes, in-place and idempotently.
#
# Qogir line-art icons draw in #5d656b (gray) with colored accents (red
# #da4453 etc). This script retints:
#   - gray strokes/fills  -> StormOS light blue #4FC3F7
#   - accent colors       -> StormOS blue #19A9FF
# so every icon system-wide (panel applets, menus, actions) inherits the
# StormOS dark-blue accent instead of stock gray/red.
#
# Run once at install time; safe to re-run.

set -uo pipefail

THEME_ROOT="/usr/share/icons"
STAMP="$THEME_ROOT/.stormos-recolor-done"

if [ -f "$STAMP" ]; then
    echo "Qogir already recolored for StormOS — skipping (rm $STAMP to force)"
    exit 0
fi

echo "Recoloring Qogir icon themes to StormOS blue..."

for theme in Qogir Qogir-dark Qogir-manjaro Qogir-manjaro-dark; do
    dir="$THEME_ROOT/$theme"
    [ -d "$dir" ] || continue
    # Every SVG in the theme (fixed sizes, hidpi variants, symbolic).
    find "$dir" -type f -name '*.svg' -print0 2>/dev/null |
    while IFS= read -r -d '' svg; do
        sed -i \
            -e 's/#5d656b/#4FC3F7/gI' \
            -e 's/#52952e/#19A9FF/gI' \
            -e 's/#da4453/#19A9FF/gI' \
            -e 's/#f67400/#19A9FF/gI' \
            -e 's/#1d99f3/#19A9FF/gI' \
            -e 's/#16a085/#19A9FF/gI' \
            -e 's/#9d7050/#7FDBFF/gI' \
            -e 's/#27ae60/#19A9FF/gI' \
            -e 's/#f44336/#19A9FF/gI' \
            -e 's/#2ecc71/#19A9FF/gI' \
            -e 's/#e67e22/#19A9FF/gI' \
            "$svg" 2>/dev/null || true
    done
    echo "  $theme: done"
done

# Drop stale caches so the new colors are picked up immediately.
rm -f "$THEME_ROOT"/Qogir*/icon-theme.cache 2>/dev/null
touch "$STAMP"
echo "Recolor complete."
