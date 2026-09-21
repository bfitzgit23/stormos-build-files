#!/usr/bin/env bash
#
# recolor-qogir.sh — bake the StormOS blue accent into the bundled Qogir
# icon themes, in-place and idempotently.
#
# Qogir line-art icons use various accent colors (red, green, yellow, orange,
# various blues). This script retints ALL of them to the StormOS palette:
#   - Gray strokes/fills   -> StormOS light blue  #4FC3F7
#   - All accent colors    -> StormOS primary     #19A9FF
#   - Brown/dark accents   -> StormOS pale        #7FDBFF
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
            -e 's/#4d4d4d/#4FC3F7/gI' \
            -e 's/#3e4245/#4FC3F7/gI' \
            -e 's/#37474f/#4FC3F7/gI' \
            -e 's/#263238/#4FC3F7/gI' \
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
            -e 's/#72d406/#19A9FF/gI' \
            -e 's/#fbc02d/#19A9FF/gI' \
            -e 's/#e5a50a/#19A9FF/gI' \
            -e 's/#ffe600/#19A9FF/gI' \
            -e 's/#ffbd55/#19A9FF/gI' \
            -e 's/#ff5474/#19A9FF/gI' \
            -e 's/#fa7c1a/#19A9FF/gI' \
            -e 's/#ff5722/#19A9FF/gI' \
            -e 's/#cc3333/#19A9FF/gI' \
            -e 's/#1c99e0/#19A9FF/gI' \
            -e 's/#4f6698/#19A9FF/gI' \
            -e 's/#003579/#19A9FF/gI' \
            -e 's/#037ad9/#19A9FF/gI' \
            -e 's/#5c9ee0/#19A9FF/gI' \
            -e 's/#638df5/#19A9FF/gI' \
            -e 's/#6ba4e7/#19A9FF/gI' \
            -e 's/#82b6ea/#19A9FF/gI' \
            -e 's/#90a9ff/#4FC3F7/gI' \
            -e 's/#bad5ff/#4FC3F7/gI' \
            -e 's/#ccdfff/#4FC3F7/gI' \
            -e 's/#b4bfd8/#4FC3F7/gI' \
            -e 's/#a2703c/#7FDBFF/gI' \
            -e 's/#5294e2/#19A9FF/gI' \
            -e 's/#2196f3/#19A9FF/gI' \
            -e 's/#3889e9/#19A9FF/gI' \
            "$svg" 2>/dev/null || true
    done
    echo "  $theme: done"
done

# Drop stale caches so the new colors are picked up immediately.
rm -f "$THEME_ROOT"/Qogir*/icon-theme.cache 2>/dev/null
touch "$STAMP"
echo "Recolor complete."
