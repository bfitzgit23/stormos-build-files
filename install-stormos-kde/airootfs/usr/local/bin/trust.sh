#!/bin/bash
for f in ~/Desktop/*.desktop; do
    [ -f "$f" ] || continue
    chmod +x "$f"
    kioclient5 exec "$f" --trust 2>/dev/null || true
done

#rm -f "$HOME/Desktop/calamares.desktop" || true
