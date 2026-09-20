#!/usr/bin/env bash
set -euo pipefail
PREFIX="${1:-/usr}"
ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "== StormOS React shell fixed installer =="
echo "Source: $ROOT"

if [[ ! -d "$ROOT/node_modules" ]]; then
  echo "node_modules is missing. Run: npm install"
  exit 1
fi

npm run build

sudo install -d "$PREFIX/share/stormos-shell/dist" "$PREFIX/share/stormos-shell"
sudo rm -rf "$PREFIX/share/stormos-shell/dist"
sudo install -d "$PREFIX/share/stormos-shell/dist"
sudo cp -a "$ROOT/dist/." "$PREFIX/share/stormos-shell/dist/"
sudo install -m 0755 "$ROOT/native/stormos-bridge.py" "$PREFIX/share/stormos-shell/stormos-bridge.py"

# Do NOT replace the known-good native GTK/WebKit host here.
# The existing /usr/bin/stormos-shell-host remains in use.

if [[ -f "$ROOT/public/stormos-wallpaper.svg" ]]; then
  sudo install -d "$PREFIX/share/backgrounds/stormos"
  sudo install -m 0644 "$ROOT/public/stormos-wallpaper.svg" "$PREFIX/share/backgrounds/stormos/stormos-wallpaper.svg"
fi

echo
echo "StormOS frontend and bridge installed."
echo "Log out and back in to restart the shell."
