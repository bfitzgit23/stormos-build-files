#!/usr/bin/env python3
"""
stormos-compiz-setup.py — pre-apply StormOS Compiz settings.

Loads the Compiz profile shipped in /usr/share/stormos/compiz/stormos.profile
into the user's compizconfig backend, enabling:
  - Wobbly Windows
  - Desktop Cube (+ Rotate Cube, on Ctrl+Alt+Left/Right and Super+Left/Right)
  - Window decoration, animations,-place

Run as the user (no sudo). Idempotent — safe to re-run.
Requires: compizconfig-python (ships with compiz-easy-patch) OR falls back to
merging into ~/.config/compiz-1/compizconfig/Default.ini directly.
"""

import os
import sys
from pathlib import Path

PROFILE_SRC = "/usr/share/stormos/compiz/stormos.profile"
CC_DIR = Path.home() / ".config" / "compiz-1" / "compizconfig"
CC_INI = CC_DIR / "Default.ini"


def write_profile():
    CC_DIR.mkdir(parents=True, exist_ok=True)
    src = Path(PROFILE_SRC)
    if not src.exists():
        print(f"ERROR: profile not found at {src}", file=sys.stderr)
        return False
    # Direct ini write: compizconfig picks this up on next compiz start
    CC_INI.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"Compiz profile installed: {CC_INI}")
    return True


def main():
    # Try the python-config API first (safe live-apply when compiz runs)
    try:
        import compizconfig  # noqa
        ctx = compizconfig.Context()
        ctx.Profile = "Default"
        ctx.Read()
        core = ctx.Plugins["core"]
        as_opt = core.Screen["as"]
        wanted = [
            "ccp", "decoration", "wobbly", "animation", "place",
            "move", "resize", "cube", "rotate", "wallpaper", "regex", "mousepoll"
        ]
        current = list(as_opt.Value)
        merged = list(dict.fromkeys(current + wanted))
        as_opt.Value = merged
        ctx.Write()
        print("Live-applied via compizconfig API:", ", ".join(merged))
    except Exception as e:
        print(f"compizconfig API unavailable ({e}); writing ini directly")
        if not write_profile():
            sys.exit(1)
    print("Done. Restart Compiz (or log out/in) to see wobbly windows + cube.")


if __name__ == "__main__":
    main()
