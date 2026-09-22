#!/usr/bin/env python3
"""
stormos-compiz-setup.py — pre-apply StormOS Compiz settings.

Installs the Compiz profile shipped in /usr/share/stormos/compiz/stormos.profile
into the user's compizconfig backend, enabling:
  - Wobbly Windows
  - Desktop Cube (+ Rotate Cube on Ctrl+Alt+Left/Right)
  - Window decoration (decor), animations, place

Primary method: write ~/.config/compiz-1/compizconfig/Default.ini directly.
This is exactly what compiz (via the ccp plugin) reads at startup, needs no
Python bindings, and works on any Python version.

Best-effort extra: if the compizconfig Python module imports cleanly AND
compiz is currently running, also live-apply the plugin list via the API.
All API failures are silently ignored — the ini write is what matters.

Run as the user (no sudo). Idempotent — safe to re-run.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

PROFILE_SRC = "/usr/share/stormos/compiz/stormos.profile"
CC_DIR = Path.home() / ".config" / "compiz-1" / "compizconfig"
CC_INI = CC_DIR / "Default.ini"

WANTED_PLUGINS = [
    "core", "composite", "opengl", "ccp", "mousepoll", "regex", "place",
    "move", "resize", "decor", "animation", "wobbly", "cube", "rotate",
    "wallpaper",
]


def write_profile() -> bool:
    """Copy the shipped profile into the user's compizconfig dir."""
    src = Path(PROFILE_SRC)
    if not src.exists():
        print(f"ERROR: profile not found at {src}", file=sys.stderr)
        return False
    CC_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, CC_INI)
    # compizconfig refuses profiles with group/world write permissions
    os.chmod(CC_INI, 0o600)
    print(f"Compiz profile installed: {CC_INI}")
    return True


def ensure_config_file() -> None:
    """Make sure the compizconfig 'config' file exists with a profile set."""
    cfg = CC_DIR / "config"
    if not cfg.exists():
        CC_DIR.mkdir(parents=True, exist_ok=True)
        cfg.write_text("[general]\nprofile = Default\nintegration = true\n",
                       encoding="utf-8")


def try_live_apply() -> None:
    """Best-effort live-apply via the compizconfig Python API.

    Never raises: any failure just means compiz will pick the settings up
    from the ini at next start instead.
    """
    if shutil.which("compiz") is None:
        return
    try:
        import compizconfig  # type: ignore
    except Exception:
        return  # module not importable on this python — fine, ini is written

    try:
        ctx = compizconfig.Context()
        ctx.Profile = "Default"
        ctx.Read()
        core = ctx.Plugins["core"]
        # active_plugins is the display option as_active_plugins in 0.9.x
        opt = core.Display["as_active_plugins"]
        current = list(opt.Value)
        merged = list(dict.fromkeys(current + WANTED_PLUGINS))
        if merged != current:
            opt.Value = merged
            ctx.Write()
            print("Live-applied plugin list via compizconfig API")
    except Exception:
        pass  # non-fatal


def main() -> None:
    ensure_config_file()
    if not write_profile():
        sys.exit(1)
    try_live_apply()
    print("Done. Restart Compiz (or log out/in) to see wobbly windows + cube.")


if __name__ == "__main__":
    main()
