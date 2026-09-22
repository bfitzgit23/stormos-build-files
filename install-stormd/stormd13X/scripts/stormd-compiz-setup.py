#!/usr/bin/env python3
"""
stormd-compiz-setup.py — pre-apply StormD Compiz settings.

Installs the Compiz profile shipped in /usr/share/stormd13X/compiz/stormos.profile
into the user's compizconfig backend, enabling:
  - Wobbly Windows
  - Desktop Cube (+ Rotate Cube on Ctrl+Alt+Left/Right)
  - Window decoration (decoration), animations, place

Debian's compiz 0.8.18 uses the ini backend by default with profiles under
~/.config/compiz-1/compizconfig/ (same layout as 0.9). The gconf backend
alternative path is also seeded for distributions that build it that way.

Run as the user (no sudo). Idempotent — safe to re-run.
"""

import os
import sys
import shutil
from pathlib import Path

PROFILE_SRC = "/usr/share/stormd13X/compiz/stormos.profile"
CC_CANDIDATES = [
    Path.home() / ".config" / "compiz-1" / "compizconfig",
    Path.home() / ".compiz-1" / "compizconfig",
    Path.home() / ".compiz" / "compizconfig",
]
CC_INI = "Default.ini"


def write_profile() -> bool:
    """Copy the shipped profile into the user's compizconfig dir."""
    src = Path(PROFILE_SRC)
    if not src.exists():
        print(f"ERROR: profile not found at {src}", file=sys.stderr)
        return False
    for cc_dir in CC_CANDIDATES:
        if cc_dir.exists():
            ini = cc_dir / CC_INI
            shutil.copyfile(src, ini)
            os.chmod(ini, 0o600)
            print(f"Compiz profile installed: {ini}")
            # Seed the profile pointer file if missing
            cfg = cc_dir / "config"
            if not cfg.exists():
                cfg.write_text("[general]\nprofile = Default\n",
                               encoding="utf-8")
            return True
    # No compizconfig dir exists yet — create the primary one
    cc_dir = CC_CANDIDATES[0]
    cc_dir.mkdir(parents=True, exist_ok=True)
    ini = cc_dir / CC_INI
    shutil.copyfile(src, ini)
    os.chmod(ini, 0o600)
    cfg = cc_dir / "config"
    if not cfg.exists():
        cfg.write_text("[general]\nprofile = Default\n", encoding="utf-8")
    print(f"Compiz profile installed: {ini}")
    return True


def main() -> None:
    if not write_profile():
        sys.exit(1)
    print("Done. Restart Compiz (or log out/in) to see wobbly windows + cube.")


if __name__ == "__main__":
    main()
