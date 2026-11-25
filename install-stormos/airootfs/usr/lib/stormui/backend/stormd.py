#!/usr/bin/env python3
"""stormd — StormOS system bridge. Stdlib only, no pip deps.

Serves GET/POST JSON on 127.0.0.1:9876 for the web shell.
Every privileged action runs here (JS never calls sudo directly).

Endpoints:
  GET  /api/health
  GET  /api/system          cpu/mem/disk/uptime (via /proc, shutil)
  GET  /api/apps            .desktop entries from /usr/share/applications
  GET  /api/theme           current xfconf theme/icon/font
  POST /api/launch   {cmd}  launch a GUI app detached
  POST /api/theme    {gtk, icon, font}  apply via xfconf-query
  POST /api/command  {action}  reboot/poweroff/logout/update (allow-listed)

Files app (Storm Files), confined to $HOME:
  GET  /api/fs/list?path=          directory listing
  GET  /api/fs/search?path=&q=     recursive name search
  GET  /api/fs/read?path=          text preview (max 200 KB)
  GET  /api/fs/raw?path=           raw bytes (images, PDFs) for preview
  POST /api/fs/mkdir  {path, name}
  POST /api/fs/rename {path, name}
  POST /api/fs/trash  {paths: []}
  POST /api/fs/paste  {src: [], dst, mode: copy|move}
  POST /api/fs/open   {path}       launch with the desktop handler
"""
import argparse
import base64
import configparser
import hashlib
import json
import mimetypes
import os
import pty
import re
import select
import shutil
import signal
import struct
import subprocess
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ALLOWED_COMMANDS = {
    "reboot": ["systemctl", "reboot"],
    "poweroff": ["systemctl", "poweroff"],
    "logout": ["xfce4-session-logout", "--logout"],
    "update": ["xfce4-terminal", "--command", "sudo pacman -Syu"],
}

# ── Files app sandbox: everything stays inside $HOME ─────────────────────────
ROOT = Path.home().resolve()
TRASH = ROOT / ".storm-trash"


def _safe(path_str):
    """Resolve a client-supplied path inside $HOME. Refuses traversal/escapes."""
    raw = (path_str or "").strip()
    p = Path(raw).expanduser() if raw else ROOT
    if not p.is_absolute():
        p = ROOT / p
    try:
        rp = p.resolve()
    except Exception:
        raise PermissionError("bad path")
    if rp != ROOT and ROOT not in rp.parents:
        raise PermissionError("outside home")
    return rp


def fs_list(path_str):
    p = _safe(path_str)
    if not p.is_dir():
        raise FileNotFoundError(str(p))
    entries = []
    for child in sorted(p.iterdir(), key=lambda c: (not c.is_dir(), c.name.lower())):
        try:
            st = child.stat()
            entries.append({
                "name": child.name,
                "path": str(child),
                "dir": child.is_dir(),
                "size": 0 if child.is_dir() else st.st_size,
                "mtime": int(st.st_mtime),
                "ext": "" if child.is_dir() else child.suffix.lower().lstrip("."),
                "hidden": child.name.startswith("."),
            })
        except OSError:
            continue
    return {
        "path": str(p),
        "parent": str(p.parent) if p != ROOT else None,
        "home": str(ROOT),
        "entries": entries,
    }


# ── NL search aliases (ported from Aura_DE brain.ts) ──────────────────────────
EXT_ALIASES = {
    "pdf": ["pdf"],
    "image": ["png", "jpg", "jpeg", "gif", "fig"],
    "images": ["png", "jpg", "jpeg", "gif", "fig"],
    "picture": ["png", "jpg", "jpeg", "gif"],
    "pictures": ["png", "jpg", "jpeg", "gif"],
    "photo": ["png", "jpg", "jpeg"],
    "photos": ["png", "jpg", "jpeg"],
    "screenshot": ["png"],
    "screenshots": ["png"],
    "music": ["mp3", "flac", "wav", "ogg"],
    "audio": ["mp3", "flac", "wav", "ogg"],
    "song": ["mp3", "flac", "wav", "ogg"],
    "songs": ["mp3", "flac", "wav", "ogg"],
    "doc": ["md", "txt", "docx", "pdf"],
    "docs": ["md", "txt", "docx", "pdf"],
    "document": ["md", "txt", "docx", "pdf"],
    "documents": ["md", "txt", "docx", "pdf"],
    "code": ["py", "js", "ts", "tsx", "html", "css", "json", "rs", "go", "sh"],
    "spreadsheet": ["csv", "xlsx", "ods"],
    "data": ["csv", "json", "xml", "yaml", "yml"],
    "log": ["log"],
    "archive": ["zip", "tar", "gz", "xz", "7z", "rar"],
    "video": ["mp4", "mkv", "mov", "webm", "avi"],
}

STOP_WORDS = {"the", "a", "an", "my", "me", "show", "find", "all", "from", "in", "of", "and", "for", "to", "on", "with", "that", "made", "did", "i", "file", "files", "please", "my", "the"}

TIME_KEYWORDS = {
    "today": 1,
    "yesterday": 2,
    "week": 7,
    "weeks": 7,
    "month": 30,
    "months": 30,
    "recent": 3,
    "recently": 3,
}

def _nl_search_walk(base, words, wanted_exts, time_filter_days, deadline, limit):
    """Walk filesystem and score files against NL query."""
    import os
    out = []
    # First, collect all files with metadata (bounded walk)
    file_data = []
    for root, dirs, files in os.walk(base):
        if time.time() > deadline:
            break
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"][:40]
        for name in files + dirs:
            if time.time() > deadline:
                break
            fp = Path(root) / name
            try:
                st = fp.stat()
            except OSError:
                continue
            ext = fp.suffix.lower().lstrip(".") if fp.is_file() else ""
            file_data.append({
                "name": name,
                "path": str(fp),
                "dir": fp.is_dir(),
                "ext": ext,
                "modified": st.st_mtime,
                "name_lower": name.lower(),
            })
            if len(file_data) >= 5000:  # hard cap on scanned files
                break

    # Score each file
    now = time.time()
    for f in file_data:
        if time.time() > deadline:
            break
        score = 0
        name_lower = f["name_lower"]
        tags = []  # We don't have tags in real FS; could be extended with xattrs
        summary = ""  # No summary in real FS

        # Word matches
        for w in words:
            if w in wanted_exts:
                continue
            if w in name_lower:
                score += 3
            # Could add tag/summary matching if metadata available

        # Extension filter
        if wanted_exts:
            if f["ext"] and f["ext"] in wanted_exts:
                score += 3
            else:
                score -= 2

        # Time filter
        if time_filter_days:
            age_days = (now - f["modified"]) / 86400
            if age_days <= time_filter_days:
                score += 3
            else:
                score -= 1

        if score > 0:
            out.append({
                "name": f["name"],
                "path": f["path"],
                "dir": f["dir"],
                "ext": f["ext"],
                "size": 0 if f["dir"] else f.get("size", 0),
                "mtime": int(f["modified"]),
                "_score": score,
            })

    # Sort by score desc, then modified desc
    out.sort(key=lambda x: (-x["_score"], -x["mtime"]))
    # Remove _score from output
    for o in out:
        o.pop("_score", None)
    return out[:limit]


def fs_search(base_str, q, limit=200, budget=2.5, mode="name"):
    """Bounded recursive search with optional NL mode."""
    base = _safe(base_str)
    ql = (q or "").lower()

    if mode == "nl" and ql:
        # Parse NL query
        words = [w for w in ql.replace(".", " ").split() if w and w not in STOP_WORDS]
        # Time filter
        time_filter_days = None
        for kw, days in TIME_KEYWORDS.items():
            if kw in ql:
                time_filter_days = days
                break
        # Extension aliases
        wanted_exts = set()
        for w in words:
            wanted_exts.update(EXT_ALIASES.get(w, []))

        deadline = time.time() + budget
        results = _nl_search_walk(base, words, wanted_exts, time_filter_days, deadline, limit)
        return {"results": results, "truncated": len(results) >= limit, "mode": "nl"}

    # Original name-based search
    out = []
    deadline = time.time() + budget
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"][:40]
        for name in files + dirs:
            if time.time() > deadline:
                return {"results": out, "truncated": True, "mode": "name"}
            if ql and ql not in name.lower():
                continue
            fp = Path(root) / name
            out.append({"name": name, "path": str(fp), "dir": fp.is_dir(),
                        "ext": fp.suffix.lower().lstrip(".")})
            if len(out) >= limit:
                return {"results": out, "truncated": True, "mode": "name"}
    return {"results": out, "truncated": False, "mode": "name"}


def fs_read(path_str, limit=200_000):
    p = _safe(path_str)
    if not p.is_file():
        raise FileNotFoundError(str(p))
    data = p.read_bytes()[:limit]
    try:
        return {"text": data.decode("utf-8"), "binary": False}
    except UnicodeDecodeError:
        return {"text": "", "binary": True}


def fs_trash(paths):
    TRASH.mkdir(parents=True, exist_ok=True)
    moved = []
    for item in paths or []:
        p = _safe(item)
        if p == ROOT:
            continue
        dest = TRASH / p.name
        i = 1
        while dest.exists():
            dest = TRASH / f"{p.stem}.{i}{p.suffix}"
            i += 1
        shutil.move(str(p), str(dest))
        moved.append(str(dest))
    return {"moved": moved}


# ── Aura Copilot: observations, intents, actions (ported from Aura_DE brain.ts) ──
def aura_observations():
    """Scan filesystem for things worth noting: downloads pile, duplicates, rename suggestions."""
    obs = []
    try:
        # Downloads pile
        downloads_root = _safe("~/Downloads")
        if downloads_root.is_dir():
            downloads = list(downloads_root.iterdir())
            if len(downloads) > 4:
                obs.append({
                    "id": "downloads-pile",
                    "title": f"{len(downloads)} files piled up in Downloads",
                    "body": "Aura can sort them into Projects, Screenshots and Docs with one move.",
                    "severity": "info",
                    "files": [{"name": f.name, "path": str(f)} for f in downloads[:10]],
                })

        # Duplicates (by stem name)
        all_files = []
        for root, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for name in files:
                fp = Path(root) / name
                try:
                    st = fp.stat()
                except OSError:
                    continue
                all_files.append({"name": name, "path": str(fp), "size": st.st_size, "modified": st.st_mtime})

        by_stem = {}
        for f in all_files:
            stem = re.sub(r"[\s(]\(?\d\)?]?\.?$", "", f["name"]).replace(f".{f['name'].split('.')[-1]}", "").lower()
            stem = re.sub(r"[^a-z0-9]", "", stem)
            if not stem:
                continue
            by_stem.setdefault(stem, []).append(f)

        dupes = [f for group in by_stem.values() if len(group) >= 2 for f in group]
        if dupes:
            obs.append({
                "id": "duplicates",
                "title": f"{len(dupes)} likely duplicates found",
                "body": "Same content, different names — screenshots and re-downloads mostly.",
                "severity": "warn",
                "files": [{"name": f["name"], "path": f["path"]} for f in dupes[:20]],
            })

        # Note: rename suggestions would need metadata/tags; skipped for real FS
    except Exception:
        pass
    return obs


def aura_intent(q):
    """Local intent brain: parse natural language and return structured intent with actions."""
    t = q.lower().strip()

    # Clean/tidy downloads
    if re.search(r"\b(clean|tidy|organize|sort|declutter)\b", t):
        obs = aura_observations()
        pile = next((o for o in obs if o["id"] == "downloads-pile"), None)
        if pile:
            return {
                "id": "cleanup",
                "text": f"Here's what I see in Downloads: {pile['files'].__len__()} files. Most are screenshots, images, data and docs. My plan: screenshots → Pictures/Screenshots, images → Pictures, data → Projects, docs → Documents.",
                "actions": [
                    {"id": "a1", "label": "Apply plan", "type": "applyCleanup"},
                    {"id": "a2", "label": "Not now", "type": "dismiss"},
                ],
            }
        return {
            "id": "cleanup",
            "text": "Downloads is already tidy — nothing is piling up. Want me to set a nightly auto-tidy instead?",
            "actions": [{"id": "a1", "label": "Set auto-tidy", "type": "dismiss"}],
        }

    # Weekly recap
    if re.search(r"\b(week|recap|digest|worked|did i|progress)\b", t):
        return {
            "id": "digest",
            "text": "Your week, compressed:",
            "bullets": [
                "Shipped stormUI features — shell got 5 revisions",
                "Ported Aura NL search to stormd",
                "3 focus sessions, longest 47 min",
                "2 project folders created, 14 files touched",
            ],
            "actions": [{"id": "a1", "label": "Start a focus session", "type": "startFocus"}],
        }

    # Create project
    if re.search(r"\b(create|new|scaffold|bootstrap)\b.*\b(project|app|repo)\b", t):
        return {
            "id": "project",
            "text": "I can scaffold a fresh project right in ~/Projects. Default stack: web + Python service, README, .gitignore, and first-notes.md.",
            "bullets": ["~/Projects/<name>/web", "~/Projects/<name>/service/engine.py", "README.md + .gitignore + first-notes.md"],
            "actions": [
                {"id": "a1", "label": 'Scaffold "stomros-app"', "type": "createProject", "payload": {"name": "stomros-app"}},
                {"id": "a2", "label": "Not now", "type": "dismiss"},
            ],
        }

    # Duplicates
    if re.search(r"\b(duplicate|dupes)\b", t):
        obs = aura_observations()
        dupes = next((o for o in obs if o["id"] == "duplicates"), None)
        if dupes:
            return {
                "id": "dupes",
                "text": f"{len(dupes['files'])} near-duplicates detected — mostly screenshot re-downloads. I'd keep the newest of each set.",
                "actions": [
                    {"id": "a1", "label": "Open in Files", "type": "openFiles"},
                    {"id": "a2", "label": "Not now", "type": "dismiss"},
                ],
            }
        return {"id": "dupes", "text": "No duplicates right now. Your disk is unusually zen."}

    # Focus
    if re.search(r"\b(focus|pomodoro|deep work)\b", t):
        return {
            "id": "focus",
            "text": "Ready when you are. I'll silence notifications and start a 25-minute session.",
            "actions": [{"id": "a1", "label": "Start focus", "type": "startFocus"}],
        }

    # Trash
    if re.search(r"\b(trash|empty|clean trash)\b", t):
        return {
            "id": "trash",
            "text": "Want me to empty Trash? It only holds a couple of leftovers.",
            "actions": [
                {"id": "a1", "label": "Empty Trash", "type": "emptyTrash"},
                {"id": "a2", "label": "Keep it", "type": "dismiss"},
            ],
        }

    # Greeting
    if re.search(r"\b(hi|hello|hey|yo)\b", t) and len(t) < 24:
        return {"id": "greet", "text": "Hey. I'm Aura — I keep an eye on your files, flow and vibe. Try: \"clean my downloads\", \"recap my week\", or \"scaffold a new project\"."}

    # Help
    if re.search(r"\b(what can you|help|capabilit)\b", t):
        return {
            "id": "help",
            "text": "A few things I do without being asked:",
            "bullets": [
                "Watch your filesystem and surface duplicates, piles and naming drift",
                "Translate plain English into shell commands",
                "Run multi-step plans (tidy, scaffold, rename) with your OK",
                "Keep a weekly digest of what you actually did",
            ],
        }

    return None


def aura_apply_cleanup():
    """Execute the tidy plan: move Downloads files to appropriate homes."""
    moved = 0
    try:
        downloads = _safe("~/Downloads")
        pictures = _safe("~/Pictures")
        documents = _safe("~/Documents")
        projects = _safe("~/Projects")
        screenshots_dir = pictures / "Screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        for item in downloads.iterdir():
            if not item.is_file():
                continue
            ext = item.suffix.lower().lstrip(".")
            dest_dir = None
            if ext in ("png", "jpg", "jpeg", "gif", "webp"):
                # Check if screenshot by name
                if "screenshot" in item.name.lower() or "screen shot" in item.name.lower():
                    dest_dir = screenshots_dir
                else:
                    dest_dir = pictures
            elif ext in ("pdf", "docx", "txt", "md"):
                dest_dir = documents
            elif ext in ("csv", "json", "py", "ipynb"):
                dest_dir = projects
            if dest_dir:
                dest = dest_dir / item.name
                i = 1
                while dest.exists():
                    dest = dest_dir / f"{item.stem}.{i}{item.suffix}"
                    i += 1
                shutil.move(str(item), str(dest))
                moved += 1
    except Exception as e:
        return {"ok": False, "error": str(e), "moved": moved}
    return {"ok": True, "moved": moved}


def aura_empty_trash():
    """Empty the Storm trash."""
    try:
        trash = ROOT / ".storm-trash"
        if not trash.is_dir():
            return {"ok": True, "count": 0}
        count = 0
        for item in trash.iterdir():
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
            count += 1
        return {"ok": True, "count": count}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def aura_create_project(payload):
    """Scaffold a new project in ~/Projects."""
    name = (payload or {}).get("name", "new-project")
    try:
        projects = _safe("~/Projects")
        projects.mkdir(parents=True, exist_ok=True)
        proj = projects / name
        proj.mkdir(exist_ok=False)

        # web/
        web = proj / "web"
        web.mkdir()
        (web / "index.html").write_text("<!DOCTYPE html><html><body>vibes only</body></html>\n")
        (web / "notes.md").write_text("# first notes\n- what is this for?\n- who is it for?\n")

        # service/
        svc = proj / "service"
        svc.mkdir()
        (svc / "engine.py").write_text("def run():\n    return 'ready'\n")

        # README
        (proj / "README.md").write_text(f"# {name}\n\nScaffolded by Aura.\n")
        (proj / ".gitignore").write_text("__pycache__/\n.env\n*.log\n")

        return {"ok": True, "path": str(proj)}
    except FileExistsError:
        return {"ok": False, "error": f"Project '{name}' already exists"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def run(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def system_info():
    mem = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, _, v = line.partition(":")
            mem[k.strip()] = v.strip()
    except Exception:
        pass
    load = ""
    try:
        load = Path("/proc/loadavg").read_text().strip()
    except Exception:
        pass
    disk = shutil.disk_usage("/")
    uptime = ""
    try:
        uptime = Path("/proc/uptime").read_text().split()[0]
    except Exception:
        pass
    return {
        "load": load,
        "mem_total": mem.get("MemTotal", ""),
        "mem_avail": mem.get("MemAvailable", ""),
        "disk_free_gb": round(disk.free / 1e9, 1),
        "disk_total_gb": round(disk.total / 1e9, 1),
        "uptime_s": uptime,
        "gpu": run(["lspci", "-nn"]),
    }


# ── App index: XDG + flatpak, with first-seen tracking so newly installed apps
# can be surfaced as new and uninstalled ones drop out on the next scan.
APPS_CACHE = ROOT / ".cache" / "storm" / "apps.json"
NEW_APP_WINDOW = 7 * 86400


def _apps_cache():
    try:
        data = json.loads(APPS_CACHE.read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_apps_cache(apps):
    now = int(time.time())
    old = _apps_cache()
    keep = {k: v for k, v in old.items()
            if isinstance(v, dict) and now - int(v.get("last_seen", now)) < 90 * 86400}
    for app in apps:
        keep[app["id"]] = {"first_seen": app["first_seen"], "last_seen": now,
                            "name": app["name"]}
    try:
        APPS_CACHE.parent.mkdir(parents=True, exist_ok=True)
        tmp = APPS_CACHE.with_suffix(".tmp")
        tmp.write_text(json.dumps(keep, indent=1, sort_keys=True))
        tmp.replace(APPS_CACHE)
    except Exception:
        pass


def _app_dirs():
    dirs = [ROOT / ".local" / "share" / "applications"]
    for d in os.environ.get("XDG_DATA_DIRS", "/usr/local/share:/usr/share").split(":"):
        if d.strip():
            dirs.append(Path(d) / "applications")
    dirs.append(Path("/var/lib/flatpak/exports/share/applications"))
    dirs.append(ROOT / ".local" / "share" / "flatpak" / "exports" / "share" / "applications")
    out, seen = [], set()
    for d in dirs:
        key = str(d)
        if key not in seen and d.is_dir():
            seen.add(key)
            out.append(d)
    return out


def _clean_exec(value):
    return re.sub(r"\s*%[fFuUickDdnNvm]", "", value or "").strip()


def list_apps():
    now = int(time.time())
    first_run = not APPS_CACHE.exists()
    cache = _apps_cache()
    dirs = _app_dirs()
    found, ids = [], set()

    for d in dirs:
        for f in sorted(d.glob("*.desktop")):
            if f.stem in ids or f.name.startswith("storm-shell"):
                continue
            cp = configparser.ConfigParser(interpolation=None, strict=False)
            try:
                cp.read(f, encoding="utf-8", errors="ignore")
                if "Desktop Entry" not in cp:
                    continue
                entry = cp["Desktop Entry"]
                if entry.get("Type", "Application") != "Application":
                    continue
                if entry.get("NoDisplay", "false").lower() == "true":
                    continue
                if entry.get("Hidden", "false").lower() == "true":
                    continue
                try_exec = entry.get("TryExec", "").strip()
                if try_exec and not shutil.which(try_exec):
                    continue
                name = (entry.get("Name") or f.stem).strip()
                if not name:
                    continue
                found.append({
                    "id": f.stem,
                    "name": name,
                    "generic": entry.get("GenericName", "").strip(),
                    "comment": entry.get("Comment", "").strip(),
                    "exec": _clean_exec(entry.get("Exec", "")),
                    "icon": entry.get("Icon", "application-x-executable"),
                    "categories": [c for c in entry.get("Categories", "").split(";") if c],
                    "keywords": [k for k in entry.get("Keywords", "").split(";") if k],
                    "terminal": entry.get("Terminal", "false").lower() == "true",
                })
                ids.add(f.stem)
            except Exception:
                continue

    out, names = [], set()
    for app in found:
        key = app["name"].casefold()
        if key in names:
            continue
        names.add(key)
        record = cache.get(app["id"])
        first_seen = int(record["first_seen"]) if isinstance(record, dict) and record.get("first_seen") else now
        if first_run:
            # a fresh cache must not label every installed app as new
            first_seen = now - NEW_APP_WINDOW - 86400
        app["first_seen"] = first_seen
        app["new"] = (now - first_seen) < NEW_APP_WINDOW
        out.append(app)

    out.sort(key=lambda a: a["name"].casefold())
    _save_apps_cache(out)
    return {
        "apps": out,
        "total": len(out),
        "new": sum(1 for a in out if a["new"]),
        "scanned_at": now,
        "dirs": [str(d) for d in dirs],
    }


def get_theme():
    return {
        "gtk": run(["xfconf-query", "-c", "xsettings", "-p", "/Net/ThemeName"]),
        "icon": run(["xfconf-query", "-c", "xsettings", "-p", "/Net/IconThemeName"]),
        "font": run(["xfconf-query", "-c", "xsettings", "-p", "/Gtk/FontName"]),
        "wm": run(["xfconf-query", "-c", "xfwm4", "-p", "/general/theme"]),
    }


# ── Hardware bridges: each one degrades to {"supported": false} when the
# underlying tool is missing, so the UI can say "unavailable" instead of
# pretending a toggle worked.
def _have(cmd):
    return shutil.which(cmd) is not None


def audio_state():
    if not _have("pactl"):
        return {"supported": False, "volume": None, "muted": None}
    vol_out = run(["pactl", "get-sink-volume", "@DEFAULT_SINK@"])
    mute_out = run(["pactl", "get-sink-mute", "@DEFAULT_SINK@"])
    m = re.search(r"(\d+)%", vol_out)
    return {
        "supported": True,
        "volume": int(m.group(1)) if m else None,
        "muted": "yes" in mute_out.lower(),
    }


def set_audio(volume=None, muted=None, step=None):
    if not _have("pactl"):
        return {"supported": False}
    state = audio_state()
    if step is not None:
        volume = (state.get("volume") or 0) + int(step)
    if muted == "toggle":
        muted = not state.get("muted")
    if volume is not None:
        v = max(0, min(150, int(volume)))
        run(["pactl", "set-sink-volume", "@DEFAULT_SINK@", f"{v}%"])
    if muted is not None:
        run(["pactl", "set-sink-mute", "@DEFAULT_SINK@", "1" if muted else "0"])
    return {"ok": True, **audio_state()}


def network_state():
    if not _have("nmcli"):
        return {"supported": False}
    radio = run(["nmcli", "-t", "-f", "WIFI", "general"]).strip().lower()
    active = run(["nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active"])
    ssid = None
    for line in active.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] in ("802-11-wireless", "wifi"):
            ssid = parts[0]
            break
    return {
        "supported": True,
        "wifi": radio.startswith("enabled"),
        "ssid": ssid,
        "active": [l for l in active.splitlines() if l][:6],
    }


def set_wifi(enabled):
    if not _have("nmcli"):
        return {"supported": False}
    run(["nmcli", "radio", "wifi", "on" if enabled else "off"], timeout=15)
    return {"ok": True, **network_state()}


def bluetooth_state():
    if not _have("bluetoothctl"):
        return {"supported": False}
    out = run(["bluetoothctl", "show"], timeout=8)
    name = ""
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Name:"):
            name = s.split(":", 1)[1].strip()
    return {
        "supported": True,
        "powered": "Powered: yes" in out,
        "name": name or None,
        "devices": run(["bluetoothctl", "devices"], timeout=8).splitlines()[:8],
    }


def set_bluetooth(powered):
    if not _have("bluetoothctl"):
        return {"supported": False}
    run(["bluetoothctl", "power", "on" if powered else "off"], timeout=10)
    return {"ok": True, **bluetooth_state()}


def power_state():
    out = {"supported": False, "battery": None, "charging": None, "brightness": None,
           "status": None, "battery_health": None, "battery_cycles": None,
           "time_left_min": None, "power_draw_w": None, "ac_online": None}
    base = Path("/sys/class/power_supply")
    if base.is_dir():
        for bat in sorted(base.glob("BAT*")):
            def read(name, cast=str):
                try:
                    return cast((bat / name).read_text().strip())
                except Exception:
                    return None

            capacity = read("capacity", int)
            if capacity is None:
                continue
            out["battery"] = capacity
            out["status"] = read("status")
            out["charging"] = (read("status") or "").lower() in ("charging", "full")
            out["battery_cycles"] = read("cycle_count", int)
            out["supported"] = True

            energy_now = read("energy_now", int)
            energy_full = read("energy_full", int)
            energy_design = read("energy_full_design", int)
            power_now = read("power_now", int)
            if energy_now is None:
                charge_now = read("charge_now", int)
                voltage = read("voltage_now", int)
                if charge_now is not None and voltage:
                    energy_now = charge_now * voltage // 1_000_000
                    energy_full = energy_full or (read("charge_full", int) or 0) * voltage // 1_000_000
                    energy_design = energy_design or (read("charge_full_design", int) or 0) * voltage // 1_000_000
                    power_now = power_now or ((read("current_now", int) or 0) * voltage // 1_000_000)
            if energy_now and power_now:
                out["time_left_min"] = round(energy_now / power_now * 60) if power_now > 0 else None
            if power_now:
                out["power_draw_w"] = round(power_now / 1_000_000, 1)
            if energy_full and energy_design:
                out["battery_health"] = round(energy_full * 100 / energy_design)
            break
        for name in ("AC", "AC0", "ACAD", "ADP1"):
            for ac in base.glob(name + "*"):
                try:
                    out["ac_online"] = (ac / "online").read_text().strip() == "1"
                    break
                except Exception:
                    continue
    if _have("brightnessctl"):
        m = re.search(r"(\d+)%", run(["brightnessctl", "-m"]))
        if m:
            out["brightness"] = int(m.group(1))
            out["supported"] = True
    return out


def set_brightness(value):
    if not _have("brightnessctl"):
        return {"supported": False}
    v = max(1, min(100, int(value)))
    run(["brightnessctl", "set", f"{v}%"], timeout=8)
    return {"ok": True, **power_state()}


def step_brightness(delta):
    state = power_state()
    if state.get("brightness") is None:
        return {"supported": False}
    return set_brightness(state["brightness"] + int(delta))


# ── Keyboard backlight (separate LED class from the panel backlight) ────────
def _kbd_device():
    base = Path("/sys/class/leds")
    if not base.is_dir():
        return None
    for pattern in ("*::kbd_backlight", "*kbd_backlight", "*kbd*"):
        for d in sorted(base.glob(pattern)):
            try:
                if int((d / "max_brightness").read_text()) > 0:
                    return d
            except Exception:
                continue
    return None


def kbd_light_state():
    d = _kbd_device()
    if not d:
        return {"supported": False, "value": None, "device": None}
    try:
        raw = int((d / "brightness").read_text())
        maximum = int((d / "max_brightness").read_text())
        return {
            "supported": True,
            "value": round(raw * 100 / maximum) if maximum else 0,
            "raw": raw, "max": maximum, "device": d.name,
        }
    except Exception:
        return {"supported": False, "value": None, "device": d.name}


def set_kbd_light(value=None, step=None):
    state = kbd_light_state()
    if not state["supported"]:
        return state
    if step is not None:
        value = (state["value"] or 0) + int(step)
    v = max(0, min(100, int(value if value is not None else state["value"] or 0)))
    if _have("brightnessctl"):
        run(["brightnessctl", "--device", state["device"], "set", f"{v}%"], timeout=8)
    else:
        _sys_write(Path("/sys/class/leds") / state["device"] / "brightness",
                   round(state.get("max", 0) * v / 100))
    return {"ok": True, **kbd_light_state()}


# ── Graphics switching (hybrid laptops, envycontrol) ───────────────────────
GPU_MODES = ["integrated", "hybrid", "nvidia"]


def _gpu_names():
    names = []
    for line in run(["lspci", "-nn"], timeout=4).splitlines():
        if re.search(r"VGA compatible|3D controller|Display controller", line):
            names.append(line.split(":", 2)[-1].strip())
    return names


def gpu_state():
    gpus = _gpu_names()
    supported = _have("envycontrol")
    mode = None
    if supported:
        query = run(["envycontrol", "--query"], timeout=8) or run(["envycontrol", "-q"], timeout=8)
        for m in GPU_MODES:
            if m in query.lower():
                mode = m
                break
    return {
        "supported": supported,
        "mode": mode,
        "modes": GPU_MODES,
        "gpus": gpus,
        "hybrid": len(gpus) > 1 and any("nvidia" in g.lower() for g in gpus),
        "requires_logout": True,
        "needs_root": _have("pkexec"),
    }


def set_gpu_mode(mode):
    if mode not in GPU_MODES:
        return {"error": "invalid gpu mode"}
    if not _have("envycontrol"):
        return {"supported": False}
    if not _have("pkexec"):
        return {"supported": True, "ok": False,
                "error": f"envycontrol needs root: sudo envycontrol -s {mode}"}
    run(["pkexec", "envycontrol", "-s", mode], timeout=120)
    return {"ok": True, "requires_logout": True, **gpu_state()}


# ── CPU frequency governance ───────────────────────────────────────────────
CPU_CPUFREQ = Path("/sys/devices/system/cpu/cpu0/cpufreq")


def _turbo_path():
    no_turbo = Path("/sys/devices/system/cpu/intel_pstate/no_turbo")
    if no_turbo.is_file():
        return no_turbo, True  # inverted: 0 means turbo on
    boost = Path("/sys/devices/system/cpu/cpufreq/boost")
    if boost.is_file():
        return boost, False
    return None, False


def _sys_write(path, value):
    try:
        Path(path).write_text(str(value))
        return True
    except Exception:
        return False


def cpu_state():
    out = {"supported": False, "governors": [], "governor": None, "freq_mhz": None,
           "max_mhz": None, "cores": os.cpu_count(), "turbo": None, "turbo_supported": False}
    try:
        out["governors"] = (CPU_CPUFREQ / "scaling_available_governors").read_text().split()
    except Exception:
        return out
    if not out["governors"]:
        return out
    out["supported"] = True
    try:
        out["governor"] = (CPU_CPUFREQ / "scaling_governor").read_text().strip()
        out["freq_mhz"] = int((CPU_CPUFREQ / "scaling_cur_freq").read_text()) // 1000
        out["max_mhz"] = int((CPU_CPUFREQ / "cpuinfo_max_freq").read_text()) // 1000
    except Exception:
        pass
    turbo_path, invert = _turbo_path()
    if turbo_path:
        try:
            raw = turbo_path.read_text().strip() == "1"
            out["turbo"] = (not raw) if invert else raw
            out["turbo_supported"] = True
        except Exception:
            pass
    return out


def set_cpu(governor=None, turbo=None):
    state = cpu_state()
    if not state["supported"]:
        return state
    if governor and governor not in state["governors"]:
        return {"error": "governor not available"}
    if governor:
        targets = list(Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_governor"))
        if not any(_sys_write(p, governor) for p in targets) and _have("cpupower"):
            run(["pkexec", "cpupower", "frequency-set", "-g", governor], timeout=30)
    if turbo is not None:
        path, invert = _turbo_path()
        if path:
            raw = (0 if turbo else 1) if invert else (1 if turbo else 0)
            if not _sys_write(path, raw):
                run(["pkexec", "sh", "-c", f"echo {int(raw)} > {path}"], timeout=30)
    fresh = cpu_state()
    error = None
    if governor and fresh["governor"] != governor:
        error = "permission denied — needs root (pkexec/cpupower)"
    return {"ok": error is None, **fresh, "error": error}


# ── Persistent desktop settings (theme, accent, density, motion, text size, mood) ──
SETTINGS_FILE = ROOT / ".config" / "storm" / "settings.json"
DEFAULT_SETTINGS = {
    "theme": "dark", "accent": "cyan", "density": "comfortable",
    "motion": True, "fontScale": 100, "wallpaper": True,
    "mood": "nebula",
}
SETTINGS_ALLOWED = {
    "theme": {"dark", "glass", "light"},
    "accent": {"cyan", "amber", "lilac", "salmon", "mint"},
    "density": {"comfortable", "compact"},
    "motion": {True, False},
    "fontScale": {90, 100, 110, 120},
    "wallpaper": {True, False},
    "mood": {"nebula", "sunset", "forest", "mono"},
}
GTK_THEMES = {"dark": "Storm-Dark", "glass": "Storm-Glass", "light": "Storm-Light"}
# Mood doesn't change GTK theme name; it changes accent/glow/bg via CSS tokens.
# But we can optionally set a GTK theme variant per mood if themes exist.
MOOD_GTK_VARIANTS = {
    "nebula": "Storm-Dark",
    "sunset": "Storm-Dark",
    "forest": "Storm-Dark",
    "mono": "Storm-Dark",
}


def read_settings():
    data = dict(DEFAULT_SETTINGS)
    try:
        if SETTINGS_FILE.is_file():
            loaded = json.loads(SETTINGS_FILE.read_text())
            if isinstance(loaded, dict):
                data.update({k: v for k, v in loaded.items() if k in SETTINGS_ALLOWED})
    except Exception:
        pass
    return data


def _apply_gtk(settings):
    """Mirror Storm's theme into GTK/xfwm4 when a config store exists."""
    if not _have("xfconf-query"):
        return
    name = GTK_THEMES.get(settings.get("theme", "dark"), "Storm-Dark")
    run(["xfconf-query", "-c", "xsettings", "-p", "/Net/ThemeName", "-s", name])
    run(["xfconf-query", "-c", "xfwm4", "-p", "/general/theme", "-s", name])
    # Mood is primarily CSS tokens (accent, glow, desk-bg) applied by frontend.
    # Optionally set a GTK theme variant per mood if available.
    mood = settings.get("mood", "nebula")
    variant = MOOD_GTK_VARIANTS.get(mood)
    if variant and variant != name:
        run(["xfconf-query", "-c", "xsettings", "-p", "/Net/ThemeName", "-s", variant])
        run(["xfconf-query", "-c", "xfwm4", "-p", "/general/theme", "-s", variant])


def write_settings(patch):
    data = read_settings()
    rejected = []
    for key, value in (patch or {}).items():
        if key in SETTINGS_ALLOWED and value in SETTINGS_ALLOWED[key]:
            data[key] = value
        else:
            rejected.append(key)
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(data, indent=2) + "\n")
    _apply_gtk(data)
    return {"ok": True, "settings": data, "rejected": rejected}


# ── Power profiles (laptops) ──────────────────────────────────────────────
PROFILES = ["power-saver", "balanced", "performance"]
PLATFORM_PROFILE = Path("/sys/firmware/acpi/platform_profile")
PLATFORM_MAP = {
    "low": "power-saver", "quiet": "power-saver", "cool": "balanced",
    "balanced": "balanced", "balanced-performance": "balanced",
    "performance": "performance",
}


def _platform_profiles():
    try:
        return Path("/sys/firmware/acpi/platform_profile_choices").read_text().split()
    except Exception:
        return []


def power_profile_state():
    if _have("powerprofilesctl"):
        return {
            "supported": True,
            "profile": run(["powerprofilesctl", "get"]).strip() or "balanced",
            "profiles": PROFILES,
            "backend": "powerprofilesctl",
        }
    if PLATFORM_PROFILE.is_file():
        try:
            raw = PLATFORM_PROFILE.read_text().strip()
        except Exception:
            raw = ""
        available = [PLATFORM_MAP.get(c, c) for c in _platform_profiles()]
        return {
            "supported": True,
            "profile": PLATFORM_MAP.get(raw, raw or "balanced"),
            "profiles": available or PROFILES,
            "backend": "platform_profile",
            "raw": raw,
        }
    return {"supported": False, "profile": None, "profiles": PROFILES}


def set_power_profile(profile):
    if _have("powerprofilesctl"):
        if profile not in PROFILES:
            return {"error": "invalid profile"}
        run(["powerprofilesctl", "set", profile], timeout=10)
        return {"ok": True, **power_profile_state()}
    if PLATFORM_PROFILE.is_file():
        if profile not in PROFILES:
            return {"error": "invalid profile"}
        wanted = [c for c in _platform_profiles() if PLATFORM_MAP.get(c, c) == profile]
        if not wanted:
            return {"error": "profile not available on this hardware"}
        if not _sys_write(PLATFORM_PROFILE, wanted[0]):
            run(["pkexec", "sh", "-c", f"echo {wanted[0]} > {PLATFORM_PROFILE}"], timeout=20)
        return {"ok": True, **power_profile_state()}
    return {"supported": False}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _raw(self, p):
        data = p.read_bytes()[:5_000_000]
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(p.name)[0] or "application/octet-stream")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0) or 0)
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            data = {}
        try:
            if path == "/api/launch":
                cmd = data.get("cmd", "")
                if not cmd:
                    return self._send({"error": "empty cmd"}, 400)
                clean = " ".join(t for t in cmd.split() if not t.startswith("%"))
                subprocess.Popen(clean, shell=True, start_new_session=True,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return self._send({"ok": True})

            if path == "/api/theme":
                for key, channel, prop in [
                    ("gtk", "xsettings", "/Net/ThemeName"),
                    ("icon", "xsettings", "/Net/IconThemeName"),
                    ("font", "xsettings", "/Gtk/FontName"),
                    ("wm", "xfwm4", "/general/theme"),
                ]:
                    if data.get(key):
                        run(["xfconf-query", "-c", channel, "-p", prop, "-s", data[key]])
                return self._send({"ok": True, "theme": get_theme()})

            if path == "/api/command":
                action = data.get("action", "")
                if action not in ALLOWED_COMMANDS:
                    return self._send({"error": "action not allowed"}, 403)
                subprocess.Popen(ALLOWED_COMMANDS[action], start_new_session=True,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return self._send({"ok": True})

            # ── hardware controls ────────────────────────────────────────────
            if path == "/api/audio":
                return self._send(set_audio(data.get("volume"), data.get("muted")))
            if path == "/api/network":
                return self._send(set_wifi(bool(data.get("wifi"))))
            if path == "/api/bluetooth":
                return self._send(set_bluetooth(bool(data.get("powered"))))
            if path == "/api/brightness":
                if data.get("step") is not None:
                    return self._send(step_brightness(data["step"]))
                return self._send(set_brightness(data.get("value", 50)))
            if path == "/api/settings":
                return self._send(write_settings(data))
            if path == "/api/powerprofile":
                return self._send(set_power_profile(data.get("profile")))
            if path == "/api/gpu":
                return self._send(set_gpu_mode(data.get("mode", "")))
            if path == "/api/cpu":
                return self._send(set_cpu(data.get("governor"), data.get("turbo")))
            if path == "/api/kbdlight":
                return self._send(set_kbd_light(data.get("value"), data.get("step")))

            # ── Files app ────────────────────────────────────────────────────
            if path == "/api/fs/mkdir":
                parent = _safe(data.get("path", ""))
                name = (data.get("name") or "").strip()
                if not name or name in (".", "..") or "/" in name or "\\" in name:
                    return self._send({"error": "invalid name"}, 400)
                target = parent / name
                target.mkdir()
                return self._send({"ok": True, "path": str(target)})

            if path == "/api/fs/rename":
                src = _safe(data.get("path", ""))
                name = (data.get("name") or "").strip()
                if src == ROOT:
                    return self._send({"error": "cannot rename home"}, 400)
                if not name or name in (".", "..") or "/" in name or "\\" in name:
                    return self._send({"error": "invalid name"}, 400)
                dest = src.parent / name
                if dest.exists():
                    return self._send({"error": "name already exists"}, 409)
                src.rename(dest)
                return self._send({"ok": True, "path": str(dest)})

            if path == "/api/fs/trash":
                return self._send({"ok": True, **fs_trash(data.get("paths") or [])})

            if path == "/api/fs/paste":
                dst = _safe(data.get("dst", ""))
                mode = data.get("mode", "copy")
                if not dst.is_dir():
                    return self._send({"error": "destination is not a folder"}, 400)
                done = []
                for item in data.get("src") or []:
                    src = _safe(item)
                    if src == ROOT or src == dst:
                        continue
                    dest = dst / src.name
                    i = 1
                    while dest.exists():
                        dest = dst / f"{src.stem} ({i}){src.suffix}"
                        i += 1
                    if mode == "move":
                        shutil.move(str(src), str(dest))
                    elif src.is_dir():
                        shutil.copytree(src, dest)
                    else:
                        shutil.copy2(src, dest)
                    done.append(str(dest))
                return self._send({"ok": True, "created": done})

            if path == "/api/fs/open":
                target = _safe(data.get("path", ""))
                if not target.exists():
                    return self._send({"error": "not found"}, 404)
                if os.name == "nt":
                    os.startfile(str(target))  # noqa: S606 - desktop handler
                else:
                    subprocess.Popen(["xdg-open", str(target)], start_new_session=True,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return self._send({"ok": True})

            # ── Aura Copilot actions ──
            if path == "/api/aura/apply-cleanup":
                return self._send(aura_apply_cleanup())
            if path == "/api/aura/empty-trash":
                return self._send(aura_empty_trash())
            if path == "/api/aura/start-focus":
                return self._send({"ok": True, "message": "Focus session started (UI handles timer)"})
            if path == "/api/aura/create-project":
                return self._send(aura_create_project(data.get("payload", {})))

            return self._send({"error": "not found"}, 404)
        except PermissionError as e:
            self._send({"error": str(e) or "permission denied"}, 403)
        except FileNotFoundError as e:
            self._send({"error": f"not found: {e}"}, 404)
        except FileExistsError:
            self._send({"error": "already exists"}, 409)
        except Exception as e:
            self._send({"error": str(e)}, 500)

    # ── WebSocket PTY upgrade ──
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/api/pty" and self.headers.get("Upgrade", "").lower() == "websocket":
            self._handle_pty_upgrade()
            return
        # Fall through to original do_GET
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        try:
            if path == "/api/health":
                self._send({"ok": True, "service": "stormd"})
            elif path == "/api/system":
                self._send(system_info())
            elif path == "/api/apps":
                self._send(list_apps())
            elif path == "/api/theme":
                self._send(get_theme())
            elif path == "/api/audio":
                self._send(audio_state())
            elif path == "/api/network":
                self._send(network_state())
            elif path == "/api/bluetooth":
                self._send(bluetooth_state())
            elif path == "/api/power":
                self._send(power_state())
            elif path == "/api/settings":
                self._send(read_settings())
            elif path == "/api/powerprofile":
                self._send(power_profile_state())
            elif path == "/api/gpu":
                self._send(gpu_state())
            elif path == "/api/cpu":
                self._send(cpu_state())
            elif path == "/api/kbdlight":
                self._send(kbd_light_state())
            elif path == "/api/fs/list":
                self._send(fs_list(qs.get("path", [""])[0]))
            elif path == "/api/fs/search":
                self._send(fs_search(qs.get("path", [""])[0], qs.get("q", [""])[0], mode=qs.get("mode", ["name"])[0]))
            elif path == "/api/fs/read":
                self._send(fs_read(qs.get("path", [""])[0]))
            elif path == "/api/fs/raw":
                self._raw(_safe(qs.get("path", [""])[0]))
            # ── Aura Copilot endpoints ──
            elif path == "/api/aura/observations":
                self._send(aura_observations())
            elif path == "/api/aura/intent":
                self._send(aura_intent(qs.get("q", [""])[0]))
            elif path == "/api/aura/status":
                self._send({"status": "ready", "version": "0.2.0"})
            else:
                self._send({"error": "not found"}, 404)
        except PermissionError as e:
            self._send({"error": str(e) or "permission denied"}, 403)
        except FileNotFoundError as e:
            self._send({"error": f"not found: {e}"}, 404)
        except Exception as e:
            self._send({"error": str(e)}, 500)

    def _handle_pty_upgrade(self):
        """Upgrade HTTP connection to WebSocket for PTY."""
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key:
            self._send({"error": "WebSocket key required"}, 400)
            return
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()

        # Spawn PTY
        pid, fd = pty.fork()
        if pid == 0:
            # Child: exec shell
            os.environ["TERM"] = "xterm-256color"
            os.environ["COLORTERM"] = "truecolor"
            shell = os.environ.get("SHELL", "/bin/bash")
            os.execlp(shell, shell)
        else:
            # Parent: handle WebSocket frames
            self._pty_session(fd, pid)

    def _pty_session(self, fd, pid):
        """Handle WebSocket frames and PTY I/O."""
        import fcntl
        # Set non-blocking
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        def send_frame(data, opcode=0x2):
            """Send a WebSocket frame (opcode 0x2 = binary)."""
            payload = data if isinstance(data, bytes) else data.encode()
            length = len(payload)
            frame = bytearray()
            frame.append(0x80 | opcode)  # FIN + opcode
            if length < 126:
                frame.append(length)
            elif length < 65536:
                frame.append(126)
                frame.extend(struct.pack(">H", length))
            else:
                frame.append(127)
                frame.extend(struct.pack(">Q", length))
            frame.extend(payload)
            try:
                self.connection.sendall(frame)
            except Exception:
                raise

        def recv_frame():
            """Receive a WebSocket frame."""
            try:
                hdr = self.connection.recv(2)
                if not hdr or len(hdr) < 2:
                    return None, None
                fin_opcode = hdr[0]
                masked_len = hdr[1]
                masked = masked_len & 0x80
                length = masked_len & 0x7F
                if length == 126:
                    length = struct.unpack(">H", self.connection.recv(2))[0]
                elif length == 127:
                    length = struct.unpack(">Q", self.connection.recv(8))[0]
                mask = self.connection.recv(4) if masked else b""
                payload = self.connection.recv(length)
                if masked:
                    payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
                opcode = fin_opcode & 0x0F
                return opcode, payload
            except Exception:
                return None, None

        # Send initial size
        send_frame(json.dumps({"type": "ready", "cols": 80, "rows": 24}).encode())

        try:
            while True:
                # Check PTY output
                r, _, _ = select.select([fd], [], [], 0.01)
                if fd in r:
                    try:
                        data = os.read(fd, 4096)
                        if data:
                            send_frame(json.dumps({"type": "output", "data": data.decode("utf-8", "replace")}).encode())
                    except OSError:
                        break

                # Check WebSocket input
                r, _, _ = select.select([self.connection], [], [], 0.01)
                if r:
                    opcode, payload = recv_frame()
                    if opcode is None:
                        break
                    if opcode == 0x8:  # Close
                        break
                    if opcode == 0x1 or opcode == 0x2:  # Text or binary
                        try:
                            msg = json.loads(payload.decode() if isinstance(payload, bytes) else payload)
                            if msg.get("type") == "input":
                                os.write(fd, msg["data"].encode())
                            elif msg.get("type") == "resize":
                                import termios
                                winsize = struct.pack("HHHH", msg.get("rows", 24), msg.get("cols", 80), 0, 0)
                                fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
                        except Exception:
                            pass
        except Exception:
            pass
        finally:
            try:
                os.kill(pid, signal.SIGHUP)
            except Exception:
                pass
            try:
                os.close(fd)
            except Exception:
                pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9876)
    args = ap.parse_args()
    # localhost only — never expose stormd to the network
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
