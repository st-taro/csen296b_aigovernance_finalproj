"""Mock cloud drive (stands in for the Google Drive / OneDrive API).

Files live under data/runtime/drive/<folder>/<name>. The API mirrors a small
subset of a drive SDK: upload, download, list, search. Paths are confined to
the drive root (no ../ traversal).
"""
import json
import re

from app import config, db

FOLDERS = ("cases", "profiles", "policies", "reports")


def _path(folder: str, name: str):
    if folder not in FOLDERS:
        raise ValueError(f"unknown drive folder '{folder}'")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    if safe.startswith("."):
        raise ValueError("invalid file name")
    root = (config.DRIVE_DIR / folder).resolve()
    root.mkdir(parents=True, exist_ok=True)
    p = (root / safe).resolve()
    if root not in p.parents:
        raise ValueError("path escapes drive folder")
    return p


def upload(folder: str, name: str, content) -> dict:
    p = _path(folder, name)
    text = content if isinstance(content, str) else json.dumps(content, indent=2, default=str)
    p.write_text(text, encoding="utf-8")
    return {"folder": folder, "name": p.name, "bytes": len(text.encode()), "modified": db.now_iso()}


def download(folder: str, name: str) -> str:
    p = _path(folder, name)
    if not p.exists():
        raise FileNotFoundError(f"{folder}/{name}")
    return p.read_text(encoding="utf-8")


def list_files(folder: str, prefix: str = "") -> list:
    root = _path(folder, "x").parent
    return sorted(f.name for f in root.iterdir() if f.is_file() and f.name.startswith(prefix))


def search(folder: str, text: str, name_filter: str = "") -> list:
    """Case-insensitive substring search over file names and contents."""
    out = []
    for name in list_files(folder):
        if name_filter and name_filter.lower() not in name.lower():
            continue
        body = download(folder, name)
        if not text or text.lower() in body.lower() or text.lower() in name.lower():
            out.append({"folder": folder, "name": name, "snippet": body[:200]})
    return out
