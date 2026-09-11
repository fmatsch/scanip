"""Dauerhafte Notizen zu Geräten.

Notizen werden über Scanvorgänge und Programmstarts hinweg gespeichert. Als
Schlüssel dient die MAC-Adresse, weil sie am Gerät hängt - ein Gerät behält
seine Notiz also auch, wenn es vom DHCP eine andere IP bekommt. Nur wenn keine
MAC bekannt ist (typisch für Geräte hinter einem Router), wird auf die IP
zurückgegriffen.

Ablage:
    Windows  %APPDATA%\\scanip\\notes.json
    macOS    ~/Library/Application Support/scanip/notes.json
    Linux    ~/.local/share/scanip/notes.json
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
from typing import Dict, List, Optional

FORMAT_VERSION = 1
MAX_LENGTH = 2000

_lock = threading.RLock()
_cache: Optional[Dict[str, Dict]] = None
_path_override: Optional[str] = None


def data_dir() -> str:
    """Plattformgerechter Ort für Benutzerdaten (nicht Cache - Notizen sind Daten)."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "scanip")


def notes_path() -> str:
    return _path_override or os.path.join(data_dir(), "notes.json")


def use_path(path: Optional[str]) -> None:
    """Setzt einen abweichenden Speicherort (für Tests)."""
    global _path_override, _cache
    with _lock:
        _path_override = path
        _cache = None


def device_key(mac: Optional[str], ip: Optional[str] = None) -> Optional[str]:
    """Schlüssel eines Geräts: bevorzugt die MAC-Adresse."""
    if mac:
        return mac.upper()
    if ip:
        return "ip:" + ip
    return None


def _load() -> Dict[str, Dict]:
    global _cache
    with _lock:
        if _cache is not None:
            return _cache
        _cache = {}
        try:
            with open(notes_path(), "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return _cache
        if isinstance(data, dict) and isinstance(data.get("notes"), dict):
            for key, entry in data["notes"].items():
                if isinstance(entry, dict) and entry.get("text"):
                    _cache[str(key).upper() if not str(key).startswith("ip:")
                           else str(key)] = entry
                elif isinstance(entry, str) and entry:        # einfaches Format
                    _cache[str(key)] = {"text": entry}
        return _cache


def _save() -> bool:
    """Schreibt die Datei atomar - ein Absturz kann keine halbe Datei hinterlassen."""
    with _lock:
        entries = _load()
        target = notes_path()
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            handle = tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", delete=False,
                dir=os.path.dirname(target), prefix=".notes-", suffix=".tmp")
            try:
                json.dump({"version": FORMAT_VERSION, "notes": entries},
                          handle, indent=2, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            finally:
                handle.close()
            os.replace(handle.name, target)
            return True
        except OSError:
            return False


def get(mac: Optional[str], ip: Optional[str] = None) -> str:
    """Notiz eines Geräts (leer, wenn keine vorhanden)."""
    entries = _load()
    for key in (device_key(mac), device_key(None, ip)):
        if key and key in entries:
            return entries[key].get("text", "")
    return ""


def set_note(mac: Optional[str], ip: Optional[str], text: str,
             name: Optional[str] = None) -> bool:
    """Speichert oder löscht (bei leerem Text) die Notiz eines Geräts."""
    key = device_key(mac, ip)
    if not key:
        return False
    text = (text or "").strip()[:MAX_LENGTH]
    with _lock:
        entries = _load()
        if not text:
            entries.pop(key, None)
        else:
            entry = entries.setdefault(key, {})
            entry["text"] = text
            entry["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
            if ip:
                entry["last_ip"] = ip
            if name:
                entry["last_name"] = name
        return _save()


def all_notes() -> Dict[str, Dict]:
    """Alle gespeicherten Notizen als {Schlüssel: Eintrag}."""
    return dict(_load())


def count() -> int:
    return len(_load())


def delete(key: str) -> bool:
    with _lock:
        entries = _load()
        if entries.pop(key, None) is None and entries.pop(key.upper(), None) is None:
            return False
        return _save()


def reload() -> None:
    """Verwirft den Zwischenspeicher - liest beim nächsten Zugriff neu."""
    global _cache
    with _lock:
        _cache = None


def format_list() -> List[str]:
    """Notizen für die Anzeige auf der Kommandozeile."""
    lines = []
    for key, entry in sorted(all_notes().items()):
        parts = [key.ljust(18), entry.get("text", "")]
        extra = [v for v in (entry.get("last_name"), entry.get("last_ip"),
                             entry.get("updated")) if v]
        if extra:
            parts.append("(" + ", ".join(extra) + ")")
        lines.append("  ".join(parts))
    return lines
