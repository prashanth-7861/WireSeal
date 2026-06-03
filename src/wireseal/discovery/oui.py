"""MAC address vendor lookup via bundled OUI prefix database."""

from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)

_OUI_DB: dict[str, str] | None = None
_OUI_PATH = Path(__file__).parent / "oui_data.json"


def _load_oui() -> dict[str, str]:
    """Load the OUI database from the bundled JSON file."""
    global _OUI_DB
    if _OUI_DB is not None:
        return _OUI_DB
    try:
        with open(_OUI_PATH, "r", encoding="utf-8") as f:
            _OUI_DB = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        log.warning("OUI database not found or invalid at %s", _OUI_PATH)
        _OUI_DB = {}
    return _OUI_DB


def lookup_vendor(mac: str) -> str:
    """Look up vendor name from a MAC address.

    Accepts any common format (aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF, etc.).
    Returns vendor name or "Unknown".
    """
    db = _load_oui()
    # Normalize: uppercase, colon-separated, first 3 octets
    clean = mac.upper().replace("-", ":").replace(".", ":")
    parts = clean.split(":")
    if len(parts) >= 3:
        prefix = ":".join(p.zfill(2) for p in parts[:3])
        return db.get(prefix, "Unknown")
    return "Unknown"
