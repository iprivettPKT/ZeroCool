"""Persistence layer for ZeroCool.

The entire dashboard is driven by a single "engagement" document that holds
everything later command modules (nmap, crackmapexec, bloodhound, etc.) will
need: scope, targets, the domain controller, domain creds and so on.

For now this is a flat JSON file on disk. It is deliberately small and
dependency-free so it is trivial to swap for SQLite/Postgres later without
touching the views.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from copy import deepcopy

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
ENGAGEMENT_FILE = os.path.join(DATA_DIR, "engagement.json")

_lock = threading.Lock()


# The canonical shape of an engagement. Add new fields here as command modules
# start needing more inputs -- everything in the GUI reads from this schema.
DEFAULT_ENGAGEMENT = {
    # --- identification ---
    "engagement_name": "",
    "client": "",
    "notes": "",

    # --- networking / scope ---
    "scope": [],          # in-scope CIDRs / ranges, e.g. "10.10.0.0/24"
    "out_of_scope": [],   # explicit exclusions
    "targets": [],         # specific hosts of interest (IP or hostname)

    # --- active directory ---
    "domain": "",          # AD domain, e.g. "corp.local"
    "dc_ip": "",           # domain controller IP
    "dc_hostname": "",     # domain controller hostname

    # --- attacker / tooling context ---
    "interface": "eth0",   # interface commands bind to
    "attacker_ip": "",     # our IP (for reverse shells, responder, etc.)
    "output_dir": "",      # where command output/loot is written
    "socks_proxy": "",     # active SOCKS proxy "host:port" for pivoting (proxychains)

    # --- credentials (list of dicts) ---
    # each: {domain, username, password, ntlm_hash, notes}
    "credentials": [],
}

# Fields that are stored as lists but edited as newline/comma separated text.
LIST_FIELDS = ("scope", "out_of_scope", "targets")


def _ensure_data_dir() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)


def load_engagement() -> dict:
    """Return the current engagement, merged over defaults so new fields added
    to DEFAULT_ENGAGEMENT always exist even for older saved files."""
    _ensure_data_dir()
    data = deepcopy(DEFAULT_ENGAGEMENT)
    if os.path.exists(ENGAGEMENT_FILE):
        try:
            with open(ENGAGEMENT_FILE, "r", encoding="utf-8") as fh:
                saved = json.load(fh)
            if isinstance(saved, dict):
                data.update({k: saved[k] for k in saved if k in data})
        except (json.JSONDecodeError, OSError):
            # Corrupt/unreadable file -- fall back to defaults rather than crash.
            pass
    return data


def save_engagement(data: dict) -> dict:
    """Persist the engagement atomically (write temp file then rename)."""
    _ensure_data_dir()
    merged = deepcopy(DEFAULT_ENGAGEMENT)
    merged.update({k: data[k] for k in data if k in merged})
    with _lock:
        fd, tmp = tempfile.mkstemp(dir=DATA_DIR, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(merged, fh, indent=2)
            os.replace(tmp, ENGAGEMENT_FILE)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
    return merged


def parse_list(raw: str) -> list[str]:
    """Turn a textarea blob (newline or comma separated) into a clean list."""
    if not raw:
        return []
    items: list[str] = []
    for chunk in raw.replace(",", "\n").splitlines():
        item = chunk.strip()
        if item and item not in items:
            items.append(item)
    return items
