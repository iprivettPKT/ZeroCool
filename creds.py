"""Credential & hash management for ZeroCool.

A structured store of everything you collect during an engagement — cleartext,
NTLM/AES hashes, Kerberos roast hashes — with:

  * paste-to-parse: drop in secretsdump / NTDS / hashcat output and auto-extract,
  * hashcat cracking: build & run a job for a hash type, then import the cracked
    plaintext back onto the credentials,
  * promote-to-engagement: push a usable cred into the engagement so the
    AD / Web / Cloud credential pickers can use it.

Stored in data/credentials.json (separate from the engagement profile).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import tempfile
import threading
import uuid
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request

import storage

creds_bp = Blueprint("creds", __name__)

CREDS_FILE = os.path.join(storage.DATA_DIR, "credentials.json")
DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"
_lock = threading.Lock()

# credential type -> hashcat mode (None = not wordlist-crackable here)
HASHCAT_MODES = {
    "ntlm": 1000, "krb5tgs": 13100, "krb5asrep": 18200,
    "dcc2": 2100, "netntlmv2": 5600, "netntlmv1": 5500,
}
CRACKABLE = [t for t, m in HASHCAT_MODES.items() if m]


# --------------------------------------------------------------------------
# store
# --------------------------------------------------------------------------

def load_creds() -> list[dict]:
    if not os.path.exists(CREDS_FILE):
        return []
    try:
        with open(CREDS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_creds(items: list[dict]) -> None:
    os.makedirs(storage.DATA_DIR, exist_ok=True)
    with _lock:
        fd, tmp = tempfile.mkstemp(dir=storage.DATA_DIR, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(items, fh, indent=2)
            os.replace(tmp, CREDS_FILE)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)


def _mk(domain, username, ctype, value, source):
    return {"domain": (domain or "").strip(), "username": (username or "").strip(),
            "type": ctype, "value": value.strip(), "source": source,
            "cracked": "", "privilege": "unknown", "validated": False, "notes": ""}


def add_creds(new: list[dict]) -> int:
    items = load_creds()
    have = {(c["domain"].lower(), c["username"].lower(), c["type"], c["value"]) for c in items}
    added = 0
    for c in new:
        key = (c["domain"].lower(), c["username"].lower(), c["type"], c["value"])
        if c["value"] and key not in have:
            c["id"] = uuid.uuid4().hex[:8]
            c["created"] = datetime.now().isoformat(timespec="seconds")
            items.append(c)
            have.add(key)
            added += 1
    if added:
        save_creds(items)
    return added


def delete_cred(cid: str) -> None:
    save_creds([c for c in load_creds() if c.get("id") != cid])


# --------------------------------------------------------------------------
# paste-to-parse
# --------------------------------------------------------------------------

def _split_du(principal: str):
    for sep in ("\\", "/"):
        if sep in principal:
            d, u = principal.split(sep, 1)
            return d, u
    return "", principal


def _krb_principal(line: str, kind: str):
    if kind == "tgs":
        m = re.search(r"\$krb5tgs\$\d+\$\*([^$]+)\$([^$]+)\$", line)
        if m:
            return m.group(2), m.group(1)  # domain, user
    else:
        m = re.search(r"\$krb5asrep\$\d+\$([^@]+)@([^:]+)", line)
        if m:
            return m.group(2), m.group(1)
    return "", ""


def parse_dump(text: str) -> list[dict]:
    """Extract credentials from pasted tool output (secretsdump, hashes, roast)."""
    out: list[dict] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("$krb5tgs$"):
            dom, user = _krb_principal(line, "tgs")
            out.append(_mk(dom, user, "krb5tgs", line, "kerberoast"))
            continue
        if line.startswith("$krb5asrep$"):
            dom, user = _krb_principal(line, "asrep")
            out.append(_mk(dom, user, "krb5asrep", line, "asrep"))
            continue

        # secretsdump AES/DES keys:  principal:aes256-...:<hexkey>
        m = re.match(r"^(.*?):(aes256-cts-hmac-sha1-96|aes128-cts-hmac-sha1-96|des-cbc-md5):([0-9a-fA-F]+)$", line)
        if m:
            dom, user = _split_du(m.group(1))
            out.append(_mk(dom, user, m.group(2).split("-")[0], m.group(3), "secretsdump"))
            continue

        # cached domain creds: principal:$DCC2$10240#user#hash
        m = re.match(r"^(.*?):(\$DCC2\$\S+)$", line)
        if m:
            dom, user = _split_du(m.group(1))
            out.append(_mk(dom, user, "dcc2", m.group(2), "secretsdump"))
            continue

        # NTDS / SAM:  principal:rid:lm:nt:::
        m = re.match(r"^([^:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::", line)
        if m:
            dom, user = _split_du(m.group(1))
            out.append(_mk(dom, user, "ntlm", m.group(4).lower(), "secretsdump"))
            continue

        # principal:nthash
        m = re.match(r"^([^:]+):([0-9a-fA-F]{32})$", line)
        if m:
            dom, user = _split_du(m.group(1))
            out.append(_mk(dom, user, "ntlm", m.group(2).lower(), "manual"))
            continue

        # NetNTLMv2:  user::domain:challenge:hmac:blob
        if re.match(r"^[^:]+::[^:]+:[0-9a-fA-F]+:[0-9a-fA-F]{32}:[0-9a-fA-F]+$", line):
            user = line.split("::", 1)[0]
            dom = line.split("::", 1)[1].split(":", 1)[0]
            out.append(_mk(dom, user, "netntlmv2", line, "responder"))
            continue

        # principal:password  (value isn't pure hex)
        m = re.match(r"^([^:]+):(.+)$", line)
        if m and not re.fullmatch(r"[0-9a-fA-F:]+", m.group(2)):
            dom, user = _split_du(m.group(1))
            out.append(_mk(dom, user, "password", m.group(2), "manual"))
            continue
    return out


# --------------------------------------------------------------------------
# cracking
# --------------------------------------------------------------------------

def loot_dir() -> str:
    eng = storage.load_engagement()
    return (eng.get("output_dir") or "").strip() or storage.DATA_DIR


def build_crack(ctype: str, wordlist: str, rules: str) -> dict:
    mode = HASHCAT_MODES.get(ctype)
    if not mode:
        return {"error": f"{ctype} is not crackable here"}
    targets = [c for c in load_creds() if c["type"] == ctype and not c.get("cracked")]
    if not targets:
        return {"error": f"no uncracked {ctype} hashes"}
    loot = loot_dir()
    os.makedirs(loot, exist_ok=True)
    hashfile = os.path.join(loot, f"hashes_{ctype}.txt")
    with open(hashfile, "w", encoding="utf-8") as fh:
        fh.write("\n".join(c["value"] for c in targets) + "\n")
    pot = os.path.join(loot, "zerocool.potfile")
    parts = ["hashcat", "-m", str(mode), "-a", "0", shlex.quote(hashfile),
             shlex.quote(wordlist or DEFAULT_WORDLIST)]
    if rules.strip():
        parts += ["-r", shlex.quote(rules.strip())]
    parts += ["--potfile-path", shlex.quote(pot)]
    return {"command": " ".join(parts), "count": len(targets)}


def import_cracked() -> int:
    pot = os.path.join(loot_dir(), "zerocool.potfile")
    if not os.path.exists(pot):
        return 0
    try:
        lines = open(pot, "r", encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return 0
    creds = load_creds()
    updated = 0
    for c in creds:
        if c.get("cracked") or not c.get("value"):
            continue
        prefix = c["value"] + ":"
        for ln in lines:
            if ln.startswith(prefix):
                c["cracked"] = ln[len(prefix):]
                updated += 1
                break
    if updated:
        save_creds(creds)
    return updated


def promote(cid: str) -> bool:
    cred = next((c for c in load_creds() if c.get("id") == cid), None)
    if not cred:
        return False
    pw = cred.get("cracked") or (cred["value"] if cred["type"] == "password" else "")
    nt = cred["value"] if cred["type"] == "ntlm" else ""
    if not (pw or nt):
        return False
    eng = storage.load_engagement()
    items = list(eng.get("credentials") or [])
    entry = {"domain": cred.get("domain", ""), "username": cred.get("username", ""),
             "password": pw, "ntlm_hash": nt, "notes": "from creds: " + cred.get("source", "")}
    if not any(e.get("username") == entry["username"] and e.get("password") == pw
               and e.get("ntlm_hash") == nt for e in items):
        items.append(entry)
        eng["credentials"] = items
        storage.save_engagement(eng)
    return True


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------

@creds_bp.route("/creds")
def creds():
    items = load_creds()
    counts = {}
    for c in items:
        counts[c["type"]] = counts.get(c["type"], 0) + 1
    cracked = sum(1 for c in items if c.get("cracked"))
    return render_template("creds.html", creds=items, counts=counts, cracked=cracked,
                           crackable=CRACKABLE, default_wordlist=DEFAULT_WORDLIST)


@creds_bp.route("/creds/import", methods=["POST"])
def creds_import():
    text = (request.get_json(silent=True) or request.form).get("dump", "")
    parsed = parse_dump(text)
    added = add_creds(parsed)
    return jsonify({"parsed": len(parsed), "added": added})


@creds_bp.route("/creds/add", methods=["POST"])
def creds_add():
    p = request.get_json(silent=True) or request.form
    c = _mk(p.get("domain", ""), p.get("username", ""), p.get("type", "password"),
            p.get("value", ""), p.get("source", "manual") or "manual")
    c["notes"] = (p.get("notes") or "").strip()
    return jsonify({"added": add_creds([c])})


@creds_bp.route("/creds/<cid>/delete", methods=["POST"])
def creds_delete(cid):
    delete_cred(cid)
    return jsonify({"ok": True})


@creds_bp.route("/creds/<cid>/promote", methods=["POST"])
def creds_promote(cid):
    return jsonify({"ok": promote(cid)})


@creds_bp.route("/creds/crack", methods=["POST"])
def creds_crack():
    p = request.get_json(silent=True) or {}
    result = build_crack(p.get("type", ""), p.get("wordlist", ""), p.get("rules", ""))
    return jsonify(result), (400 if result.get("error") else 200)


@creds_bp.route("/creds/import-cracked", methods=["POST"])
def creds_import_cracked():
    return jsonify({"updated": import_cracked()})


@creds_bp.route("/creds/data")
def creds_data():
    return jsonify({"creds": load_creds()})
