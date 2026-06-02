"""Loot & Reporting module for ZeroCool.

- Findings: a simple CRUD store (data/findings.json) of issues you record during
  the engagement, with severity.
- Loot: lists files written to the engagement output dir (scan output, hashes,
  screenshots, …) and serves them back (path-validated to the loot dir).
- Report: assembles everything — engagement metadata, scope, findings, parsed
  nmap hosts/services, credentials, and the command log — into a printable HTML
  report and a downloadable Markdown file.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import uuid
from datetime import datetime

from flask import (Blueprint, Response, abort, flash, redirect,
                   render_template, request, send_file, url_for)

import parser as nmap_parser
import runner
import storage

reporting_bp = Blueprint("reporting", __name__)

FINDINGS_FILE = os.path.join(storage.DATA_DIR, "findings.json")
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
STATUSES = ["Open", "Confirmed", "Remediated", "Accepted Risk"]

_lock = threading.Lock()


# --------------------------------------------------------------------------
# findings store
# --------------------------------------------------------------------------

def load_findings() -> list[dict]:
    if not os.path.exists(FINDINGS_FILE):
        return []
    try:
        with open(FINDINGS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_findings(items: list[dict]) -> None:
    os.makedirs(storage.DATA_DIR, exist_ok=True)
    with _lock:
        fd, tmp = tempfile.mkstemp(dir=storage.DATA_DIR, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(items, fh, indent=2)
            os.replace(tmp, FINDINGS_FILE)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)


def add_finding(data: dict) -> dict:
    items = load_findings()
    data["id"] = uuid.uuid4().hex[:8]
    data["created"] = datetime.now().isoformat(timespec="seconds")
    items.append(data)
    save_findings(items)
    return data


def update_finding(fid: str, data: dict) -> bool:
    items = load_findings()
    found = False
    for f in items:
        if f.get("id") == fid:
            f.update(data)  # preserves id/created, overwrites the editable fields
            found = True
            break
    if found:
        save_findings(items)
    return found


def delete_finding(fid: str) -> None:
    save_findings([f for f in load_findings() if f.get("id") != fid])


def _finding_fields(form) -> dict:
    return {
        "severity": form.get("severity", "Info"),
        "status": form.get("status", "Open"),
        "host": (form.get("host") or "").strip(),
        "port": (form.get("port") or "").strip(),
        "description": (form.get("description") or "").strip(),
        "evidence": (form.get("evidence") or "").strip(),
        "recommendation": (form.get("recommendation") or "").strip(),
    }


# --------------------------------------------------------------------------
# finding library + auto-detection
# --------------------------------------------------------------------------

def _t(title, severity, description, recommendation):
    return {"title": title, "severity": severity,
            "description": description, "recommendation": recommendation}

FINDING_TEMPLATES = {
    # --- cleartext / exposed services ---
    "telnet-cleartext": _t("Cleartext Protocol — Telnet", "High",
        "Telnet transmits credentials and session data without encryption, allowing interception of authentication material by an on-path attacker.",
        "Disable Telnet and use SSH for remote administration."),
    "ftp-cleartext": _t("Cleartext Protocol — FTP", "Medium",
        "FTP transmits credentials and file contents in cleartext.",
        "Replace with SFTP/FTPS, or restrict to trusted networks and disable anonymous access."),
    "http-no-tls": _t("Unencrypted Web Service (HTTP)", "Low",
        "A web service is served over plain HTTP. Any credentials or session tokens are exposed to interception.",
        "Serve the application over HTTPS and redirect HTTP to HTTPS with HSTS."),
    "cleartext-mail": _t("Cleartext Mail Protocol", "Medium",
        "A mail service (POP3/IMAP/SMTP) is exposed without enforced TLS, exposing mailbox credentials.",
        "Require STARTTLS/implicit TLS and disable plaintext authentication."),
    "snmp-exposed": _t("SNMP Service Exposed", "Medium",
        "SNMP is reachable and may use default community strings (public/private), disclosing system information.",
        "Restrict SNMP to management networks, use SNMPv3 with auth/priv, and change default community strings."),
    "ldap-cleartext": _t("LDAP Without TLS", "Medium",
        "LDAP is exposed over cleartext (389), allowing interception of directory queries and bind credentials.",
        "Require LDAPS (636) / StartTLS and disable simple binds over cleartext."),
    "smb-exposed": _t("SMB Service Accessible", "Info",
        "SMB file sharing is reachable on the network. Verify signing is enforced and shares are not anonymously accessible.",
        "Enforce SMB signing, disable SMBv1, and review share permissions."),
    "smbv1": _t("SMBv1 Enabled", "High",
        "The legacy SMBv1 protocol is enabled and is vulnerable to multiple exploits (e.g., MS17-010/EternalBlue).",
        "Disable SMBv1 across the estate; use SMBv2/3 only."),
    "rdp-exposed": _t("RDP Service Exposed", "Medium",
        "Remote Desktop is reachable on the network, broadening the attack surface for credential attacks and known RDP CVEs.",
        "Restrict RDP to a jump host/VPN, require NLA, and enforce MFA."),
    "vnc-exposed": _t("VNC Service Exposed", "High",
        "A VNC service is exposed; VNC often lacks strong authentication and may permit unauthenticated access.",
        "Restrict VNC to management networks, require strong auth, and tunnel over SSH/VPN."),
    "x11-exposed": _t("X11 Service Exposed", "High",
        "An open X11 server can allow keystroke capture and screen access from the network.",
        "Disable X11 TCP listening (-nolisten tcp) and use SSH X11 forwarding."),
    "db-exposed": _t("Database Service Network-Exposed", "High",
        "A database service is reachable from the network, exposing it to brute-force and known database CVEs.",
        "Bind databases to localhost or restrict via firewall; require strong authentication."),
    "redis-noauth": _t("Redis Exposed (Likely No Auth)", "High",
        "Redis is exposed and by default requires no authentication, allowing data access and often RCE.",
        "Enable 'requirepass', bind to localhost, and firewall the port."),
    "mongodb-noauth": _t("MongoDB Exposed (Likely No Auth)", "High",
        "MongoDB is exposed and may permit unauthenticated access to all databases.",
        "Enable authentication, bind to localhost, and restrict network access."),
    "rpcbind-nfs": _t("RPCbind / NFS Exposed", "Medium",
        "RPCbind/NFS is reachable; misconfigured exports (no_root_squash) can lead to privilege escalation.",
        "Restrict NFS to trusted hosts, review /etc/exports, and avoid no_root_squash."),
    "dns-exposed": _t("DNS Server Exposed", "Low",
        "A DNS server is reachable; test for zone transfers and open-resolver behaviour.",
        "Restrict zone transfers to authorised secondaries and disable open recursion."),
    "rservices": _t("Berkeley r-services Enabled", "High",
        "rsh/rlogin/rexec transmit credentials in cleartext and historically permit trust-based bypass.",
        "Disable r-services entirely and use SSH."),
    "ipmi-exposed": _t("IPMI / BMC Exposed", "Medium",
        "IPMI is reachable and is affected by authentication-bypass and hash-disclosure issues.",
        "Restrict BMC interfaces to an isolated management VLAN and patch firmware."),
    # --- version-based ---
    "vsftpd-backdoor": _t("vsftpd 2.3.4 Backdoor", "Critical",
        "vsftpd 2.3.4 contains a well-known backdoor that yields a root shell.",
        "Upgrade vsftpd immediately and investigate for compromise."),
    "outdated-iis": _t("Outdated Microsoft IIS", "Medium",
        "An end-of-life IIS version is in use, exposing the host to numerous unpatched vulnerabilities.",
        "Upgrade to a supported Windows Server / IIS release."),
    "outdated-apache": _t("Outdated Apache httpd", "Medium",
        "An outdated Apache httpd branch is in use and likely missing security fixes.",
        "Upgrade to a current, supported Apache release."),
    # --- library-only (not auto-detected) ---
    "ftp-anonymous": _t("Anonymous FTP Access", "High",
        "The FTP server permits anonymous login, exposing files without authentication.",
        "Disable anonymous access or restrict it to a dedicated, read-only directory."),
    "smb-signing": _t("SMB Signing Not Required", "Medium",
        "SMB signing is not enforced, enabling NTLM relay attacks.",
        "Require SMB signing on servers and clients via GPO."),
    "default-creds": _t("Default Credentials", "High",
        "A service accepts vendor-default credentials, granting unauthorised access.",
        "Change all default credentials and enforce a strong password policy."),
    "weak-tls": _t("Weak TLS Configuration", "Medium",
        "The service supports deprecated protocols/ciphers (SSLv3/TLS1.0, RC4, weak DH).",
        "Disable legacy protocols and weak ciphers; prefer TLS 1.2+ with modern ciphers."),
    "missing-sec-headers": _t("Missing HTTP Security Headers", "Low",
        "Responses lack headers such as HSTS, CSP, X-Content-Type-Options and X-Frame-Options.",
        "Add the recommended security headers to all HTTP responses."),
    "dir-listing": _t("Directory Listing Enabled", "Medium",
        "The web server returns directory indexes, disclosing file and structure information.",
        "Disable automatic directory indexing."),
    "asrep-roast": _t("AS-REP Roastable Accounts", "High",
        "Accounts with Kerberos pre-authentication disabled allow offline cracking of AS-REP responses.",
        "Enable Kerberos pre-authentication for all accounts and enforce strong passwords."),
    "kerberoast": _t("Kerberoastable Service Accounts", "High",
        "Service accounts with SPNs allow request of crackable service tickets.",
        "Use group Managed Service Accounts (gMSA) or long random passwords; limit SPNs."),
    "llmnr-poison": _t("LLMNR / NBT-NS Poisoning", "High",
        "LLMNR/NBT-NS broadcast resolution permits credential interception and relay.",
        "Disable LLMNR and NBT-NS via GPO; enable SMB signing."),
    "weak-pass-policy": _t("Weak Password Policy", "Medium",
        "The domain/host password policy permits short or non-complex passwords.",
        "Enforce length >= 14, complexity, lockout thresholds, and screen against breached passwords."),
    # --- NSE-confirmable ---
    "ms17-010": _t("MS17-010 (EternalBlue)", "Critical",
        "The host is vulnerable to MS17-010, permitting unauthenticated remote code execution over SMB.",
        "Apply MS17-010 patches immediately and disable SMBv1."),
    "ssl-heartbleed": _t("OpenSSL Heartbleed (CVE-2014-0160)", "High",
        "The TLS service is vulnerable to Heartbleed, leaking memory contents including keys and credentials.",
        "Upgrade OpenSSL and rotate any potentially exposed keys/credentials."),
    "ssl-poodle": _t("SSLv3 POODLE (CVE-2014-3566)", "Medium",
        "The service supports SSLv3 and is vulnerable to the POODLE padding-oracle attack.",
        "Disable SSLv3 entirely."),
    "db-empty-pass": _t("Database Account With Empty Password", "High",
        "A database account (e.g. root/sa) has no password, granting unauthenticated administrative access.",
        "Set strong passwords on all database accounts and restrict network access."),
    "nfs-export": _t("Exposed NFS Exports", "Medium",
        "NFS exports are accessible from the network and may permit file access or privilege escalation.",
        "Restrict exports to trusted hosts, use Kerberos/root_squash, and avoid no_root_squash."),
    "dns-open-resolver": _t("Open DNS Resolver", "Medium",
        "The DNS server performs recursion for arbitrary clients and can be abused for amplification DDoS.",
        "Disable recursion for external clients or restrict it to internal networks."),
    "smb-anon-shares": _t("Anonymous SMB Share Access", "High",
        "SMB shares are readable without authentication, potentially disclosing sensitive files.",
        "Remove anonymous/guest access and review share permissions."),
}

# port -> template key
PORT_RULES = {
    21: "ftp-cleartext", 23: "telnet-cleartext", 110: "cleartext-mail", 143: "cleartext-mail",
    161: "snmp-exposed", 389: "ldap-cleartext", 445: "smb-exposed", 139: "smb-exposed",
    3389: "rdp-exposed", 5900: "vnc-exposed", 5901: "vnc-exposed", 6000: "x11-exposed",
    1433: "db-exposed", 3306: "db-exposed", 5432: "db-exposed", 27017: "mongodb-noauth",
    6379: "redis-noauth", 111: "rpcbind-nfs", 2049: "rpcbind-nfs", 53: "dns-exposed",
    512: "rservices", 513: "rservices", 514: "rservices", 623: "ipmi-exposed",
}
# service-name substring -> template key
SERVICE_RULES = {
    "telnet": "telnet-cleartext", "ftp": "ftp-cleartext", "vnc": "vnc-exposed",
    "snmp": "snmp-exposed", "ms-sql": "db-exposed", "mysql": "db-exposed",
    "postgres": "db-exposed", "mongodb": "mongodb-noauth", "redis": "redis-noauth",
    "ms-wbt-server": "rdp-exposed", "x11": "x11-exposed",
}
# product/version substring -> template key (matches both nmap product+version
# like "Apache httpd 2.2.8" and banner-style like "Apache/2.2").
VERSION_RULES = {
    "vsftpd 2.3.4": "vsftpd-backdoor",
    "apache/2.2": "outdated-apache", "apache httpd 2.2": "outdated-apache",
    "apache/2.0": "outdated-apache", "apache httpd 2.0": "outdated-apache",
    "microsoft-iis/6": "outdated-iis", "iis httpd 6": "outdated-iis",
    "microsoft-iis/5": "outdated-iis", "iis httpd 5": "outdated-iis",
}


def detect_candidates(hosts: list[dict]) -> list[dict]:
    """Map parsed nmap hosts/services to candidate findings."""
    cands = []
    seen = set()

    def emit(key, ip, port):
        tpl = FINDING_TEMPLATES.get(key)
        if not tpl:
            return
        sig = (key, ip, str(port))
        if sig in seen:
            return
        seen.add(sig)
        cands.append({"key": key, "title": tpl["title"], "severity": tpl["severity"],
                      "description": tpl["description"], "recommendation": tpl["recommendation"],
                      "host": ip, "port": str(port), "confirmed": False,
                      "status": "Open", "evidence": ""})

    for h in hosts:
        ip = h.get("ip", "")
        for p in h.get("ports", []):
            port = p.get("port", 0)
            svc = (p.get("service") or "").lower()
            prod = ((p.get("product") or "") + " " + (p.get("version") or "")).lower()
            if port in PORT_RULES:
                emit(PORT_RULES[port], ip, port)
            for name, key in SERVICE_RULES.items():
                if name in svc:
                    emit(key, ip, port)
            for sub, key in VERSION_RULES.items():
                if sub in prod:
                    emit(key, ip, port)
            if "http" in svc and port not in (443, 8443):
                emit("http-no-tls", ip, port)
    cands.sort(key=lambda c: SEV_ORDER.get(c["severity"], 99))
    return cands


# NSE script id (or prefix) -> rule. `any`/`all` are output substring checks
# (case-insensitive); omit both to match on the script merely being present.
NSE_RULES = [
    {"script": "smb2-security-mode", "any": ["not required"], "key": "smb-signing"},
    {"script": "smb-security-mode", "any": ["not required", "disabled"], "key": "smb-signing"},
    {"script": "smb-vuln-ms17-010", "any": ["vulnerable"], "key": "ms17-010"},
    {"script": "smb-enum-shares", "any": ["access: read", "anonymous"], "key": "smb-anon-shares"},
    {"script": "ftp-anon", "any": ["allowed", "login allowed"], "key": "ftp-anonymous"},
    {"script": "ssl-enum-ciphers", "any": ["sslv3", "tlsv1.0", "rc4", "broken", "weak", " e "], "key": "weak-tls"},
    {"script": "ssl-heartbleed", "any": ["vulnerable"], "key": "ssl-heartbleed"},
    {"script": "ssl-poodle", "any": ["vulnerable"], "key": "ssl-poodle"},
    {"script": "mysql-empty-password", "any": ["account", "empty"], "key": "db-empty-pass"},
    {"script": "ms-sql-empty-password", "any": [""], "key": "db-empty-pass"},
    {"script": "nfs-showmount", "key": "nfs-export"},
    {"script": "dns-recursion", "any": ["enabled"], "key": "dns-open-resolver"},
    {"script": "http-default-accounts", "any": ["found", "valid"], "key": "default-creds"},
    {"script": "snmp-brute", "any": ["valid credentials"], "key": "snmp-exposed"},
]


def _iter_scripts(hosts):
    for h in hosts:
        ip = h.get("ip", "")
        for s in h.get("scripts", []):       # host-level
            yield ip, "", s
        for p in h.get("ports", []):         # port-level
            for s in p.get("scripts", []):
                yield ip, str(p.get("port", "")), s


def detect_nse(hosts: list[dict]) -> list[dict]:
    """Turn NSE script *output* into confirmed findings (with evidence)."""
    out = []
    seen = set()
    for ip, port, s in _iter_scripts(hosts):
        sid = (s.get("id") or "")
        text = (s.get("output") or "").lower()
        for rule in NSE_RULES:
            if not (sid == rule["script"] or sid.startswith(rule["script"])):
                continue
            if "any" in rule and not any((x.lower() in text) for x in rule["any"]):
                continue
            if "all" in rule and not all((x.lower() in text) for x in rule["all"]):
                continue
            tpl = FINDING_TEMPLATES.get(rule["key"])
            if not tpl:
                continue
            sig = (rule["key"], ip, port)
            if sig in seen:
                continue
            seen.add(sig)
            out.append({"key": rule["key"], "title": tpl["title"],
                        "severity": rule.get("severity", tpl["severity"]),
                        "description": tpl["description"], "recommendation": tpl["recommendation"],
                        "host": ip, "port": port, "confirmed": True, "status": "Confirmed",
                        "evidence": (s.get("output") or "").strip()[:2000]})
            break
    out.sort(key=lambda c: SEV_ORDER.get(c["severity"], 99))
    return out


# --------------------------------------------------------------------------
# loot / activity helpers
# --------------------------------------------------------------------------

def _hsize(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def loot_files(loot: str, limit: int = 1000) -> list[dict]:
    files = []
    if loot and os.path.isdir(loot):
        for root, _dirs, fnames in os.walk(loot):
            for fn in fnames:
                full = os.path.join(root, fn)
                try:
                    size = os.path.getsize(full)
                except OSError:
                    size = 0
                files.append({"path": full, "rel": os.path.relpath(full, loot),
                              "size": size, "hsize": _hsize(size)})
                if len(files) >= limit:
                    return sorted(files, key=lambda x: x["rel"])
    return sorted(files, key=lambda x: x["rel"])


def load_activity(limit: int = 1000) -> list[dict]:
    out = []
    path = runner.ACTIVITY_LOG
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            out.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass
    return out[-limit:]


# --------------------------------------------------------------------------
# report assembly
# --------------------------------------------------------------------------

def report_context() -> dict:
    eng = storage.load_engagement()
    findings = sorted(load_findings(), key=lambda f: SEV_ORDER.get(f.get("severity"), 99))
    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEVERITIES}

    hosts = []
    loot = (eng.get("output_dir") or "").strip()
    files = nmap_parser.find_scan_files(loot) if loot else []
    if files:
        hosts = nmap_parser.aggregate(files)["hosts"]

    return {
        "eng": eng,
        "findings": findings,
        "counts": counts,
        "hosts": hosts,
        "commands": load_activity(),
        "date": datetime.now().strftime("%Y-%m-%d"),
        "severities": SEVERITIES,
    }


def build_markdown(ctx: dict) -> str:
    eng = ctx["eng"]
    L: list[str] = []
    L.append(f"# {eng.get('engagement_name') or 'Engagement'} — Penetration Test Report")
    L.append("")
    if eng.get("client"):
        L.append(f"**Client:** {eng['client']}  ")
    L.append(f"**Date:** {ctx['date']}  ")
    if eng.get("domain"):
        L.append(f"**Domain:** {eng['domain']}  ")
    L.append("")

    L.append("## Scope")
    for s in eng.get("scope", []) or ["_none defined_"]:
        L.append(f"- {s}")
    if eng.get("out_of_scope"):
        L.append("")
        L.append("**Out of scope:**")
        for s in eng["out_of_scope"]:
            L.append(f"- {s}")
    L.append("")

    L.append("## Summary of Findings")
    L.append("")
    L.append("| Severity | Count |")
    L.append("|---|---|")
    for sev in ctx["severities"]:
        L.append(f"| {sev} | {ctx['counts'][sev]} |")
    L.append("")

    L.append("## Findings")
    L.append("")
    if not ctx["findings"]:
        L.append("_No findings recorded._")
    for i, f in enumerate(ctx["findings"], 1):
        L.append(f"### {i}. [{f.get('severity', '?')}] {f.get('title', 'Untitled')}")
        affected = f.get("host", "")
        if affected and f.get("port"):
            affected += f":{f['port']}"
        if affected:
            L.append(f"**Affected:** {affected}  ")
        if f.get("status"):
            L.append(f"**Status:** {f['status']}  ")
        L.append("")
        if f.get("description"):
            L.append("**Description**")
            L.append("")
            L.append(f["description"])
            L.append("")
        if f.get("evidence"):
            L.append("**Evidence**")
            L.append("")
            L.append("```")
            L.append(f["evidence"])
            L.append("```")
            L.append("")
        if f.get("recommendation"):
            L.append("**Recommendation**")
            L.append("")
            L.append(f["recommendation"])
            L.append("")

    if ctx["hosts"]:
        L.append("## Hosts & Services")
        L.append("")
        for h in ctx["hosts"]:
            ports = ", ".join(
                (f"{p['port']}/{p['proto']} {p['service']}".strip()) for p in h["ports"])
            names = f" ({', '.join(h['hostnames'])})" if h["hostnames"] else ""
            L.append(f"- **{h['ip']}**{names} — {ports or 'no open ports'}")
        L.append("")

    if eng.get("credentials"):
        L.append("## Credentials")
        L.append("")
        for c in eng["credentials"]:
            secret = c.get("password") or (f"NT:{c['ntlm_hash']}" if c.get("ntlm_hash") else "")
            note = f" ({c['notes']})" if c.get("notes") else ""
            L.append(f"- `{c.get('domain', '')}\\{c.get('username', '')} : {secret}`{note}")
        L.append("")

    if ctx["commands"]:
        L.append("## Appendix: Command Log")
        L.append("")
        for c in ctx["commands"]:
            L.append(f"- `{c.get('command', '')}` — {c.get('status', '')} "
                     f"(exit {c.get('exit_code')})")
        L.append("")

    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------

def _detect_from_scans(eng):
    loot_dir = (eng.get("output_dir") or "").strip()
    files = nmap_parser.find_scan_files(loot_dir) if loot_dir else []
    hosts = nmap_parser.aggregate(files)["hosts"] if files else []
    nse = detect_nse(hosts)                 # confirmed (with evidence)
    seen = {(c["key"], c["host"], c["port"]) for c in nse}
    leads = [c for c in detect_candidates(hosts)
             if (c["key"], c["host"], c["port"]) not in seen]
    return nse + leads                       # confirmed first, then leads


@reporting_bp.route("/loot")
def loot():
    eng = storage.load_engagement()
    findings = sorted(load_findings(), key=lambda f: SEV_ORDER.get(f.get("severity"), 99))
    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEVERITIES}
    loot_dir = (eng.get("output_dir") or "").strip()

    # Auto-detected candidates, minus anything already recorded.
    existing = {(f.get("title"), f.get("host"), str(f.get("port", ""))) for f in findings}
    candidates = [c for c in _detect_from_scans(eng)
                  if (c["title"], c["host"], c["port"]) not in existing]

    # Library templates as a sorted list for quick-add.
    library = sorted(
        ({"key": k, **v} for k, v in FINDING_TEMPLATES.items()),
        key=lambda t: (SEV_ORDER.get(t["severity"], 99), t["title"]))

    return render_template("loot.html", eng=eng, findings=findings, counts=counts,
                           severities=SEVERITIES, statuses=STATUSES,
                           files=loot_files(loot_dir), loot_dir=loot_dir,
                           command_count=len(load_activity()),
                           candidates=candidates, library=library)


@reporting_bp.route("/loot/detect-all", methods=["POST"])
def loot_detect_all():
    eng = storage.load_engagement()
    existing = {(f.get("title"), f.get("host"), str(f.get("port", ""))) for f in load_findings()}
    added = 0
    for c in _detect_from_scans(eng):
        sig = (c["title"], c["host"], c["port"])
        if sig in existing:
            continue
        add_finding({"title": c["title"], "severity": c["severity"],
                     "status": c.get("status", "Open"),
                     "host": c["host"], "port": c["port"], "description": c["description"],
                     "evidence": c.get("evidence", ""), "recommendation": c["recommendation"]})
        existing.add(sig)
        added += 1
    flash(f"Added {added} detected finding(s).", "success")
    return redirect(url_for("reporting.loot"))


@reporting_bp.route("/loot/finding", methods=["POST"])
def loot_finding_add():
    title = (request.form.get("title") or "").strip()
    if not title:
        flash("Finding needs a title.", "error")
        return redirect(url_for("reporting.loot"))
    add_finding({"title": title, **_finding_fields(request.form)})
    flash("Finding added.", "success")
    return redirect(url_for("reporting.loot"))


@reporting_bp.route("/loot/finding/<fid>/edit", methods=["POST"])
def loot_finding_edit(fid):
    title = (request.form.get("title") or "").strip()
    if not title:
        flash("Finding needs a title.", "error")
        return redirect(url_for("reporting.loot"))
    ok = update_finding(fid, {"title": title, **_finding_fields(request.form)})
    flash("Finding updated." if ok else "Finding not found.", "success" if ok else "error")
    return redirect(url_for("reporting.loot"))


@reporting_bp.route("/loot/finding/<fid>/delete", methods=["POST"])
def loot_finding_delete(fid):
    delete_finding(fid)
    flash("Finding deleted.", "success")
    return redirect(url_for("reporting.loot"))


@reporting_bp.route("/loot/file")
def loot_file():
    eng = storage.load_engagement()
    loot_dir = (eng.get("output_dir") or "").strip()
    req = request.args.get("path", "")
    if not loot_dir or not req:
        abort(404)
    real_loot = os.path.realpath(loot_dir)
    real = os.path.realpath(req)
    if not (real == real_loot or real.startswith(real_loot + os.sep)) or not os.path.isfile(real):
        abort(403)
    return send_file(real, as_attachment=bool(request.args.get("dl")))


@reporting_bp.route("/report")
def report():
    return render_template("report.html", **report_context())


@reporting_bp.route("/report.md")
def report_md():
    md = build_markdown(report_context())
    eng = storage.load_engagement()
    name = (eng.get("engagement_name") or "zerocool").replace(" ", "_")
    return Response(md, mimetype="text/markdown",
                    headers={"Content-Disposition": f"attachment; filename={name}_report.md"})
