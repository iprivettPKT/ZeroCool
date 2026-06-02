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

import base64
import json
import os
import re
import tempfile
import threading
import uuid
from datetime import datetime

from flask import (Blueprint, Response, abort, flash, jsonify, redirect,
                   render_template, request, send_file, url_for)

import parser as nmap_parser
import runner
import storage

reporting_bp = Blueprint("reporting", __name__)

FINDINGS_FILE = os.path.join(storage.DATA_DIR, "findings.json")
EVIDENCE_DIR = os.path.join(storage.DATA_DIR, "findings_evidence")
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

    # --- web application ---
    "sqli": _t("SQL Injection", "Critical",
        "User input is incorporated into SQL queries without parameterisation, allowing an attacker to read/modify the database and potentially achieve code execution.",
        "Use parameterised queries / prepared statements, validate input, and apply least-privilege DB accounts."),
    "cmd-injection": _t("OS Command Injection", "Critical",
        "User input is passed to a system shell, allowing arbitrary command execution on the server.",
        "Avoid shelling out with user input; use safe APIs, allow-lists, and strict input validation."),
    "rfi": _t("Remote File Inclusion", "Critical",
        "The application includes remote files based on user input, enabling remote code execution.",
        "Disable remote includes (allow_url_include=Off) and use a strict allow-list of local resources."),
    "insecure-deser": _t("Insecure Deserialization", "High",
        "Untrusted data is deserialised, which can lead to remote code execution or object injection.",
        "Avoid native deserialisation of untrusted input; use signed, schema-validated formats."),
    "ssrf": _t("Server-Side Request Forgery (SSRF)", "High",
        "The server can be coerced into making requests to arbitrary URLs, reaching internal services and cloud metadata.",
        "Allow-list outbound destinations, block link-local/internal ranges, and disable unused URL schemes."),
    "xxe": _t("XML External Entity (XXE) Injection", "High",
        "The XML parser resolves external entities, enabling file disclosure, SSRF and DoS.",
        "Disable external entity and DTD processing in the XML parser."),
    "idor": _t("Insecure Direct Object Reference (IDOR)", "High",
        "Object identifiers can be manipulated to access other users' data without authorisation.",
        "Enforce object-level authorisation on every request; use unpredictable identifiers."),
    "lfi": _t("Local File Inclusion / Path Traversal", "High",
        "User input reaches file paths, allowing disclosure of arbitrary files (and sometimes RCE).",
        "Canonicalise and validate paths against an allow-list; never use raw user input in file operations."),
    "file-upload": _t("Unrestricted File Upload", "High",
        "Arbitrary file types can be uploaded and executed, leading to remote code execution.",
        "Validate type/extension/content, store outside the web root, and disable execution in the upload dir."),
    "xss-stored": _t("Stored Cross-Site Scripting (XSS)", "High",
        "Attacker-supplied script is persisted and executed in other users' browsers.",
        "Context-aware output encoding, input validation, and a strong Content-Security-Policy."),
    "xss-reflected": _t("Reflected Cross-Site Scripting (XSS)", "Medium",
        "Unsanitised input is reflected into responses and executed in the victim's browser.",
        "Context-aware output encoding and a Content-Security-Policy."),
    "csrf": _t("Cross-Site Request Forgery (CSRF)", "Medium",
        "State-changing requests lack anti-CSRF protection and can be forged from another site.",
        "Use anti-CSRF tokens and SameSite cookies."),
    "cors-misconfig": _t("CORS Misconfiguration", "Medium",
        "An overly permissive CORS policy (e.g. reflecting Origin with credentials) exposes data cross-origin.",
        "Restrict Access-Control-Allow-Origin to trusted origins; never combine wildcard with credentials."),
    "weak-jwt": _t("Weak JWT Implementation", "High",
        "JWTs accept weak/none algorithms or use a guessable secret, allowing token forgery.",
        "Enforce a strong algorithm, reject 'none', and use a high-entropy signing key."),
    "open-redirect": _t("Open Redirect", "Low",
        "The application redirects to attacker-controlled URLs, aiding phishing.",
        "Validate redirect targets against an allow-list of internal paths."),
    "exposed-git": _t("Exposed .git Directory", "Medium",
        "The version-control directory is web-accessible, disclosing source code and secrets.",
        "Block access to .git/ and remove it from the web root."),
    "exposed-env": _t("Exposed Configuration / .env File", "High",
        "Configuration files containing secrets are web-accessible.",
        "Move secrets out of the web root and deny access to config files."),
    "backup-files": _t("Exposed Backup / Source Files", "Medium",
        "Backup or source files (.bak, .old, .zip) are downloadable, disclosing code and credentials.",
        "Remove backup artefacts from the web root and block their extensions."),
    "admin-panel": _t("Exposed Administrative Interface", "Medium",
        "An admin/management interface is reachable from untrusted networks.",
        "Restrict admin interfaces by network/VPN and enforce strong auth + MFA."),
    "verbose-errors": _t("Verbose Error Messages / Stack Traces", "Low",
        "Detailed errors disclose stack traces, paths and technology details aiding further attacks.",
        "Return generic errors to users and log details server-side."),
    "http-methods": _t("Dangerous HTTP Methods Enabled", "Low",
        "Methods such as PUT/DELETE/TRACE are enabled and may allow file upload or XST.",
        "Disable unused HTTP methods at the server."),
    "outdated-components": _t("Outdated / Vulnerable Components", "Medium",
        "Out-of-date frameworks, libraries or CMS plugins with known vulnerabilities are in use.",
        "Patch and maintain an inventory of components; subscribe to vulnerability feeds."),
    "clickjacking": _t("Clickjacking (No Frame Protection)", "Low",
        "Responses lack X-Frame-Options/CSP frame-ancestors and can be framed for UI-redress attacks.",
        "Set X-Frame-Options: DENY or CSP frame-ancestors 'none'."),

    # --- AD / Windows ---
    "unconstrained-deleg": _t("Unconstrained Delegation", "High",
        "A host/account with unconstrained delegation can capture and reuse TGTs of any authenticating user, including DCs.",
        "Remove unconstrained delegation; use constrained or RBCD, and mark sensitive accounts non-delegable."),
    "rbcd-abuse": _t("Resource-Based Constrained Delegation Abuse", "High",
        "Write access to a computer's msDS-AllowedToActOnBehalfOfOtherIdentity allows impersonation to that host.",
        "Restrict write access to computer objects and audit delegation settings."),
    "esc1": _t("ADCS ESC1 — Misconfigured Certificate Template", "Critical",
        "A certificate template allows requesters to specify the subject (SAN), enabling impersonation of any user incl. domain admins.",
        "Remove ENROLLEE_SUPPLIES_SUBJECT, require manager approval, and restrict enrolment rights."),
    "dcsync-rights": _t("Excessive DCSync Rights", "High",
        "A non-tier-0 principal holds replication rights (DS-Replication-Get-Changes-All), allowing extraction of all domain hashes.",
        "Remove replication rights from non-DC accounts and monitor DCSync activity."),
    "dangerous-acl": _t("Dangerous ACL (GenericAll / WriteDACL)", "High",
        "A low-privileged principal has powerful rights over a privileged object, enabling takeover.",
        "Review and tighten ACLs on privileged users, groups and OUs."),
    "password-in-desc": _t("Password in AD Object Description", "Medium",
        "Credentials are stored in the description/notes of AD objects, readable by any authenticated user.",
        "Remove secrets from object attributes and rotate the exposed credentials."),
    "laps-not-deployed": _t("LAPS Not Deployed", "Medium",
        "Local administrator passwords are not randomised/managed, enabling lateral movement via shared passwords.",
        "Deploy Windows LAPS to randomise and rotate local admin passwords."),
    "null-session": _t("SMB Null Session", "Medium",
        "The host permits anonymous (null) SMB sessions, disclosing users, shares and policy information.",
        "Restrict anonymous access (RestrictAnonymous/RestrictAnonymousSAM)."),
    "anon-ldap": _t("Anonymous LDAP Bind", "Medium",
        "The directory permits anonymous binds, disclosing directory information.",
        "Disable anonymous LDAP binds."),

    # --- cloud ---
    "public-bucket": _t("Publicly Accessible Cloud Storage", "High",
        "A storage bucket/container is readable (or writable) by anyone, exposing or allowing tampering of data.",
        "Set the bucket private, enable public-access blocks, and review object ACLs/policies."),
    "permissive-iam": _t("Overly Permissive IAM Policy", "High",
        "An identity has excessive permissions (e.g. wildcard actions/resources), enabling privilege escalation.",
        "Apply least privilege, scope actions/resources, and review policies regularly."),
    "exposed-metadata": _t("Cloud Metadata Endpoint Exposure", "High",
        "The instance metadata service is reachable (often via SSRF), exposing temporary cloud credentials.",
        "Enforce IMDSv2 / metadata hardening and block SSRF paths to 169.254.169.254."),
    "no-mfa": _t("MFA Not Enforced", "Medium",
        "Privileged or all accounts can authenticate without multi-factor authentication.",
        "Enforce MFA for all users, especially privileged and break-glass accounts."),
    "public-snapshot": _t("Public Disk Snapshot / Image", "High",
        "A disk snapshot or machine image is shared publicly, potentially exposing data and secrets.",
        "Make snapshots/images private and audit sharing settings."),

    # --- general ---
    "weak-password": _t("Weak / Guessable Passwords", "High",
        "Accounts use weak, default or easily guessable passwords, cracked offline or via spraying.",
        "Enforce a strong password policy, screen against breached passwords, and use MFA."),
    "password-reuse": _t("Password Reuse Across Accounts", "Medium",
        "The same password is used across multiple accounts/systems, amplifying the impact of a single compromise.",
        "Use unique passwords per account and a password manager; monitor for reuse."),
    "hardcoded-creds": _t("Hardcoded Credentials", "High",
        "Credentials or API keys are embedded in source code, scripts or config under version control.",
        "Remove secrets from code, rotate them, and use a secrets manager."),
    "no-lockout": _t("No Account Lockout Policy", "Medium",
        "Authentication has no lockout/throttling, enabling unlimited brute-force / password spraying.",
        "Implement lockout thresholds and rate-limiting / progressive delays."),
    "info-disclosure": _t("Sensitive Information Disclosure", "Medium",
        "The application or service discloses sensitive information (PII, internal details, secrets).",
        "Remove sensitive data from responses and restrict access on a need-to-know basis."),
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
        if f.get("evidence_image"):
            L.append(f"**Evidence (screenshot):** `data/findings_evidence/{f['evidence_image']}`")
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


@reporting_bp.route("/loot/finding/screenshot", methods=["POST"])
def loot_finding_screenshot():
    """Create a finding from a captured terminal screenshot (a PNG data URL)."""
    payload = request.get_json(silent=True) or {}
    title = (payload.get("title") or "").strip()
    if not title:
        return jsonify({"error": "title required"}), 400

    image_name = None
    data_url = payload.get("image", "")
    if isinstance(data_url, str) and data_url.startswith("data:image/png;base64,"):
        try:
            raw = base64.b64decode(data_url.split(",", 1)[1])
            os.makedirs(EVIDENCE_DIR, exist_ok=True)
            image_name = uuid.uuid4().hex[:12] + ".png"
            with open(os.path.join(EVIDENCE_DIR, image_name), "wb") as fh:
                fh.write(raw)
        except (ValueError, OSError):
            image_name = None

    f = add_finding({
        "title": title,
        "severity": payload.get("severity", "Info"),
        "status": payload.get("status", "Open"),
        "host": (payload.get("host") or "").strip(),
        "port": (payload.get("port") or "").strip(),
        "description": (payload.get("description") or "").strip(),
        "evidence": (payload.get("evidence") or "").strip(),
        "recommendation": (payload.get("recommendation") or "").strip(),
        "evidence_image": image_name,
    })
    return jsonify({"ok": True, "id": f["id"], "image": image_name})


@reporting_bp.route("/loot/evidence/<name>")
def loot_evidence(name):
    """Serve a screenshot evidence image (filename only, no traversal)."""
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.png", name or ""):
        abort(404)
    path = os.path.join(EVIDENCE_DIR, name)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)


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
