"""Web module for ZeroCool.

A data-driven catalog of web-app testing commands (ffuf, feroxbuster, gobuster,
whatweb, nuclei, nikto, wpscan, sqlmap, gowitness, …) built from the engagement
target plus a URL / wordlist / threads bar. Same pattern as the AD module:
read context -> build command -> stream through the runner (and optionally
prefix proxychains, or send into a caught shell).
"""

from __future__ import annotations

import os
import shlex

from flask import Blueprint, jsonify, render_template, request

import storage
import tools

web_bp = Blueprint("web", __name__)

DIR_WL = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
SUB_WL = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
PARAM_WL = "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"


def _q(v: str) -> str:
    return shlex.quote(v) if v else ""


def cmd(*parts: str) -> str:
    return " ".join(p for p in parts if p)


def pv(ctx: dict, name: str, default: str = "") -> str:
    return (ctx["p"].get(name) or "").strip() or default


def loot(ctx: dict, name: str) -> str:
    return os.path.join(ctx["loot"], name) if ctx["loot"] else ""


def build_context(params: dict, eng: dict) -> dict:
    targets = eng.get("targets") or []
    default_url = ""
    if targets:
        t = targets[0]
        default_url = t if t.startswith("http") else "http://" + t
    url = (params.get("url") or "").strip() or default_url
    return {
        "url": url.rstrip("/"),
        "wordlist": (params.get("wordlist") or "").strip() or DIR_WL,
        "threads": (params.get("threads") or "40").strip(),
        "domain": (eng.get("domain") or "").strip(),
        "loot": (eng.get("output_dir") or "").strip(),
        "proxychains": str(params.get("proxychains", "")).lower() in ("1", "true", "on", "yes"),
        "p": params,
    }


def _outflag(ctx, flag, name):
    f = loot(ctx, name)
    return f"{flag} {_q(f)}" if f else ""


# --- Fingerprint ---
def b_whatweb(ctx): return cmd("whatweb -a3", _q(ctx["url"]))
def b_headers(ctx): return cmd("curl -sSIL", _q(ctx["url"]))
def b_wafw00f(ctx): return cmd("wafw00f", _q(ctx["url"]))
def b_nuclei_tech(ctx): return cmd("nuclei -u", _q(ctx["url"]), "-tags tech,tech-detect -silent")


# --- Content discovery ---
def b_ffuf(ctx):
    ext = pv(ctx, "ext", "")
    return cmd("ffuf -u", _q(ctx["url"] + "/FUZZ"), "-w", _q(ctx["wordlist"]),
               "-t", ctx["threads"], ("-e " + ext) if ext else "",
               "-mc 200,204,301,302,307,401,403,405 -ac",
               _outflag(ctx, "-o", "ffuf.json"), pv(ctx, "extra", ""))

def b_ferox(ctx):
    ext = pv(ctx, "ext", "")
    return cmd("feroxbuster -u", _q(ctx["url"]), "-w", _q(ctx["wordlist"]),
               "-t", ctx["threads"], ("-x " + ext) if ext else "",
               _outflag(ctx, "-o", "feroxbuster.txt"))

def b_gobuster(ctx):
    ext = pv(ctx, "ext", "")
    return cmd("gobuster dir -u", _q(ctx["url"]), "-w", _q(ctx["wordlist"]),
               "-t", ctx["threads"], ("-x " + ext) if ext else "",
               _outflag(ctx, "-o", "gobuster.txt"))

def b_dirsearch(ctx):
    ext = pv(ctx, "ext", "")
    return cmd("dirsearch -u", _q(ctx["url"]), "-w", _q(ctx["wordlist"]),
               ("-e " + ext) if ext else "-e php,html,txt")


# --- Vhost / subdomain ---
def b_ffuf_vhost(ctx):
    dom = pv(ctx, "vhost_domain", ctx["domain"] or "target.tld")
    return cmd("ffuf -u", _q(ctx["url"]), "-H", _q(f"Host: FUZZ.{dom}"),
               "-w", _q(pv(ctx, "wordlist2", SUB_WL)),
               ("-fs " + pv(ctx, "fs", "")) if pv(ctx, "fs") else "-ac")

def b_gobuster_vhost(ctx):
    return cmd("gobuster vhost -u", _q(ctx["url"]),
               "-w", _q(pv(ctx, "wordlist2", SUB_WL)), "--append-domain")

def b_gobuster_dns(ctx):
    return cmd("gobuster dns -d", _q(pv(ctx, "vhost_domain", ctx["domain"] or "target.tld")),
               "-w", _q(pv(ctx, "wordlist2", SUB_WL)))


# --- Parameters ---
def b_ffuf_param(ctx):
    return cmd("ffuf -u", _q(ctx["url"] + "?FUZZ=1"),
               "-w", _q(pv(ctx, "wordlist2", PARAM_WL)),
               ("-fs " + pv(ctx, "fs", "")) if pv(ctx, "fs") else "-ac")

def b_arjun(ctx): return cmd("arjun -u", _q(ctx["url"]))


# --- Vuln scanning ---
def b_nikto(ctx): return cmd("nikto -h", _q(ctx["url"]), _outflag(ctx, "-o", "nikto.txt"))
def b_nuclei(ctx): return cmd("nuclei -u", _q(ctx["url"]), pv(ctx, "extra", ""), _outflag(ctx, "-o", "nuclei.txt"))
def b_wpscan(ctx):
    tok = pv(ctx, "api_token", "")
    return cmd("wpscan --url", _q(ctx["url"]), "--enumerate vp,vt,u --random-user-agent",
               ("--api-token " + tok) if tok else "")
def b_sqlmap(ctx):
    return cmd("sqlmap -u", _q(ctx["url"]), "--batch", pv(ctx, "extra", "--crawl=2 --level=2 --risk=1"))


# --- Screenshots ---
def b_gowitness(ctx): return cmd("gowitness single", _q(ctx["url"]))
def b_eyewitness(ctx):
    return cmd("eyewitness --web --single", _q(ctx["url"]), "--no-prompt",
               ("-d " + _q(loot(ctx, "eyewitness"))) if ctx["loot"] else "")


I = lambda name, label, ph="", default="": {"name": name, "label": label, "placeholder": ph, "default": default}
EXT = I("ext", "Extensions", "php,html,txt")
EXTRA = I("extra", "Extra flags", "")

ACTIONS = [
    dict(id="whatweb", cat="Fingerprint", label="WhatWeb", desc="Identify technologies / CMS.", build=b_whatweb),
    dict(id="headers", cat="Fingerprint", label="HTTP headers", desc="curl -I (follow redirects).", build=b_headers),
    dict(id="wafw00f", cat="Fingerprint", label="wafw00f", desc="Detect a WAF.", build=b_wafw00f),
    dict(id="nuclei_tech", cat="Fingerprint", label="Nuclei tech-detect", desc="Tech fingerprint via nuclei.", build=b_nuclei_tech),

    dict(id="ffuf", cat="Content discovery", label="ffuf (dirs)", desc="Fast content discovery.",
         build=b_ffuf, inputs=[EXT, EXTRA]),
    dict(id="ferox", cat="Content discovery", label="feroxbuster", desc="Recursive content discovery.",
         build=b_ferox, inputs=[EXT]),
    dict(id="gobuster", cat="Content discovery", label="gobuster dir", desc="Directory brute force.",
         build=b_gobuster, inputs=[EXT]),
    dict(id="dirsearch", cat="Content discovery", label="dirsearch", desc="Content discovery (py).",
         build=b_dirsearch, inputs=[EXT]),

    dict(id="ffuf_vhost", cat="Vhost / DNS", label="ffuf vhost", desc="Virtual-host fuzzing (Host header).",
         build=b_ffuf_vhost, inputs=[I("vhost_domain", "Base domain", "target.tld"),
                                     I("wordlist2", "Wordlist", SUB_WL, SUB_WL), I("fs", "Filter size", "")]),
    dict(id="gobuster_vhost", cat="Vhost / DNS", label="gobuster vhost", desc="Vhost brute force.",
         build=b_gobuster_vhost, inputs=[I("wordlist2", "Wordlist", SUB_WL, SUB_WL)]),
    dict(id="gobuster_dns", cat="Vhost / DNS", label="gobuster dns", desc="Subdomain brute force.",
         build=b_gobuster_dns, inputs=[I("vhost_domain", "Domain", "target.tld"),
                                       I("wordlist2", "Wordlist", SUB_WL, SUB_WL)]),

    dict(id="ffuf_param", cat="Parameters", label="ffuf params", desc="GET parameter fuzzing.",
         build=b_ffuf_param, inputs=[I("wordlist2", "Wordlist", PARAM_WL, PARAM_WL), I("fs", "Filter size", "")]),
    dict(id="arjun", cat="Parameters", label="Arjun", desc="Parameter discovery.", build=b_arjun),

    dict(id="nikto", cat="Vuln scanning", label="Nikto", desc="Classic web server scanner.", build=b_nikto),
    dict(id="nuclei", cat="Vuln scanning", label="Nuclei", desc="Template-based vuln scanner.",
         build=b_nuclei, inputs=[I("extra", "Extra (e.g. -severity high,critical)", "")]),
    dict(id="wpscan", cat="Vuln scanning", label="WPScan", desc="WordPress scanner.",
         build=b_wpscan, inputs=[I("api_token", "API token (opt)", "")]),
    dict(id="sqlmap", cat="Vuln scanning", label="sqlmap", desc="SQL injection. Authorized targets only.",
         build=b_sqlmap, inputs=[I("extra", "Options", "--crawl=2 --level=2 --risk=1", "--crawl=2 --level=2 --risk=1")]),

    dict(id="gowitness", cat="Screenshots", label="gowitness", desc="Screenshot the page.", build=b_gowitness),
    dict(id="eyewitness", cat="Screenshots", label="EyeWitness", desc="Screenshot + report.", build=b_eyewitness),
]

ACTIONS_BY_ID = {a["id"]: a for a in ACTIONS}


def serializable_catalog():
    return [{"id": a["id"], "cat": a["cat"], "label": a["label"], "desc": a["desc"],
             "inputs": a.get("inputs", [])} for a in ACTIONS]


@web_bp.route("/web")
def web():
    eng = storage.load_engagement()
    catalog = serializable_catalog()
    cats = []
    for a in catalog:
        if a["cat"] not in cats:
            cats.append(a["cat"])
    # default URL from first target for the shared bar
    targets = eng.get("targets") or []
    default_url = ""
    if targets:
        default_url = targets[0] if targets[0].startswith("http") else "http://" + targets[0]
    return render_template("web.html", eng=eng, catalog=catalog, categories=cats,
                           default_url=default_url, dir_wl=DIR_WL)


@web_bp.route("/web/build", methods=["POST"])
def web_build():
    payload = request.get_json(silent=True) or {}
    action = ACTIONS_BY_ID.get(payload.get("action_id"))
    if not action:
        return jsonify({"error": "unknown action"}), 400
    eng = storage.load_engagement()
    ctx = build_context(payload.get("params", {}), eng)
    command = action["build"](ctx)
    if ctx["proxychains"]:
        command = tools.proxychains_prefix() + command
    warnings = []
    if not ctx["url"]:
        warnings.append("No URL — set a target or type one above.")
    return jsonify({"command": command, "warnings": warnings, "label": action["label"]})
