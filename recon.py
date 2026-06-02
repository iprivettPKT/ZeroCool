"""Recon & Scanning module (nmap) for ZeroCool.

A Flask Blueprint that turns the engagement's scope/targets plus a few options
into a ready-to-run nmap command. The command is built server-side (single
source of truth), previewed live in the UI, then handed to the shared runner so
its output streams into the embedded terminal and lands in the Activity Log.

This sets the pattern for future modules: read the engagement, build a command,
hand it to runner via the existing /terminal endpoints.
"""

from __future__ import annotations

import os
import re
import shlex

from flask import Blueprint, jsonify, render_template, request

import storage
import tools

recon_bp = Blueprint("recon", __name__)


# Scan profiles. `flags` are always added; `discovery` skips port/detection opts.
PROFILES = {
    "discovery": {"label": "Host discovery — no port scan (-sn)", "flags": ["-sn"]},
    "quick":     {"label": "Quick — top 100 ports (-F)", "flags": ["-F"]},
    "top1000":   {"label": "Standard — top 1000 ports", "flags": []},
    "full":      {"label": "Full TCP — all 65535 ports (-p-)", "flags": ["-p-"]},
    "custom":    {"label": "Custom port list", "flags": []},
}

TARGET_SOURCES = ("scope", "targets", "custom")

_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _sanitize_name(name: str) -> str:
    name = _NAME_RE.sub("_", (name or "").strip()).strip("_")
    return name or "scan"


def resolve_targets(opts: dict, eng: dict) -> list[str]:
    source = opts.get("source", "scope")
    if source == "targets":
        return list(eng.get("targets") or [])
    if source == "custom":
        return storage.parse_list(opts.get("custom_targets", ""))
    return list(eng.get("scope") or [])


def build_nmap(opts: dict, eng: dict) -> dict:
    """Return {command, targets, warnings, output_base} for the given options."""
    warnings: list[str] = []
    profile_key = opts.get("profile", "top1000")
    profile = PROFILES.get(profile_key, PROFILES["top1000"])

    parts: list[str] = ["nmap"]

    # Timing template.
    timing = (opts.get("timing") or "4").strip()
    if timing in {"0", "1", "2", "3", "4", "5"}:
        parts.append(f"-T{timing}")

    # Profile flags.
    parts.extend(profile["flags"])

    if profile_key == "custom":
        ports = (opts.get("ports") or "").strip()
        if ports:
            # keep it a single arg; nmap accepts comma/range port specs
            parts.append(f"-p {ports}")
        else:
            warnings.append("Custom profile selected but no ports given.")

    # proxychains can only carry TCP connect() calls — so SYN/UDP/OS-detect and
    # ICMP host discovery don't work through a SOCKS proxy.
    proxied = _truthy(opts.get("proxychains"))

    # Detection options (meaningless for pure host discovery).
    if profile_key != "discovery":
        if _truthy(opts.get("sV")):
            parts.append("-sV")
        if _truthy(opts.get("sC")):
            parts.append("-sC")
        if _truthy(opts.get("osdetect")):
            if proxied:
                warnings.append("OS detection (-O) skipped — it can't work through a SOCKS proxy.")
            else:
                parts.append("-O")
        if _truthy(opts.get("udp")):
            if proxied:
                warnings.append("UDP scan skipped — proxychains is TCP-only.")
            else:
                parts.append("-sU")
                warnings.append("UDP scan can be very slow and needs root.")
        if _truthy(opts.get("vuln")):
            parts.append("--script vuln")

    # Force TCP-connect + no-ping when proxied (only form that survives a SOCKS proxy).
    if proxied:
        if "-sT" not in parts:
            parts.append("-sT")
        if "-Pn" not in parts:
            parts.append("-Pn")
        if profile_key == "discovery":
            warnings.append("Host discovery (-sn) can't run through a SOCKS proxy — pick a port-scan profile.")
        if not eng.get("socks_proxy"):
            warnings.append("No SOCKS proxy set — configure one in Pivoting first.")

    # Extra raw flags, appended verbatim.
    extra = (opts.get("extra") or "").strip()
    if extra:
        parts.append(extra)

    # Exclusions only make sense when scanning the whole scope.
    if opts.get("source", "scope") == "scope":
        excl = [e for e in (eng.get("out_of_scope") or []) if e]
        if excl:
            parts.append("--exclude " + ",".join(excl))

    # Output: -oA into <loot>/nmap/<name> when an output dir is configured.
    output_base = None
    prefix = ""
    outdir = (eng.get("output_dir") or "").strip()
    if outdir:
        name = _sanitize_name(opts.get("name", "scan"))
        nmap_dir = os.path.join(outdir, "nmap")
        output_base = os.path.join(nmap_dir, name)
        parts.append("-oA " + shlex.quote(output_base))
        # Ensure the directory exists at run time.
        prefix = f"mkdir -p {shlex.quote(nmap_dir)} && "
    else:
        warnings.append("No engagement output dir set — results won't be saved (-oA skipped).")

    # Targets last.
    targets = resolve_targets(opts, eng)
    if not targets:
        warnings.append("No targets resolved — set scope/targets or enter custom targets.")
    parts.extend(targets)

    proxy_prefix = tools.proxychains_prefix() if proxied else ""
    command = prefix + proxy_prefix + " ".join(parts)
    return {
        "command": command,
        "targets": targets,
        "warnings": warnings,
        "output_base": output_base,
    }


def _truthy(val) -> bool:
    return str(val).lower() in ("1", "true", "on", "yes")


def _opts_from_request() -> dict:
    payload = request.get_json(silent=True)
    if payload is None:
        payload = request.form.to_dict()
    return payload or {}


@recon_bp.route("/recon")
def recon():
    eng = storage.load_engagement()
    return render_template("recon.html", eng=eng, profiles=PROFILES)


@recon_bp.route("/recon/build", methods=["POST"])
def recon_build():
    eng = storage.load_engagement()
    result = build_nmap(_opts_from_request(), eng)
    return jsonify(result)
