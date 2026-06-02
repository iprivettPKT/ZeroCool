"""Nmap results parser for ZeroCool.

Reads the .xml files that the Recon module writes via `-oA` (into
<output_dir>/nmap/) and turns them into a hosts/services view. Parsed hosts can
be promoted into the engagement `targets`, which every other module reads from,
and each host links straight into the AD / Recon modules with its IP prefilled.

Pure stdlib (xml.etree) — no extra dependencies.
"""

from __future__ import annotations

import glob
import os
import xml.etree.ElementTree as ET

from flask import Blueprint, flash, redirect, render_template, request, url_for

import storage

results_bp = Blueprint("results", __name__)

# Ports that hint at a follow-up module.
SMB_PORTS = {139, 445}
WEB_PORTS = {80, 443, 8080, 8443, 8000}
LDAP_PORTS = {389, 636, 3268, 3269}


def find_scan_files(loot_dir: str) -> list[str]:
    """All nmap .xml files under the loot dir (and its nmap/ subdir), newest first."""
    if not loot_dir or not os.path.isdir(loot_dir):
        return []
    seen: dict[str, float] = {}
    for pattern in (os.path.join(loot_dir, "*.xml"),
                    os.path.join(loot_dir, "nmap", "*.xml")):
        for path in glob.glob(pattern):
            try:
                seen[path] = os.path.getmtime(path)
            except OSError:
                seen[path] = 0.0
    return sorted(seen, key=lambda p: seen[p], reverse=True)


def parse_nmap_xml(path: str) -> dict:
    """Parse one nmap XML file into {file, args, started, hosts:[...], error}."""
    out = {"file": path, "name": os.path.basename(path), "args": "", "started": "",
           "hosts": [], "error": None}
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        out["error"] = str(exc)
        return out

    out["args"] = root.get("args", "")
    out["started"] = root.get("startstr", "")

    for host_el in root.findall("host"):
        status = host_el.find("status")
        state = status.get("state") if status is not None else "unknown"

        ip = ""
        mac = ""
        vendor = ""
        for addr in host_el.findall("address"):
            kind = addr.get("addrtype")
            if kind == "ipv4" or (kind == "ipv6" and not ip):
                ip = addr.get("addr", "")
            elif kind == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")

        hostnames = [hn.get("name", "") for hn in host_el.findall("hostnames/hostname")
                     if hn.get("name")]

        os_name = ""
        best = -1
        for osm in host_el.findall("os/osmatch"):
            try:
                acc = int(osm.get("accuracy", "0"))
            except ValueError:
                acc = 0
            if acc > best:
                best = acc
                os_name = osm.get("name", "")

        ports = []
        for port_el in host_el.findall("ports/port"):
            pstate_el = port_el.find("state")
            pstate = pstate_el.get("state") if pstate_el is not None else ""
            if pstate.startswith("closed") or pstate.startswith("filtered"):
                continue  # only surface open / open|filtered
            svc = port_el.find("service")
            try:
                portid = int(port_el.get("portid", "0"))
            except ValueError:
                portid = 0
            scripts = [{"id": s.get("id", ""), "output": s.get("output", "")}
                       for s in port_el.findall("script") if s.get("id")]
            ports.append({
                "port": portid,
                "proto": port_el.get("protocol", ""),
                "state": pstate,
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
                "scripts": scripts,
            })
        ports.sort(key=lambda p: (p["proto"], p["port"]))

        # Host-level NSE scripts (smb-*, snmp-*, etc. run against the host).
        host_scripts = [{"id": s.get("id", ""), "output": s.get("output", "")}
                        for s in host_el.findall("hostscript/script") if s.get("id")]

        if not ip and not ports:
            continue
        out["hosts"].append({
            "ip": ip, "hostnames": hostnames, "state": state,
            "mac": mac, "vendor": vendor, "os": os_name, "ports": ports,
            "scripts": host_scripts,
        })
    return out


def aggregate(paths: list[str]) -> dict:
    """Merge several parsed scans into one host map keyed by IP."""
    hosts: dict[str, dict] = {}
    files = []
    errors = []
    for path in paths:
        parsed = parse_nmap_xml(path)
        files.append({"name": parsed["name"], "args": parsed["args"],
                      "started": parsed["started"], "error": parsed["error"],
                      "hosts": len(parsed["hosts"])})
        if parsed["error"]:
            errors.append(f"{parsed['name']}: {parsed['error']}")
            continue
        for h in parsed["hosts"]:
            key = h["ip"] or (h["hostnames"][0] if h["hostnames"] else parsed["name"])
            entry = hosts.setdefault(key, {
                "ip": h["ip"], "hostnames": [], "state": h["state"],
                "mac": h["mac"], "vendor": h["vendor"], "os": h["os"],
                "ports": {}, "sources": set(), "scripts": [], "_sids": set(),
            })
            entry["sources"].add(parsed["name"])
            for s in h.get("scripts", []):
                if s.get("id") and s["id"] not in entry["_sids"]:
                    entry["scripts"].append(s)
                    entry["_sids"].add(s["id"])
            for hn in h["hostnames"]:
                if hn not in entry["hostnames"]:
                    entry["hostnames"].append(hn)
            if h["os"] and not entry["os"]:
                entry["os"] = h["os"]
            if h["state"] == "up":
                entry["state"] = "up"
            for p in h["ports"]:
                pk = f"{p['proto']}/{p['port']}"
                # keep the entry with the most service detail
                if pk not in entry["ports"] or len(str(p)) > len(str(entry["ports"][pk])):
                    entry["ports"][pk] = p

    # finalise: ports dict -> sorted list, sources set -> sorted list, add hints
    host_list = []
    for entry in hosts.values():
        plist = sorted(entry["ports"].values(), key=lambda p: (p["proto"], p["port"]))
        open_ports = {p["port"] for p in plist}
        host_list.append({
            "ip": entry["ip"],
            "hostnames": entry["hostnames"],
            "state": entry["state"],
            "mac": entry["mac"], "vendor": entry["vendor"], "os": entry["os"],
            "ports": plist,
            "scripts": entry["scripts"],
            "sources": sorted(entry["sources"]),
            "has_smb": bool(open_ports & SMB_PORTS),
            "has_web": bool(open_ports & WEB_PORTS),
            "has_ldap": bool(open_ports & LDAP_PORTS),
        })
    host_list.sort(key=lambda h: _ip_sort_key(h["ip"]))

    total_ports = sum(len(h["ports"]) for h in host_list)
    services = sorted({p["service"] for h in host_list for p in h["ports"] if p["service"]})
    return {
        "hosts": host_list, "files": files, "errors": errors,
        "stats": {"hosts": len(host_list), "ports": total_ports, "services": len(services)},
        "services": services,
    }


def _ip_sort_key(ip: str):
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, tuple(int(p) for p in parts))
    return (1, ip)


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------

@results_bp.route("/results")
def results():
    eng = storage.load_engagement()
    # Source dir: explicit ?dir= overrides the engagement loot dir.
    loot = (request.args.get("dir") or eng.get("output_dir") or "").strip()
    files = find_scan_files(loot)

    selected = request.args.get("file", "all")
    if selected != "all" and selected in files:
        paths = [selected]
    else:
        selected = "all"
        paths = files

    data = aggregate(paths) if paths else {
        "hosts": [], "files": [], "errors": [], "services": [],
        "stats": {"hosts": 0, "ports": 0, "services": 0}}

    return render_template(
        "results.html", eng=eng, loot=loot, files=files,
        selected=selected, data=data,
        existing_targets=set(eng.get("targets") or []),
    )


@results_bp.route("/results/add-targets", methods=["POST"])
def results_add_targets():
    ips = [i.strip() for i in request.form.getlist("ip") if i.strip()]
    if not ips:
        flash("No hosts selected.", "error")
        return redirect(request.referrer or url_for("results.results"))
    eng = storage.load_engagement()
    targets = list(eng.get("targets") or [])
    added = 0
    for ip in ips:
        if ip not in targets:
            targets.append(ip)
            added += 1
    eng["targets"] = targets
    storage.save_engagement(eng)
    flash(f"Added {added} host(s) to engagement targets.", "success")
    return redirect(request.referrer or url_for("results.results"))
