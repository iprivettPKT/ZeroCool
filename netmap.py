"""Network map / graphing module for ZeroCool.

Turns the parsed nmap results (parser.aggregate) into an interactive graph:

  * topology view — attacker -> subnet (/24) -> host, hosts coloured by role
    (DC / web / database / generic) and sized by open-port count;
  * services view — service-type nodes linked to the hosts that expose them,
    to visualise attack surface.

The graph data is served as JSON to a Cytoscape.js front-end.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request

import parser as nmap_parser
import storage

netmap_bp = Blueprint("netmap", __name__)

DB_PORTS = {1433, 3306, 5432, 27017, 6379, 1521}
REMOTE_PORTS = {22: "ssh", 3389: "rdp", 5900: "vnc", 23: "telnet"}


def _subnet(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "other"


def _role(host: dict) -> str:
    open_ports = {p["port"] for p in host.get("ports", [])}
    if host.get("has_ldap") and (host.get("has_smb") or 88 in open_ports):
        return "dc"
    if open_ports & DB_PORTS:
        return "db"
    if host.get("has_web"):
        return "web"
    if host.get("has_smb"):
        return "windows"
    return "host"


def _host_detail(host: dict) -> dict:
    ports = [f"{p['port']}/{p['proto']} {p['service']}".strip() for p in host.get("ports", [])]
    return {
        "ip": host.get("ip", ""),
        "hostnames": host.get("hostnames", []),
        "os": host.get("os", ""),
        "ports": ports,
        "role": _role(host),
    }


def _load_hosts(eng):
    loot = (eng.get("output_dir") or "").strip()
    files = nmap_parser.find_scan_files(loot) if loot else []
    return nmap_parser.aggregate(files)["hosts"] if files else []


def build_graph(eng, mode="topology"):
    hosts = _load_hosts(eng)
    attacker = (eng.get("attacker_ip") or "").strip()
    nodes, edges = [], []

    def host_node(h):
        ip = h["ip"]
        label = ip + (("\n" + h["hostnames"][0]) if h.get("hostnames") else "")
        nodes.append({"data": {
            "id": "host:" + ip, "label": label, "type": "host",
            "role": _role(h), "ports": len(h.get("ports", [])),
            "detail": _host_detail(h),
        }})

    if mode == "services":
        svc_seen = {}
        for h in hosts:
            host_node(h)
            for p in h.get("ports", []):
                svc = (p.get("service") or f"{p['proto']}/{p['port']}").strip() or "unknown"
                sid = "svc:" + svc
                if svc not in svc_seen:
                    svc_seen[svc] = sid
                    nodes.append({"data": {"id": sid, "label": svc, "type": "service"}})
                edges.append({"data": {"id": f"e:{sid}->{h['ip']}", "source": sid, "target": "host:" + h["ip"]}})
    else:  # topology
        if attacker:
            nodes.append({"data": {"id": "attacker", "label": attacker + "\n(you)", "type": "attacker"}})
        subnets = {}
        for h in hosts:
            sn = _subnet(h["ip"])
            if sn not in subnets:
                sid = "net:" + sn
                subnets[sn] = sid
                nodes.append({"data": {"id": sid, "label": sn, "type": "subnet"}})
                if attacker:
                    edges.append({"data": {"id": f"e:att->{sid}", "source": "attacker", "target": sid}})
            host_node(h)
            edges.append({"data": {"id": f"e:{subnets[sn]}->{h['ip']}", "source": subnets[sn], "target": "host:" + h["ip"]}})

    return {"nodes": nodes, "edges": edges, "host_count": len(hosts)}


@netmap_bp.route("/map")
def netmap():
    eng = storage.load_engagement()
    return render_template("netmap.html", eng=eng)


@netmap_bp.route("/map/data")
def netmap_data():
    eng = storage.load_engagement()
    mode = request.args.get("mode", "topology")
    return jsonify(build_graph(eng, mode))
