"""Advanced settings for ZeroCool — currently remote access.

ZeroCool's UI stays bound to 127.0.0.1 (it runs arbitrary commands as root, so
it must never be exposed on a network). To reach it from another machine you
forward the port over SSH. This page makes that one step:

  * detects the box's reachable (VPN/LAN) IPs,
  * builds the `ssh -L` tunnel command (with an optional private key),
  * serves a connect script for the operator's machine, and
  * serves a systemd unit so ZeroCool runs headless on boot.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys

from flask import Blueprint, Response, render_template, request

settings_bp = Blueprint("settings", __name__)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PORT = "5001"
VPN_PREFIXES = ("tun", "wg", "ppp", "tap", "nordlynx", "proton")


def _port() -> str:
    host = request.host if request else ""
    if ":" in host:
        return host.rsplit(":", 1)[1]
    return DEFAULT_PORT


def local_ips() -> list[dict]:
    """Non-loopback IPv4 addresses, VPN-looking interfaces first."""
    found: list[dict] = []
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                             capture_output=True, text=True, timeout=3).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            iface = parts[1]
            if iface == "lo" or iface.startswith(("docker", "virbr", "br-")):
                continue
            for i, tok in enumerate(parts):
                if tok == "inet" and i + 1 < len(parts):
                    ip = parts[i + 1].split("/")[0]
                    if ip and not ip.startswith("127."):
                        found.append({"iface": iface, "ip": ip,
                                      "vpn": iface.startswith(VPN_PREFIXES)})
    except (OSError, subprocess.SubprocessError):
        pass

    if not found:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            found.append({"iface": "?", "ip": s.getsockname()[0], "vpn": False})
            s.close()
        except OSError:
            pass

    found.sort(key=lambda x: (not x["vpn"], x["iface"]))
    return found


def _current_user() -> str:
    return os.environ.get("SUDO_USER") or os.environ.get("USER") or "kali"


def connect_script(port: str) -> str:
    return f"""#!/usr/bin/env bash
# zerocool-connect.sh — open the remote ZeroCool UI over an SSH tunnel.
# Usage: ./zerocool-connect.sh [-i keyfile] user@kali-box [port]
set -euo pipefail
IDENTITY=""
while getopts "i:" opt; do
  case "$opt" in
    i) IDENTITY="-i $OPTARG" ;;
    *) echo "usage: $0 [-i keyfile] user@host [port]" >&2; exit 1 ;;
  esac
done
shift $((OPTIND - 1))
TARGET="${{1:?usage: $0 [-i keyfile] user@host [port]}}"
PORT="${{2:-{port}}}"
URL="http://127.0.0.1:$PORT"
echo "[*] tunnelling localhost:$PORT -> $TARGET (127.0.0.1:$PORT)"
echo "[*] opening $URL  (Ctrl-C closes the tunnel)"
( sleep 2
  if command -v xdg-open >/dev/null; then xdg-open "$URL"
  elif command -v open >/dev/null; then open "$URL"
  fi ) >/dev/null 2>&1 &
exec ssh -N $IDENTITY -o ExitOnForwardFailure=yes -L "$PORT:127.0.0.1:$PORT" "$TARGET"
"""


def systemd_unit() -> str:
    return f"""[Unit]
Description=ZeroCool pentest dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={_current_user()}
WorkingDirectory={APP_DIR}
ExecStart={sys.executable} {os.path.join(APP_DIR, 'app.py')}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
"""


@settings_bp.route("/settings")
def settings():
    return render_template("settings.html", ips=local_ips(), port=_port(),
                           user=_current_user(), app_dir=APP_DIR)


@settings_bp.route("/settings/connect-script")
def connect_script_dl():
    return Response(connect_script(_port()), mimetype="text/x-shellscript",
                    headers={"Content-Disposition": "attachment; filename=zerocool-connect.sh"})


@settings_bp.route("/settings/connect-service")
def connect_service_dl():
    return Response(systemd_unit(), mimetype="text/plain",
                    headers={"Content-Disposition": "attachment; filename=zerocool.service"})
