"""Command execution engine for ZeroCool.

Runs operator commands as background subprocesses, captures combined
stdout/stderr line-by-line, and keeps a full persistent audit log of
everything that has been executed (command, cwd, timestamps, exit code and
complete output) so it can be reviewed, screenshotted, or dropped into a report.

This is a local-operator tool: commands run through the operator's own shell
(`/bin/bash -c`) with their own environment. The Flask app binds to localhost
only -- do not expose it on the network.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import uuid
from datetime import datetime

import tools

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
JOBS_DIR = os.path.join(DATA_DIR, "jobs")          # one <id>.json per command
ACTIVITY_LOG = os.path.join(DATA_DIR, "activity.jsonl")  # append-only audit trail

ACTIVE_STATUSES = ("pending", "running")
DONE_STATUSES = ("finished", "failed", "killed")

_jobs: dict[str, "Job"] = {}   # in-memory jobs for the current process
_registry_lock = threading.Lock()


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class Job:
    """A single executed command and its captured output."""

    def __init__(self, command: str, cwd: str):
        self.id = uuid.uuid4().hex[:12]
        self.command = command
        self.cwd = cwd
        self.created = _now()
        self.started: str | None = None
        self.ended: str | None = None
        self.status = "pending"
        self.exit_code: int | None = None
        self.lines: list[dict] = []   # {n, ts, stream, text}
        self.proc: subprocess.Popen | None = None
        self._lock = threading.Lock()

    def add_line(self, text: str, stream: str = "stdout") -> None:
        with self._lock:
            self.lines.append(
                {"n": len(self.lines), "ts": _now(), "stream": stream, "text": text}
            )

    def snapshot(self, since: int = 0) -> dict:
        """Return job state plus any output lines after index `since`."""
        with self._lock:
            return {
                "id": self.id,
                "command": self.command,
                "cwd": self.cwd,
                "status": self.status,
                "exit_code": self.exit_code,
                "created": self.created,
                "started": self.started,
                "ended": self.ended,
                "total_lines": len(self.lines),
                "lines": self.lines[since:],
            }

    def record(self) -> dict:
        """Full record (all lines) for persistence / history."""
        snap = self.snapshot(since=0)
        return snap


def run_command(command: str, cwd: str | None = None) -> Job:
    """Start `command` in the background and return its Job immediately."""
    cwd = (cwd or "").strip() or os.path.expanduser("~")
    if not os.path.isdir(cwd):
        cwd = os.path.expanduser("~")
    job = Job(command, cwd)
    with _registry_lock:
        _jobs[job.id] = job
    threading.Thread(target=_execute, args=(job,), daemon=True).start()
    return job


def _execute(job: Job) -> None:
    job.started = _now()
    job.status = "running"
    _persist(job)  # persist early so it appears in history while running

    # Pre-flight: auto-fetch a missing known script (or hint at a missing
    # package), and make ./tools/ available on PATH for fetched scripts.
    env = os.environ.copy()
    try:
        prep = tools.prepare(job.command)
        for msg in prep.get("messages", []):
            stream = "stderr" if "could not" in msg else "stdout"
            job.add_line(msg, stream)
        path_prepend = prep.get("path_prepend")
        if path_prepend:
            env["PATH"] = path_prepend + os.pathsep + env.get("PATH", "")
    except Exception as exc:  # pragma: no cover - never let provisioning break a run
        job.add_line(f"[zerocool] dependency pre-flight skipped: {exc}", "stderr")

    try:
        job.proc = subprocess.Popen(
            job.command,
            shell=True,
            executable="/bin/bash",
            cwd=job.cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,  # own process group so we can kill the tree
            env=env,
        )
    except Exception as exc:  # pragma: no cover - defensive
        job.add_line(f"[zerocool] failed to start: {exc}", stream="stderr")
        job.status = "failed"
        job.ended = _now()
        _persist(job)
        return

    assert job.proc.stdout is not None
    for line in job.proc.stdout:
        job.add_line(line.rstrip("\n"))
    job.proc.wait()
    job.exit_code = job.proc.returncode

    job.ended = _now()
    if job.status != "killed":
        job.status = "finished" if job.exit_code == 0 else "failed"
    _persist(job)


def kill_job(job_id: str) -> bool:
    """Terminate a running job's process group."""
    job = _jobs.get(job_id)
    if not job or job.status not in ACTIVE_STATUSES or not job.proc:
        return False
    job.status = "killed"
    try:
        os.killpg(os.getpgid(job.proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    return True


def get_job(job_id: str) -> Job | None:
    return _jobs.get(job_id)


# --------------------------------------------------------------------------
# persistence / history
# --------------------------------------------------------------------------

def _ensure_dirs() -> None:
    os.makedirs(JOBS_DIR, exist_ok=True)


def _persist(job: Job) -> None:
    """Write the full job record and append a summary to the audit log."""
    _ensure_dirs()
    rec = job.record()
    # Full per-job output (overwrite each time so it reflects latest state).
    with open(os.path.join(JOBS_DIR, f"{job.id}.json"), "w", encoding="utf-8") as fh:
        json.dump(rec, fh, indent=2)
    # Append a one-line audit entry only once the job has finished.
    if job.status in DONE_STATUSES:
        summary = {
            "id": rec["id"],
            "ts": rec["ended"] or rec["created"],
            "command": rec["command"],
            "cwd": rec["cwd"],
            "status": rec["status"],
            "exit_code": rec["exit_code"],
            "lines": rec["total_lines"],
        }
        with open(ACTIVITY_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(summary) + "\n")


def load_history() -> list[dict]:
    """All jobs, newest first. In-memory (live) jobs take precedence over
    their persisted copies so running jobs show current state."""
    _ensure_dirs()
    records: dict[str, dict] = {}
    for name in os.listdir(JOBS_DIR):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(JOBS_DIR, name), "r", encoding="utf-8") as fh:
                rec = json.load(fh)
            records[rec["id"]] = rec
        except (json.JSONDecodeError, OSError, KeyError):
            continue
    with _registry_lock:
        for job in _jobs.values():
            records[job.id] = job.record()
    return sorted(records.values(), key=lambda r: r.get("created", ""), reverse=True)


def load_job_record(job_id: str) -> dict | None:
    """Full record for one job (memory first, then disk)."""
    job = _jobs.get(job_id)
    if job:
        return job.record()
    path = os.path.join(JOBS_DIR, f"{job_id}.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return None
    return None
