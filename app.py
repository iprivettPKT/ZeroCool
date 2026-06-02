"""ZeroCool -- a GUI control panel for professional penetration testing.

    "Mess with the best, die like the rest."

This is the Flask entrypoint. Right now it owns engagement configuration
(scope / targets / DC / domain / creds). Command modules (recon, AD, web,
etc.) will be added as Blueprints that read the engagement document and shell
out to the underlying tools.
"""

from __future__ import annotations

import json
import time

from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    stream_with_context,
    url_for,
)

import runner
import storage
import tools
from ad import ad_bp
from cloud import cloud_bp
from fileserver import files_bp
from netmap import netmap_bp
from parser import results_bp
from pivot import pivot_bp
from privesc import privesc_bp
from recon import recon_bp
from reporting import reporting_bp
from sessions import shells_bp
from web import web_bp

app = Flask(__name__)
app.secret_key = "zerocool-dev-key-change-me"  # only used for flash messages
app.register_blueprint(recon_bp)
app.register_blueprint(ad_bp)
app.register_blueprint(results_bp)
app.register_blueprint(shells_bp)
app.register_blueprint(files_bp)
app.register_blueprint(pivot_bp)
app.register_blueprint(privesc_bp)
app.register_blueprint(web_bp)
app.register_blueprint(reporting_bp)
app.register_blueprint(netmap_bp)
app.register_blueprint(cloud_bp)


@app.context_processor
def inject_globals():
    """Make the engagement available to every template (sidebar status etc.)."""
    return {"engagement": storage.load_engagement()}


@app.route("/")
def dashboard():
    eng = storage.load_engagement()
    # Cheap "is this configured yet?" checklist for the landing page.
    checklist = [
        ("Engagement name", bool(eng["engagement_name"])),
        ("In-scope ranges", bool(eng["scope"])),
        ("Targets", bool(eng["targets"])),
        ("Domain", bool(eng["domain"])),
        ("Domain controller", bool(eng["dc_ip"])),
        ("Credentials", bool(eng["credentials"])),
        ("Attacker IP / interface", bool(eng["attacker_ip"])),
    ]
    return render_template("dashboard.html", eng=eng, checklist=checklist)


@app.route("/engagement", methods=["GET", "POST"])
def engagement():
    if request.method == "POST":
        eng = storage.load_engagement()

        # Plain text fields.
        for field in (
            "engagement_name",
            "client",
            "notes",
            "domain",
            "dc_ip",
            "dc_hostname",
            "interface",
            "attacker_ip",
            "output_dir",
        ):
            eng[field] = request.form.get(field, "").strip()

        # List fields (textarea -> list).
        for field in storage.LIST_FIELDS:
            eng[field] = storage.parse_list(request.form.get(field, ""))

        # Credentials arrive as parallel arrays from the repeatable rows.
        eng["credentials"] = _parse_credentials(request.form)

        storage.save_engagement(eng)
        flash("Engagement saved.", "success")
        return redirect(url_for("engagement"))

    return render_template("engagement.html", eng=storage.load_engagement())


def _parse_credentials(form) -> list[dict]:
    """Rebuild the credentials list from the dynamic table rows."""
    domains = form.getlist("cred_domain")
    usernames = form.getlist("cred_username")
    passwords = form.getlist("cred_password")
    hashes = form.getlist("cred_hash")
    notes = form.getlist("cred_notes")

    creds: list[dict] = []
    for i in range(len(usernames)):
        username = (usernames[i] if i < len(usernames) else "").strip()
        password = (passwords[i] if i < len(passwords) else "").strip()
        ntlm = (hashes[i] if i < len(hashes) else "").strip()
        # Skip fully empty rows.
        if not (username or password or ntlm):
            continue
        creds.append(
            {
                "domain": (domains[i] if i < len(domains) else "").strip(),
                "username": username,
                "password": password,
                "ntlm_hash": ntlm,
                "notes": (notes[i] if i < len(notes) else "").strip(),
            }
        )
    return creds


# --------------------------------------------------------------------------
# Terminal: run commands and stream output
# --------------------------------------------------------------------------

@app.route("/terminal")
def terminal():
    eng = storage.load_engagement()
    # cwd defaults to the engagement loot dir if set, else home.
    default_cwd = eng.get("output_dir") or ""
    # Engagement-aware quick commands (operator can edit before running).
    quick = _quick_commands(eng)
    return render_template(
        "terminal.html", eng=eng, default_cwd=default_cwd, quick=quick
    )


@app.route("/terminal/run", methods=["POST"])
def terminal_run():
    payload = request.get_json(silent=True) or request.form
    command = (payload.get("command") or "").strip()
    cwd = (payload.get("cwd") or "").strip()
    if not command:
        return jsonify({"error": "empty command"}), 400
    job = runner.run_command(command, cwd=cwd)
    return jsonify(job.snapshot())


@app.route("/terminal/stream/<job_id>")
def terminal_stream(job_id):
    """Server-Sent Events stream of a job's output, newest lines pushed live."""

    @stream_with_context
    def gen():
        cursor = 0
        # Allow the client to resume from a known line via ?since=
        try:
            cursor = max(0, int(request.args.get("since", 0)))
        except (TypeError, ValueError):
            cursor = 0
        while True:
            job = runner.get_job(job_id)
            if job is None:
                yield _sse({"type": "error", "message": "unknown job"})
                return
            snap = job.snapshot(since=cursor)
            for ln in snap["lines"]:
                yield _sse({"type": "line", **ln})
            cursor = snap["total_lines"]
            if snap["status"] in runner.DONE_STATUSES:
                yield _sse(
                    {
                        "type": "done",
                        "status": snap["status"],
                        "exit_code": snap["exit_code"],
                        "ended": snap["ended"],
                    }
                )
                return
            time.sleep(0.25)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/terminal/kill/<job_id>", methods=["POST"])
def terminal_kill(job_id):
    return jsonify({"killed": runner.kill_job(job_id)})


@app.route("/terminal/job/<job_id>")
def terminal_job(job_id):
    """Full record of a job — used to restore drawer tabs across navigations."""
    rec = runner.load_job_record(job_id)
    if rec is None:
        return jsonify({"error": "unknown job"}), 404
    return jsonify(rec)


# --------------------------------------------------------------------------
# Activity log
# --------------------------------------------------------------------------

@app.route("/activity")
def activity():
    return render_template("activity.html", jobs=runner.load_history())


@app.route("/activity/<job_id>")
def activity_detail(job_id):
    rec = runner.load_job_record(job_id)
    if rec is None:
        flash("Unknown job.", "error")
        return redirect(url_for("activity"))
    return render_template("activity_detail.html", job=rec)


# --------------------------------------------------------------------------
# Dependencies / tool provisioning
# --------------------------------------------------------------------------

@app.route("/tools")
def tools_page():
    return render_template("tools.html", status=tools.status_all())


@app.route("/tools/fetch/<name>", methods=["POST"])
def tools_fetch(name):
    result = tools.fetch_script(name)
    code = 200 if result.get("ok") else 502
    return jsonify(result), code


@app.route("/tools/status")
def tools_status():
    return jsonify(tools.status_all())


def _sse(obj: dict) -> str:
    return f"data: {json.dumps(obj)}\n\n"


def _quick_commands(eng: dict) -> list[dict]:
    """Build a few ready-to-run commands from the engagement, as templates the
    operator can review and edit before executing."""
    items: list[dict] = []
    scope = " ".join(eng.get("scope", []))
    first_target = (eng.get("targets") or [""])[0]
    dc_ip = eng.get("dc_ip", "")
    domain = eng.get("domain", "")
    cred = (eng.get("credentials") or [None])[0]

    if scope:
        items.append({
            "label": "Nmap host discovery (scope)",
            "command": f"nmap -sn {scope}",
        })
    if first_target:
        items.append({
            "label": "Nmap full TCP + scripts (first target)",
            "command": f"nmap -sC -sV -p- -T4 {first_target}",
        })
    if dc_ip and cred and cred.get("username"):
        secret = cred.get("password") or cred.get("ntlm_hash") or "PASSWORD"
        items.append({
            "label": "netexec SMB enum (DC)",
            "command": f"nxc smb {dc_ip} -u '{cred['username']}' -p '{secret}'",
        })
    if dc_ip and domain:
        items.append({
            "label": "Kerberoast (GetUserSPNs)",
            "command": (
                f"impacket-GetUserSPNs {domain}/USER:PASSWORD "
                f"-dc-ip {dc_ip} -request"
            ),
        })
    return items


if __name__ == "__main__":
    # Bind to localhost by default; pentest data should not be exposed on the
    # network without the operator's explicit choice.
    # threaded=True so SSE streams don't block other requests.
    app.run(host="127.0.0.1", port=5001, debug=True, threaded=True)
