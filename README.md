# ZeroCool

<img width="1895" height="771" alt="image" src="https://github.com/user-attachments/assets/b591500d-4ac1-4551-a8e5-777be77e9d44" />

> *"Mess with the best, die like the rest."*

A web-based control panel for professional penetration testing engagements,
built with Flask. Named after the hacker from *Hackers* (1995). ZeroCool gives
you a single GUI over the whole engagement workflow — recon, network mapping,
Active Directory, web, cloud, privilege escalation, shells, pivoting, file
transfer and reporting — all driven by one shared engagement profile, with
every command logged.

---

## Features

| Module | What it does |
|---|---|
| **Engagement** | Central profile: scope, targets, domain/DC, attacker IP, interface, loot dir, credentials, SOCKS proxy. Everything else reads from here. |
| **Terminal** | Run arbitrary commands with live streaming output. |
| **Activity Log** | Every command ever run, with full output, status and exit code (audit trail). |
| **Dependencies** | Status of required tools; auto-fetch missing scripts, one-click install of packaged tools. |
| **Recon & Scanning** | Build & run nmap from your scope/targets (profiles, detection, timing); saves `-oA` output. |
| **Scan Results** | Parses nmap XML (incl. NSE script output) into a hosts/services view; promote hosts to targets; jump into AD/Web. |
| **Network Map** | Interactive graph (Cytoscape.js) of the discovered network — topology (attacker → subnet → host, coloured by role) and a services view, with per-host quick-links. |
| **Active Directory** | 100+ actions — enumeration, Kerberos (AS-REP/Kerberoast/S4U/ticketer), secrets/DCSync, an extensive NetExec catalog (DPAPI, lsassy, GPP, LAPS, gMSA, WebDAV, exec, file transfer…), BloodHound, lateral movement, coercion (PetitPotam/PrinterBug/DFSCoerce/ShadowCoerce/ntlmrelayx), ADCS/Certipy, and a large set of vuln/misconfig checks. |
| **Web** | ffuf / feroxbuster / gobuster / dirsearch / whatweb / nuclei / nikto / wpscan / sqlmap / gowitness, driven by URL + wordlist. |
| **Cloud Recon** | AWS / Azure / GCP / M365-Entra / multi-cloud enumeration (ScoutSuite, Prowler, AzureHound, ROADrecon, cloud_enum, S3Scanner, o365spray, subfinder…) from a keyword + domain. |
| **Privilege Escalation** | Linux & Windows technique catalog (LinPEAS/WinPEAS/PowerUp, SUID/sudo/caps, Potato, AlwaysInstallElevated, …) with stage-and-serve helpers. |
| **Reverse Shells** | Multi-session TCP handler with an xterm.js console, PTY upgrade and raw interactive mode; reverse-shell payload generator. |
| **Pivoting & Tunnels** | Chisel / Ligolo-ng / SSH (-L/-R/-D) / sshuttle / socat recipes, plus a proxychains config that the AD/Web modules can route through. |
| **File Transfer** | Managed HTTP server — directory listing + downloads and PUT/POST uploads — with a transfer log and ready-made download/upload commands. |
| **Loot & Reporting** | Findings tracker (add/edit/delete), a finding library, auto-detection from nmap results (incl. **confirmed** findings from NSE script output), loot browser, and HTML / Markdown report export. |

Cross-cutting niceties:

- **Auth handling** — password / pass-the-hash / Kerberos formatted correctly per tool family.
- **Send → session** — fire any built AD / web / cloud / privesc command straight into a caught reverse shell.
- **proxychains** — route AD, Web and Cloud commands through a pivot's SOCKS proxy.
- **Auto-provisioning** — missing standalone scripts (coercion, LinPEAS, …) are fetched on demand; packaged tools get an install command.
- **Persistence** — module selections, form options, the terminal output and the resizable multi-tab quick-terminal drawer all survive navigation and browser restarts.

---

## Requirements

- Python 3.10+
- Flask 3.x (`pip install -r requirements.txt`)
- The pentest tooling you intend to drive (nmap, NetExec, impacket, certipy,
  ffuf, etc.) — typically already present on Kali. Cloud recon additionally
  uses the relevant CLIs (aws / az / gcloud) and tools like ScoutSuite. The
  **Dependencies** page shows what's installed and how to get the rest.

## Run

```bash
git clone <your-repo-url> zerocool
cd zerocool
python3 -m venv .venv && source .venv/bin/activate   # optional
pip install -r requirements.txt
python3 app.py
# open http://127.0.0.1:5001
```

The control UI binds to `127.0.0.1` only. Listeners and the file server bind
`0.0.0.0` by design (targets must reach them) — keep those scoped to the
engagement network.

## Layout

```
app.py            Flask entrypoint + blueprint registration
storage.py        engagement persistence (data/engagement.json)
runner.py         command execution engine + activity log + tool auto-fetch
tools.py          dependency registry, script fetcher, proxychains config
parser.py         nmap XML parser (hosts/services + NSE output)
recon.py          nmap command builder
netmap.py         network map / graph builder
ad.py             Active Directory catalog
web.py            web testing catalog
cloud.py          cloud recon catalog (AWS/Azure/GCP/M365)
privesc.py        privilege escalation catalog
pivot.py          tunnelling recipes + proxychains
sessions.py       reverse-shell listeners + sessions
fileserver.py     managed HTTP file server
reporting.py      findings, detections, report export
templates/        Jinja templates
static/           CSS, JS (incl. vendored xterm.js + cytoscape.js)
```

Runtime data (engagement, findings, job output, fetched tools) lives under
`data/` and `tools/` and is gitignored.

---

## Authorized use only

ZeroCool is for **authorized** security testing — penetration tests with
written permission, lab environments, and CTFs. You are responsible for
operating only within an agreed scope and under the relevant rules of
engagement. Do not use it against systems you do not own or have explicit
permission to test.
