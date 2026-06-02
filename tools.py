"""Dependency provisioning for ZeroCool.

Two kinds of dependencies:

  * SCRIPTS  — standalone files (the coercion .py's) that aren't packaged.
               These we can fetch directly from their canonical repos into
               ./tools/ and mark executable. Done automatically by the runner
               right before a command runs.

  * PACKAGES — tools installed via apt/pipx/gem (impacket, nxc, certipy, …).
               These can't just be downloaded, so we surface the exact install
               command (run on demand from the Dependencies page or shown as a
               hint when a command needs a missing one).

The runner prepends ./tools/ to PATH for every command, so fetched scripts are
found without changing the command the operator sees.
"""

from __future__ import annotations

import os
import shutil
import stat
import urllib.error
import urllib.request

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(PROJECT_DIR, "tools")

# Standalone scripts we can fetch directly (pinned to known upstreams).
SCRIPTS = {
    "petitpotam.py": {
        "label": "PetitPotam (MS-EFSR coercion)",
        "url": "https://raw.githubusercontent.com/topotam/PetitPotam/master/PetitPotam.py",
    },
    "printerbug.py": {
        "label": "PrinterBug (MS-RPRN coercion)",
        "url": "https://raw.githubusercontent.com/dirkjanm/krbrelayx/master/printerbug.py",
    },
    "dfscoerce.py": {
        "label": "DFSCoerce (MS-DFSNM coercion)",
        "url": "https://raw.githubusercontent.com/Wh04m1001/DFSCoerce/main/dfscoerce.py",
    },
    "shadowcoerce.py": {
        "label": "ShadowCoerce (MS-FSRVP coercion)",
        "url": "https://raw.githubusercontent.com/ShutdownRepo/ShadowCoerce/master/shadowcoerce.py",
    },
    "lse.sh": {
        "label": "linux-smart-enumeration (privesc)",
        "url": "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh",
    },
    "linux-exploit-suggester.sh": {
        "label": "linux-exploit-suggester (privesc)",
        "url": "https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh",
    },
    "PowerUp.ps1": {
        "label": "PowerUp (Windows privesc checks)",
        "url": "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1",
    },
}

# Package-managed tools: binary name -> how to install it.
PACKAGES = {
    "nmap":             {"label": "Nmap", "install": "apt-get install -y nmap"},
    "nxc":              {"label": "NetExec", "install": "pipx install netexec || sudo apt-get install -y netexec"},
    "certipy":          {"label": "Certipy", "install": "pipx install certipy-ad"},
    "evil-winrm":       {"label": "Evil-WinRM", "install": "sudo gem install evil-winrm || sudo apt-get install -y evil-winrm"},
    "responder":        {"label": "Responder", "install": "sudo apt-get install -y responder"},
    "coercer":          {"label": "Coercer", "install": "pipx install coercer"},
    "enum4linux-ng":    {"label": "enum4linux-ng", "install": "pipx install enum4linux-ng || sudo apt-get install -y enum4linux-ng"},
    "bloodhound-python": {"label": "BloodHound.py", "install": "pipx install bloodhound"},
    "ldapsearch":       {"label": "ldap-utils (ldapsearch)", "install": "sudo apt-get install -y ldap-utils"},
    "pre2k":            {"label": "pre2k", "install": "pipx install pre2k"},
    "rpcclient":        {"label": "Samba client (rpcclient)", "install": "sudo apt-get install -y smbclient"},
    "impacket-secretsdump": {"label": "Impacket suite", "install": "pipx install impacket || sudo apt-get install -y python3-impacket"},
}

# Any impacket-* binary is provided by the impacket package.
IMPACKET_INSTALL = "pipx install impacket || sudo apt-get install -y python3-impacket"

# Tunnelling / pivoting tools.
PACKAGES.update({
    "chisel":       {"label": "Chisel (TCP/SOCKS over HTTP)", "install": "sudo apt-get install -y chisel || go install github.com/jpillora/chisel@latest"},
    "ligolo-proxy": {"label": "Ligolo-ng proxy", "install": "sudo apt-get install -y ligolo-ng"},
    "proxychains4": {"label": "proxychains-ng", "install": "sudo apt-get install -y proxychains4"},
    "sshuttle":     {"label": "sshuttle (VPN over SSH)", "install": "pipx install sshuttle || sudo apt-get install -y sshuttle"},
    "socat":        {"label": "socat", "install": "sudo apt-get install -y socat"},
})

# Web testing tools.
PACKAGES.update({
    "ffuf":         {"label": "ffuf", "install": "sudo apt-get install -y ffuf"},
    "feroxbuster":  {"label": "feroxbuster", "install": "sudo apt-get install -y feroxbuster"},
    "gobuster":     {"label": "gobuster", "install": "sudo apt-get install -y gobuster"},
    "dirsearch":    {"label": "dirsearch", "install": "sudo apt-get install -y dirsearch"},
    "whatweb":      {"label": "WhatWeb", "install": "sudo apt-get install -y whatweb"},
    "nuclei":       {"label": "Nuclei", "install": "sudo apt-get install -y nuclei"},
    "nikto":        {"label": "Nikto", "install": "sudo apt-get install -y nikto"},
    "wpscan":       {"label": "WPScan", "install": "sudo gem install wpscan || sudo apt-get install -y wpscan"},
    "sqlmap":       {"label": "sqlmap", "install": "sudo apt-get install -y sqlmap"},
    "gowitness":    {"label": "gowitness", "install": "go install github.com/sensepost/gowitness@latest"},
    "wafw00f":      {"label": "wafw00f", "install": "sudo apt-get install -y wafw00f"},
    "arjun":        {"label": "Arjun", "install": "pipx install arjun || sudo apt-get install -y arjun"},
})

# Cloud recon tools.
PACKAGES.update({
    "aws":          {"label": "AWS CLI", "install": "pipx install awscli || sudo apt-get install -y awscli"},
    "az":           {"label": "Azure CLI", "install": "curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash"},
    "gcloud":       {"label": "Google Cloud SDK", "install": "sudo apt-get install -y google-cloud-cli"},
    "scout":        {"label": "ScoutSuite", "install": "pipx install scoutsuite"},
    "prowler":      {"label": "Prowler", "install": "pipx install prowler"},
    "cloud_enum":   {"label": "cloud_enum", "install": "pipx install cloud-enum"},
    "s3scanner":    {"label": "S3Scanner", "install": "pipx install s3scanner"},
    "o365spray":    {"label": "o365spray", "install": "pipx install o365spray"},
    "subfinder":    {"label": "subfinder", "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "amass":        {"label": "amass", "install": "sudo apt-get install -y amass"},
    "azurehound":   {"label": "AzureHound", "install": "go install github.com/bloodhoundad/azurehound/v2@latest"},
    "roadrecon":    {"label": "ROADrecon", "install": "pipx install roadrecon"},
})

PROXYCHAINS_CONF = os.path.join(TOOLS_DIR, "proxychains.conf")


def write_proxychains_conf(socks_host: str, socks_port, proxy_dns: bool = True) -> str:
    """Write a proxychains-ng config pointing at the given SOCKS5 proxy."""
    ensure_tools_dir()
    lines = [
        "# generated by ZeroCool",
        "strict_chain",
        "proxy_dns" if proxy_dns else "# proxy_dns",
        "tcp_read_time_out 15000",
        "tcp_connect_time_out 8000",
        "[ProxyList]",
        f"socks5 {socks_host} {socks_port}",
    ]
    with open(PROXYCHAINS_CONF, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return PROXYCHAINS_CONF


def proxychains_prefix() -> str:
    """Prefix to route a command through the configured proxy."""
    if os.path.exists(PROXYCHAINS_CONF):
        return f"proxychains4 -q -f {PROXYCHAINS_CONF} "
    return "proxychains4 -q "


def ensure_tools_dir() -> None:
    os.makedirs(TOOLS_DIR, exist_ok=True)


def locate(binary: str) -> str | None:
    """Path to `binary` on PATH or in our tools dir, else None."""
    if not binary:
        return None
    found = shutil.which(binary)
    if found:
        return found
    candidate = os.path.join(TOOLS_DIR, binary)
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    return None


def primary_binary(command: str) -> str:
    """Best-effort extraction of the executable a command will invoke.

    Handles a leading `mkdir … &&` prefix (recon) and a leading `sudo`.
    """
    segment = command.split("&&")[-1].strip()
    tokens = segment.split()
    if not tokens:
        return ""
    idx = 1 if tokens[0] == "sudo" and len(tokens) > 1 else 0
    return tokens[idx]


def install_command(binary: str) -> str | None:
    if binary in PACKAGES:
        return PACKAGES[binary]["install"]
    if binary.startswith("impacket-"):
        return IMPACKET_INSTALL
    return None


# --------------------------------------------------------------------------
# install environment adaptation
# --------------------------------------------------------------------------

def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


_sudo_ok = None


def can_sudo_nopasswd() -> bool:
    """True if sudo works without a password (cached). The runner has no TTY,
    so a sudo that needs a password would fail — we use this to warn up front."""
    global _sudo_ok
    if _sudo_ok is None:
        if is_root() or not shutil.which("sudo"):
            _sudo_ok = is_root()
        else:
            import subprocess
            try:
                _sudo_ok = subprocess.run(
                    ["sudo", "-n", "true"], capture_output=True, timeout=5).returncode == 0
            except (OSError, subprocess.SubprocessError):
                _sudo_ok = False
    return _sudo_ok


def adapt_command(cmd: str) -> str:
    """Adapt an install command to the runtime: drop sudo when already root and
    make apt non-interactive so installs don't hang waiting on a prompt."""
    if not cmd:
        return cmd
    if is_root():
        cmd = cmd.replace("sudo ", "")
    if "apt-get install" in cmd and "DEBIAN_FRONTEND" not in cmd:
        cmd = cmd.replace("apt-get install", "DEBIAN_FRONTEND=noninteractive apt-get install")
    return cmd


def prereqs() -> dict:
    """What's available for installing things, so the UI can warn proactively."""
    return {
        "root": is_root(),
        "sudo_nopasswd": can_sudo_nopasswd(),
        "pipx": bool(shutil.which("pipx")),
        "go": bool(shutil.which("go")),
        "gem": bool(shutil.which("gem")),
        "apt": bool(shutil.which("apt-get")),
        "git": bool(shutil.which("git")),
        "curl": bool(shutil.which("curl")),
    }


def fetch_script(name: str, timeout: int = 25) -> dict:
    """Download a known script into tools/ and make it executable."""
    spec = SCRIPTS.get(name)
    if not spec:
        return {"ok": False, "error": f"{name} is not a known fetchable script"}
    ensure_tools_dir()
    dest = os.path.join(TOOLS_DIR, name)
    try:
        req = urllib.request.Request(spec["url"], headers={"User-Agent": "ZeroCool"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}
    if not data:
        return {"ok": False, "error": "empty response"}
    with open(dest, "wb") as fh:
        fh.write(data)
    st = os.stat(dest)
    os.chmod(dest, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return {"ok": True, "path": dest, "bytes": len(data)}


def prepare(command: str) -> dict:
    """Pre-flight a command: auto-fetch a missing known script, or surface an
    install hint for a missing packaged tool. Returns messages + the PATH dir
    the runner should prepend so fetched scripts resolve."""
    messages: list[str] = []
    binary = primary_binary(command)
    if binary and locate(binary) is None:
        if binary in SCRIPTS:
            messages.append(f"[zerocool] {binary} not found — fetching from {SCRIPTS[binary]['url']}")
            result = fetch_script(binary)
            if result.get("ok"):
                messages.append(f"[zerocool] fetched {binary} → tools/ ({result['bytes']} bytes), made executable")
            else:
                messages.append(f"[zerocool] could not fetch {binary}: {result.get('error')}")
        else:
            hint = adapt_command(install_command(binary))
            if hint:
                messages.append(f"[zerocool] {binary} not found — install it from the Dependencies page or run: {hint}")
            else:
                messages.append(f"[zerocool] note: {binary} was not found on PATH")
    return {"binary": binary, "messages": messages, "path_prepend": TOOLS_DIR}


def status_all() -> dict:
    """Installed/missing status for every known dependency (for the UI)."""
    ensure_tools_dir()
    scripts = []
    for name, spec in SCRIPTS.items():
        loc = locate(name)
        scripts.append({
            "name": name, "label": spec["label"], "url": spec["url"],
            "installed": bool(loc), "path": loc or "",
        })
    packages = []
    for name, spec in PACKAGES.items():
        loc = locate(name)
        packages.append({
            "name": name, "label": spec["label"], "install": adapt_command(spec["install"]),
            "installed": bool(loc), "path": loc or "",
        })
    return {"scripts": scripts, "packages": packages, "tools_dir": TOOLS_DIR,
            "prereqs": prereqs()}
