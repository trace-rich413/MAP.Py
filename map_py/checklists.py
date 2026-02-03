"""Evidence-first privilege escalation checklists for enumeration."""

import os


WINDOWS_CHECKLIST = """# Windows Privilege Escalation Enumeration Checklist

## Identity & Access
- `whoami` — Current user
- `whoami /priv` — Current user privileges (watch for SeImpersonatePrivilege, SeDebugPrivilege, etc.)
- `whoami /groups` — Group membership

## System Information
- `systeminfo` — OS version, build, architecture, installed patches
- `wmic os get caption,version,buildnumber` — OS details
- `Get-HotFix` (PowerShell) — Installed patches

## Installed Software
- `wmic product list brief` — Installed applications
- `Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*` (PowerShell)
- Check for vulnerable software versions

## Services & Startup
- `services` (GUI) or `net start` — View services
- `wmic service list brief` — Service listing with status
- `sc query` — Service query with permissions
- `tasklist /svc` — Running processes and their services
- Check service binaries for write permissions or missing DLLs

## Scheduled Tasks
- `tasklist` and `tasksched.msc` — Scheduled tasks
- `schtasks /query /fo LIST /v` — Detailed task listing
- Check for tasks running as SYSTEM or admin with writable paths

## Network & Connections
- `netstat -ano` — Active connections and listening ports
- `ipconfig /all` — Network configuration
- `arp -a` — ARP cache

## File System & Permissions
- `icacls C:\` — Check NTFS permissions on critical directories
- Look for world-writable directories or BUILTIN\Users write access
- Check Program Files permissions
- Check Windows folder permissions

## Registry
- `reg query HKLM\Software\` — Registry keys (beware sensitive data)
- Look for credentials, service configurations, AutoRun keys
- Check for AlwaysInstallElevated: `reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`

## Credentials & Secrets
- Check for plaintext credentials in:
  - Environment variables: `set`
  - Command history: `doskey /history`
  - PowerShell history: `Get-History` or `(Get-PSReadlineOption).HistorySavePath`
  - .git config files
  - Configuration files in user directories
  - Temp folders
- `cmdkey /list` — Stored credentials

## Token Impersonation (Information Only)
- If **SeImpersonatePrivilege** or **SeAssignPrimaryTokenPrivilege** is present:
  - Token impersonation is theoretically possible via techniques like Rotten Potato or PrintSpoofer/GodPotato class exploits.
  - **DO NOT execute or download exploit binaries without explicit authorization.**
  - Manually research and test only in your lab environment if needed.
  - Focus on understanding the risk surface; lab testing is your responsibility.

## Kernel & Driver Exploitation
- Identify missing patches and known CVEs
- Cross-reference with exploit databases (ExploitDB, Metasploit)
- **Do not execute kernel exploits without full authorization and lab environment.**

## Running Processes & DLL Injection
- `tasklist /v` — Running processes
- `wmic process list brief` — Process listing
- Check for vulnerable processes running as SYSTEM
- Look for DLL hijacking opportunities (missing/weak DLL search paths)

## Common Misconfigurations
- Unquoted service paths
- Weak folder/file permissions on service binaries
- Hard-coded credentials in scripts
- Overly permissive share permissions (SMB)
- Weak password policies or cached credentials

---
**Notes:**
- Collect evidence systematically; do not skip steps.
- Save command outputs for your report.
- Cross-reference findings with known CVEs and exploit techniques.
- Exploitation is your responsibility; this checklist is enumeration only.
"""

LINUX_CHECKLIST = """# Linux Privilege Escalation Enumeration Checklist

## Identity & Access
- `id` — Current user ID, GID, groups
- `sudo -l` — Sudoers privileges (can run as root?)
- `groups` — User's groups
- `getent group` — All groups on system

## System Information
- `uname -a` — Kernel version and architecture
- `cat /proc/version` — Kernel and GCC version
- `hostnamectl` — Hostname and OS info
- `lsb_release -a` — Distro info
- `cat /etc/os-release` — Detailed OS info

## Installed Software & Libraries
- `dpkg -l` (Debian/Ubuntu) or `rpm -qa` (RHEL/CentOS) — Package list
- `apt list --upgradable` (Debian/Ubuntu) — Available upgrades
- `apt-cache policy <package>` — Check specific package versions
- Look for known vulnerable versions

## Kernel Modules & Drivers
- `lsmod` — Loaded kernel modules
- `modinfo <module>` — Module information
- Check for custom or outdated modules with known vulnerabilities

## Running Processes
- `ps aux` — All running processes
- `ps auxww` — Full command lines
- Look for processes running as root with writable binaries or scripts
- Check service processes for vulnerabilities

## File System & Permissions
- `ls -la /` — Root directory permissions
- `ls -la /home/` — Home directory permissions
- `ls -la /opt/` — Optional software directory
- `ls -la /etc/` — Configuration directory
- `find / -perm -4000 2>/dev/null` — SUID binaries
- `find / -perm -2000 2>/dev/null` — SGID binaries
- Check for world-writable directories: `find / -type d -perm -002 2>/dev/null`
- Check for SUID/SGID binaries that might be exploitable

## Capabilities
- `getcap -r / 2>/dev/null` — Binaries with Linux capabilities
- Look for capabilities like cap_setuid, cap_setgid, cap_sys_admin on common binaries

## Sudo Configuration
- `cat /etc/sudoers` (if readable) — Sudoers rules
- `sudo -l -n` — Non-interactive sudoers check
- Look for NOPASSWD entries or paths without full paths
- Check for environment variable inheritance (env_keep, env_reset)

## Cron Jobs
- `crontab -l` — Current user's cron jobs
- `cat /etc/crontab` — System cron jobs
- `ls -la /etc/cron.d/` — Drop-in cron jobs
- `ls -la /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/` — Scheduled scripts
- Check permissions on executed scripts (writable by unprivileged users?)

## SSH Configuration
- `cat ~/.ssh/authorized_keys` — Authorized SSH keys
- `cat ~/.ssh/id_rsa` — Private SSH keys (if present)
- `ssh-keyscan localhost` — Check local SSH keys
- Check permissions on .ssh directory and files

## Network & Connections
- `netstat -tlnp` or `ss -tlnp` — Listening ports and associated processes
- `ifconfig` or `ip addr` — Network configuration
- Look for services only listening on localhost (might be exploitable)

## Configuration Files & Secrets
- `cat ~/.bash_history` — Command history
- `cat ~/.bashrc ~/.bash_profile` — Shell configuration
- `cat ~/.ssh/config` — SSH client configuration
- `cat /root/.ssh/authorized_keys` (if readable) — Root SSH keys
- Look for plaintext credentials in config files
- Check for .git directories with credentials
- Search for API keys, database passwords, tokens

## Password Policy & Shadow Files
- `cat /etc/passwd` — User accounts
- `cat /etc/shadow` (if readable) — Password hashes
- `cat /etc/group` — Group information
- `cat /etc/gshadow` (if readable) — Group password hashes
- Check for weak or default credentials

## Shared Libraries & Library Paths
- `ldconfig -p` — Shared library cache
- Check LD_LIBRARY_PATH environment variable
- Look for missing or world-writable libraries
- Check /etc/ld.so.conf and /etc/ld.so.conf.d/

## Package Manager & Apt Configuration
- `cat /etc/apt/sources.list` — APT sources
- `ls /etc/apt/sources.list.d/` — Additional APT sources
- Check for insecure or unauthenticated sources

## Container/Virtualization Detection
- `cat /proc/cpuinfo` — CPU info (watch for hypervisor indicators)
- `cat /proc/1/cgroup` — Cgroup info (Docker/container detection)
- `cat /proc/cmdline` — Kernel command line

## Local Service Exploitation
- Identify vulnerable services and research:
  - Version-specific exploits
  - Default credentials
  - Configuration weaknesses
- Check service logs for useful information: `/var/log/`

## Common Misconfigurations
- SUID binaries with vulnerability history (older versions)
- Scripts in /etc/init.d or /usr/local/bin that are world-writable
- Misconfigured sudo rules (NOPASSWD, wildcard paths)
- World-writable cron jobs or startup scripts
- Weak file permissions on sensitive files (/etc/hosts, /etc/resolv.conf)
- Predictable file names in /tmp with insecure permissions

---
**Notes:**
- Systematic enumeration is critical; check every vector.
- Document all findings with timestamps and command output.
- Cross-reference discovered vulnerabilities with CVE databases and exploit PoCs.
- Privilege escalation attempts are your responsibility; this checklist is enumeration only.
- Always prioritize stability; avoid crashing services or systems.
"""

def write_checklist(os_name: str, out_dir: str) -> str:
    """
    Write the appropriate privilege escalation checklist to disk.
    
    Args:
        os_name: 'windows', 'linux', or 'unknown'
        out_dir: Directory to write the checklist file to
    
    Returns:
        Path to the written checklist file
    """
    os.makedirs(out_dir, exist_ok=True)
    
    if os_name.lower() == 'windows':
        filename = 'windows_checklist.md'
        content = WINDOWS_CHECKLIST
    elif os_name.lower() == 'linux':
        filename = 'linux_checklist.md'
        content = LINUX_CHECKLIST
    else:
        # For unknown, write both
        windows_path = os.path.join(out_dir, 'windows_checklist.md')
        linux_path = os.path.join(out_dir, 'linux_checklist.md')
        with open(windows_path, 'w') as f:
            f.write(WINDOWS_CHECKLIST)
        with open(linux_path, 'w') as f:
            f.write(LINUX_CHECKLIST)
        return windows_path  # Return primary path
    
    filepath = os.path.join(out_dir, filename)
    with open(filepath, 'w') as f:
        f.write(content)
    
    return filepath