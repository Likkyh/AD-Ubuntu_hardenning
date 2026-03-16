# Bidouille — AD DC + Ubuntu Hardening Script

Automated hardening script for **Windows Server 2025 Active Directory Domain Controllers** and **Ubuntu workstations**.

| Attribute | Value |
|-----------|-------|
| Company | Bidouille (automotive sector) |
| ISSP | ISO 27002 v2 |
| CIS Reference | CIS Microsoft Windows Server 2025 Benchmark v2.0.0 — Level 1 DC |
| Coverage | 351 Windows DC items + 113 Ubuntu items |

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Usage](#usage)
4. [What it does](#what-it-does)
5. [Verification](#verification)
6. [Rollback](#rollback)
7. [Reports](#reports)
8. [Not automated — manual actions required](#not-automated--manual-actions-required)
9. [Project structure](#project-structure)

---

## Prerequisites

### Windows Server 2025 (Domain Controller)

- Python 3.10+ installed ([python.org](https://python.org))
- Run PowerShell / CMD **as Administrator**
- AD DS role installed (`Install-WindowsFeature AD-Domain-Services`)
- RSAT tools available (`auditpol`, `secedit`, `netsh`, `reg`)
- Active Directory PowerShell module (`RSAT-AD-PowerShell`)

### Ubuntu (workstation/server)

- Ubuntu 20.04 LTS or later
- Python 3.8+
- `sudo` / root access

---

## Installation

```bash
# Clone the repository
git clone https://github.com/<your-org>/ad-hardening.git
cd ad-hardening

# Create Python virtual environment
python3 -m venv .venv

# Activate it
# Linux/macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Generate compliance report only (no changes applied)

Safe to run anywhere, no privileges required:

```bash
# Linux
.venv/bin/python3 harden.py --report-only

# Windows
.venv\Scripts\python harden.py --report-only
```

This generates:
- `IMPLEMENTATION.md` — full hardening table with status
- `IMPLEMENTATION.ods` — LibreOffice Calc sheet (color-coded)

---

### Full hardening run

> **Warning**: This modifies system configuration. Always run `--report-only` first and review the backup directory after each run.

**Windows (Domain Controller) — run as Administrator:**

```powershell
# In an elevated PowerShell or CMD
.venv\Scripts\python harden.py
```

**Ubuntu — run as root:**

```bash
sudo .venv/bin/python3 harden.py
```

**Skip backup (not recommended — only if storage is constrained):**

```bash
sudo .venv/bin/python3 harden.py --no-backup
```

**Override OS detection (for testing):**

```bash
.venv/bin/python3 harden.py --os-override ubuntu --report-only
```

---

## What it does

### Windows DC hardening

The script applies settings in this order:

| Step | Module / Method | CIS Sections |
|------|----------------|--------------|
| 1 | Account policies (secedit INF) | 1.1, 1.2 |
| 2 | User rights assignment (secedit INF) | 2.2 |
| 3 | Security options (secedit + registry) | 2.3 |
| 4 | UAC settings (registry) | 2.3.17 |
| 5 | Print Spooler disabled | 5.1 |
| 6 | Windows Firewall (all 3 profiles) | 9.x |
| 7 | Advanced Audit Policy (auditpol) | 17.x |
| 8 | Administrative Templates (registry) | 18.x |
| 9 | LAPS configuration | 18.9.26 |
| 10 | ISSP-specific (PSO, BitLocker) | ISSP §7.1/7.2/5.1 |

### Ubuntu hardening

| Step | Method | CIS/ISSP |
|------|--------|----------|
| 1 | sysctl kernel parameters | CIS 3.x |
| 2 | SSH daemon hardening | CIS 5.2 |
| 3 | PAM (pwquality + faillock + history) | CIS 5.4 |
| 4 | /etc/login.defs | CIS 5.4 |
| 5 | Disable unused services | CIS 2.x |
| 6 | UFW firewall | CIS 3.5 |
| 7 | auditd rules | CIS 4.x |
| 8 | File permissions | CIS 6.x |
| 9 | Filesystem (fstab, core dumps) | CIS 1.x |
| 10 | AppArmor enforce | CIS 1.7 |
| 11 | User account hardening | CIS 5.x |
| 12 | Cron/at restrictions | CIS 5.1.8 |
| 13 | GNOME screen lock (300s) | ISSP §4.2 |
| 14 | unattended-upgrades | ISSP §5.1 |
| 15 | AIDE file integrity | CIS 1.3 |
| 16 | rsyslog + logrotate + chrony | CIS 4.2 |
| 17 | System banners (/etc/motd, issue) | CIS 1.8 |
| 18 | Sudo configuration | CIS 5.3 |
| 19 | LUKS encryption check | ISSP §5.1 |
| 20 | Kernel module blacklist | CIS 1.1.x |

---

## Verification

### Windows DC

```powershell
# Check account policies
secedit /analyze /db secedit_verify.sdb /cfg hardening.inf /verbose

# Check audit policy
auditpol /get /category:*

# Check fine-grained password policies
Get-ADFineGrainedPasswordPolicy -Filter * | Format-Table Name,MinPasswordLength,MaxPasswordAge

# Check firewall status
netsh advfirewall show allprofiles state

# Check Spooler is disabled
Get-Service Spooler | Select-Object Name,Status,StartType

# Check registry values (example: UAC)
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System |
    Select-Object EnableLUA, ConsentPromptBehaviorAdmin, FilterAdministratorToken

# Check BitLocker
Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,EncryptionMethod
```

### Ubuntu

```bash
# Firewall
sudo ufw status verbose

# Kernel parameters
sysctl -a | grep -E 'ip_forward|syncookies|randomize_va|dmesg_restrict'

# SSH config
sudo sshd -T | grep -E 'permitrootlogin|maxauthtries|clientalive|ciphers'

# PAM password quality
cat /etc/security/pwquality.conf

# Audit rules
sudo auditctl -l

# AppArmor
sudo aa-status

# Login definitions
grep -E 'PASS_MAX|PASS_MIN|PASS_WARN|UMASK' /etc/login.defs

# Automatic updates
systemctl status unattended-upgrades

# AIDE (after 24h for initial DB)
sudo aide --check

# Services disabled
systemctl is-enabled avahi-daemon cups vsftpd 2>&1

# Check LUKS
lsblk -o NAME,TYPE,FSTYPE | grep crypt
```

---

## Rollback

### Windows DC

A timestamped backup is created in `backups/backup_YYYYMMDD_HHMMSS/` before each run. It contains:

| File | Content |
|------|---------|
| `secedit_backup.inf` | Full security policy export |
| `HKLM_SYSTEM.reg` | HKLM\SYSTEM registry hive |
| `HKLM_SOFTWARE.reg` | HKLM\SOFTWARE registry hive |
| `auditpol_backup.csv` | Audit policy settings |
| `firewall_backup.wfw` | Windows Firewall rules |

**Restore procedure:**

```powershell
# Restore security policy (account policies, user rights, security options)
secedit /configure /db secedit_restore.sdb /cfg backups\backup_YYYYMMDD_HHMMSS\secedit_backup.inf /overwrite

# Restore registry hives
reg import backups\backup_YYYYMMDD_HHMMSS\HKLM_SYSTEM.reg
reg import backups\backup_YYYYMMDD_HHMMSS\HKLM_SOFTWARE.reg

# Restore audit policy
auditpol /restore /file:backups\backup_YYYYMMDD_HHMMSS\auditpol_backup.csv

# Restore firewall
netsh advfirewall import backups\backup_YYYYMMDD_HHMMSS\firewall_backup.wfw
```

### Ubuntu

Backup files are stored in `backups/backup_YYYYMMDD_HHMMSS/`. Each backed-up file is named after its path with `/` replaced by `_`.

**Restore procedure:**

```bash
BACKUP_DIR="backups/backup_YYYYMMDD_HHMMSS"

# Restore SSH config
sudo cp "$BACKUP_DIR/etc_ssh_sshd_config" /etc/ssh/sshd_config
sudo systemctl restart ssh

# Restore PAM
sudo cp -r "$BACKUP_DIR/etc_pam.d" /etc/pam.d/

# Restore login.defs
sudo cp "$BACKUP_DIR/etc_login.defs" /etc/login.defs

# Restore sysctl
sudo cp "$BACKUP_DIR/etc_sysctl.conf" /etc/sysctl.conf
sudo rm -f /etc/sysctl.d/99-cis-hardening.conf
sudo sysctl -p

# Restore sudoers
sudo cp "$BACKUP_DIR/etc_sudoers" /etc/sudoers
sudo rm -f /etc/sudoers.d/cis-hardening

# Remove audit rules
sudo rm -f /etc/audit/rules.d/99-cis-hardening.rules
sudo systemctl restart auditd

# Remove UFW rules (re-enable original policy)
sudo ufw --force reset

# Remove kernel module blacklist
sudo rm -f /etc/modprobe.d/cis-hardening.conf

# Restore motd/issue
sudo cp "$BACKUP_DIR/etc_motd" /etc/motd
sudo cp "$BACKUP_DIR/etc_issue" /etc/issue
sudo cp "$BACKUP_DIR/etc_issue.net" /etc/issue.net
```

> **Note**: sysctl changes from the running kernel are lost on reboot. If you rollback before rebooting, also run `sudo sysctl -p /path/to/original/sysctl.conf`.

---

## Reports

The script generates two compliance reports:

### `IMPLEMENTATION.md`

A Markdown table with all 464 hardening items, their status, and reasons for any items not automated.

```
| ID      | Category     | Hardening Point         | Source    | Status          | Reason |
|---------|-------------|-------------------------|-----------|-----------------|--------|
| WDC-001 | Account Policy | Password history = 24 | CIS 1.1.1 | Implemented     |        |
| WDC-344 | ISSP        | Breakglass account      | ISSP §8   | Not Implemented | Procedural: ... |
```

### `IMPLEMENTATION.ods`

LibreOffice Calc spreadsheet with 3 sheets:

| Sheet | Contents |
|-------|----------|
| **Windows DC** | All WDC-xxx items |
| **Ubuntu** | All UBU-xxx items |
| **Summary** | Item counts by OS and status |

Color coding:
- 🟢 Green — `Implemented`
- 🔴 Red — `Not Implemented`
- 🟡 Yellow — `Manual` (procedural, cannot be automated)

---

## Not automated — manual actions required

These items require human intervention. They are documented in `IMPLEMENTATION.md` with full justification.

### Windows DC

| ID | Item | Action required |
|----|------|----------------|
| WDC-344 | Emergency breakglass account | Print password, seal in envelope, store in physical safe (ISSP §8) |
| WDC-345 | Account deactivation lifecycle | Configure HR/IAM integration for 90-day disable → day 91 delete |
| WDC-346 | CMDB inventory | Maintain asset inventory — script produces a point-in-time snapshot only |
| WDC-347 | VPN enforcement | Configure VPN gateway (OpenVPN/WireGuard/other) |
| WDC-349 | Centralized AV management | Deploy SCCM/Intune or dedicated AV management server |
| WDC-350 | Offsite backup | Configure backup infrastructure with offsite replication |
| WDC-351 | Separate admin accounts | Enforce naming convention `adm_<username>` for all admin accounts |

### Ubuntu

| ID | Item | Action required |
|----|------|----------------|
| UBU-036 | SSH key-only auth | Pre-deploy SSH keys for all admins, then set `PasswordAuthentication no` |
| UBU-037 | AllowGroups/AllowUsers | Define authorized SSH groups for this machine and add to sshd_config |
| UBU-086 | GRUB password | Run `grub-mkpasswd-pbkdf2`, add hash to `/etc/grub.d/40_custom`, `update-grub` |
| UBU-111 | USB storage disable | Run `echo 'install usb-storage /bin/true' >> /etc/modprobe.d/usb.conf` if no USB needed |
| UBU-113 | VPN enforcement | Install and configure VPN client (OpenVPN/WireGuard) |

---

## Project structure

```
.
├── harden.py                   # Main entry point
├── requirements.txt            # Python dependencies (odfpy)
├── IMPLEMENTATION.md           # Compliance table (auto-generated)
├── .gitignore
├── README.md
├── modules/
│   ├── __init__.py
│   ├── logger.py               # Colored console + file logging
│   ├── backup.py               # Pre-hardening backup
│   ├── report.py               # IMPLEMENTATION.md + .ods generation
│   ├── windows_dc.py           # Windows Server 2025 DC hardening
│   └── ubuntu.py               # Ubuntu workstation hardening
├── backups/                    # Auto-created — gitignored (sensitive)
└── logs/                       # Auto-created — gitignored
```

---

## License

Internal use only — Bidouille. Not for public distribution.
