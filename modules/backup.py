"""
modules/backup.py — Pre-hardening configuration backup.

Creates a timestamped snapshot of the current system configuration BEFORE any
hardening change is applied. This allows full rollback if needed.

Windows backup includes:
  - Security policy (secedit export → .inf)
  - Registry hives (HKLM\\SYSTEM, HKLM\\SOFTWARE, HKLM\\SECURITY)
  - Audit policy (auditpol → .csv)
  - Windows Firewall rules (.wfw)

Linux backup includes:
  - /etc/ssh/sshd_config, /etc/pam.d/, /etc/login.defs
  - /etc/security/pwquality.conf, /etc/security/limits.conf
  - /etc/sysctl.conf, /etc/sysctl.d/
  - /etc/ufw/, /etc/audit/, /etc/sudoers*
  - /etc/motd, /etc/issue, /etc/issue.net
  - Live sysctl dump (sysctl -a)
  - UFW status

See README.md → Rollback section for restore commands.
"""

import os
import platform
import shutil
import subprocess
from datetime import datetime

from modules.logger import get_logger, log_ok, log_warn


def create_backup_dir(base_dir: str) -> str:
    """
    Create a uniquely named backup directory under base_dir using the current
    timestamp (format: backup_YYYYMMDD_HHMMSS).

    Args:
        base_dir: Parent directory (e.g. project_root/backups/).

    Returns:
        Absolute path to the newly created backup directory.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(base_dir, f"backup_{timestamp}")
    os.makedirs(backup_path, exist_ok=True)
    get_logger().info(f"Backup directory created: {backup_path}")
    return backup_path


def _run_backup_cmd(cmd: list, label: str) -> bool:
    """
    Run a single backup command and log the result.

    Unlike the hardening helpers, this one returns a bool so the caller knows
    whether the backup step succeeded.  A failed backup step is a warning, not
    a fatal error — the hardening run will still proceed.

    Args:
        cmd:   Command + arguments as a list (passed to subprocess.run).
        label: Human-readable description for log output.

    Returns:
        True if the command exited with code 0, False otherwise.
    """
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            log_ok(f"Backup: {label}")
            return True
        else:
            log_warn(
                f"Backup '{label}' exited with code {result.returncode}: "
                f"{result.stderr.strip()[:200]}"
            )
            return False
    except FileNotFoundError:
        # The command (secedit, auditpol, etc.) is not available on this machine
        log_warn(f"Backup '{label}': command not found — skipping")
        return False
    except subprocess.TimeoutExpired:
        log_warn(f"Backup '{label}': timed out after 120s — skipping")
        return False
    except Exception as exc:
        log_warn(f"Backup '{label}': unexpected error — {exc}")
        return False


def backup_windows(backup_dir: str) -> None:
    """
    Export Windows system configuration to the backup directory.

    Files produced:
      secedit_backup.inf  — full local security policy (account policies,
                            user rights, security options)
      HKLM_SYSTEM.reg     — HKLM\\SYSTEM registry hive
      HKLM_SOFTWARE.reg   — HKLM\\SOFTWARE registry hive
      HKLM_SECURITY.reg   — HKLM\\SECURITY registry hive
      auditpol_backup.csv — advanced audit policy subcategory settings
      firewall_backup.wfw — Windows Firewall configuration

    Args:
        backup_dir: Directory where backup files will be written.
    """
    logger = get_logger()
    logger.info("Starting Windows backup...")

    # Export current security policy (account policies + user rights + security options)
    secedit_path = os.path.join(backup_dir, "secedit_backup.inf")
    _run_backup_cmd(
        ["secedit", "/export", "/cfg", secedit_path, "/quiet"],
        "secedit security policy"
    )

    # Export key registry hives that the hardening script will modify
    for hive, filename in [
        ("HKLM\\SYSTEM",   "HKLM_SYSTEM.reg"),
        ("HKLM\\SOFTWARE", "HKLM_SOFTWARE.reg"),
        ("HKLM\\SECURITY", "HKLM_SECURITY.reg"),
    ]:
        reg_path = os.path.join(backup_dir, filename)
        _run_backup_cmd(
            ["reg", "export", hive, reg_path, "/y"],
            f"Registry {hive}"
        )

    # Export advanced audit policy (all subcategories)
    auditpol_path = os.path.join(backup_dir, "auditpol_backup.csv")
    _run_backup_cmd(
        ["auditpol", "/backup", f"/file:{auditpol_path}"],
        "auditpol audit policy"
    )

    # Export Windows Firewall rules (all 3 profiles: domain, private, public)
    fw_path = os.path.join(backup_dir, "firewall_backup.wfw")
    _run_backup_cmd(
        ["netsh", "advfirewall", "export", fw_path],
        "Windows Firewall"
    )

    log_ok(f"Windows backup complete → {backup_dir}")


def backup_linux(backup_dir: str) -> None:
    """
    Copy Linux system configuration files to the backup directory.

    Each source path is flattened to a single filename by replacing '/' with '_'
    so that '/etc/ssh/sshd_config' becomes 'etc_ssh_sshd_config' in the backup.
    Directories are copied recursively.

    Also saves:
      sysctl_current.txt — output of 'sysctl -a' (live kernel parameters)
      ufw_status.txt     — output of 'ufw status verbose'

    Args:
        backup_dir: Directory where backup files will be written.
    """
    logger = get_logger()
    logger.info("Starting Linux backup...")

    # List of files and directories to copy verbatim
    sources = [
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d",
        "/etc/pam.d",
        "/etc/login.defs",
        "/etc/security/pwquality.conf",
        "/etc/security/limits.conf",
        "/etc/sysctl.conf",
        "/etc/sysctl.d",
        "/etc/ufw",
        "/etc/audit",
        "/etc/cron.allow",
        "/etc/at.allow",
        "/etc/motd",
        "/etc/issue",
        "/etc/issue.net",
        "/etc/sudoers",
        "/etc/sudoers.d",
    ]

    for src in sources:
        if not os.path.exists(src):
            # Not present on this system — silently skip
            continue

        # Flatten the path: /etc/ssh/sshd_config → etc_ssh_sshd_config
        dest = os.path.join(backup_dir, src.lstrip("/").replace("/", "_"))
        try:
            if os.path.isdir(src):
                shutil.copytree(src, dest, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dest)
            log_ok(f"Copied {src}")
        except PermissionError:
            log_warn(f"Permission denied reading {src} — skipping")
        except Exception as exc:
            log_warn(f"Could not copy {src}: {exc}")

    # Dump all live kernel parameters so we can verify what was active before
    sysctl_dump = os.path.join(backup_dir, "sysctl_current.txt")
    try:
        result = subprocess.run(
            ["sysctl", "-a"], capture_output=True, text=True, timeout=30
        )
        with open(sysctl_dump, "w") as f:
            f.write(result.stdout)
        log_ok("sysctl -a dump saved")
    except FileNotFoundError:
        log_warn("sysctl not found — skipping kernel parameter dump")
    except Exception as exc:
        log_warn(f"sysctl dump failed: {exc}")

    # Save current UFW firewall status for reference
    ufw_status = os.path.join(backup_dir, "ufw_status.txt")
    try:
        result = subprocess.run(
            ["ufw", "status", "verbose"], capture_output=True, text=True, timeout=10
        )
        with open(ufw_status, "w") as f:
            f.write(result.stdout)
        log_ok("UFW status saved")
    except FileNotFoundError:
        log_warn("ufw not found — skipping firewall status dump")
    except Exception as exc:
        log_warn(f"UFW status save failed: {exc}")

    log_ok(f"Linux backup complete → {backup_dir}")


def perform_backup(backup_base_dir: str) -> str:
    """
    Create a pre-hardening backup appropriate for the current OS.

    This is the main entry point called by harden.py.

    Args:
        backup_base_dir: Root backup directory (e.g. project_root/backups/).

    Returns:
        Path to the timestamped backup directory that was created.
    """
    backup_dir = create_backup_dir(backup_base_dir)

    if platform.system() == "Windows":
        backup_windows(backup_dir)
    else:
        backup_linux(backup_dir)

    return backup_dir
