"""
Backup module: exports current configuration before hardening.
Windows: secedit, registry, auditpol, firewall
Linux: sshd_config, PAM, sysctl, ufw, audit
"""

import os
import platform
import shutil
import subprocess
from datetime import datetime

from modules.logger import get_logger, log_ok, log_warn, log_fail


def create_backup_dir(base_dir: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(base_dir, f"backup_{timestamp}")
    os.makedirs(backup_path, exist_ok=True)
    get_logger().info(f"Backup directory: {backup_path}")
    return backup_path


def _run(cmd, backup_dir: str, label: str):
    logger = get_logger()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            log_ok(f"Backup: {label}")
        else:
            log_warn(f"Backup {label} returned code {result.returncode}: {result.stderr.strip()}")
    except Exception as e:
        log_warn(f"Backup {label} failed: {e}")


def backup_windows(backup_dir: str):
    logger = get_logger()
    logger.info("Starting Windows backup...")

    # secedit export
    secedit_path = os.path.join(backup_dir, "secedit_backup.inf")
    _run(
        ["secedit", "/export", "/cfg", secedit_path, "/quiet"],
        backup_dir, "secedit policy"
    )

    # Registry exports
    for hive, filename in [
        ("HKLM\\SYSTEM", "HKLM_SYSTEM.reg"),
        ("HKLM\\SOFTWARE", "HKLM_SOFTWARE.reg"),
        ("HKLM\\SECURITY", "HKLM_SECURITY.reg"),
    ]:
        reg_path = os.path.join(backup_dir, filename)
        _run(
            ["reg", "export", hive, reg_path, "/y"],
            backup_dir, f"Registry {hive}"
        )

    # Audit policy
    auditpol_path = os.path.join(backup_dir, "auditpol_backup.csv")
    _run(
        ["auditpol", "/backup", f"/file:{auditpol_path}"],
        backup_dir, "auditpol"
    )

    # Firewall
    fw_path = os.path.join(backup_dir, "firewall_backup.wfw")
    _run(
        ["netsh", "advfirewall", "export", fw_path],
        backup_dir, "Windows Firewall"
    )

    log_ok(f"Windows backup complete → {backup_dir}")


def backup_linux(backup_dir: str):
    logger = get_logger()
    logger.info("Starting Linux backup...")

    # Files and directories to copy
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
            continue
        dest = os.path.join(backup_dir, src.lstrip("/").replace("/", "_"))
        try:
            if os.path.isdir(src):
                shutil.copytree(src, dest, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dest)
            log_ok(f"Copied {src}")
        except Exception as e:
            log_warn(f"Could not copy {src}: {e}")

    # sysctl dump
    sysctl_dump = os.path.join(backup_dir, "sysctl_current.txt")
    try:
        result = subprocess.run(
            ["sysctl", "-a"], capture_output=True, text=True, timeout=30
        )
        with open(sysctl_dump, "w") as f:
            f.write(result.stdout)
        log_ok("sysctl -a dump saved")
    except Exception as e:
        log_warn(f"sysctl dump failed: {e}")

    # UFW status
    ufw_status = os.path.join(backup_dir, "ufw_status.txt")
    try:
        result = subprocess.run(
            ["ufw", "status", "verbose"], capture_output=True, text=True, timeout=10
        )
        with open(ufw_status, "w") as f:
            f.write(result.stdout)
        log_ok("UFW status saved")
    except Exception as e:
        log_warn(f"UFW status save failed: {e}")

    log_ok(f"Linux backup complete → {backup_dir}")


def perform_backup(backup_base_dir: str) -> str:
    backup_dir = create_backup_dir(backup_base_dir)
    system = platform.system()
    if system == "Windows":
        backup_windows(backup_dir)
    else:
        backup_linux(backup_dir)
    return backup_dir
