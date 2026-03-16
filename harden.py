#!/usr/bin/env python3
"""
harden.py — Bidouille AD DC + Ubuntu Hardening Script
======================================================
Auto-detects OS and applies CIS/ISSP hardening.

Usage:
  Windows (as Administrator):  python harden.py
  Linux (as root):             sudo python3 harden.py
  Report only (any OS):        python3 harden.py --report-only
  Skip backup:                 python3 harden.py --no-backup

Company:  Bidouille (automotive sector)
ISSP:     ISO 27002 v2
CIS Ref:  CIS Microsoft Windows Server 2025 Benchmark v2.0.0 — Level 1 DC
"""

import argparse
import os
import platform
import sys
from datetime import datetime
from pathlib import Path

# ─── Project root ─────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent.resolve()
LOG_DIR = SCRIPT_DIR / "logs"
BACKUP_DIR = SCRIPT_DIR / "backups"

# ─── Ensure modules are importable ────────────────────────────────────────────
sys.path.insert(0, str(SCRIPT_DIR))


def _banner():
    width = 70
    print("=" * width)
    print("  Bidouille — System Hardening Script".center(width))
    print("  CIS Windows Server 2025 L1 DC + ISSP ISO 27002 v2".center(width))
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(width))
    print("=" * width)
    print()


def _detect_os() -> tuple[str, bool]:
    """
    Returns (os_type, is_dc) where:
      os_type: 'windows' | 'ubuntu' | 'linux' | 'unknown'
      is_dc:   True if Windows Domain Controller
    """
    system = platform.system()

    if system == "Windows":
        # Check if this is a Domain Controller
        try:
            import subprocess
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-NoProfile", "-Command",
                 "(Get-WmiObject Win32_ComputerSystem).DomainRole"],
                capture_output=True, text=True, timeout=15
            )
            role = result.stdout.strip()
            # DomainRole: 4 = Backup DC, 5 = Primary DC
            is_dc = role in ("4", "5")
        except Exception:
            is_dc = False
        return "windows", is_dc

    elif system == "Linux":
        # Check Linux distro
        try:
            with open("/etc/os-release") as f:
                content = f.read().lower()
            if "ubuntu" in content:
                return "ubuntu", False
            elif "debian" in content:
                return "debian", False
            else:
                return "linux", False
        except FileNotFoundError:
            return "linux", False

    return "unknown", False


def _check_privileges(os_type: str) -> bool:
    """Verify the script is running with admin/root privileges."""
    if os_type == "windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def main():
    parser = argparse.ArgumentParser(
        description="Bidouille System Hardening Script — CIS/ISSP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Generate IMPLEMENTATION.md and .ods without applying any changes"
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip pre-hardening backup (not recommended)"
    )
    parser.add_argument(
        "--os-override",
        choices=["windows", "ubuntu", "linux"],
        help="Override OS detection (for testing)"
    )
    args = parser.parse_args()

    _banner()

    # ── Setup logging ──
    from modules.logger import setup_logger, get_logger, log_ok, log_warn, log_fail
    logger = setup_logger(str(LOG_DIR))
    from modules.logger import get_log_path
    logger.info(f"Log file: {get_log_path()}")

    # ── OS detection ──
    if args.os_override:
        os_type = args.os_override
        is_dc = (os_type == "windows")
        logger.info(f"OS override: {os_type} (is_dc={is_dc})")
    else:
        os_type, is_dc = _detect_os()

    logger.info(f"Detected OS: {os_type} | Domain Controller: {is_dc}")
    logger.info(f"Python: {sys.version}")
    logger.info(f"Platform: {platform.platform()}")
    logger.info(f"Hostname: {platform.node()}")
    logger.info("")

    # ── Report-only mode ──
    if args.report_only:
        logger.info("Report-only mode — generating IMPLEMENTATION.md and IMPLEMENTATION.ods")
        from modules.report import generate_reports
        generate_reports(str(SCRIPT_DIR))
        logger.info("Done. No system changes were made.")
        return 0

    # ── Privilege check ──
    if not _check_privileges(os_type):
        logger.error(
            "This script must be run as Administrator (Windows) or root (Linux)."
        )
        if os_type == "windows":
            logger.error("Right-click your terminal and select 'Run as Administrator'.")
        else:
            logger.error("Run: sudo python3 harden.py")
        return 1

    log_ok(f"Running with sufficient privileges")

    # ── Backup ──
    if not args.no_backup:
        from modules.backup import perform_backup
        logger.info("Creating pre-hardening backup...")
        backup_path = perform_backup(str(BACKUP_DIR))
        logger.info(f"Backup saved to: {backup_path}")
    else:
        log_warn("Backup skipped (--no-backup flag)")

    # ── Hardening ──
    exit_code = 0
    if os_type == "windows":
        if is_dc:
            logger.info("Target: Windows Server 2025 Domain Controller")
            from modules.windows_dc import harden
            harden()
        else:
            logger.warning(
                "This machine does not appear to be a Domain Controller. "
                "Applying Windows DC hardening anyway (some DC-specific settings may not apply)."
            )
            from modules.windows_dc import harden
            harden()

    elif os_type in ("ubuntu", "linux", "debian"):
        logger.info(f"Target: {os_type.capitalize()} workstation/server")
        from modules.ubuntu import harden
        harden()

    else:
        logger.error(f"Unsupported OS: {os_type}. Supported: Windows, Ubuntu/Debian Linux.")
        exit_code = 1

    # ── Generate reports ──
    logger.info("\nGenerating compliance reports...")
    try:
        from modules.report import generate_reports
        generate_reports(str(SCRIPT_DIR))
    except Exception as e:
        log_warn(f"Report generation failed: {e}")

    # ── Summary ──
    from modules.logger import get_log_path
    log_file = get_log_path()
    print()
    print("=" * 70)
    print("  Hardening run complete.")
    print(f"  Log:    {log_file}")
    print(f"  Report: {SCRIPT_DIR / 'IMPLEMENTATION.md'}")
    print(f"  Sheet:  {SCRIPT_DIR / 'IMPLEMENTATION.ods'}")
    if not args.no_backup:
        print(f"  Backup: {BACKUP_DIR}")
    print("=" * 70)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
