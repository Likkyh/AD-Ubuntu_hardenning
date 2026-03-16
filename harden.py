#!/usr/bin/env python3
"""
harden.py — Bidouille AD DC + Ubuntu Hardening Script
======================================================
Single entry point that auto-detects the OS and dispatches to the appropriate
hardening module.

Behaviour:
  Windows Server 2025 (detected as Domain Controller)
    → modules/windows_dc.py  (CIS L1 DC + ISSP)
  Ubuntu / Debian Linux
    → modules/ubuntu.py      (CIS Ubuntu + ISSP)

Usage:
  Windows (as Administrator):   python harden.py
  Linux   (as root):            sudo python3 harden.py
  Report only (no changes):     python3 harden.py --report-only
  Skip backup:                  python3 harden.py --no-backup
  Override OS detection:        python3 harden.py --os-override ubuntu

Company:  Bidouille (automotive sector)
ISSP:     ISO 27002 v2
CIS Ref:  CIS Microsoft Windows Server 2025 Benchmark v2.0.0 — Level 1 DC
"""

import argparse
import os
import platform
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ── Project root paths ────────────────────────────────────────────────────────
# All relative paths (logs/, backups/, reports) are anchored here so the script
# works correctly regardless of the working directory it is launched from.
SCRIPT_DIR = Path(__file__).parent.resolve()
LOG_DIR    = SCRIPT_DIR / "logs"
BACKUP_DIR = SCRIPT_DIR / "backups"

# Make local modules importable when the script is invoked directly
sys.path.insert(0, str(SCRIPT_DIR))


def _banner() -> None:
    """Print a startup banner with the script title and current timestamp."""
    width = 70
    print("=" * width)
    print("  Bidouille — System Hardening Script".center(width))
    print("  CIS Windows Server 2025 L1 DC + ISSP ISO 27002 v2".center(width))
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(width))
    print("=" * width)
    print()


def _detect_os() -> tuple[str, bool]:
    """
    Auto-detect the operating system and whether this machine is an AD DC.

    On Windows, the Domain Controller role is identified via WMI's
    Win32_ComputerSystem.DomainRole property:
      0 = Standalone Workstation
      1 = Member Workstation
      2 = Standalone Server
      3 = Member Server
      4 = Backup Domain Controller
      5 = Primary Domain Controller

    Returns:
        (os_type, is_dc) where:
          os_type: "windows" | "ubuntu" | "debian" | "linux" | "unknown"
          is_dc:   True only when running on a Windows DC (roles 4 or 5)
    """
    system = platform.system()

    if system == "Windows":
        is_dc = False
        try:
            result = subprocess.run(
                [
                    "powershell", "-NonInteractive", "-NoProfile", "-Command",
                    "(Get-WmiObject Win32_ComputerSystem).DomainRole"
                ],
                capture_output=True, text=True, timeout=15
            )
            role = result.stdout.strip()
            # Roles 4 and 5 are DC roles
            is_dc = role in ("4", "5")
        except FileNotFoundError:
            # PowerShell not found — unlikely on a real Windows machine
            print("[WARN] PowerShell not found; cannot determine DC role.")
        except subprocess.TimeoutExpired:
            print("[WARN] DC role detection timed out; defaulting to non-DC.")
        except OSError as exc:
            # Covers WinError, permission issues launching powershell, etc.
            print(f"[WARN] DC role detection failed ({exc}); defaulting to non-DC.")
        return "windows", is_dc

    elif system == "Linux":
        # Read /etc/os-release to determine the specific Linux distribution
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
            # /etc/os-release missing — very unusual, treat as generic Linux
            return "linux", False

    return "unknown", False


def _check_privileges(os_type: str) -> bool:
    """
    Verify that the script is running with the privileges required to modify
    system configuration.

    Windows: must be run as Administrator (elevated token).
    Linux:   must be run as root (UID 0).

    Args:
        os_type: "windows" | "ubuntu" | "debian" | "linux"

    Returns:
        True if sufficient privileges are detected, False otherwise.
    """
    if os_type == "windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            # ctypes or windll not available — assume not elevated
            return False
    else:
        # On POSIX systems, UID 0 means root
        return os.geteuid() == 0


def main() -> int:
    """
    Parse arguments, detect the environment, run the backup, dispatch to the
    correct hardening module, and generate compliance reports.

    Returns:
        Exit code: 0 = success, 1 = error (unsupported OS, missing privileges…)
    """
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
        help="Force a specific OS profile instead of auto-detecting"
    )
    args = parser.parse_args()

    _banner()

    # ── Logging setup ─────────────────────────────────────────────────────────
    from modules.logger import setup_logger, log_ok, log_warn, get_log_path
    logger = setup_logger(str(LOG_DIR))
    logger.info(f"Log file: {get_log_path()}")

    # ── OS detection ──────────────────────────────────────────────────────────
    if args.os_override:
        # Manual override: treat the given OS as the target.
        # When overriding to "windows" we assume DC because that is the only
        # Windows profile this script supports.
        os_type = args.os_override
        is_dc   = (os_type == "windows")
        logger.info(f"OS override applied: {os_type} (is_dc={is_dc})")
    else:
        os_type, is_dc = _detect_os()

    logger.info(f"Target OS : {os_type}  |  Domain Controller: {is_dc}")
    logger.info(f"Python    : {sys.version.split()[0]}")
    logger.info(f"Platform  : {platform.platform()}")
    logger.info(f"Hostname  : {platform.node()}")
    logger.info("")

    # ── Report-only mode ──────────────────────────────────────────────────────
    # Generates IMPLEMENTATION.md + IMPLEMENTATION.ods without touching the
    # system configuration.  Safe to run on any machine, no privileges needed.
    if args.report_only:
        logger.info("Report-only mode — generating compliance reports (no changes applied)")
        from modules.report import generate_reports
        generate_reports(str(SCRIPT_DIR))
        logger.info("Done.")
        return 0

    # ── Privilege check ───────────────────────────────────────────────────────
    if not _check_privileges(os_type):
        logger.error("Insufficient privileges. This script must run as:")
        if os_type == "windows":
            logger.error("  → Administrator  (right-click → Run as Administrator)")
        else:
            logger.error("  → root           (sudo python3 harden.py)")
        return 1

    log_ok("Running with sufficient privileges")

    # ── Pre-hardening backup ──────────────────────────────────────────────────
    if not args.no_backup:
        from modules.backup import perform_backup
        logger.info("Creating pre-hardening backup (do not interrupt)...")
        backup_path = perform_backup(str(BACKUP_DIR))
        logger.info(f"Backup saved to: {backup_path}")
    else:
        log_warn("Backup skipped (--no-backup). Rollback will not be possible.")

    # ── Hardening dispatch ────────────────────────────────────────────────────
    exit_code = 0

    if os_type == "windows":
        if not is_dc:
            log_warn(
                "This machine does not appear to be a Domain Controller "
                "(DomainRole not 4 or 5). Applying DC profile anyway — "
                "some DC-specific settings may fail silently."
            )
        from modules.windows_dc import harden
        harden()

    elif os_type in ("ubuntu", "debian", "linux"):
        from modules.ubuntu import harden
        harden()

    else:
        logger.error(
            f"Unsupported OS: '{os_type}'. "
            "Supported targets: Windows Server 2025 (DC), Ubuntu / Debian Linux."
        )
        exit_code = 1

    # ── Compliance reports ────────────────────────────────────────────────────
    # Always generate reports at the end of a run (even if some items failed)
    # so the admin has a full picture of what was and wasn't applied.
    logger.info("\nGenerating compliance reports...")
    try:
        from modules.report import generate_reports
        generate_reports(str(SCRIPT_DIR))
    except Exception as exc:
        log_warn(f"Report generation failed: {exc}")

    # ── Run summary ───────────────────────────────────────────────────────────
    log_file = get_log_path()
    print()
    print("=" * 70)
    print("  Hardening run complete.")
    print(f"  Log    : {log_file}")
    print(f"  Report : {SCRIPT_DIR / 'IMPLEMENTATION.md'}")
    print(f"  Sheet  : {SCRIPT_DIR / 'IMPLEMENTATION.ods'}")
    if not args.no_backup:
        print(f"  Backup : {BACKUP_DIR}")
    print("=" * 70)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
