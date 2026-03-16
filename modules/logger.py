"""
modules/logger.py — Logging setup for the hardening script.

Provides:
  - Colored console output (green=OK, yellow=WARN, red=FAIL)
  - Simultaneous write to a timestamped log file under logs/
  - Helper functions used throughout the hardening modules

Each log line follows the format:
  [ID] Setting name  old=<old_value>  new=<new_value>
"""

import logging
import os
import sys
from datetime import datetime

# ── ANSI escape codes for terminal color output ───────────────────────────────
# These are ignored when output is redirected to a file (isatty() check below).
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


class ColoredFormatter(logging.Formatter):
    """
    Custom log formatter that adds ANSI color codes to console output.
    Colors are only applied when writing to an actual terminal (not a pipe/file).
    """
    COLORS = {
        logging.DEBUG:    CYAN,
        logging.INFO:     GREEN,
        logging.WARNING:  YELLOW,
        logging.ERROR:    RED,
        logging.CRITICAL: RED + BOLD,
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, RESET)
        msg = super().format(record)
        # Only colorize when connected to a real terminal
        if sys.stdout.isatty():
            return f"{color}{msg}{RESET}"
        return msg


class PlainFormatter(logging.Formatter):
    """Plain formatter (no colors) used for the log file."""
    pass


# ── Module-level singletons ───────────────────────────────────────────────────
# These are set once by setup_logger() and reused by get_logger() / get_log_path().
_logger: logging.Logger | None = None
_log_path: str | None = None


def setup_logger(log_dir: str) -> logging.Logger:
    """
    Initialize the logger. Must be called once at startup before any other
    logging function is used.

    Creates:
      - A console handler with colored output (INFO level and above)
      - A file handler writing to logs/harden_YYYYMMDD_HHMMSS.log (DEBUG and above)

    Args:
        log_dir: Directory where the log file will be written (created if absent).

    Returns:
        The configured logger instance.
    """
    global _logger, _log_path

    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    _log_path = os.path.join(log_dir, f"harden_{timestamp}.log")

    # Retrieve (or create) the named logger; clear any previously attached handlers
    # so calling setup_logger() twice doesn't duplicate output.
    logger = logging.getLogger("harden")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # Console handler — INFO and above, colored when running in a terminal
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(ColoredFormatter("%(levelname)-8s %(message)s"))
    logger.addHandler(ch)

    # File handler — DEBUG and above, plain text with timestamps
    fh = logging.FileHandler(_log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(PlainFormatter("%(asctime)s %(levelname)-8s %(message)s"))
    logger.addHandler(fh)

    _logger = logger
    return logger


def get_logger() -> logging.Logger:
    """
    Return the active logger.
    If setup_logger() hasn't been called yet, falls back to the root 'harden'
    logger without file output (safe for --report-only invocations).
    """
    global _logger
    if _logger is None:
        _logger = logging.getLogger("harden")
    return _logger


def get_log_path() -> str | None:
    """
    Return the path of the current log file, or None if logging hasn't been
    initialized yet (e.g. --report-only mode before setup_logger()).
    """
    return _log_path


# ── Convenience helpers ───────────────────────────────────────────────────────
# These wrap the standard logger methods and provide a consistent format for
# status messages printed throughout the hardening modules.

def log_item(item_id: str, name: str, old_val=None, new_val=None, status: str = "OK") -> None:
    """
    Log a single hardening item showing its old and new values.

    Args:
        item_id:  CIS/ISSP identifier, e.g. "WDC-001" or "UBU-024".
        name:     Human-readable description of the setting.
        old_val:  Value before hardening (optional).
        new_val:  Value after hardening (optional).
        status:   "OK" | "WARN" | "SKIP" | "FAIL"
    """
    logger = get_logger()
    parts = [f"[{item_id}] {name}"]
    if old_val is not None:
        parts.append(f"old={old_val!r}")
    if new_val is not None:
        parts.append(f"new={new_val!r}")
    msg = "  ".join(parts)

    if status == "OK":
        logger.info(msg)
    elif status == "WARN":
        logger.warning(msg)
    elif status == "SKIP":
        logger.info(f"(SKIP) {msg}")
    else:
        logger.error(msg)


def log_section(title: str) -> None:
    """Print a prominent section header to visually separate hardening stages."""
    logger = get_logger()
    bar = "=" * 70
    logger.info(f"\n{bar}\n  {title}\n{bar}")


def log_ok(msg: str) -> None:
    """Log a successful operation."""
    get_logger().info(f"  [OK]   {msg}")


def log_warn(msg: str) -> None:
    """Log a non-fatal warning (setting skipped or partially applied)."""
    get_logger().warning(f"  [WARN] {msg}")


def log_fail(msg: str) -> None:
    """Log a failed operation (setting could not be applied)."""
    get_logger().error(f"  [FAIL] {msg}")


def log_skip(msg: str) -> None:
    """Log a deliberately skipped item (manual action required, or out of scope)."""
    get_logger().info(f"  [SKIP] {msg}")
