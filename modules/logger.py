"""
Colored console + file logging module.
Logs each hardening item: [ID] Setting name → old_value → new_value
"""

import logging
import os
import sys
from datetime import datetime

# ANSI color codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


class ColoredFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: CYAN,
        logging.INFO: GREEN,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: RED + BOLD,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, RESET)
        msg = super().format(record)
        if sys.stdout.isatty():
            return f"{color}{msg}{RESET}"
        return msg


class PlainFormatter(logging.Formatter):
    """No-color formatter for file output."""
    pass


_logger = None
_log_path = None


def setup_logger(log_dir: str) -> logging.Logger:
    global _logger, _log_path

    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    _log_path = os.path.join(log_dir, f"harden_{timestamp}.log")

    logger = logging.getLogger("harden")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # Console handler (colored)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(ColoredFormatter("%(levelname)-8s %(message)s"))
    logger.addHandler(ch)

    # File handler (plain text)
    fh = logging.FileHandler(_log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(PlainFormatter("%(asctime)s %(levelname)-8s %(message)s"))
    logger.addHandler(fh)

    _logger = logger
    return logger


def get_logger() -> logging.Logger:
    global _logger
    if _logger is None:
        _logger = logging.getLogger("harden")
    return _logger


def get_log_path() -> str:
    return _log_path or ""


def log_item(item_id: str, name: str, old_val=None, new_val=None, status: str = "OK"):
    """Log a hardening item with old→new values."""
    logger = get_logger()
    parts = [f"[{item_id}] {name}"]
    if old_val is not None:
        parts.append(f"  old={old_val!r}")
    if new_val is not None:
        parts.append(f"  new={new_val!r}")
    msg = "  ".join(parts)
    if status == "OK":
        logger.info(msg)
    elif status == "WARN":
        logger.warning(msg)
    elif status == "SKIP":
        logger.info(f"(SKIP) {msg}")
    else:
        logger.error(msg)


def log_section(title: str):
    logger = get_logger()
    bar = "=" * 70
    logger.info(f"\n{bar}\n  {title}\n{bar}")


def log_ok(msg: str):
    get_logger().info(f"  [OK]   {msg}")


def log_warn(msg: str):
    get_logger().warning(f"  [WARN] {msg}")


def log_fail(msg: str):
    get_logger().error(f"  [FAIL] {msg}")


def log_skip(msg: str):
    get_logger().info(f"  [SKIP] {msg}")
