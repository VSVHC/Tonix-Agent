"""
logger.py
─────────
Centralised logging setup for the Tonix Agent.

Usage anywhere in the backend:
    from backend.logger import get_logger
    log = get_logger(__name__)
    log.info("Scan started")
    log.error("Something broke", exc_info=True)

Outputs:
  - Console  : coloured, human-readable
  - File     : logs/pentest_agent.log  (rotating, 10 MB × 5 backups)
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


# ── ANSI colour codes for console output ──────────────────
_RESET  = "\033[0m"
_GREY   = "\033[38;5;240m"
_CYAN   = "\033[36m"
_YELLOW = "\033[33m"
_RED    = "\033[31m"
_BOLD_RED = "\033[1;31m"

_LEVEL_COLOURS: dict[int, str] = {
    logging.DEBUG:    _GREY,
    logging.INFO:     _CYAN,
    logging.WARNING:  _YELLOW,
    logging.ERROR:    _RED,
    logging.CRITICAL: _BOLD_RED,
}


class _ColouredFormatter(logging.Formatter):
    """Console formatter that adds ANSI colours per log level."""

    FMT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    DATE = "%H:%M:%S"

    def format(self, record: logging.LogRecord) -> str:
        colour = _LEVEL_COLOURS.get(record.levelno, _RESET)
        formatter = logging.Formatter(
            fmt=f"{colour}{self.FMT}{_RESET}",
            datefmt=self.DATE,
        )
        return formatter.format(record)


class _PlainFormatter(logging.Formatter):
    """Plain formatter for file output (no ANSI codes)."""

    FMT  = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    DATE = "%Y-%m-%d %H:%M:%S"

    def __init__(self) -> None:
        super().__init__(fmt=self.FMT, datefmt=self.DATE)


# ── One-time setup flag ────────────────────────────────────
_configured = False


def configure_logging(
    level: str = "INFO",
    log_dir: Path | None = None,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
) -> None:
    """
    Call once at application startup (from main.py lifespan).
    Subsequent calls are no-ops.
    """
    global _configured
    if _configured:
        return
    _configured = True

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # ── Console handler ────────────────────────────────────
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(_ColouredFormatter())
    root.addHandler(console)

    # ── File handler ───────────────────────────────────────
    if log_dir:
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "pentest_agent.log"
        file_handler = RotatingFileHandler(
            filename=log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(_PlainFormatter())
        root.addHandler(file_handler)

    # Silence noisy third-party loggers
    for noisy in ("httpx", "httpcore", "asyncio", "aiosqlite"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger. Use as: log = get_logger(__name__)"""
    return logging.getLogger(name)
