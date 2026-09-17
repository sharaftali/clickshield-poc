"""
Centralized logging configuration.

Call `setup_logging()` once at application startup (in main.py lifespan).
Everywhere else, use:

    import logging
    logger = logging.getLogger(__name__)
"""
from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path

from app.core.config import settings


LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "clickshield.log"

# Consistent format across console and file
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Third-party loggers that are too noisy at INFO
NOISY_LOGGERS = {
    "uvicorn.access": logging.WARNING,
    "sqlalchemy.engine": logging.WARNING,
    "httpx": logging.WARNING,
    "httpcore": logging.WARNING,
    "asyncio": logging.WARNING,
}


def setup_logging() -> None:
    """
    Configure root logger with:
      - Console handler (stdout)
      - Rotating file handler (logs/clickshield.log)
    """
    LOG_DIR.mkdir(exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)

    # Avoid duplicate handlers on uvicorn --reload
    if root.handlers:
        root.handlers.clear()

    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    # ---- Console handler ----
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
    console.setFormatter(formatter)
    root.addHandler(console)

    # ---- Rotating file handler ----
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=10 * 1024 * 1024,   # 10 MB
        backupCount=5,                # keep clickshield.log.1 .. .5
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    # ---- Quiet down noisy libraries ----
    for name, level in NOISY_LOGGERS.items():
        logging.getLogger(name).setLevel(level)

    logging.getLogger(__name__).info(
        "Logging configured (file=%s, level=%s)",
        LOG_FILE,
        logging.getLevelName(root.level),
    )
