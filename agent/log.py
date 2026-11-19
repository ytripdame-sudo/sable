"""Logging setup.

The destination is resolved before any Win32 call, so a crash on the first API call
still leaves a trail. The file always records DEBUG. The debug flag only changes
what reaches the console, and under PyInstaller --noconsole there is no console at
all, which is why the file handler is attached explicitly instead of being left to
``basicConfig``'s stream handler.

Handlers are keyed on the logger, never on a module global. The payload carries its
own copy of this file, so two copies of the module both start with empty globals and
both attach a handler to the one logger named ``sable``: every line doubled, two
writers on one file. The logger object is the only thing both copies share.
"""

from __future__ import annotations

import logging
import os
import sys
import tempfile
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Final

LOG_NAME: Final[str] = "sable"
LOG_FILENAME: Final[str] = "sable.log"
LOG_MAX_BYTES: Final[int] = 2 * 1024 * 1024
LOG_BACKUPS: Final[int] = 1
LOG_FORMAT: Final[str] = "%(asctime)s %(levelname)-7s %(name)s %(message)s"

logger: Final[logging.Logger] = logging.getLogger(LOG_NAME)


def log_path() -> Path:
    """``%TEMP%\\sable.log``, falling back to the stdlib temp dir when TEMP is unset."""
    try:
        base = Path(os.environ["TEMP"])
    except KeyError:
        base = Path(tempfile.gettempdir())
    return base / LOG_FILENAME


def _file_handler() -> logging.Handler | None:
    path = log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = RotatingFileHandler(
            path,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUPS,
            encoding="utf-8",
            delay=False,
        )
    except OSError:
        # A locked or unwritable log must not stop the run; the console still works.
        return None
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    return handler


def _console_handler(debug: bool) -> logging.Handler | None:
    stream = sys.stderr
    if stream is None:
        # --noconsole gives the process no stderr; adding a StreamHandler(None)
        # would raise on the first record.
        return None
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.DEBUG if debug else logging.WARNING)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    return handler


def configure(debug: bool = False) -> logging.Logger:
    """Attach handlers once and set console verbosity. Safe to call repeatedly."""
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    if not any(isinstance(handler, RotatingFileHandler) for handler in logger.handlers):
        file_handler = _file_handler()
        if file_handler is not None:
            logger.addHandler(file_handler)

    # RotatingFileHandler subclasses StreamHandler, so it is excluded explicitly.
    for handler in [
        existing
        for existing in logger.handlers
        if isinstance(existing, logging.StreamHandler)
        and not isinstance(existing, RotatingFileHandler)
    ]:
        logger.removeHandler(handler)

    console = _console_handler(debug)
    if console is not None:
        logger.addHandler(console)

    return logger


__all__ = ["LOG_FILENAME", "configure", "log_path", "logger"]
