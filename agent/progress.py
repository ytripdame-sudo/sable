"""Upload progress, one shape for every channel.

An archive takes minutes to leave on a slow uplink and the relay is the only thing
standing between a finished run and a delivered one. Without a line in the log, "still
uploading" and "hung on a dead socket" look identical for as long as the timeout lasts.

The reporter is deliberately dumb: bytes sent, a percentage, and a rate. It is called
from inside the request body's iterator, so it measures what the socket actually pulled
rather than what the file contains — a send that stalls at 40% is visible as a stall.

Throttled by whole percent. A 200 MB archive at 1 MiB per chunk is two hundred calls;
printing each one would spend more time in the log than in the upload.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Final

from . import log

# One line per this many percent.
STEP: Final[int] = 5

Report = Callable[[int, int, int, float], None]


def _size(count: int) -> str:
    if count >= 1024 * 1024 * 1024:
        return f"{count / (1024 ** 3):.2f} GiB"
    if count >= 1024 * 1024:
        return f"{count / (1024 ** 2):.1f} MiB"
    if count >= 1024:
        return f"{count / 1024:.1f} KiB"
    return f"{count} B"


class Reporter:
    """Tracks one upload. ``advance`` is safe to call from any thread.

    A reporter that fails to report never fails the upload: an exception inside the
    callback is logged once and the counter keeps going. The upload is the job; the
    line is a courtesy.
    """

    def __init__(
        self,
        total: int,
        report: Report | None = None,
        *,
        step: int = STEP,
        label: str = "upload",
    ) -> None:
        self.total = max(1, int(total))
        self.sent = 0
        self.label = label
        self._step = max(1, int(step))
        self._report = report
        self._last = -1
        self._started = time.monotonic()
        self._warned = False

    @property
    def percent(self) -> int:
        return min(100, self.sent * 100 // self.total)

    def expect(self, total: int) -> None:
        """Correct the total before the first byte goes out.

        The caller knows how big the *file* is; the sink counts the bytes the socket
        actually pulls, which is the multipart body around it. Measured in the guest:
        ``11.5 KiB of 10.6 KiB`` on a 10.6 KiB archive, because the boundary and the
        field headers were counted into a total that did not include them. The body
        knows its own length before the first block, so this replaces the estimate with
        the number the sent count is actually measured against.
        """
        if total > 0:
            self.total = int(total)

    @property
    def elapsed(self) -> float:
        return max(0.0, time.monotonic() - self._started)

    def advance(self, count: int) -> None:
        """Add ``count`` sent bytes and report when the percentage has moved enough."""
        if count <= 0:
            return
        self.sent += int(count)
        percent = self.percent
        if self._last < 0 or percent >= self._last + self._step or percent >= 100:
            self._emit(percent, force=False)

    def finish(self) -> None:
        """Report the final state once, whatever the last step was."""
        self._emit(self.percent, force=True)

    def _emit(self, percent: int, *, force: bool) -> None:
        if self._report is None:
            return
        if not force and percent <= self._last:
            return
        self._last = percent
        try:
            self._report(percent, self.sent, self.total, self.elapsed)
        except Exception:
            if not self._warned:
                self._warned = True
                log.logger.debug("progress: reporter raised", exc_info=True)


def log_reporter(label: str = "upload") -> Report:
    """A report function that writes one line per step at debug level."""

    def report(percent: int, sent: int, total: int, elapsed: float) -> None:
        rate = sent / elapsed if elapsed > 0 else 0.0
        log.logger.debug(
            "%s: %d%% %s of %s at %s/s",
            label,
            percent,
            _size(sent),
            _size(total),
            _size(int(rate)),
        )

    return report


def quiet_reporter() -> Report:
    """A report function that does nothing. Used by tests that only care about ordering."""

    def report(percent: int, sent: int, total: int, elapsed: float) -> None:
        del percent, sent, total, elapsed

    return report


__all__ = ["STEP", "Report", "Reporter", "log_reporter", "quiet_reporter"]
