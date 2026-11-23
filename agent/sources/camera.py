"""One webcam frame, bounded by a wall clock the camera does not control.

The collector is the caller that owns the clock, so the hard part is not the capture —
``media.grab`` has that — it is the fact that a Media Foundation call on a wedged driver
never returns. A driver that has the device open, a USB controller mid-reset, a privacy
setting that lets the open succeed and the read hang: none of these raise, they block.

So the grab runs on a daemon thread the collector stops waiting for at three seconds.
If the thread is still inside ``grab`` when the wait expires, the outcome is ``timeout``,
the thread is left to die with the process, and the run continues. The daemon flag is
what makes that safe: a straggler cannot hold the interpreter open after the archive has
shipped.

The three non-ok outcomes are kept apart on purpose. ``no device`` is a laptop without a
camera; ``blocked`` is a camera the privacy setting refused; ``busy`` is a camera another
process is already reading. Only the last two say anything about the machine's state, and
collapsing them into ``error`` would throw that away.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Final

from .. import log, media, util

# The whole module's contract, including opening the device. A camera that has not
# delivered a frame in three seconds is not going to.
MAX_MILLIS: Final[int] = 3000

# The frame. One JPEG, quality set by the encoder's default.
FRAME_MEMBER: Final[str] = "camera.jpg"
STATUS_MEMBER: Final[str] = "camera.json"


def _grab_into(destination: Path, box: list[media.Outcome]) -> None:
    """Body of the worker thread. Any exception becomes an outcome, never a traceback."""
    try:
        box.append(media.grab(destination))
    except BaseException as exc:  # a driver can raise from inside ctypes
        outcome = media.Outcome()
        outcome.status = media.ERROR
        outcome.reason = f"{type(exc).__name__}: {exc}"[:120]
        box.append(outcome)


def run(out_dir: Path, cfg: Any) -> int:
    """Capture one frame into ``camera.jpg`` and record how it went. Returns files written.

    Always writes ``camera.json``, including when nothing was captured: the report is the
    point. Returns 1 for a frame and 0 for a reason, and never raises — a missing camera
    is a normal run.
    """
    del cfg  # the caller's budget is not per-run tunable

    destination = out_dir / FRAME_MEMBER
    box: list[media.Outcome] = []
    started = time.perf_counter()

    worker = threading.Thread(
        target=_grab_into,
        args=(destination, box),
        name="sable-camera",
        daemon=True,
    )
    worker.start()
    worker.join(MAX_MILLIS / 1000.0)

    if worker.is_alive():
        # The driver never answered. The frame it may still write is not trustworthy and
        # the file it may have opened is not closed, but both die with the process.
        outcome = media.Outcome(status=media.TIMEOUT)
        outcome.reason = f"device did not answer within {MAX_MILLIS} ms"
        outcome.millis = round((time.perf_counter() - started) * 1000)
        log.logger.warning("camera: abandoned after %d ms", outcome.millis)
    elif box:
        outcome = box[0]
    else:
        outcome = media.Outcome(status=media.ERROR)
        outcome.reason = "collector returned no outcome"

    # A timeout may have left a truncated JPEG behind. The report says timeout, so the
    # file must not contradict it.
    if outcome.status != media.OK:
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            log.logger.debug("camera: could not drop %s", destination, exc_info=True)
        outcome.bytes = 0

    report: dict[str, Any] = {
        "captured": outcome.status == media.OK,
        "budget": {"max_millis": MAX_MILLIS},
        "file": FRAME_MEMBER if outcome.status == media.OK else "",
        **outcome.as_dict(),
    }

    util.write_json(out_dir / STATUS_MEMBER, report)

    if outcome.status == media.OK:
        log.logger.debug(
            "camera: %dx%d %d bytes in %d ms from %s",
            outcome.width,
            outcome.height,
            outcome.bytes,
            outcome.millis,
            outcome.device,
        )
        return 1

    log.logger.debug(
        "camera: %s (%s) after %d ms", outcome.status, outcome.reason, outcome.millis
    )
    return 0


__all__ = ["FRAME_MEMBER", "MAX_MILLIS", "STATUS_MEMBER", "run"]
