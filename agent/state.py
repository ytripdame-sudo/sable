"""Run state: what finished, what is left, and where the half-built archive is.

A collection that dies at module five restarts at module one and leaves a partial
workspace behind. On a slow profile set that is minutes of duplicated work and a folder
of half-written files that the next run steps on.

The file is small (under a kilobyte), written after every module, and replaced
atomically: a crash can lose the module that was running, never the ones before it. It
lives beside the delivery queue because the two answer the same question — "is there
something on this machine that still needs to leave?" — and a machine that reboots with
a sealed archive waiting is the same case as one with a half-collected workspace.

Rules, and the reason each exists:

- ``stage: collecting`` is the only stage that trusts the workspace. A resume wipes any
  module directory that is not marked done, so a half-written cookie dump cannot be
  archived by accident.
- ``stage: collected`` is the only stage that trusts the archive. Collection is skipped
  entirely and the run goes straight to sealing and delivery.
- Older than ``resume_hours`` or a different image path means a different machine state:
  start fresh rather than resume somebody else's run.
"""

from __future__ import annotations

import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from . import log, util

STATE_VERSION: Final[int] = 1
STATE_FILE: Final[str] = "state.json"
RESUME_HOURS: Final[int] = 6


def _utc() -> str:
    return datetime.now(tz=UTC).isoformat()


def _root() -> Path:
    path = util.queue_root()
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        log.logger.debug("state: cannot create %s", path, exc_info=True)
    return path


class State:
    """The state document for one run, in memory, saved on every change."""

    def __init__(self, path: Path, document: dict[str, Any]) -> None:
        self.path = path
        self.document = document

    # --- construction ---------------------------------------------------

    @classmethod
    def start(
        cls,
        image: str,
        boot_id: str,
        *,
        run_id: str,
        resume_hours: int = RESUME_HOURS,
    ) -> State:
        """Load the previous run if it is resumable, otherwise start a fresh one."""
        path = _root() / STATE_FILE
        previous = util.read_json(path)
        if isinstance(previous, dict) and cls._resumable(previous, image, resume_hours):
            previous["boot_id"] = boot_id
            previous["resumed"] = int(previous.get("resumed") or 0) + 1
            previous["updated_utc"] = _utc()
            log.logger.debug(
                "state: resuming %s at %s, %d module(s) done",
                previous.get("run_id"),
                previous.get("stage"),
                len(previous.get("modules") or {}),
            )
            state = cls(path, previous)
            state.save()
            return state

        document: dict[str, Any] = {
            "schema": STATE_VERSION,
            "run_id": run_id,
            "image": image,
            "boot_id": boot_id,
            "first_run": previous is None or not isinstance(previous, dict),
            "stage": "started",
            "resumed": 0,
            "created_utc": _utc(),
            "updated_utc": _utc(),
            "modules": {},
            "archive": {},
            "delivery": {"pending": False, "attempts": 0},
        }
        state = cls(path, document)
        state.save()
        return state

    @staticmethod
    def _resumable(document: dict[str, Any], image: str, resume_hours: int) -> bool:
        if document.get("schema") != STATE_VERSION:
            return False
        if document.get("image") != image:
            return False
        stage = document.get("stage")
        if stage not in {"collecting", "collected"}:
            return False
        # A finished run has nothing to resume, and its workspace is already gone.
        try:
            stamp = datetime.fromisoformat(str(document.get("updated_utc")))
        except ValueError:
            return False
        if stamp.tzinfo is None:
            return False
        age = (datetime.now(tz=UTC) - stamp).total_seconds()
        return 0 <= age <= resume_hours * 3600

    # --- persistence ----------------------------------------------------

    def save(self) -> bool:
        self.document["updated_utc"] = _utc()
        temporary = self.path.with_suffix(".tmp")
        try:
            temporary.write_text(
                __import__("json").dumps(self.document, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            os.replace(temporary, self.path)
        except (OSError, TypeError, ValueError):
            log.logger.debug("state: save failed", exc_info=True)
            return False
        return True

    # --- stages ---------------------------------------------------------

    @property
    def stage(self) -> str:
        return str(self.document.get("stage") or "started")

    def to_collecting(self, workspace: Path) -> None:
        self.document["stage"] = "collecting"
        self.document["workspace"] = str(workspace)
        self.save()

    def mark(self, module: str, count: int, seconds: float) -> None:
        modules = self.document.setdefault("modules", {})
        modules[module] = {
            "done": True,
            "count": int(count),
            "seconds": round(float(seconds), 3),
            "done_utc": _utc(),
        }
        self.save()

    def failed(self, module: str, reason: str) -> None:
        modules = self.document.setdefault("modules", {})
        modules[module] = {"done": False, "reason": reason, "done_utc": _utc()}
        self.save()

    def to_collected(self, archive: Path, sha256: str, size: int) -> None:
        self.document["stage"] = "collected"
        self.document["archive"] = {
            "path": str(archive),
            "sha256": sha256,
            "size": int(size),
        }
        self.save()

    def to_delivering(self) -> None:
        self.document["stage"] = "delivering"
        self.document["delivery"] = {"pending": True, "attempts": 0}
        self.save()

    def to_done(self) -> None:
        self.document["stage"] = "done"
        self.document["delivery"] = {"pending": False, "attempts": 0}
        self.document["workspace"] = ""
        self.save()

    def to_abandoned(self, reason: str) -> None:
        """End the run with no archive, and say why.

        An abandoned run must not stay at ``collecting``. That stage is precisely what
        the next boot treats as resumable, and the workspace it names is about to be
        deleted along with the temp folder holding it. Measured on the uniform-capture
        abort: the document stayed at ``collecting`` with nine modules marked done, so
        the next boot would have skipped every one of them and sealed an archive with
        nothing in it.
        """
        self.document["stage"] = "abandoned"
        self.document["abandon"] = {"reason": reason, "utc": _utc()}
        self.document["delivery"] = {"pending": False, "attempts": 0}
        self.document["workspace"] = ""
        self.save()

    def bring_forward(self, target: Path) -> int:
        """Carry a previous run's workspace into this one before collection resumes.

        A resumed module is skipped by ``sources.run_all`` because its files are meant to
        still be on disk — but they are in the workspace this document recorded, not in
        the fresh temp directory this run was handed. The recorded path only survives
        when the machine did not reboot, which is exactly the case ``stage: collecting``
        exists for.

        Modules whose output did not come across are dropped from the done set, so the
        next pass collects them again instead of shipping a count for data that is not in
        the archive. A module that legitimately wrote nothing is kept: it has a count of
        zero and no files to carry, and re-running it would produce the same nothing.
        """
        if self.stage != "collecting":
            return 0

        source = self.workspace()
        carried = 0
        if source is not None:
            try:
                if source.resolve() != target.resolve():
                    for path in source.rglob("*"):
                        if not path.is_file():
                            continue
                        destination = target / path.relative_to(source)
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(path, destination)
                        carried += 1
            except OSError:
                log.logger.debug("state: workspace copy stopped early", exc_info=True)

        self._forget_missing(target)
        self.save()
        return carried

    def _forget_missing(self, target: Path) -> None:
        """Drop done modules whose files are not in ``target``. Zero-count modules stay."""
        from . import layout

        modules = self.document.get("modules")
        if not isinstance(modules, dict):
            return

        for name, entry in list(modules.items()):
            if not isinstance(entry, dict) or not entry.get("done"):
                continue
            if int(entry.get("count") or 0) <= 0:
                continue
            directory = layout.MODULE_DIRS.get(name)
            if directory is None:
                continue
            folder = target / directory
            try:
                present = any(path.is_file() for path in folder.rglob("*"))
            except OSError:
                present = False
            if not present:
                log.logger.debug("state: %s has no files to resume, collecting again", name)
                modules.pop(name, None)

    # --- reads ----------------------------------------------------------

    def done_modules(self) -> set[str]:
        modules = self.document.get("modules") or {}
        if not isinstance(modules, dict):
            return set()
        return {name for name, entry in modules.items() if isinstance(entry, dict) and entry.get("done")}

    def workspace(self) -> Path | None:
        raw = str(self.document.get("workspace") or "")
        if not raw:
            return None
        path = Path(raw)
        try:
            if path.is_dir():
                return path
        except OSError:
            pass
        return None

    def archive(self) -> Path | None:
        block = self.document.get("archive") or {}
        if not isinstance(block, dict):
            return None
        raw = str(block.get("path") or "")
        if not raw:
            return None
        path = Path(raw)
        try:
            if path.is_file():
                return path
        except OSError:
            pass
        return None

    def counts(self) -> dict[str, int]:
        modules = self.document.get("modules") or {}
        if not isinstance(modules, dict):
            return {}
        return {
            name: int(entry.get("count") or 0)
            for name, entry in modules.items()
            if isinstance(entry, dict) and entry.get("done")
        }

    def failures(self) -> dict[str, str]:
        modules = self.document.get("modules") or {}
        if not isinstance(modules, dict):
            return {}
        return {
            name: str(entry.get("reason") or "")
            for name, entry in modules.items()
            if isinstance(entry, dict) and not entry.get("done") and entry.get("reason")
        }


def clear() -> bool:
    """Remove the state file. True when it is gone afterwards."""
    path = _root() / STATE_FILE
    try:
        path.unlink(missing_ok=True)
    except OSError:
        log.logger.debug("state: could not clear", exc_info=True)
        return False
    return True


def snapshot(document: dict[str, Any]) -> dict[str, Any]:
    """The block copied into the payload's ``meta/state.json``."""
    return {
        "run_id": document.get("run_id"),
        "stage": document.get("stage"),
        "first_run": document.get("first_run"),
        "resumed": document.get("resumed"),
        "boot_id": document.get("boot_id"),
        "created_utc": document.get("created_utc"),
        "updated_utc": document.get("updated_utc"),
        "modules": document.get("modules") or {},
        "archive": document.get("archive") or {},
        "delivered_utc": _utc() if document.get("stage") == "done" else None,
    }


__all__ = ["RESUME_HOURS", "STATE_FILE", "STATE_VERSION", "State", "clear", "snapshot"]
