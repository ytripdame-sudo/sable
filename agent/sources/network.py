"""Network adapter inventory.

One artifact, ``network.json``, built entirely from ``winapi.adapters()``. No IP
addresses: ``GetAdaptersAddresses`` returns them on the unicast-address chain, and
``winapi`` deliberately does not walk that chain, because the SOCKADDR union needs a
family switch that belongs next to the declaration. The adapter list, its hardware
addresses and its operational state are what this module can state truthfully.

A machine with no adapters writes nothing and returns 0 rather than emitting an
artifact with an empty list, so an empty file never reads as "no network".
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

from .. import util, winapi
from . import system

_IF_TYPES: Final[dict[int, str]] = {
    6: "ethernet",
    23: "ppp",
    24: "loopback",
    71: "wifi",
    131: "tunnel",
    243: "wwan",
}

_OPER_STATUS: Final[dict[int, str]] = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "not_present",
    7: "lower_layer_down",
}


def _if_type_name(value: int) -> str:
    if value in _IF_TYPES:
        return _IF_TYPES[value]
    return f"type_{value}"


def _oper_status_name(value: int) -> str:
    if value in _OPER_STATUS:
        return _OPER_STATUS[value]
    return f"status_{value}"


def _entry(adapter: winapi.AdapterInfo) -> dict[str, Any]:
    return {
        "friendly_name": adapter.friendly_name,
        "description": adapter.description,
        "mac": adapter.mac,
        "if_index": adapter.if_index,
        "if_type": adapter.if_type,
        "if_type_name": _if_type_name(adapter.if_type),
        "oper_status": adapter.oper_status,
        "oper_status_name": _oper_status_name(adapter.oper_status),
        "up": adapter.oper_status == 1,
    }


def run(out_dir: Path, cfg: Any) -> int:
    """Write ``network.json``. Returns the number of adapters written."""
    found = winapi.adapters()
    if not found:
        return 0

    entries = [_entry(adapter) for adapter in found]
    payload: dict[str, Any] = {
        "hostname": system.machine_name(),
        "primary_mac": winapi.first_physical_mac(),
        "count": len(entries),
        "adapters": entries,
    }

    if not util.write_json(out_dir / "network.json", payload):
        return 0
    return len(entries)


__all__ = ["run"]
