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

import json
import socket
import urllib.request
from pathlib import Path
from typing import Any, Final

from .. import log, util, winapi
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

# Plain HTTP: this endpoint answers geolocation questions and nothing else, so there is
# nothing to protect in transit and the free tier does not offer TLS. A paid key would
# be a credential to ship inside an artifact, which is a worse trade than one unsealed
# lookup.
_LOCATION_URL: Final[str] = (
    "http://ip-api.com/json/"
    "?fields=status,country,countryCode,regionName,city,isp,org,query,timezone"
)
_LOCATION_TIMEOUT: Final[float] = 5.0
_LOCATION_AGENT: Final[str] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

_LOCATION_FIELDS: Final[tuple[tuple[str, str], ...]] = (
    ("query", "public_ip"),
    ("city", "city"),
    ("regionName", "region"),
    ("country", "country"),
    ("countryCode", "country_code"),
    ("isp", "isp"),
    ("org", "org"),
    ("timezone", "timezone"),
)


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


def _lan_address() -> str | None:
    """The address this machine would leave the network from.

    A connected UDP socket resolves a route without putting a single packet on the
    wire, so this is a routing lookup and not a probe of anything.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(1.0)
            probe.connect(("8.8.8.8", 80))
            return str(probe.getsockname()[0])
    except OSError:
        return None


def location() -> dict[str, Any]:
    """Wide-area identity: the local address, and what the public one geolocates to.

    The lookup is optional and every failure is swallowed. A machine behind a dead
    network still has a hostname and a LAN address worth sending, and a status message
    is not worth failing a collection over. The short timeout exists because this runs
    before the message that says the run started.
    """
    payload: dict[str, Any] = {}

    lan = _lan_address()
    if lan:
        payload["lan_ip"] = lan

    try:
        request = urllib.request.Request(_LOCATION_URL)
        request.add_header("User-Agent", _LOCATION_AGENT)
        with urllib.request.urlopen(request, timeout=_LOCATION_TIMEOUT) as response:
            answer = json.loads(response.read(8 * 1024).decode("utf-8", "replace"))
    except Exception:
        log.logger.debug("network: location lookup failed", exc_info=True)
        return payload

    if not isinstance(answer, dict) or answer.get("status") != "success":
        return payload

    for source, target in _LOCATION_FIELDS:
        value = answer.get(source)
        if isinstance(value, str) and value.strip():
            payload[target] = value.strip()

    return payload


__all__ = ["location", "run"]
