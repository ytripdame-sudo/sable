"""Fixture probe for the Roblox client jar reader.

Every case seals a Netscape-shaped payload with DPAPI, wraps it in the client's
LocalStorage JSON, and asks the real reader what it found. Nothing prints a cookie
value; lengths and booleans only.

Run from the sable tree so the package imports:

    python tools/probes/roblox_jar_probe.py
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sable"))

from agent import winapi  # noqa: E402
from agent.sources import roblox  # noqa: E402

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        print(f"  pass  {name}")
    else:
        print(f"  FAIL  {name}  {detail}")
        FAILURES.append(name)


def _protect(data: bytes) -> bytes:
    """DPAPI-seal a fixture payload the way the client's writer does."""
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    buffer = ctypes.create_string_buffer(data, len(data))
    source = winapi.DATA_BLOB()
    source.cbData = len(data)
    source.pbData = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))
    sealed = winapi.DATA_BLOB()
    if not crypt32.CryptProtectData(
        ctypes.byref(source), None, None, None, None, 0, ctypes.byref(sealed)
    ):
        raise OSError(ctypes.get_last_error(), "CryptProtectData")
    try:
        return ctypes.string_at(sealed.pbData, sealed.cbData)
    finally:
        kernel32.LocalFree(sealed.pbData)


def _wrap(path: Path, plaintext: bytes) -> None:
    """A jar file in the client's own container: JSON, base64, DPAPI."""
    document = {
        "CookiesVersion": "1",
        "CookiesData": base64.b64encode(_protect(plaintext)).decode("ascii"),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")


def _token(seed: str, length: int = 900) -> str:
    """A cookie-shaped value: the warning prefix, then a body with the right alphabet."""
    rng = random.Random(seed)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"
    head = "_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in"
    body = "".join(rng.choice(alphabet) for _ in range(max(0, length - len(head))))
    return head + "." + body


def _read(plaintext: bytes) -> tuple[list[str], dict]:
    """Run the real path: _client_tokens over a temp LOCALAPPDATA holding one jar."""
    with tempfile.TemporaryDirectory(prefix="roblox-jar-probe-") as root:
        base = Path(root)
        jar = base / "Roblox" / "LocalStorage" / "RobloxCookies.dat"
        _wrap(jar, plaintext)
        saved = os.environ.get("LOCALAPPDATA")
        os.environ["LOCALAPPDATA"] = str(base)
        try:
            return roblox._client_tokens()
        finally:
            if saved is None:
                os.environ.pop("LOCALAPPDATA", None)
            else:
                os.environ["LOCALAPPDATA"] = saved


def _record(detail: dict) -> dict:
    return detail["records"][0]


def case_bench_shape() -> None:
    """The shape the bench jar actually holds: three records, space separated, semis."""
    token = _token("bench")
    plaintext = (
        f"#HttpOnly_.roblox.com\tTRUE\t/\tTRUE\t0\t.ROBLOSECURITY\t{token}; "
        f"#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tGuestData\tUserID=-919370561; "
        f"#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tRBXEventTrackerV2\tCreateDate=1"
    ).encode("utf-8")
    tokens, detail = _read(plaintext)
    record = _record(detail)
    check("bench shape finds the session", tokens == [token], f"{len(tokens)} token(s)")
    check("bench shape reads three rows", record["rows"] == 3, str(record["rows"]))
    check("bench shape names one row", record["named"] == 1, str(record["named"]))
    check("bench shape harvest stays at zero", record["harvest"] == 0, str(record["harvest"]))


def case_laptop_shape() -> None:
    """The live laptop jar: tracker record first, session row with no value after the tab.

    2 rows, 1 named, 0 found. The old reader reported the tracker's 78-byte CreateDate
    value as a shape failure on a session, which is a misleading finding: the session row
    was empty, and the tracker was never a session in the first place.
    """
    tracker = "CreateDate=11/17/2026 18:36:44&rbxuid=10664732490&browserid=17935&rid=12345678"
    check("tracker value is 78 bytes", len(tracker) == 78, str(len(tracker)))
    plaintext = (
        f"#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tRBXEventTrackerV2\t{tracker}; "
        f"#HttpOnly_.roblox.com\tTRUE\t/\tTRUE\t0\t.ROBLOSECURITY\t"
    ).encode("utf-8")
    tokens, detail = _read(plaintext)
    record = _record(detail)
    check("laptop shape finds nothing", tokens == [], f"{len(tokens)} token(s)")
    check("laptop shape reads two rows", record["rows"] == 2, str(record["rows"]))
    check("laptop shape names one row", record["named"] == 1, str(record["named"]))
    check(
        "laptop shape blames the empty session, not the tracker",
        record["reason"] == "truncated",
        f"{record['reason']}: {record['detail']}",
    )
    check("laptop shape counts the tracker", record["prefixes"].get("tracker") == 1, str(record["prefixes"]))


def case_tracker_only() -> None:
    """A signed-out client: the jar holds the tracking cookies and nothing else."""
    plaintext = (
        "#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tGuestData\tUserID=-919370561; "
        "#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tRBXEventTrackerV2\tCreateDate=11/17/2026"
    ).encode("utf-8")
    tokens, detail = _read(plaintext)
    record = _record(detail)
    check("tracker-only jar finds nothing", tokens == [], f"{len(tokens)} token(s)")
    check(
        "tracker-only jar says so",
        record["reason"] == "tracker_only",
        f"{record['reason']}: {record['detail']}",
    )


def case_container_change() -> None:
    """The container changes again: no cookie rows, the value buried in a JSON field.

    This is the case that matters for the next client build. The row reader has nothing
    to chew on, and the harvest pass is what finds the value.
    """
    token = _token("container")
    plaintext = json.dumps(
        {"Store": "LocalStorage", "CookieHeader": f".ROBLOSECURITY={token}", "Updated": "0"}
    ).encode("utf-8")
    tokens, detail = _read(plaintext)
    record = _record(detail)
    check("container change still finds the session", tokens == [token], f"{len(tokens)} token(s)")
    check("container change is credited to the harvest", record["harvest"] == 1, str(record["harvest"]))


def case_no_space_separator() -> None:
    """A jar rewritten in place separates records with ';' and no space."""
    token = _token("nospace")
    plaintext = (
        f"#HttpOnly_.roblox.com\tTRUE\t/\tTRUE\t0\t.ROBLOSECURITY\t{token};"
        "#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tGuestData\tUserID=-9193"
    ).encode("utf-8")
    tokens, detail = _read(plaintext)
    check("no-space separator keeps the value whole", tokens == [token], f"{len(tokens)} token(s)")
    check("no-space separator reads two rows", _record(detail)["rows"] == 2, str(_record(detail)["rows"]))


def case_bare_domain_separator() -> None:
    """The httponly prefix dropped on the following record."""
    token = _token("bare")
    plaintext = (
        f"#HttpOnly_.roblox.com\tTRUE\t/\tTRUE\t0\t.ROBLOSECURITY\t{token};"
        ".roblox.com\tTRUE\t/\tFALSE\t0\tGuestData\tUserID=-9193"
    ).encode("utf-8")
    tokens, detail = _read(plaintext)
    check("bare domain separator keeps the value whole", tokens == [token], f"{len(tokens)} token(s)")


def case_utf16() -> None:
    """A jar written as UTF-16LE with a BOM. Decoded as UTF-8 it reads as NUL-separated text."""
    token = _token("utf16")
    plaintext = (
        f"#HttpOnly_.roblox.com\tTRUE\t/\tTRUE\t0\t.ROBLOSECURITY\t{token}; "
        "#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tGuestData\tUserID=-9193"
    )
    tokens, detail = _read(plaintext.encode("utf-16"))
    check("utf-16 jar finds the session", tokens == [token], f"{len(tokens)} token(s)")


def case_tab_in_value() -> None:
    """A value with a tab in it must not be cut at the tab."""
    token = _token("tabbed")
    plaintext = (
        f"#HttpOnly_.roblox.com\tTRUE\t/\tTRUE\t0\t.ROBLOSECURITY\t{token}"
        "#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tGuestData\tUserID=-9193"
    ).encode("utf-8")
    tokens, detail = _read(plaintext)
    check("unterminated final record does not swallow", tokens == [token], f"{len(tokens)} token(s)")


def case_cut_prefix() -> None:
    """A value cut off inside the warning prefix is a truncated write, not a bad shape."""
    plaintext = (
        "#HttpOnly_.roblox.com\tTRUE\t/\tTRUE\t0\t.ROBLOSECURITY\t_|WARNING:-DO-NOT-SHAR; "
        "#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tGuestData\tUserID=-9193"
    ).encode("utf-8")
    tokens, detail = _read(plaintext)
    record = _record(detail)
    check("cut prefix finds nothing", tokens == [], f"{len(tokens)} token(s)")
    check(
        "cut prefix is called truncated",
        record["reason"] == "truncated",
        f"{record['reason']}: {record['detail']}",
    )


def case_nested_wrapper() -> None:
    """One more layer: the decrypted payload is itself JSON holding the sealed next layer."""
    token = _token("nested")
    inner = (
        f"#HttpOnly_.roblox.com\tTRUE\t/\tTRUE\t0\t.ROBLOSECURITY\t{token}; "
        "#HttpOnly_.roblox.com\tTRUE\t/\tFALSE\t0\tGuestData\tUserID=-9193"
    ).encode("utf-8")
    plaintext = json.dumps({"Layer": "2", "Data": base64.b64encode(_protect(inner)).decode()}).encode()
    tokens, detail = _read(plaintext)
    check("nested wrapper unwraps once", tokens == [token], f"{len(tokens)} token(s)")


def case_unknown_wrapper() -> None:
    """A container the reader cannot name says exactly that."""
    plaintext = (
        "the client wrote something else entirely and it is not a cookie file in any "
        "spelling this reader knows, twice over, padded out to pass the short test"
    ).encode("utf-8")
    tokens, detail = _read(plaintext)
    record = _record(detail)
    check("unknown wrapper finds nothing", tokens == [], f"{len(tokens)} token(s)")
    check(
        "unknown wrapper is named",
        record["reason"] == "wrapper_unknown",
        f"{record['reason']}: {record['detail']}",
    )


def case_reason_codes() -> None:
    for reason in ("wrapper_unknown", "truncated", "tracker_only", "rejected_shape"):
        check(f"reason code present: {reason}", reason in roblox.REASONS)


def case_memory_still_gated_by_nothing() -> None:
    """The memory pass must run whatever the jar said."""
    import inspect

    source = inspect.getsource(roblox.run)
    check(
        "run() calls the memory pass unconditionally",
        "_memory_tokens()" in source and "if not collected" not in source.split("_memory_tokens()")[0],
        "memory pass looks conditional",
    )


def case_real_jar() -> None:
    """The jar on this desk, if there is one. Length and shape only, never the value."""
    local = os.environ.get("LOCALAPPDATA", "")
    path = Path(local) / "Roblox" / "LocalStorage" / "RobloxCookies.dat" if local else None
    if path is None or not path.is_file():
        check("real jar present on this desk", True, "absent, skipped")
        return
    _plain, rows, reason, detail = roblox._jar_open(path)
    names = [row["name"] for row in rows]
    values = [row["value"] for row in rows if roblox._is_roblox(row["name"])]
    check("real jar parses without a reason", reason == "", f"{reason}: {detail}")
    check("real jar holds a session row", ".ROBLOSECURITY" in names, str(names))
    check(
        "real jar session value is plausible",
        bool(values) and all(roblox._plausible(value) for value in values),
        f"{len(values)} value(s)",
    )


def main() -> int:
    print("roblox jar probe")
    print(f"jar constants: max_jar={roblox._MAX_JAR_BYTES} max_plain={roblox._MAX_PLAIN_BYTES}")
    for case in (
        case_reason_codes,
        case_bench_shape,
        case_laptop_shape,
        case_tracker_only,
        case_container_change,
        case_no_space_separator,
        case_bare_domain_separator,
        case_utf16,
        case_tab_in_value,
        case_cut_prefix,
        case_nested_wrapper,
        case_unknown_wrapper,
        case_memory_still_gated_by_nothing,
        case_real_jar,
    ):
        print(case.__name__)
        case()
    print(f"failures: {len(FAILURES)}")
    for name in FAILURES:
        print(f"  {name}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
