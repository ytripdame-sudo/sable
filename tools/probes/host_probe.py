"""Which anonymous host actually accepts and serves a file from this network.

Catbox uploads fine but its download host is reset at the TLS layer here, so a link
that exists is still a link nobody can open. Each candidate is asked the same way the
artifact would ask: multipart, browser agent, then fetch one byte back.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from agent import relay  # noqa: E402

PROBE = Path(r"C:\Users\Kuzenee\Desktop\55555\_harness\out\host-probe.zip")
PROBE.parent.mkdir(parents=True, exist_ok=True)
PROBE.write_bytes(b"PK\x03\x04" + b"sable" * 512)
UA = relay._USER_AGENT


def fetch(url: str) -> str:
    request = urllib.request.Request(url, method="GET")
    request.add_header("User-Agent", UA)
    request.add_header("Range", "bytes=0-0")
    try:
        with urllib.request.urlopen(request, timeout=40, context=relay._SSL) as response:
            return f"{response.status} ok"
    except urllib.error.HTTPError as exc:
        return f"http {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return f"{type(exc).__name__}: {exc}"


def post(url: str, field: str, extra: dict[str, str] | None = None) -> tuple[int, bytes]:
    body, boundary = relay._multipart(
        extra or {},
        field,
        PROBE.name,
        PROBE.read_bytes(),
        "application/zip",
    )
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    request.add_header("Content-Length", str(len(body)))
    request.add_header("User-Agent", UA)
    try:
        with urllib.request.urlopen(request, timeout=90, context=relay._SSL) as response:
            return int(response.status), response.read(4096)
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read(300)
    except Exception as exc:  # noqa: BLE001
        return 0, f"{type(exc).__name__}: {exc}".encode()


def test_pixeldrain() -> None:
    status, body = post("https://pixeldrain.com/api/file", "file")
    print(f"pixeldrain upload {status} {body[:160]!r}")
    if status == 200:
        try:
            identifier = json.loads(body)["id"]
        except Exception:  # noqa: BLE001
            return
        url = f"https://pixeldrain.com/u/{identifier}"
        print(f"pixeldrain link   {url}  -> {fetch(url)}")


def test_gofile() -> None:
    request = urllib.request.Request("https://api.gofile.io/servers", method="GET")
    request.add_header("User-Agent", UA)
    try:
        with urllib.request.urlopen(request, timeout=40, context=relay._SSL) as response:
            servers = json.loads(response.read(4096))
        server = servers["data"]["servers"][0]["name"]
    except Exception as exc:  # noqa: BLE001
        print(f"gofile servers    {type(exc).__name__}: {exc}")
        return
    status, body = post(f"https://{server}.gofile.io/contents/uploadfile", "file")
    print(f"gofile upload     {status} {body[:200]!r}")


def test_tmpfiles() -> None:
    status, body = post("https://tmpfiles.org/api/v1/upload", "file")
    print(f"tmpfiles upload   {status} {body[:160]!r}")
    if status == 200:
        try:
            url = json.loads(body)["data"]["url"].replace("tmpfiles.org/", "tmpfiles.org/dl/")
        except Exception:  # noqa: BLE001
            return
        print(f"tmpfiles link     {url}  -> {fetch(url)}")


def test_uguu() -> None:
    status, body = post("https://uguu.se/upload?output=text", "files[]")
    print(f"uguu upload       {status} {body[:160]!r}")
    if status == 200:
        url = body.decode("utf-8", "replace").strip()
        print(f"uguu link         {url}  -> {fetch(url)}")


def test_zero_x_zero() -> None:
    status, body = post("https://0x0.st", "file")
    print(f"0x0 upload        {status} {body[:160]!r}")
    if status == 200:
        url = body.decode("utf-8", "replace").strip()
        print(f"0x0 link          {url}  -> {fetch(url)}")


for name, fn in (
    ("pixeldrain", test_pixeldrain),
    ("gofile", test_gofile),
    ("tmpfiles", test_tmpfiles),
    ("uguu", test_uguu),
    ("0x0", test_zero_x_zero),
):
    print(f"--- {name} ---", flush=True)
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        print(f"{name} FAILED {type(exc).__name__}: {exc}")
