"""The account enrichment: parsing, gating, and the promise that it cannot raise."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

from agent import identity


def config(sessions: bool = True, roblox: bool = True) -> Any:
    return SimpleNamespace(sources=SimpleNamespace(sessions=sessions, roblox=roblox))


def reply(status: int = 200, document: Any = None, error: str = "", headers: Any = None):
    body = b"" if document is None else json.dumps(document).encode("utf-8")
    return identity._Reply(status, body, error, dict(headers or {}))


def workspace(tmp_path: Path, *, discord: bool = False, roblox: bool = False) -> Path:
    accounts = tmp_path / "accounts"
    accounts.mkdir(parents=True, exist_ok=True)
    if discord:
        (accounts / "sessions.json").write_text(
            json.dumps(
                [
                    {
                        "token": "discord-token",
                        "browser": "brave",
                        "profile": "Default",
                        "valid": True,
                    }
                ]
            ),
            encoding="utf-8",
        )
    if roblox:
        (accounts / "roblox_session.txt").write_text("roblox-cookie\n", encoding="utf-8")
    return tmp_path


# --- Discord ------------------------------------------------------------------


def test_discord_record_carries_the_fields_the_reference_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    me = {
        "id": "123456789012345678",
        "username": "caf\u00e9",
        "global_name": "Bench",
        "discriminator": "0",
        "email": "bench@example.com",
        "phone": "+15550100",
        "mfa_enabled": True,
        "verified": True,
        "premium_type": 3,
        "avatar": "a_deadbeef",
    }
    billing = [
        {"type": 1, "brand": "visa", "last_4": "4242", "default": True},
        {"type": 2, "email": "pay@example.com"},
    ]
    codes = [{"code": "GIFT-1"}, {"code": "GIFT-2"}, {"code": "GIFT-1"}]

    def fake(url: str, headers: dict[str, str], deadline: float, **_: Any):
        assert headers["Authorization"] == "discord-token"
        if url.endswith("/users/@me"):
            return reply(document=me)
        if url.endswith("payment-sources"):
            return reply(document=billing)
        if url.endswith("outbound-promotions/codes"):
            return reply(document=codes)
        raise AssertionError(url)

    monkeypatch.setattr(identity, "_request", fake)

    record = identity._discord_account("discord-token", "brave/Default", 1e9)
    assert record is not None
    assert record["id"] == "123456789012345678"
    assert record["nitro"] == "full"
    assert record["premium_type"] == 3
    assert record["mfa_enabled"] is True
    assert record["avatar_url"] == (
        "https://cdn.discordapp.com/avatars/123456789012345678/a_deadbeef.gif"
    )
    assert record["billing"] == [
        {"kind": "card", "brand": "visa", "last_4": "4242", "default": True},
        {"kind": "paypal", "email": "pay@example.com"},
    ]
    assert record["gift_codes"] == ["GIFT-1", "GIFT-2"]
    assert record["errors"] == []


def test_nitro_tiers_are_mapped_not_guessed() -> None:
    assert identity._NITRO[0] == "none"
    assert identity._NITRO[1] == "classic"
    assert identity._NITRO[2] == "boost"
    assert identity._NITRO[3] == "full"
    assert 4 not in identity._NITRO


def test_a_rate_limited_billing_call_is_a_string_not_an_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake(url: str, headers: dict[str, str], deadline: float, **_: Any):
        if url.endswith("/users/@me"):
            return reply(document={"id": "1", "username": "x"})
        return reply(status=429)

    monkeypatch.setattr(identity, "_request", fake)

    record = identity._discord_account("t", "brave/Default", 1e9)
    assert record is not None
    assert record["id"] == "1"
    assert "billing: rate_limited" in record["errors"]
    assert "gifts: rate_limited" in record["errors"]


def test_an_unauthorized_token_keeps_the_record_and_the_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        identity, "_request", lambda *a, **k: reply(status=401)
    )
    record = identity._discord_account("t", "brave/Default", 1e9)
    assert record is not None
    assert "id" not in record
    assert record["errors"] == ["user: unauthorized"]


# --- Roblox -------------------------------------------------------------------


def test_roblox_record_is_built_from_the_endpoints_that_own_the_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake(url: str, headers: dict[str, str], deadline: float, **_: Any):
        assert headers["Cookie"] == ".ROBLOSECURITY=cookie"
        if url.endswith("/v1/users/authenticated"):
            return reply(document={"id": 42, "name": "bench", "displayName": "Bench"})
        if url.endswith("/v1/users/42"):
            return reply(document={"created": "2019-04-11T00:00:00Z", "isBanned": False})
        if url.endswith("/validate-membership"):
            return reply(document=True)
        if "avatar-headshot" in url:
            return reply(document={"data": [{"imageUrl": "https://tr.rbxcdn.com/x.png"}]})
        raise AssertionError(url)

    monkeypatch.setattr(identity, "_request", fake)

    record = identity._roblox_account("cookie", "roblox_session.txt:0", 1e9)
    assert record is not None
    assert record["id"] == 42
    assert record["name"] == "bench"
    assert record["display_name"] == "Bench"
    assert record["premium"] is True
    assert record["is_banned"] is False
    assert record["avatar_url"] == "https://tr.rbxcdn.com/x.png"
    assert isinstance(record["account_age_days"], int)
    assert record["account_age_days"] > 365
    assert record["errors"] == []


def test_roblox_retries_once_with_the_csrf_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, str]] = []

    def fake(url: str, headers: dict[str, str], deadline: float, **_: Any):
        calls.append(dict(headers))
        if "X-CSRF-TOKEN" not in headers:
            return identity._Reply(
                403, b"", "", {"x-csrf-token": "csrf-value"}
            )
        return reply(document={"id": 7, "name": "bench"})

    monkeypatch.setattr(identity, "_request", fake)

    document, error = identity._roblox_get(
        "https://users.roblox.com/v1/users/authenticated", "cookie", 1e9
    )
    assert error == ""
    assert document == {"id": 7, "name": "bench"}
    assert calls[0].get("X-CSRF-TOKEN") is None
    assert calls[1]["X-CSRF-TOKEN"] == "csrf-value"


def test_a_403_without_a_header_falls_back_to_the_handshake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []

    def fake(url: str, headers: dict[str, str], deadline: float, **_: Any):
        seen.append(url)
        if url.endswith("/v2/logout"):
            return identity._Reply(403, b"", "", {"x-csrf-token": "handshake"})
        if "X-CSRF-TOKEN" in headers:
            return reply(document={"ok": True})
        return identity._Reply(403, b"", "", {})

    monkeypatch.setattr(identity, "_request", fake)

    document, error = identity._roblox_get("https://users.roblox.com/v1/x", "cookie", 1e9)
    assert error == ""
    assert document == {"ok": True}
    assert any(url.endswith("/v2/logout") for url in seen)


# --- the deadline -------------------------------------------------------------


def test_the_deadline_is_checked_before_the_socket_is_opened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(*_: Any, **__: Any) -> None:
        raise AssertionError("a call past the deadline must not open a socket")

    monkeypatch.setattr(identity.urllib.request, "urlopen", explode)

    result = identity._request("https://example.com", {}, deadline=0.0)
    assert result.status == 0
    assert result.error == "deadline"


def test_the_per_call_timeout_never_exceeds_the_remaining_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[float] = []

    class FakeResponse:
        status = 200
        headers: ClassVar[dict[str, str]] = {}

        def read(self, _size: int) -> bytes:
            return b"{}"

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *_: Any) -> None:
            return None

    def fake_open(_request: Any, timeout: float) -> FakeResponse:
        seen.append(timeout)
        return FakeResponse()

    monkeypatch.setattr(identity.urllib.request, "urlopen", fake_open)
    monkeypatch.setattr(identity.time, "monotonic", lambda: 100.0)

    identity._request("https://example.com", {}, deadline=100.5)
    assert seen == [0.5]


def test_an_oversize_body_is_refused_rather_than_truncated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeResponse:
        status = 200
        headers: ClassVar[dict[str, str]] = {}

        def read(self, size: int) -> bytes:
            return b"x" * size

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *_: Any) -> None:
            return None

    monkeypatch.setattr(identity.urllib.request, "urlopen", lambda *a, **k: FakeResponse())

    result = identity._request("https://example.com", {}, deadline=1e9)
    assert result.error == "oversize"
    assert result.body == b""


# --- collect ------------------------------------------------------------------


def test_collect_rides_the_collector_flags_and_writes_ascii_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = workspace(tmp_path, discord=True, roblox=True)

    def fake(url: str, headers: dict[str, str], deadline: float, **_: Any):
        if "discord.com" in url:
            if url.endswith("/users/@me"):
                return reply(document={"id": "1", "username": "caf\u00e9", "premium_type": 2})
            return reply(document=[])
        if url.endswith("/v1/users/authenticated"):
            return reply(document={"id": 5, "name": "bench"})
        if url.endswith("/v1/users/5"):
            return reply(document={"created": "2020-01-01T00:00:00Z"})
        if url.endswith("/validate-membership"):
            return reply(document=False)
        return reply(document={"data": []})

    monkeypatch.setattr(identity, "_request", fake)

    assert identity.collect(root, config()) == 2

    raw = (root / "accounts" / identity.IDENTITY_FILE).read_bytes()
    assert all(byte < 128 for byte in raw), "identity.json must be pure ASCII"
    assert b"\\u00e9" in raw

    document = json.loads(raw.decode("ascii"))
    assert document["schema"] == 1
    assert document["discord"][0]["nitro"] == "boost"
    assert document["roblox"][0]["id"] == 5
    assert document["roblox"][0]["premium"] is False


def test_the_token_is_never_written_to_the_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = workspace(tmp_path, discord=True)

    monkeypatch.setattr(
        identity,
        "_request",
        lambda *a, **k: reply(document={"id": "1", "username": "x"}),
    )

    identity.collect(root, config(roblox=False))
    text = (root / "accounts" / identity.IDENTITY_FILE).read_text(encoding="utf-8")
    assert "discord-token" not in text


def test_a_disabled_flag_collects_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = workspace(tmp_path, discord=True, roblox=True)

    def explode(*_: Any, **__: Any) -> None:
        raise AssertionError("no call may be made when both flags are off")

    monkeypatch.setattr(identity, "_request", explode)

    assert identity.collect(root, config(sessions=False, roblox=False)) == 0
    assert not (root / "accounts" / identity.IDENTITY_FILE).exists()


def test_a_missing_sources_block_is_off_not_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = workspace(tmp_path, discord=True)

    def explode(*_: Any, **__: Any) -> None:
        raise AssertionError("no call may be made without a config")

    monkeypatch.setattr(identity, "_request", explode)

    assert identity.collect(root, SimpleNamespace()) == 0


def test_enrichment_answers_zero_rather_than_raising(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = workspace(tmp_path, discord=True, roblox=True)

    def explode(*_: Any, **__: Any) -> None:
        raise RuntimeError("transport on fire")

    monkeypatch.setattr(identity, "_request", explode)

    assert identity.collect(root, config()) == 0


def test_an_invalid_token_is_not_spent_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = workspace(tmp_path)
    (root / "accounts" / "sessions.json").write_text(
        json.dumps([{"token": "dead", "valid": False}]), encoding="utf-8"
    )

    def explode(*_: Any, **__: Any) -> None:
        raise AssertionError("a token Discord already refused must not be retried")

    monkeypatch.setattr(identity, "_request", explode)
    assert identity.collect(root, config()) == 0


def test_the_deadline_lands_in_the_record(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = workspace(tmp_path, discord=True)
    monkeypatch.setattr(
        identity,
        "_request",
        lambda *a, **k: identity._Reply(0, b"", "deadline", {}),
    )

    assert identity.collect(root, config(roblox=False)) == 0
    document = json.loads(
        (root / "accounts" / identity.IDENTITY_FILE).read_text(encoding="utf-8")
    )
    assert document["discord"][0]["errors"] == ["user: deadline"]
    assert document["deadline_seconds"] == 8.0


def test_roblox_enrichment_rides_the_browsers_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """There is no sources.roblox. The collector is enabled by browsers; so is this."""
    root = workspace(tmp_path, roblox=True)
    cfg = SimpleNamespace(sources=SimpleNamespace(browsers=True, sessions=False))

    def fake(url: str, headers: dict[str, str], deadline: float, **_: Any):
        if url.endswith("/v1/users/authenticated"):
            return reply(document={"id": 9, "name": "bench"})
        if url.endswith("/v1/users/9"):
            return reply(document={"created": "2021-01-01T00:00:00Z"})
        if url.endswith("/validate-membership"):
            return reply(document=True)
        return reply(document={"data": []})

    monkeypatch.setattr(identity, "_request", fake)

    assert identity._enabled(cfg, "roblox") is True
    assert identity._enabled(cfg, "sessions") is False
    assert identity.collect(root, cfg) == 1

# --- the verdict on the row --------------------------------------------------


def test_a_live_credential_is_marked_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(url: str, headers: dict[str, str], deadline: float, **_: Any):
        if url.endswith("/users/@me"):
            return reply(document={"id": "1", "username": "bench"})
        return reply(document=[])

    monkeypatch.setattr(identity, "_request", fake)
    record = identity._discord_account("t", "brave/Default", 1e9)
    assert record is not None
    assert record["status"] == identity.VALID


@pytest.mark.parametrize("status", [401, 403])
def test_a_refused_credential_is_marked_dead(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    # 403 is a refusal for Roblox only after the CSRF retry, and Discord has no handshake
    # at all: the origin is stating that this credential does not work.
    monkeypatch.setattr(
        identity, "_request", lambda *a, **k: identity._Reply(status, b"", "", {})
    )
    record = identity._discord_account("t", "brave/Default", 1e9)
    assert record is not None
    assert record["status"] == identity.DEAD


@pytest.mark.parametrize(
    ("status", "error"),
    [(429, ""), (500, ""), (0, "deadline"), (0, "transport"), (200, "")],
)
def test_a_check_that_did_not_answer_is_not_a_dead_credential(
    monkeypatch: pytest.MonkeyPatch, status: int, error: str
) -> None:
    """The distinction that keeps this from being worse than no check at all.

    A rate limit, a server fault, a timeout and a 200 whose body changed shape all say
    nothing about the credential. Calling any of them dead would drop a live cookie from
    the dump, and the only other copy is on a machine that is not coming back.
    """
    body = b"{}" if status == 200 else b""
    monkeypatch.setattr(
        identity, "_request", lambda *a, **k: identity._Reply(status, body, error, {})
    )
    record = identity._discord_account("t", "brave/Default", 1e9)
    assert record is not None
    assert record["status"] == identity.UNKNOWN


def test_the_status_sidecar_names_every_row_and_totals_the_verdicts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = workspace(tmp_path, discord=True, roblox=True)

    def fake(url: str, headers: dict[str, str], deadline: float, **_: Any):
        if url.endswith("/users/@me"):
            return reply(document={"id": "1", "username": "bench"})
        if url.endswith("/v1/users/authenticated"):
            return identity._Reply(401, b"", "", {})
        return reply(document=[])

    monkeypatch.setattr(identity, "_request", fake)

    assert identity.collect(root, config()) == 1
    status = json.loads(
        (root / "accounts" / identity.STATUS_FILE).read_text(encoding="utf-8")
    )

    assert status["counts"] == {identity.VALID: 1, identity.DEAD: 1, identity.UNKNOWN: 0}
    rows = {(row["platform"], row["status"]) for row in status["rows"]}
    assert rows == {("discord", identity.VALID), ("roblox", identity.DEAD)}
    dead = next(row for row in status["rows"] if row["status"] == identity.DEAD)
    assert dead["reason"] == "session: unauthorized"
    alive = next(row for row in status["rows"] if row["status"] == identity.VALID)
    assert "reason" not in alive


def test_only_a_valid_row_counts_as_resolved(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = workspace(tmp_path, discord=True)
    monkeypatch.setattr(
        identity, "_request", lambda *a, **k: identity._Reply(429, b"", "", {})
    )
    # An unknown verdict is not a resolved account, and it is not a dead one either.
    assert identity.collect(root, config(roblox=False)) == 0
    status = json.loads(
        (root / "accounts" / identity.STATUS_FILE).read_text(encoding="utf-8")
    )
    assert status["rows"][0]["status"] == identity.UNKNOWN
    assert status["rows"][0]["reason"] == "user: rate_limited"


def test_the_status_file_is_in_the_identity_module_layout() -> None:
    """A file a module writes has to be a file the layout says it may write."""
    from agent import layout

    assert identity.STATUS_FILE in layout.MODULE_PREFIXES["identity"]
