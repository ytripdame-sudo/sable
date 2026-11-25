"""Check the premise of the cookie table without holding a real credential. GUEST ONLY.

`agent/cookies.py` decides that a row is dead when the origin answers 401. That is only a fact
about the row if the origin also answers **401 for a credential that is not one** — if a garbage
value comes back 200, the endpoint is not authenticating on that cookie at all and every verdict
the module produces from it is wrong in the dangerous direction (a live session marked valid
forever, or a dead one indistinguishable from a live one).

So this probe sends three deliberately invalid cookies, one per entry, and reads the answers. It
is not a test of a real session; it is a test of the table, and it belongs on a guest because it
makes three requests to three third parties from the machine that runs it.

What each outcome means:

| answer | reading |
|---|---|
| 401 | the premise holds: an invalid value is refused, so a 401 from a real one is a statement |
| 403 | inconclusive: a WAF or a user-agent filter answers this too, which is why the module refuses to read it as a death |
| 200 | the premise is broken: this cookie is not what the endpoint authenticates on |

Usage, on `VUURTH` or inside `SABLE-CLEAN`, from the repo root:

    python tools/probes/cookies_check.py
    python tools/probes/cookies_check.py --json

Exit code 0 means every entry answered 401 or 403.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agent import cookies, identity  # noqa: E402

# Shaped like a real value and certain not to be one: each entry's own cookie name with a random
# tail. A server that checks the signature only still refuses it.
NOT_A_CREDENTIAL = "sable-probe-not-a-session-0000000000000000"


def seed(workspace: Path) -> None:
    """One jar holding one row per table entry, all of them garbage."""
    rows = [
        {"host": f".{check.host}", "name": check.name, "value": NOT_A_CREDENTIAL, "expires": None}
        for check in cookies.CHECKS
    ]
    target = workspace / "browsers" / "probe" / "Default"
    target.mkdir(parents=True, exist_ok=True)
    (target / "cookies.json").write_text(json.dumps(rows), encoding="utf-8")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print the verdict document")
    options = parser.parse_args(argv)

    config = types.SimpleNamespace(sources=types.SimpleNamespace(browsers=True))

    with tempfile.TemporaryDirectory(prefix="sable-cookie-probe-") as folder:
        workspace = Path(folder)
        seed(workspace)

        marked = cookies.validate(workspace, config)
        document = json.loads(
            (workspace / "accounts" / cookies.STATUS_FILE).read_text(encoding="utf-8")
        )

        if options.json:
            print(json.dumps(document, indent=2))
        else:
            print(f"{marked} rows marked, {document['requests']} requests")
            width = max((len(row["kind"]) for row in document["rows"]), default=8)
            for row in document["rows"]:
                verdict = row["status"]
                reason = row.get("reason", "")
                print(f"  {row['kind']:<{width}}  {verdict:<7}  {reason}".rstrip())

        broken = [
            row
            for row in document["rows"]
            if row["status"] == cookies.VALID
        ]
        if broken:
            print("\nFAIL  an invalid value was accepted as a live session:")
            for row in broken:
                print(f"  {row['kind']}: {row['host']} answered 200")
            return 1

        unknown = [row for row in document["rows"] if row["status"] == cookies.UNKNOWN]
        if unknown:
            print(
                f"\nPASS  {len(unknown)} inconclusive — check the reasons above before trusting "
                "a verdict from that entry"
            )
        else:
            print("\nPASS  every entry refused an invalid value")
        return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
