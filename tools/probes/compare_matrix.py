"""Diff two GUI audit reports, check for check.

The desktop and the laptop run the same matrix against the same source zip with the
same launcher stub. What must agree: every case name, every verdict, every check label
and its result, the artifact size, the member count, and the config that reached
``cfg.json``. What is allowed to differ: timings, absolute paths, and the sealed bytes
themselves, because the salt and nonce are drawn fresh per build by design.

    python compare_matrix.py _out/audit/matrix.json laptop.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

VOLATILE = ("seconds", "artifact", "extras")
# Absolute paths are the only thing the two machines legitimately disagree on: the audit
# writes under its own ``_out`` tree. A drive-rooted string is reduced to its leaf so a
# path comparison still catches a different *file* while ignoring a different *root*.
_PATH_KEYS = ("out_dir", "output", "directory")


def _scrub(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: _scrub(item)
            for key, item in value.items()
            if key not in _PATH_KEYS
        }
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    if isinstance(value, str):
        text = value.strip()
        if len(text) > 2 and text[1] == ":" and text[2] in "\\/":
            return "<root>/" + text.replace("\\", "/").rsplit("/", 1)[-1]
        if text.startswith("\\\\"):
            return "<unc>/" + text.replace("\\", "/").rsplit("/", 1)[-1]
    return value


def load(path: Path) -> dict[str, dict]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return {case["name"]: case for case in document["cases"]}


def shape(case: dict) -> dict:
    """The part of a case two machines must agree on."""
    return {
        "passed": case["passed"],
        "bytes": case["bytes"],
        "members": case["members"],
        "gate_enabled": case["gate_enabled"],
        "config": _scrub(case["config"]),
        "rows": [(row["label"], row["ok"]) for row in case["rows"]],
    }


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2

    left_path, right_path = Path(sys.argv[1]), Path(sys.argv[2])
    left, right = load(left_path), load(right_path)

    only_left = sorted(set(left) - set(right))
    only_right = sorted(set(right) - set(left))
    shared = sorted(set(left) & set(right))

    agree = 0
    lines = []
    for name in shared:
        a, b = shape(left[name]), shape(right[name])
        if a == b:
            agree += 1
            lines.append((name, "same", "", len(a["rows"])))
            continue
        reasons = []
        if a["passed"] != b["passed"]:
            reasons.append(f"verdict {a['passed']} vs {b['passed']}")
        if a["bytes"] != b["bytes"]:
            reasons.append(f"bytes {a['bytes']:,} vs {b['bytes']:,}")
        if a["members"] != b["members"]:
            reasons.append(f"members {a['members']} vs {b['members']}")
        if a["gate_enabled"] != b["gate_enabled"]:
            reasons.append(f"gate {a['gate_enabled']} vs {b['gate_enabled']}")
        if a["config"] != b["config"]:
            reasons.append("form state differs")
        if a["rows"] != b["rows"]:
            left_rows = dict(a["rows"])
            right_rows = dict(b["rows"])
            differing = sorted(
                label for label in set(left_rows) | set(right_rows)
                if left_rows.get(label) != right_rows.get(label)
            )
            reasons.append("checks differ: " + ", ".join(differing[:4]))
        if len(a["rows"]) != len(b["rows"]):
            reasons.append(f"{len(a['rows'])} vs {len(b['rows'])} checks")
        lines.append((name, "DIFF", "; ".join(reasons), len(a["rows"])))

    print(f"{'case':<22} {'verdict':<7} {'checks':>6}  note")
    print("-" * 78)
    for name, verdict, note, checks in lines:
        print(f"{name:<22} {verdict:<7} {checks:>6}  {note}")

    if only_left:
        print(f"\nonly in {left_path.name}: {', '.join(only_left)}")
    if only_right:
        print(f"\nonly in {right_path.name}: {', '.join(only_right)}")

    total_checks = sum(len(shape(left[name])["rows"]) for name in shared)
    print(
        f"\n{agree}/{len(shared)} cases identical | {total_checks} checks compared | "
        f"{len(only_left)} left-only | {len(only_right)} right-only"
    )
    return 0 if agree == len(shared) and not only_left and not only_right else 1


if __name__ == "__main__":
    raise SystemExit(main())
