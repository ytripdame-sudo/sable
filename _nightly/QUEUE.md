# Nightly queue

One item per night. The loop takes the **first unchecked line that does not contain
`@human`**, works only that item, and stops when the gate is green.

Order is the priority. Move lines freely; the loop reads top to bottom.

`@human` marks work that needs a decision, a credential, a new manifest entry, or a
workflow edit. The loop skips those and reports them.

- [ ] **Per-source wall time in the run record.** `agent/sources/camera.py:76` and
      `agent/sources/screen.py` already compute `millis` per pass, but the run record does
      not carry a per-source total, which is why the 426 MB run's ceiling is unmeasured
      (`HANDOFF.md` §10 item 2). Find where the aggregate record is assembled, make each
      source's elapsed milliseconds visible there, and add
      `tests/test_nightly_source_timing.py` proving the key exists, is an `int`, is
      non-negative, and covers every source that ran. No new modules.

- [ ] **`progress.py` rate arithmetic.** `Progress.report` divides `sent` by `elapsed` and
      guards `elapsed > 0`; check the other direction too — a zero or negative `total`, and
      a `sent` larger than `total`, which happens when the body grows. Add
      `tests/test_nightly_progress_bounds.py`. Fix `progress.py` only if a case actually
      misbehaves; a guard that already holds needs no change.

- [x] **CI gate** — `@human`. Closed. `.github/workflows/gate.yml` runs on
      `windows-latest`, four jobs, green at `7d1269f` (run #3). The workflow stays
      bench-owned: the loop may not edit it, and this line is struck so it stops
      appearing in reports.

- [ ] **The native port** — `@human`. A product decision, not code. `HANDOFF.md` §10 item 1
      carries the measured numbers; the recommendation on the table is to stay on
      PyInstaller and fix the `%TEMP%` tree instead.

- [ ] **Sable PRO packaging** — `@human`. One-dir build, installer, signing. Design wants
      someone awake.
