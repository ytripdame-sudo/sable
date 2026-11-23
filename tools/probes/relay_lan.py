"""Local relay that accepts a LAN connection, so a run on another machine is visible.

Same job as ``live_receiver.py`` with two differences that matter for watching a
second machine: it binds every interface by default, and every POST is printed with a
timestamp the moment it arrives, so the log reads as a live feed.

  python relay_lan.py <outdir> [port]

Nothing leaves this PC. Files land in <outdir>; status JSON is printed and saved.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "received")
PORT = int(sys.argv[2] if len(sys.argv) > 2 else 8099)
BIND = "0.0.0.0"

OUT.mkdir(parents=True, exist_ok=True)


def stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


class Server(ThreadingHTTPServer):
    """A server that refuses to share its port.

    ``ThreadingHTTPServer`` sets ``allow_reuse_address = True``. On Windows
    ``SO_REUSEADDR`` does not mean "reuse a port in TIME_WAIT" — it means "any
    process may bind a port another process is already listening on", and both keep
    listening. A receiver left over from an earlier session then takes a share of the
    deliveries, the files land in the old outdir, and the run reads as "the artifact
    never arrived" while the log says the POST succeeded. Measured: two receivers on
    8099, one bench upload split between two output directories.

    Failing to bind is the correct behaviour. A port that is taken is a stale process
    to kill, not a condition to work around.
    """

    allow_reuse_address = False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    def do_GET(self) -> None:  # noqa: N802
        """Serve a file out of the same directory the deliveries land in.

        The receiving machine is the one that has to run the artifact, and opening a
        second port for the handover means a second firewall rule and a second thing
        to forget. One port, one rule: POST delivers, GET collects.

        ``Path(name).name`` is the whole path defence — a request for
        ``../../secrets`` reduces to ``secrets`` in the outdir, which is not there.
        """
        wanted = Path(self.path.lstrip("/").split("?")[0]).name
        target = OUT / wanted if wanted else None

        if target is None or not target.is_file():
            listing = sorted(entry.name for entry in OUT.iterdir() if entry.is_file())
            payload = ("\n".join(listing) + "\n").encode("utf-8")
            self._answer(200, payload)
            return

        size = target.stat().st_size
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        with target.open("rb") as handle:
            while True:
                block = handle.read(1 << 20)
                if not block:
                    break
                self.wfile.write(block)
        print(f"[{stamp()}] {self.client_address[0]} GET {wanted}  {size} bytes", flush=True)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        content_type = self.headers.get("Content-Type") or ""
        body = self.rfile.read(length)
        peer = self.client_address[0]

        print(f"[{stamp()}] {peer} POST {self.path}  {length} bytes", flush=True)

        if content_type.startswith("application/json"):
            try:
                document = json.loads(body.decode("utf-8", "replace"))
                text = document.get("content", "")
            except ValueError:
                text = body.decode("utf-8", "replace")
            # Printed whole and unescaped: this is the message the operator will see,
            # so the local feed and the channel should look the same.
            print(text, flush=True)
            print("-" * 60, flush=True)
            name = f"status-{self.path.strip('/').replace('/', '-') or 'root'}.json"
            (OUT / name).write_bytes(body)
            self._answer(204, b"")
            return

        if "boundary=" not in content_type:
            self._answer(400, b"no boundary")
            return

        boundary = content_type.split("boundary=", 1)[1].strip().strip('"').encode()
        saved: list[str] = []
        for part in body.split(b"--" + boundary):
            if b"\r\n\r\n" not in part or b"filename=" not in part:
                continue
            head, payload = part.split(b"\r\n\r\n", 1)
            payload = payload[:-2] if payload.endswith(b"\r\n") else payload
            name = head.split(b"filename=", 1)[1].split(b"\r\n")[0].strip(b'"').decode(
                "utf-8", "replace"
            )
            target = OUT / Path(name).name
            target.write_bytes(payload)
            saved.append(f"{target.name} ({len(payload)} bytes)")
            print(f"[{stamp()}] saved {target.name}  {len(payload)} bytes", flush=True)

        if not saved:
            self._answer(400, b"no file part")
            return
        self._answer(200, ("stored: " + ", ".join(saved)).encode())

    def _answer(self, status: int, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    try:
        server = Server((BIND, PORT), Handler)
    except OSError as exc:
        print(f"[{stamp()}] cannot bind {BIND}:{PORT} — {exc}", flush=True)
        print(f"[{stamp()}] a receiver is already running; stop it first", flush=True)
        raise SystemExit(1) from exc
    print(f"[{stamp()}] relay on http://{BIND}:{PORT}/  -> {OUT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
