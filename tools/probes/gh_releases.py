"""List the releases on the phantom repo through the API, with their hosted links.

The channel's proof is server-side: the release page exists, its body carries a link,
and the archive behind that link hashes to the bytes that were sent. This prints all
three so the report can quote a page rather than a claim.

    python gh_releases.py
"""

from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

REPO = "ytripdame-sudo/SableResults"
URL = f"https://api.github.com/repos/{REPO}/releases"


def fetch(token: str) -> list[dict]:
    request = urllib.request.Request(URL)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("User-Agent", "sable-harness")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def main() -> int:
    import sys

    token = sys.argv[1] if len(sys.argv) > 1 else ""
    if not token:
        raise SystemExit("usage: gh_releases.py <token>")

    releases = fetch(token)
    print(f"releases {len(releases)}")
    for item in releases:
        body = item.get("body") or ""
        links = [match.rstrip(")") for match in re.findall(r"https?://\S+", body)]
        print(f"{item['tag_name']}  {item['name']}  {item['created_at']}")
        print(f"  page {item['html_url']}")
        for link in links:
            print(f"  host {link}")
        for line in body.splitlines():
            if line.startswith("`sha256`"):
                print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
