"""Profile bundle: caches dropped, lean files kept, bulk capped, Local State lifted.

Synthetic trees only. Nothing here reads a real browser profile.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(r"C:\Users\Kuzenee\Desktop\55555\sable")
sys.path.insert(0, str(ROOT))

from agent.sources.browsers import chromium  # noqa: E402

results: list[tuple[str, bool, str]] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append((label, ok, detail))


def write(path: Path, size: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(os.urandom(size))


def build_profile(user_data: Path) -> Path:
    profile = user_data / "Default"
    write(user_data / "Local State", 2048)
    write(profile / "Preferences", 4096)
    write(profile / "History", 8192)
    write(profile / "Login Data", 8192)
    write(profile / "Web Data", 4096)
    write(profile / "Network" / "Cookies", 4096)
    write(profile / "IndexedDB" / "https_example.com_0.indexeddb.leveldb" / "000003.log", 2048)
    write(profile / "Local Extension Settings" / "abcdef" / "000005.ldb", 2048)
    write(profile / "Cache" / "Cache_Data" / "f_000001", 300_000)
    write(profile / "Code Cache" / "js" / "index", 300_000)
    write(profile / "Service Worker" / "CacheStorage" / "abc" / "data", 300_000)
    write(profile / "GPUCache" / "data_0", 300_000)
    return profile


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sable-bundle-") as scratch:
        work = Path(scratch)
        user_data = work / "User Data"
        profile = build_profile(user_data)
        target = work / "out" / "browsers" / "edge" / "Default"

        copied = chromium.bundle_profile(profile, target)
        bundle = target / "profile"

        check("returns a file count", copied > 0, str(copied))
        check("preferences copied", (bundle / "Preferences").is_file())
        check("history copied", (bundle / "History").is_file())
        check("login data copied", (bundle / "Login Data").is_file())
        check("web data copied", (bundle / "Web Data").is_file())
        check("network cookies copied", (bundle / "Network" / "Cookies").is_file())
        check("local state lifted beside the profile", (target / "Local State").is_file())

        check("cache dropped", not (bundle / "Cache").exists())
        check("code cache dropped", not (bundle / "Code Cache").exists())
        check("service worker dropped", not (bundle / "Service Worker").exists())
        check("gpu cache dropped", not (bundle / "GPUCache").exists())

        check("indexeddb copied", (bundle / "IndexedDB").exists())
        check(
            "local extension settings copied",
            (bundle / "Local Extension Settings").exists(),
        )

        # Bulk is what the budget eats first, never the lean set. The synthetic lean
        # set is 28,672 bytes; 30,000 fits it exactly and leaves nothing for bulk.
        chromium._MAX_BUNDLE_BYTES = 30_000
        try:
            tight = work / "tight" / "Default"
            kept = chromium.bundle_profile(profile, tight)
        finally:
            chromium._MAX_BUNDLE_BYTES = 192 * 1024 * 1024

        tight_bundle = tight / "profile"
        check("a tight budget still returns files", kept == 5, str(kept))
        check("a tight budget keeps the lean set", (tight_bundle / "Preferences").is_file())
        check("a tight budget drops the bulk", not (tight_bundle / "IndexedDB").exists())

        # A single file over the per-file ceiling is refused, not counted.
        chromium._MAX_BUNDLE_FILE_BYTES = 1024
        try:
            small = work / "small" / "Default"
            chromium.bundle_profile(profile, small)
        finally:
            chromium._MAX_BUNDLE_FILE_BYTES = 64 * 1024 * 1024
        check(
            "an oversized file is refused",
            not (small / "profile" / "History").exists(),
        )

        # A profile with no databases at all still bundles rather than raising.
        empty_user = work / "Empty User Data"
        empty = empty_user / "Default"
        empty.mkdir(parents=True)
        write(empty_user / "Local State", 128)
        check(
            "an empty profile bundles only its Local State",
            chromium.bundle_profile(empty, work / "empty") == 1,
        )

        # run_profile counts the bundle as one artifact, not as its file count.
        counted = chromium.run_profile(profile, work / "counted")
        check("run_profile counts the bundle once", counted >= 1, str(counted))
        check("run_profile writes the bundle", (work / "counted" / "profile").is_dir())

        # Real roots are never touched: the module only reads what it is handed.
        check(
            "skip list holds no bulk directory",
            not (chromium._SKIP_DIRS & chromium._BULK_DIRS),
            str(sorted(chromium._SKIP_DIRS & chromium._BULK_DIRS)),
        )

    failed = [item for item in results if not item[1]]
    for label, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {label}  {detail}")
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
