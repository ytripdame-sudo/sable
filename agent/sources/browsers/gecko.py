"""Firefox (Gecko) saved logins.

The profile is copied before anything is read from it. ``key4.db`` is opened from the
copy, never in place: a running Firefox keeps it open, and the original must not be
touched by a reader that has no business writing to it.

Two PBE generations exist and both are read here. The candidate list is built from
the DER, the password check picks the winner, and nothing is guessed: a derivation
that does not reproduce ``password-check`` is discarded.

Legacy (pre-144):

1. ``metadata`` row ``id='password'`` holds two DER blobs. ``item1`` carries the
   global salt; ``item2`` carries the PBE parameters and the password check.
2. The PBE key is ``PBKDF2-HMAC-SHA1(SHA1(globalSalt || password), entrySalt,
   iterations, 24)``. With no master password the password is empty.
3. That key 3DES-CBC-decrypts the password check, which must come back starting
   ``password-check``.
4. The same key decrypts the ``nssPrivate`` entry to the 24-byte SDR master key.
5. Each ``logins.json`` field is base64 DER, decrypted 3DES-CBC with that key.

Firefox 144 (October 2025) moved to PBES2:

1. ``item2`` is ``SEQ[ SEQ[ OID pbes2, SEQ[ kdf, scheme ] ], OCTET STRING ct ]``.
2. The KDF is PBKDF2 with an explicit PRF, ``hmacWithSHA256`` on current builds.
3. The scheme is AES-256-CBC with a 14-byte IV that NSS writes as a DER OCTET
   STRING; the IV handed to the cipher is the 16-byte encoding, header included.
4. ``nssPrivate.a11`` decrypts to 32 bytes plus one 16-byte PKCS#7 block.
5. The same master key decrypts the ``logins.json`` fields with AES-256-CBC.

The cipher is chosen by OID, never by key length: a 24-byte key is 3DES in the
legacy layout and AES-192 in PBES2, and picking on length alone decrypts the wrong
algorithm with the right number of bytes.
"""

from __future__ import annotations

import base64
import hashlib
import sqlite3
from pathlib import Path
from typing import Any, Final, NamedTuple

from ... import log, util

_PASSWORD_CHECK: Final[bytes] = b"password-check"

_MAX_LOGINS: Final[int] = 1000
_MAX_NSS_ROWS: Final[int] = 32
_MAX_DER_DEPTH: Final[int] = 8
# NSS ships 10000 rounds, but the cap is what a hostile or future file is allowed
# to cost us, not a claim about the current default. 200k is roughly 100 ms of
# PBKDF2-SHA256 per candidate, which keeps a corrupt key4.db from becoming a stall.
_MAX_ITERATIONS: Final[int] = 200_000
_MAX_BLOB_BYTES: Final[int] = 64 * 1024

_TAG_INTEGER: Final[int] = 0x02
_TAG_OCTET_STRING: Final[int] = 0x04
_TAG_OID: Final[int] = 0x06
_TAG_SEQUENCE: Final[int] = 0x30
_TAG_CONSTRUCTED: Final[int] = 0x20

_OID_PBES2: Final[str] = "1.2.840.113549.1.5.13"
_OID_PBKDF2: Final[str] = "1.2.840.113549.1.5.12"
_OID_DES_EDE3_CBC: Final[str] = "1.2.840.113549.3.7"
_OID_AES128_CBC: Final[str] = "2.16.840.1.101.3.4.1.2"
_OID_AES192_CBC: Final[str] = "2.16.840.1.101.3.4.1.22"
_OID_AES256_CBC: Final[str] = "2.16.840.1.101.3.4.1.42"

_PRF_OIDS: Final[dict[str, str]] = {
    "1.2.840.113549.2.7": "sha1",
    "1.2.840.113549.2.8": "sha224",
    "1.2.840.113549.2.9": "sha256",
    "1.2.840.113549.2.10": "sha384",
    "1.2.840.113549.2.11": "sha512",
}


class _Scheme(NamedTuple):
    name: str
    block: int
    key_bytes: int
    iv_bytes: int


_SCHEMES: Final[dict[str, _Scheme]] = {
    "des3": _Scheme("des3", 8, 24, 8),
    "aes128": _Scheme("aes128", 16, 16, 16),
    "aes192": _Scheme("aes192", 16, 24, 16),
    "aes256": _Scheme("aes256", 16, 32, 16),
}

_CIPHER_OIDS: Final[dict[str, str]] = {
    _OID_DES_EDE3_CBC: "des3",
    _OID_AES128_CBC: "aes128",
    _OID_AES192_CBC: "aes192",
    _OID_AES256_CBC: "aes256",
}


class _Element(NamedTuple):
    tag: int
    value: bytes
    raw: bytes


class _Pbe(NamedTuple):
    salt: bytes
    iterations: int
    iv: bytes
    ciphertext: bytes
    scheme: str
    prf: str
    key_bytes: int
    # Legacy derives PBKDF2 from SHA1(globalSalt || password); PBES2 feeds the
    # password to PBKDF2 untouched. Both readings are offered and the password
    # check decides, because a wrong reading cannot reproduce the oracle.
    prehash: bool


# --- DER ----------------------------------------------------------------------


def _der_length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    encoded = size.to_bytes(max(1, (size.bit_length() + 7) // 8), "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_parse(data: bytes) -> list[_Element]:
    """Top-level DER elements of ``data``. Raises ValueError on anything malformed."""
    elements: list[_Element] = []
    offset = 0
    limit = len(data)

    while offset < limit:
        start = offset
        tag = data[offset]
        offset += 1
        if offset >= limit:
            raise ValueError("truncated tag")

        first = data[offset]
        offset += 1
        if first < 0x80:
            length = first
        else:
            count = first & 0x7F
            if count == 0 or count > 4:
                raise ValueError("unsupported length form")
            if offset + count > limit:
                raise ValueError("truncated length")
            length = int.from_bytes(data[offset:offset + count], "big")
            offset += count

        if offset + length > limit:
            raise ValueError("truncated value")

        elements.append(_Element(tag, data[offset:offset + length], data[start:offset + length]))
        offset += length

    return elements


def _oid(value: bytes) -> str:
    """Dotted form of an OBJECT IDENTIFIER body. Empty string on garbage."""
    if not value:
        return ""
    parts = [str(value[0] // 40), str(value[0] % 40)]
    number = 0
    for byte in value[1:]:
        number = (number << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(number))
            number = 0
    return ".".join(parts)


def _walk_elements(blob: bytes, depth: int) -> list[_Element]:
    """Every element inside a constructed blob, in document order."""
    if depth > _MAX_DER_DEPTH or len(blob) > _MAX_BLOB_BYTES:
        return []
    try:
        elements = _der_parse(blob)
    except ValueError:
        return []

    found: list[_Element] = []
    for element in elements:
        found.append(element)
        if element.tag & _TAG_CONSTRUCTED:
            found.extend(_walk_elements(element.value, depth + 1))
    return found


def _fit_iv(element: _Element, size: int) -> bytes | None:
    """The IV a cipher of ``size`` bytes would be handed, or None."""
    value = element.value
    if len(value) == size:
        return value
    if size == 16 and len(value) == 14:
        # NSS writes the AES IV as the DER encoding of a 14-byte OCTET STRING and
        # feeds all 16 bytes to the cipher. The encoded form is the IV.
        return element.raw
    return None


def _encrypted_pairs(blob: bytes, scheme: _Scheme) -> list[tuple[bytes, bytes]]:
    """(iv, ciphertext) readings of an encrypted blob, explicit IV first."""
    elements = _walk_elements(blob, 0)
    pairs: list[tuple[bytes, bytes]] = []

    for index, element in enumerate(elements):
        if element.tag != _TAG_OCTET_STRING:
            continue
        iv = _fit_iv(element, scheme.iv_bytes)
        if iv is None:
            continue
        for follower in elements[index + 1:]:
            if follower.tag != _TAG_OCTET_STRING or not follower.value:
                continue
            if len(follower.value) % scheme.block:
                continue
            pairs.append((iv, follower.value))
            break

    for element in elements:
        if element.tag != _TAG_OCTET_STRING:
            continue
        value = element.value
        if len(value) <= scheme.iv_bytes:
            continue
        body = value[scheme.iv_bytes:]
        if len(body) % scheme.block:
            continue
        pairs.append((value[:scheme.iv_bytes], body))

    return pairs


# --- crypto -------------------------------------------------------------------


def _derive(global_salt: bytes, candidate: _Pbe, password: bytes) -> bytes:
    material = (
        hashlib.sha1(global_salt + password).digest() if candidate.prehash else password
    )
    rounds = max(1, min(candidate.iterations, _MAX_ITERATIONS))
    return hashlib.pbkdf2_hmac(
        candidate.prf, material, candidate.salt, rounds, candidate.key_bytes
    )


def _decrypt(scheme_name: str, key: bytes, iv: bytes, ciphertext: bytes) -> bytes | None:
    # Imported here so this module stays importable without pycryptodome.
    scheme = _SCHEMES.get(scheme_name)
    if scheme is None:
        return None
    if len(key) != scheme.key_bytes or len(iv) != scheme.iv_bytes:
        return None
    if not ciphertext or len(ciphertext) % scheme.block:
        return None
    try:
        if scheme_name == "des3":
            from Crypto.Cipher import DES3

            return DES3.new(key, DES3.MODE_CBC, iv).decrypt(ciphertext)
        from Crypto.Cipher import AES

        return AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    except ValueError:
        return None


def _strip_padding(data: bytes, block: int) -> bytes:
    if not data:
        return b""
    pad = data[-1]
    if 1 <= pad <= block and data.endswith(bytes([pad]) * pad):
        return data[:-pad]
    return data


# --- key4.db ------------------------------------------------------------------


def _global_salt(item1: bytes) -> bytes | None:
    try:
        outer = _der_parse(item1)
    except ValueError:
        return None
    for element in outer:
        if element.tag == _TAG_OCTET_STRING:
            return element.value
        if element.tag == _TAG_SEQUENCE:
            try:
                inner = _der_parse(element.value)
            except ValueError:
                continue
            for child in inner:
                if child.tag == _TAG_OCTET_STRING:
                    return child.value
    return None


def _prf_name(element: _Element) -> str:
    try:
        parts = _der_parse(element.value)
    except ValueError:
        return "sha1"
    if not parts or parts[0].tag != _TAG_OID:
        return "sha1"
    return _PRF_OIDS.get(_oid(parts[0].value), "sha1")


def _pbkdf2_params(kdf: _Element) -> tuple[bytes | None, int, int | None, str]:
    """(salt, iterations, keyLength, prf) from a PBKDF2 AlgorithmIdentifier."""
    if kdf.tag != _TAG_SEQUENCE:
        return None, 1, None, "sha1"
    try:
        parts = _der_parse(kdf.value)
    except ValueError:
        return None, 1, None, "sha1"
    if not parts or parts[0].tag != _TAG_OID or _oid(parts[0].value) != _OID_PBKDF2:
        return None, 1, None, "sha1"
    if len(parts) < 2 or parts[1].tag != _TAG_SEQUENCE:
        return None, 1, None, "sha1"
    try:
        params = _der_parse(parts[1].value)
    except ValueError:
        return None, 1, None, "sha1"

    salt: bytes | None = None
    prf = "sha1"
    integers: list[bytes] = []

    for element in params:
        if element.tag == _TAG_OCTET_STRING and salt is None:
            salt = element.value
        elif element.tag == _TAG_INTEGER:
            integers.append(element.value)
        elif element.tag == _TAG_SEQUENCE:
            prf = _prf_name(element)

    iterations = int.from_bytes(integers[0], "big") if integers else 1
    key_length = int.from_bytes(integers[1], "big") if len(integers) > 1 else None
    return salt, iterations, key_length, prf


def _encryption_scheme(scheme: _Element) -> tuple[str | None, bytes | None]:
    if scheme.tag != _TAG_SEQUENCE:
        return None, None
    try:
        parts = _der_parse(scheme.value)
    except ValueError:
        return None, None
    if not parts or parts[0].tag != _TAG_OID:
        return None, None
    name = _CIPHER_OIDS.get(_oid(parts[0].value))
    if name is None:
        return None, None
    resolved = _SCHEMES[name]
    if len(parts) < 2 or parts[1].tag != _TAG_OCTET_STRING:
        return None, None
    return name, _fit_iv(parts[1], resolved.iv_bytes)


def _layout_legacy(children: list[_Element]) -> list[_Pbe]:
    """The pre-144 readings. Both produce 3DES candidates and the oracle picks."""
    candidates: list[_Pbe] = []

    # Layout A: SEQ[ SEQ[ OID, OCTET STRING salt, INTEGER iterations ], OCTET STRING iv||ct ]
    head = children[0]
    if head.tag == _TAG_SEQUENCE:
        try:
            params = _der_parse(head.value)
        except ValueError:
            params = []
        salt: bytes | None = None
        iterations = 1
        for element in params:
            if element.tag == _TAG_OCTET_STRING and salt is None:
                salt = element.value
            elif element.tag == _TAG_INTEGER:
                iterations = int.from_bytes(element.value, "big")
        body = children[1].value if children[1].tag == _TAG_OCTET_STRING else b""
        if salt is not None and len(body) > 8:
            candidates.append(
                _Pbe(salt, iterations, body[:8], body[8:], "des3", "sha1", 24, True)
            )

    # Layout B: SEQ[ OCTET STRING salt, INTEGER iterations, OCTET STRING iv, OCTET STRING ct ]
    if (
        len(children) >= 4
        and children[0].tag == _TAG_OCTET_STRING
        and children[1].tag == _TAG_INTEGER
    ):
        iv = children[2].value
        ciphertext = children[3].value
        if len(iv) == 8 and ciphertext:
            candidates.append(
                _Pbe(
                    children[0].value,
                    int.from_bytes(children[1].value, "big"),
                    iv,
                    ciphertext,
                    "des3",
                    "sha1",
                    24,
                    True,
                )
            )

    return candidates


def _layout_pbes2(children: list[_Element]) -> list[_Pbe]:
    """The 144+ reading: PBES2 wrapping PBKDF2 and an AES scheme."""
    head = children[0]
    if head.tag != _TAG_SEQUENCE:
        return []
    try:
        algorithm = _der_parse(head.value)
    except ValueError:
        return []
    if not algorithm or algorithm[0].tag != _TAG_OID:
        return []
    if _oid(algorithm[0].value) != _OID_PBES2:
        return []
    if len(algorithm) < 2 or algorithm[1].tag != _TAG_SEQUENCE:
        return []
    try:
        params = _der_parse(algorithm[1].value)
    except ValueError:
        return []
    if len(params) < 2:
        return []

    salt, iterations, key_length, prf = _pbkdf2_params(params[0])
    scheme_name, iv = _encryption_scheme(params[1])
    if salt is None or scheme_name is None or iv is None:
        return []

    if len(children) < 2 or children[1].tag != _TAG_OCTET_STRING:
        return []
    ciphertext = children[1].value
    if not ciphertext:
        return []

    scheme = _SCHEMES[scheme_name]
    if len(ciphertext) % scheme.block:
        return []
    if key_length is not None and key_length != scheme.key_bytes:
        # A key length that disagrees with the cipher means the parameters are
        # not what they claim. No oracle would verify, so do not burn the CPU.
        return []

    return [
        _Pbe(salt, iterations, iv, ciphertext, scheme_name, prf, scheme.key_bytes, False),
        _Pbe(salt, iterations, iv, ciphertext, scheme_name, prf, scheme.key_bytes, True),
    ]


def _pbe_candidates(item2: bytes) -> list[_Pbe]:
    """Every plausible reading of the PBE block. The password check picks one."""
    try:
        outer = _der_parse(item2)
    except ValueError:
        return []
    if not outer or outer[0].tag != _TAG_SEQUENCE:
        return []
    try:
        children = _der_parse(outer[0].value)
    except ValueError:
        return []
    if len(children) < 2:
        return []

    return _layout_legacy(children) + _layout_pbes2(children)


def _metadata(connection: sqlite3.Connection) -> tuple[bytes, bytes] | None:
    try:
        row = connection.execute(
            "SELECT item1, item2 FROM metadata WHERE id = 'password'"
        ).fetchone()
    except sqlite3.Error:
        log.logger.debug("gecko: metadata read failed", exc_info=True)
        return None
    if row is None:
        return None

    first, second = row[0], row[1]
    if not isinstance(first, (bytes, bytearray)) or not isinstance(second, (bytes, bytearray)):
        return None
    return bytes(first), bytes(second)


def _unlock(global_salt: bytes, item2: bytes, password: bytes) -> tuple[bytes, str] | None:
    """(PBE key, scheme name), but only if it reproduces the password check."""
    for candidate in _pbe_candidates(item2):
        key = _derive(global_salt, candidate, password)
        plaintext = _decrypt(candidate.scheme, key, candidate.iv, candidate.ciphertext)
        if plaintext is None:
            continue
        if plaintext.startswith(_PASSWORD_CHECK):
            return key, candidate.scheme
    return None


def _master_key(
    connection: sqlite3.Connection, pbe_key: bytes, scheme_name: str
) -> bytes | None:
    scheme = _SCHEMES[scheme_name]
    try:
        rows = connection.execute(
            "SELECT a11 FROM nssPrivate WHERE a11 IS NOT NULL"
        ).fetchall()
    except sqlite3.Error:
        log.logger.debug("gecko: nssPrivate read failed", exc_info=True)
        return None

    for row in rows[:_MAX_NSS_ROWS]:
        blob = row[0]
        if not isinstance(blob, (bytes, bytearray)):
            continue
        for iv, ciphertext in _encrypted_pairs(bytes(blob), scheme):
            plaintext = _decrypt(scheme_name, pbe_key, iv, ciphertext)
            if plaintext is None:
                continue
            key = _strip_padding(plaintext, scheme.block)
            if len(key) == scheme.key_bytes:
                return key

    return None


def _profile_key(profile: Path, scratch: Path) -> tuple[bytes, str] | None:
    source = profile / "key4.db"
    if not source.is_file():
        return None

    copy = scratch / "key4.db"
    if not util.copy_with_sidecars(source, copy):
        return None

    try:
        connection = sqlite3.connect(str(copy))
    except sqlite3.Error:
        log.logger.debug("gecko: cannot open the key4 copy", exc_info=True)
        return None

    try:
        meta = _metadata(connection)
        if meta is None:
            return None
        salt = _global_salt(meta[0])
        if salt is None:
            log.logger.debug("gecko: no global salt in key4.db")
            return None
        unlocked = _unlock(salt, meta[1], b"")
        if unlocked is None:
            # Either a master password is set, or the layout is not one this
            # parser reads. Both are reported, neither is guessed at.
            log.logger.debug("gecko: password check did not verify")
            return None
        pbe_key, scheme_name = unlocked
        master = _master_key(connection, pbe_key, scheme_name)
        if master is None:
            log.logger.debug("gecko: no master key in nssPrivate")
            return None
        return master, scheme_name
    finally:
        connection.close()


# --- logins.json --------------------------------------------------------------


def _field(entry: dict[str, Any], name: str) -> str:
    if name not in entry:
        return ""
    value = entry[name]
    if isinstance(value, str):
        return value
    return ""


def _stamp(entry: dict[str, Any], name: str) -> str | None:
    if name not in entry:
        return None
    value = entry[name]
    if not isinstance(value, int):
        return None
    # logins.json carries milliseconds since the Unix epoch.
    return util.unix_time(value // 1000)


def _decrypt_field(
    entry: dict[str, Any], name: str, key: bytes, scheme_name: str
) -> bytes | None:
    if name not in entry:
        return None
    text = entry[name]
    if not isinstance(text, str) or not text:
        return None
    try:
        blob = base64.b64decode(text, validate=False)
    except (ValueError, TypeError):
        return None

    scheme = _SCHEMES[scheme_name]
    for iv, ciphertext in _encrypted_pairs(blob, scheme):
        plaintext = _decrypt(scheme_name, key, iv, ciphertext)
        if plaintext is None:
            continue
        value = _strip_padding(plaintext, scheme.block)
        if value:
            return value
    return None


def _logins(profile: Path, target: Path, key: bytes, scheme_name: str) -> int:
    document = util.read_json(profile / "logins.json")
    if not isinstance(document, dict):
        return 0
    if "logins" not in document:
        return 0
    records = document["logins"]
    if not isinstance(records, list):
        return 0

    entries: list[dict[str, Any]] = []

    for record in records:
        if len(entries) >= _MAX_LOGINS:
            break
        if not isinstance(record, dict):
            continue
        password = _decrypt_field(record, "encryptedPassword", key, scheme_name)
        if password is None:
            continue
        username = _decrypt_field(record, "encryptedUsername", key, scheme_name)
        entries.append(
            {
                "host": _field(record, "hostname"),
                "username": "" if username is None else username.decode("utf-8", "replace"),
                "password": password.decode("utf-8", "replace"),
                "form_url": _field(record, "formSubmitURL"),
                "realm": _field(record, "httpRealm"),
                "created": _stamp(record, "timeCreated"),
                "last_used": _stamp(record, "timeLastUsed"),
                "changed": _stamp(record, "timePasswordChanged"),
            }
        )

    if not entries:
        return 0
    if not util.write_json(target / "passwords.json", entries):
        return 0
    return len(entries)


def run_profile(profile: Path, target: Path) -> int:
    """Collect one Firefox profile's logins. Returns the number written."""
    if not profile.is_dir():
        return 0
    if not (profile / "logins.json").is_file():
        return 0

    with util.temp_workspace("sable-gecko-") as scratch:
        unlocked = _profile_key(profile, scratch)
        if unlocked is None:
            log.logger.debug("gecko: %s has no usable key4.db", profile.name)
            return 0
        key, scheme_name = unlocked
        written = _logins(profile, target, key, scheme_name)

    log.logger.debug("gecko: %s wrote %d (%s)", profile.name, written, scheme_name)
    return written


__all__ = ["run_profile"]
