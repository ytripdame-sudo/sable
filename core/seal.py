"""Seal half of the archive encryption.

The decrypt half is ``agent.loader._open_sealed``, and it has to be there rather than
here: the stub decrypts before it can import anything that is inside the archive it
has not opened yet. That split means the format is written down twice, so the
constants below are the contract and ``tests/test_contracts.py`` seals with this
module and opens with the loader. A change to one without the other is a red test,
not a silent mismatch discovered on a target machine.

Layout, byte for byte:

    salt(16) || nonce(12) || ciphertext(n) || tag(16)

The salt is fresh per artifact and the nonce is fresh per seal. PBKDF2-HMAC-SHA256
stretches the key text, AES-256-GCM authenticates the ciphertext, and the tag is
appended rather than carried separately so the blob is one opaque run of bytes.

``core/`` may not import ``agent/``, so the constants are declared here as well. The
duplication is deliberate and pinned by test; importing them across the boundary
would invert the dependency the project spends a test enforcing.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Final

SALT_SIZE: Final[int] = 16
NONCE_SIZE: Final[int] = 12
TAG_SIZE: Final[int] = 16
KEY_BYTES: Final[int] = 32
KDF_ITERATIONS: Final[int] = 200_000

SEALED_OVERHEAD: Final[int] = SALT_SIZE + NONCE_SIZE + TAG_SIZE
MIN_SEALED_BYTES: Final[int] = SEALED_OVERHEAD + 1


class SealError(RuntimeError):
    """The seal could not be produced. Raised, never returned."""


def sealed_size(plaintext_size: int) -> int:
    """Bytes the sealed blob occupies for a given plaintext size."""
    if plaintext_size < 0:
        raise SealError(f"plaintext size {plaintext_size} is negative")
    return plaintext_size + SEALED_OVERHEAD


def seal(plaintext: bytes, key_text: str) -> bytes:
    """Seal ``plaintext`` under ``key_text``. Returns salt || nonce || ct || tag."""
    if not key_text:
        raise SealError("seal key is empty")
    if not plaintext:
        raise SealError("refusing to seal an empty archive")

    # Imported inside the function so importing this module stays cheap for the CLI,
    # which only needs it on the seal step.
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import PBKDF2

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)

    key = PBKDF2(
        key_text.encode("utf-8"),
        salt,
        dkLen=KEY_BYTES,
        count=KDF_ITERATIONS,
        hmac_hash_module=SHA256,
    )

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    blob = salt + nonce + ciphertext + tag
    if len(blob) != sealed_size(len(plaintext)):
        raise SealError(f"sealed {len(blob)} bytes, expected {sealed_size(len(plaintext))}")
    return blob


def seal_file(source: Path, destination: Path, key_text: str) -> Path:
    """Seal a file to ``destination`` through a staging file and an atomic replace."""
    try:
        plaintext = source.read_bytes()
    except OSError as exc:
        raise SealError(f"{source}: cannot read ({exc.strerror})") from exc

    blob = seal(plaintext, key_text)

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = destination.with_name(destination.name + ".part")
        staging.write_bytes(blob)
        # Same directory, so the replace is atomic: a half-written seal is never
        # visible under the final name.
        os.replace(staging, destination)
    except OSError as exc:
        raise SealError(f"{destination}: cannot write ({exc.strerror})") from exc

    return destination


__all__ = [
    "KEY_BYTES",
    "KDF_ITERATIONS",
    "MIN_SEALED_BYTES",
    "NONCE_SIZE",
    "SALT_SIZE",
    "SEALED_OVERHEAD",
    "TAG_SIZE",
    "SealError",
    "seal",
    "seal_file",
    "sealed_size",
]
