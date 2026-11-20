//! The SABL container: what a built artifact looks like from the last byte backwards.
//!
//! ```text
//! [ launcher ][ ballast ][ sealed blob ][ trailer 868 ][ footer 12 ]
//! ```
//!
//! The footer is `SBLT` and a little-endian offset, so it is one seek from EOF. The
//! trailer is a fixed width, so its start is the same arithmetic. The key lives in the
//! trailer, which is why one frozen launcher opens every artifact built with it: the
//! launcher carries the reader, not the key.
//!
//! The sealed blob itself is `salt(16) || nonce(12) || ciphertext(n) || tag(16)`, AES-256-GCM
//! keyed on PBKDF2-HMAC-SHA256 of the seal key text.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::kdf::{container_key, NONCE_SIZE, SALT_SIZE, TAG_SIZE};
use crate::{random_bytes, Error, Result};

pub const FOOTER_MAGIC: [u8; 4] = *b"SBLT";
pub const FOOTER_SIZE: u64 = 12;
pub const TRAILER_MAGIC: [u8; 4] = *b"SBLK";
pub const KEY_SLOT: usize = 64;
pub const MUTEX_SLOT: usize = 800;
pub const TRAILER_SIZE: u64 = (4 + KEY_SLOT + MUTEX_SLOT) as u64;

/// A ceiling on the decrypted payload. The same number the Python reader uses: an
/// artifact claiming more than this is a corrupt header, not a large build.
pub const MAX_SEALED_BYTES: u64 = 512 * 1024 * 1024;

pub struct Trailer {
    pub seal_key: String,
    pub mutex: String,
}

fn file_size(image: &Path) -> Result<u64> {
    let metadata = std::fs::metadata(image)?;
    Ok(metadata.len())
}

/// One NUL-terminated slot. Everything after the first NUL is padding.
fn slot_text(field: &[u8], name: &str) -> Result<String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if end == 0 {
        return Err(Error::Shape(format!("trailer {name} is empty")));
    }
    std::str::from_utf8(&field[..end])
        .map(|text| text.to_string())
        .map_err(|_| Error::Shape(format!("trailer {name} is not UTF-8")))
}

pub fn read_trailer(image: &Path) -> Result<Trailer> {
    let size = file_size(image)?;
    let minimum = TRAILER_SIZE + FOOTER_SIZE + 1;
    if size < minimum {
        return Err(Error::Shape(format!(
            "{}: {size} bytes cannot carry a trailer",
            image.display()
        )));
    }

    let mut handle = File::open(image)?;
    handle.seek(SeekFrom::Start(size - FOOTER_SIZE - TRAILER_SIZE))?;
    let mut block = vec![0u8; TRAILER_SIZE as usize];
    handle.read_exact(&mut block)?;

    if block[..4] != TRAILER_MAGIC {
        return Err(Error::Shape(format!(
            "{}: no SBLK trailer",
            image.display()
        )));
    }

    let head = TRAILER_MAGIC.len();
    Ok(Trailer {
        seal_key: slot_text(&block[head..head + KEY_SLOT], "seal key")?,
        mutex: slot_text(&block[head + KEY_SLOT..], "mutex")?,
    })
}

pub fn archive_offset(image: &Path) -> Result<u64> {
    let size = file_size(image)?;
    let tail = FOOTER_SIZE + TRAILER_SIZE;
    if size <= tail + 1 {
        return Err(Error::Shape(format!(
            "{}: {size} bytes cannot carry a footer",
            image.display()
        )));
    }

    let mut handle = File::open(image)?;
    handle.seek(SeekFrom::Start(size - FOOTER_SIZE))?;
    let mut footer = [0u8; FOOTER_SIZE as usize];
    handle.read_exact(&mut footer)?;

    if footer[..4] != FOOTER_MAGIC {
        return Err(Error::Shape(format!("{}: no SBLT footer", image.display())));
    }

    let mut offset_bytes = [0u8; 8];
    offset_bytes.copy_from_slice(&footer[4..12]);
    let offset = u64::from_le_bytes(offset_bytes);

    if offset == 0 || offset >= size - tail {
        return Err(Error::Shape(format!(
            "{}: footer offset {offset} is outside the file",
            image.display()
        )));
    }
    Ok(offset)
}

/// The sealed blob, from the footer's offset up to the trailer.
pub fn read_sealed(image: &Path) -> Result<Vec<u8>> {
    let size = file_size(image)?;
    let offset = archive_offset(image)?;
    let end = size - FOOTER_SIZE - TRAILER_SIZE;
    let length = end.saturating_sub(offset);

    if length == 0 || length > MAX_SEALED_BYTES {
        return Err(Error::Shape(format!("sealed blob is {length} bytes")));
    }

    let mut handle = File::open(image)?;
    handle.seek(SeekFrom::Start(offset))?;
    let mut blob = vec![0u8; length as usize];
    handle.read_exact(&mut blob)?;
    Ok(blob)
}

/// Decrypt one sealed blob. The tag is checked before a single byte is returned.
pub fn open_sealed(blob: &[u8], seal_key: &str) -> Result<Vec<u8>> {
    let minimum = SALT_SIZE + NONCE_SIZE + TAG_SIZE + 1;
    if blob.len() < minimum {
        return Err(Error::Shape(format!(
            "sealed blob is {} bytes, needs {minimum}",
            blob.len()
        )));
    }

    let salt = &blob[..SALT_SIZE];
    let nonce = &blob[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
    let tag = &blob[blob.len() - TAG_SIZE..];
    let ciphertext = &blob[SALT_SIZE + NONCE_SIZE..blob.len() - TAG_SIZE];

    let key = container_key(seal_key, salt);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| Error::Auth("verifier"))?;

    // The crate wants ciphertext and tag together, which is how GCM defines them.
    let mut sealed = Vec::with_capacity(ciphertext.len() + TAG_SIZE);
    sealed.extend_from_slice(ciphertext);
    sealed.extend_from_slice(tag);

    cipher
        .decrypt(Nonce::from_slice(nonce), sealed.as_slice())
        .map_err(|_| Error::Auth("tag"))
}

/// Seal a payload into a container blob. Used by the interop test and by anything that
/// needs to produce what `core/seal.py` produces.
pub fn seal_blob(plaintext: &[u8], seal_key: &str) -> Result<Vec<u8>> {
    if seal_key.is_empty() {
        return Err(Error::Shape("seal key is empty".into()));
    }
    if plaintext.is_empty() {
        return Err(Error::Shape("refusing to seal an empty archive".into()));
    }

    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];
    random_bytes(&mut salt)?;
    random_bytes(&mut nonce)?;

    let key = container_key(seal_key, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| Error::Auth("verifier"))?;
    let sealed = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| Error::Auth("verifier"))?;

    let mut blob = Vec::with_capacity(SALT_SIZE + NONCE_SIZE + sealed.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&sealed);
    Ok(blob)
}

/// Write a whole artifact: launcher bytes, ballast, sealed blob, trailer, footer.
///
/// This is the shape `core/forge.py` writes, and it exists here so a test can prove the
/// Rust reader against a container assembled by Rust rather than only against Python.
pub fn write_image(
    launcher: &Path,
    ballast: &[u8],
    sealed: &[u8],
    seal_key: &str,
    mutex: &str,
    destination: &Path,
) -> Result<u64> {
    if seal_key.len() >= KEY_SLOT {
        return Err(Error::Shape(format!(
            "seal key is {} bytes, the slot holds {}",
            seal_key.len(),
            KEY_SLOT - 1
        )));
    }
    if mutex.len() >= MUTEX_SLOT {
        return Err(Error::Shape(format!(
            "mutex is {} bytes, the slot holds {}",
            mutex.len(),
            MUTEX_SLOT - 1
        )));
    }

    let mut body = std::fs::read(launcher)?;
    body.extend_from_slice(ballast);

    let offset = body.len() as u64;
    body.extend_from_slice(sealed);

    let mut trailer = Vec::with_capacity(TRAILER_SIZE as usize);
    trailer.extend_from_slice(&TRAILER_MAGIC);
    trailer.resize(TRAILER_MAGIC.len() + KEY_SLOT, 0);
    trailer[TRAILER_MAGIC.len()..TRAILER_MAGIC.len() + seal_key.len()]
        .copy_from_slice(seal_key.as_bytes());
    trailer.resize(TRAILER_MAGIC.len() + KEY_SLOT + MUTEX_SLOT, 0);
    let mutex_start = TRAILER_MAGIC.len() + KEY_SLOT;
    trailer[mutex_start..mutex_start + mutex.len()].copy_from_slice(mutex.as_bytes());
    body.extend_from_slice(&trailer);

    body.extend_from_slice(&FOOTER_MAGIC);
    body.extend_from_slice(&offset.to_le_bytes());

    std::fs::write(destination, &body)?;
    Ok(body.len() as u64)
}
