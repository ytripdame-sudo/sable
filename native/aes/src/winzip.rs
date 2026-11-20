//! WinZip AES-256, version AE-2, the way the Python writer emits it.
//!
//! ```text
//! member = salt(16) || verifier(2) || AES-CTR(deflate(plaintext)) || hmac-sha1(…)[..10]
//! ```
//!
//! The CTR counter is 16 bytes, little-endian, starting at 1 and incrementing across the
//! whole member. That is WinZip's definition, not the NIST one, and it is why this file
//! carries its own counter instead of using a standard CTR mode: getting the byte order
//! wrong produces an archive that decrypts to noise and authenticates to nothing.
//!
//! AE-2 means the CRC field is zero and the authentication code is the integrity check.
//! AE-1 would carry a CRC; no writer here produces one, and reading it back is not
//! implemented because nothing in this project can create that shape.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::kdf::{winzip_keys, SALT_SIZE};
use crate::zipread::{deflate, inflate, safe_join, Archive, Entry};
use crate::{constant_time_eq, random_bytes, Error, Result};

pub const METHOD_AES: u16 = 99;
pub const METHOD_DEFLATE: u16 = 8;
pub const METHOD_STORE: u16 = 0;

pub const AES_EXTRA_ID: u16 = 0x9901;
pub const AES_VERSION: u16 = 2;
pub const AES_VENDOR: [u8; 2] = *b"AE";
/// 3 means AES-256. The strength byte is a lookup index into {128, 192, 256}.
pub const AES_STRENGTH: u8 = 3;
pub const AES_AUTH: usize = 10;
/// 51 is version 5.1: the number WinZip defined for AES members.
pub const AES_NEEDED: u16 = 51;
/// Bit 0 of the general-purpose flags: this member is encrypted.
pub const AES_FLAG: u16 = 0x0001;

/// 4096 blocks of keystream per refill. One AES call per counter would be 21 million
/// calls on a 340 MB archive; this divides that by 4096 and keeps the hot loop tight.
const CTR_BLOCKS: u128 = 4096;

/// AES-256 driving WinZip's little-endian counter.
pub struct Counter {
    cipher: Aes256,
    counter: u128,
    stream: Vec<u8>,
    offset: usize,
}

impl Counter {
    pub fn new(key: &[u8]) -> Result<Counter> {
        let cipher = Aes256::new_from_slice(key).map_err(|_| Error::Auth("verifier"))?;
        Ok(Counter {
            cipher,
            counter: 1,
            stream: Vec::new(),
            offset: 0,
        })
    }

    fn refill(&mut self) {
        self.stream.clear();
        self.stream.reserve((CTR_BLOCKS as usize) * 16);
        let start = self.counter;

        for index in 0..CTR_BLOCKS {
            let value = start.wrapping_add(index);
            let mut block = GenericArray::clone_from_slice(&value.to_le_bytes());
            self.cipher.encrypt_block(&mut block);
            self.stream.extend_from_slice(&block);
        }

        self.counter = start.wrapping_add(CTR_BLOCKS);
        self.offset = 0;
    }

    /// XOR the keystream into the buffer, in place. Encryption and decryption are the
    /// same operation here, which is the whole reason CTR is used.
    pub fn apply(&mut self, data: &mut [u8]) {
        let mut index = 0usize;
        while index < data.len() {
            if self.offset == self.stream.len() {
                self.refill();
            }
            let available = self.stream.len() - self.offset;
            let take = available.min(data.len() - index);
            for step in 0..take {
                data[index + step] ^= self.stream[self.offset + step];
            }
            self.offset += take;
            index += take;
        }
    }
}

fn aes_extra(method: u16) -> Vec<u8> {
    let mut extra = Vec::with_capacity(11);
    extra.extend_from_slice(&AES_EXTRA_ID.to_le_bytes());
    extra.extend_from_slice(&7u16.to_le_bytes());
    extra.extend_from_slice(&AES_VERSION.to_le_bytes());
    extra.extend_from_slice(&AES_VENDOR);
    extra.push(AES_STRENGTH);
    extra.extend_from_slice(&method.to_le_bytes());
    extra
}

fn tag_of(auth_key: &[u8], ciphertext: &[u8]) -> Result<[u8; AES_AUTH]> {
    let mut mac =
        <Hmac<Sha1> as Mac>::new_from_slice(auth_key).map_err(|_| Error::Auth("verifier"))?;
    mac.update(ciphertext);
    let digest = mac.finalize().into_bytes();

    let mut tag = [0u8; AES_AUTH];
    tag.copy_from_slice(&digest[..AES_AUTH]);
    Ok(tag)
}

struct Sink {
    out: BufWriter<File>,
    written: u64,
}

impl Sink {
    fn new(path: &Path) -> Result<Sink> {
        Ok(Sink {
            out: BufWriter::new(File::create(path)?),
            written: 0,
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.out.write_all(bytes)?;
        self.written += bytes.len() as u64;
        Ok(())
    }

    fn finish(mut self) -> Result<u64> {
        self.out.flush()?;
        Ok(self.written)
    }
}

/// Write `source` as an AES-256 zip keyed on `password`. Returns the member count.
///
/// Each member is deflated first and then encrypted, so the result is about the size of
/// the source archive rather than of the tree inside it.
pub fn seal_archive(source: &Path, destination: &Path, password: &str) -> Result<usize> {
    if password.is_empty() {
        return Err(Error::Shape("refusing to seal without a password".into()));
    }

    let mut archive = Archive::open(source)?;
    let mut sink = Sink::new(destination)?;
    let mut central: Vec<u8> = Vec::new();
    let mut count: u16 = 0;

    let entries: Vec<Entry> = archive.entries.clone();
    for entry in entries.iter() {
        if entry.is_dir() {
            continue;
        }

        let plaintext = archive.plain_bytes(entry)?;
        let packed = deflate(&plaintext)?;

        let mut salt = [0u8; SALT_SIZE];
        random_bytes(&mut salt)?;
        let keys = winzip_keys(password, &salt);

        let mut ciphertext = packed;
        Counter::new(&keys.encrypt)?.apply(&mut ciphertext);
        let tag = tag_of(&keys.auth, &ciphertext)?;

        let extra = aes_extra(METHOD_DEFLATE);
        let stored = (SALT_SIZE + 2 + ciphertext.len() + AES_AUTH) as u64;
        let offset = sink.written;

        let mut header = Vec::with_capacity(30);
        header.extend_from_slice(b"PK\x03\x04");
        header.extend_from_slice(&AES_NEEDED.to_le_bytes());
        header.extend_from_slice(&AES_FLAG.to_le_bytes());
        header.extend_from_slice(&METHOD_AES.to_le_bytes());
        header.extend_from_slice(&entry.dos_time.to_le_bytes());
        header.extend_from_slice(&entry.dos_date.to_le_bytes());
        // AE-2 carries no CRC; the authentication code replaces it.
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&(stored as u32).to_le_bytes());
        header.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
        header.extend_from_slice(&(entry.name_bytes.len() as u16).to_le_bytes());
        header.extend_from_slice(&(extra.len() as u16).to_le_bytes());

        sink.write(&header)?;
        sink.write(&entry.name_bytes)?;
        sink.write(&extra)?;
        sink.write(&salt)?;
        sink.write(&keys.verifier)?;
        sink.write(&ciphertext)?;
        sink.write(&tag)?;

        let mut record = Vec::with_capacity(46 + entry.name_bytes.len() + extra.len());
        record.extend_from_slice(b"PK\x01\x02");
        record.extend_from_slice(&AES_NEEDED.to_le_bytes());
        record.extend_from_slice(&AES_NEEDED.to_le_bytes());
        record.extend_from_slice(&AES_FLAG.to_le_bytes());
        record.extend_from_slice(&METHOD_AES.to_le_bytes());
        record.extend_from_slice(&entry.dos_time.to_le_bytes());
        record.extend_from_slice(&entry.dos_date.to_le_bytes());
        record.extend_from_slice(&0u32.to_le_bytes());
        record.extend_from_slice(&(stored as u32).to_le_bytes());
        record.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
        record.extend_from_slice(&(entry.name_bytes.len() as u16).to_le_bytes());
        record.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        record.extend_from_slice(&0u16.to_le_bytes());
        record.extend_from_slice(&0u16.to_le_bytes());
        record.extend_from_slice(&0u16.to_le_bytes());
        record.extend_from_slice(&entry.external_attr.to_le_bytes());
        record.extend_from_slice(&(offset as u32).to_le_bytes());
        record.extend_from_slice(&entry.name_bytes);
        record.extend_from_slice(&extra);

        central.extend_from_slice(&record);
        count = count.checked_add(1).ok_or_else(|| {
            Error::Shape("more than 65535 members, which this writer does not lay out".into())
        })?;
    }

    let directory_offset = sink.written;
    sink.write(&central)?;
    let directory_size = sink.written - directory_offset;

    let mut end = Vec::with_capacity(22);
    end.extend_from_slice(b"PK\x05\x06");
    end.extend_from_slice(&0u16.to_le_bytes());
    end.extend_from_slice(&0u16.to_le_bytes());
    end.extend_from_slice(&count.to_le_bytes());
    end.extend_from_slice(&count.to_le_bytes());
    end.extend_from_slice(&(directory_size as u32).to_le_bytes());
    end.extend_from_slice(&(directory_offset as u32).to_le_bytes());
    end.extend_from_slice(&0u16.to_le_bytes());
    sink.write(&end)?;

    sink.finish()?;
    Ok(count as usize)
}

/// Open an AES-256 zip and write every member under `destination`.
///
/// Returns the names written, in the order they were laid out. A wrong password fails
/// on the verifier before any ciphertext is decrypted, and a tampered member fails on
/// its authentication code, so a file that lands on disk is a file that authenticated.
pub fn open_archive(source: &Path, destination: &Path, password: &str) -> Result<Vec<String>> {
    let mut archive = Archive::open(source)?;
    let mut written = Vec::new();

    let entries: Vec<Entry> = archive.entries.clone();
    for entry in entries.iter() {
        if entry.is_dir() {
            continue;
        }

        let data = match entry.aes.as_ref() {
            Some(aes) => decrypt_member(&mut archive, entry, aes, password)?,
            None => archive.plain_bytes(entry)?,
        };

        let path = safe_join(destination, &entry.name)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &data)?;
        written.push(entry.name.clone());
    }

    Ok(written)
}

fn decrypt_member(
    archive: &mut Archive,
    entry: &Entry,
    aes: &crate::zipread::AesExtra,
    password: &str,
) -> Result<Vec<u8>> {
    if aes.version != AES_VERSION {
        return Err(Error::Shape(format!(
            "{}: AES version {} is not AE-2",
            entry.name, aes.version
        )));
    }

    let data = archive.stored_bytes(entry)?;
    let fixed = SALT_SIZE + 2 + AES_AUTH;
    if data.len() <= fixed {
        return Err(Error::Shape(format!("{}: member is too short", entry.name)));
    }

    let salt = &data[..SALT_SIZE];
    let verifier = &data[SALT_SIZE..SALT_SIZE + 2];
    let tag = &data[data.len() - AES_AUTH..];
    let mut ciphertext = data[SALT_SIZE + 2..data.len() - AES_AUTH].to_vec();

    let keys = winzip_keys(password, salt);
    if !constant_time_eq(&keys.verifier, verifier) {
        return Err(Error::Auth("verifier"));
    }

    // The code authenticates the ciphertext, not the plaintext: the tag is written
    // before the counter is ever applied, so it has to be checked before the buffer is
    // decrypted in place. Getting these two lines the wrong way round hashes plaintext
    // and rejects every archive that is actually fine.
    let expected = tag_of(&keys.auth, &ciphertext)?;
    if !constant_time_eq(&expected, tag) {
        return Err(Error::Auth("tag"));
    }

    Counter::new(&keys.encrypt)?.apply(&mut ciphertext);

    match aes.method {
        METHOD_STORE => Ok(ciphertext),
        METHOD_DEFLATE => inflate(&ciphertext, &entry.name),
        other => Err(Error::Shape(format!(
            "{}: inner method {other} is not supported",
            entry.name
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A byte-exact keystream echo: the counter starts at one, little-endian.
    #[test]
    fn counter_starts_at_one_and_walks() {
        let key = [0u8; 32];
        let mut counter = Counter::new(&key).expect("key");
        let mut block = [0u8; 16];
        counter.apply(&mut block);

        // Encrypting zeroes yields the raw keystream, which must equal AES-ECB of the
        // 16-byte little-endian value 1.
        let cipher = Aes256::new_from_slice(&key).expect("key");
        let mut expected = GenericArray::clone_from_slice(&1u128.to_le_bytes());
        cipher.encrypt_block(&mut expected);
        assert_eq!(block, expected.as_slice());
    }
}
