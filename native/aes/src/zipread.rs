//! A zip reader with a small surface: open, list, hand back one member's bytes.
//!
//! Deliberately not a general zip library. It reads what this project's archives
//! contain — stored and deflated members, no zip64, no split volumes, no data
//! descriptors worth trusting — and it reads the central directory rather than walking
//! local headers, because the central directory is what every writer fills in.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::{Error, Result};

const EOCD_SIGNATURE: [u8; 4] = *b"PK\x05\x06";
const CENTRAL_SIGNATURE: [u8; 4] = *b"PK\x01\x02";
const LOCAL_SIGNATURE: [u8; 4] = *b"PK\x03\x04";
const EOCD_SIZE: usize = 22;
/// The comment can be 64 KiB, so the record starts somewhere in the last 64 KiB plus
/// the record itself.
const EOCD_SEARCH: u64 = 65_557;

pub const METHOD_STORE: u16 = 0;
pub const METHOD_DEFLATE: u16 = 8;

/// A ceiling on one member after decompression. A deflated member claiming to expand
/// past this is a bomb or a corrupt length, and either way it is not a file to hand
/// to an allocator.
pub const MAX_MEMBER_BYTES: usize = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct AesExtra {
    pub version: u16,
    pub strength: u8,
    pub method: u16,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub name_bytes: Vec<u8>,
    pub flags: u16,
    pub method: u16,
    pub dos_time: u16,
    pub dos_date: u16,
    pub crc: u32,
    pub compressed: u64,
    pub uncompressed: u64,
    pub external_attr: u32,
    pub local_offset: u64,
    pub aes: Option<AesExtra>,
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }
}

pub struct Archive {
    file: File,
    pub entries: Vec<Entry>,
}

fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// The AES extra field, when one is present.
fn aes_extra(extra: &[u8]) -> Result<Option<AesExtra>> {
    let mut at = 0usize;
    while at + 4 <= extra.len() {
        let identifier = read_u16(extra, at);
        let size = read_u16(extra, at + 2) as usize;
        let start = at + 4;
        if start + size > extra.len() {
            return Err(Error::Shape("extra field runs past its member".into()));
        }
        if identifier == 0x9901 && size >= 7 {
            return Ok(Some(AesExtra {
                version: read_u16(extra, start),
                strength: extra[start + 4],
                method: read_u16(extra, start + 5),
            }));
        }
        at = start + size;
    }
    Ok(None)
}

impl Archive {
    pub fn open(path: &Path) -> Result<Archive> {
        let mut file = File::open(path)?;
        let size = file.metadata()?.len();
        if size < EOCD_SIZE as u64 {
            return Err(Error::Shape(format!(
                "{}: {size} bytes is not a zip",
                path.display()
            )));
        }

        let window = size.min(EOCD_SEARCH);
        let mut tail = vec![0u8; window as usize];
        file.seek(SeekFrom::Start(size - window))?;
        file.read_exact(&mut tail)?;

        let mut found = None;
        // Backwards: the record that matters is the last one, because an archive's
        // own comment could contain the bytes of an earlier signature.
        let mut at = tail.len().saturating_sub(EOCD_SIZE);
        loop {
            if tail[at..at + 4] == EOCD_SIGNATURE {
                found = Some(at);
                break;
            }
            if at == 0 {
                break;
            }
            at -= 1;
        }

        let at = found.ok_or_else(|| {
            Error::Shape(format!("{}: no end-of-directory record", path.display()))
        })?;

        let count = read_u16(&tail, at + 10) as u64;
        let directory_size = read_u32(&tail, at + 12) as u64;
        let directory_offset = read_u32(&tail, at + 16) as u64;

        if count == 0xFFFF || directory_offset == 0xFFFF_FFFF || directory_size == 0xFFFF_FFFF {
            return Err(Error::Shape(
                "zip64 archives are not read by this crate; the writer never produces one".into(),
            ));
        }
        if directory_offset + directory_size > size {
            return Err(Error::Shape("central directory runs past EOF".into()));
        }

        let mut directory = vec![0u8; directory_size as usize];
        file.seek(SeekFrom::Start(directory_offset))?;
        file.read_exact(&mut directory)?;

        let mut entries = Vec::with_capacity(count as usize);
        let mut at = 0usize;
        for _ in 0..count {
            if at + 46 > directory.len() {
                return Err(Error::Shape("central directory is short".into()));
            }
            if directory[at..at + 4] != CENTRAL_SIGNATURE {
                return Err(Error::Shape(
                    "central directory record is not PK\\x01\\x02".into(),
                ));
            }

            let flags = read_u16(&directory, at + 8);
            let method = read_u16(&directory, at + 10);
            let dos_time = read_u16(&directory, at + 12);
            let dos_date = read_u16(&directory, at + 14);
            let crc = read_u32(&directory, at + 16);
            let compressed = read_u32(&directory, at + 20) as u64;
            let uncompressed = read_u32(&directory, at + 24) as u64;
            let name_len = read_u16(&directory, at + 28) as usize;
            let extra_len = read_u16(&directory, at + 30) as usize;
            let comment_len = read_u16(&directory, at + 32) as usize;
            let external_attr = read_u32(&directory, at + 38);
            let local_offset = read_u32(&directory, at + 42) as u64;

            let name_start = at + 46;
            let extra_start = name_start + name_len;
            let record_end = extra_start + extra_len + comment_len;
            if record_end > directory.len() {
                return Err(Error::Shape("central directory record is short".into()));
            }

            let name_bytes = directory[name_start..extra_start].to_vec();
            let name = String::from_utf8(name_bytes.clone())
                .map_err(|_| Error::Shape("member name is not UTF-8".into()))?;
            let aes = aes_extra(&directory[extra_start..extra_start + extra_len])?;

            entries.push(Entry {
                name,
                name_bytes,
                flags,
                method,
                dos_time,
                dos_date,
                crc,
                compressed,
                uncompressed,
                external_attr,
                local_offset,
                aes,
            });

            at = record_end;
        }

        Ok(Archive { file, entries })
    }

    /// One member's stored bytes: still deflated, still encrypted, exactly as they sit
    /// in the file. Framing is the caller's business.
    pub fn stored_bytes(&mut self, entry: &Entry) -> Result<Vec<u8>> {
        self.file.seek(SeekFrom::Start(entry.local_offset))?;
        let mut header = [0u8; 30];
        self.file.read_exact(&mut header)?;
        if header[..4] != LOCAL_SIGNATURE {
            return Err(Error::Shape(format!(
                "{}: local header is not PK\\x03\\x04",
                entry.name
            )));
        }

        let name_len = read_u16(&header, 26) as u64;
        let extra_len = read_u16(&header, 28) as u64;
        let data_start = entry.local_offset + 30 + name_len + extra_len;

        if entry.compressed > MAX_MEMBER_BYTES as u64 {
            return Err(Error::Shape(format!(
                "{}: {} bytes is past the member ceiling",
                entry.name, entry.compressed
            )));
        }

        self.file.seek(SeekFrom::Start(data_start))?;
        let mut data = vec![0u8; entry.compressed as usize];
        self.file.read_exact(&mut data)?;
        Ok(data)
    }

    /// One member, decompressed. Only for unencrypted members.
    pub fn plain_bytes(&mut self, entry: &Entry) -> Result<Vec<u8>> {
        if entry.aes.is_some() || entry.method == 99 {
            return Err(Error::Shape(format!(
                "{}: member is encrypted, open it with a key",
                entry.name
            )));
        }

        let data = self.stored_bytes(entry)?;
        match entry.method {
            METHOD_STORE => Ok(data),
            METHOD_DEFLATE => inflate(&data, &entry.name),
            other => Err(Error::Shape(format!(
                "{}: compression method {other} is not read here",
                entry.name
            ))),
        }
    }
}

/// Raw deflate, with a ceiling so a corrupt length cannot ask for the whole address
/// space.
pub fn inflate(data: &[u8], label: &str) -> Result<Vec<u8>> {
    use std::io::Read;

    let mut decoder = flate2::read::DeflateDecoder::new(data);
    let mut out = Vec::new();
    let mut limited = (&mut decoder).take(MAX_MEMBER_BYTES as u64 + 1);
    limited
        .read_to_end(&mut out)
        .map_err(|cause| Error::Deflate(format!("{label}: {cause}")))?;

    if out.len() > MAX_MEMBER_BYTES {
        return Err(Error::Deflate(format!(
            "{label}: expands past the member ceiling"
        )));
    }
    Ok(out)
}

/// Raw deflate at maximum effort, matching what `zlib.compressobj(9, DEFLATED, -15)`
/// produces in size terms. The bytes need not be identical — any valid deflate stream
/// decodes — but the size should be in the same neighbourhood.
pub fn deflate(data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;

    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

/// A member name joined onto a destination folder, refusing anything that would leave
/// it. An archive is untrusted input even when we made it.
pub fn safe_join(root: &Path, name: &str) -> Result<std::path::PathBuf> {
    let trimmed = name.replace('\\', "/");
    let mut path = root.to_path_buf();

    for part in trimmed.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.contains(':') {
            return Err(Error::Shape(format!(
                "member name {name:?} leaves the folder"
            )));
        }
        path.push(part);
    }

    if path == root {
        return Err(Error::Shape(format!("member name {name:?} is empty")));
    }
    Ok(path)
}
