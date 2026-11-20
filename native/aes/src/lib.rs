//! Two formats, one crate: the WinZip AES-256 archive the agent transmits, and the
//! SABL container the launcher reads before it can import anything.
//!
//! Both are already written down twice in the Python tree, once to seal and once to
//! open, because the launcher cannot import the module that seals. This is the third
//! copy and the last one: the byte layout below is the contract, and `tests/interop`
//! proves it against files the Python side actually produced.
//!
//! Nothing here is clever. A counter, an HMAC, a GCM tag, a zip header. The work is in
//! matching the field order and the little-endian counters, not in the cryptography.

use std::fmt;
use std::io;

pub mod container;
pub mod kdf;
pub mod winzip;
pub mod zipread;

pub use container::{open_sealed, read_sealed, read_trailer, seal_blob, Trailer};
pub use winzip::{open_archive, seal_archive};

#[derive(Debug)]
pub enum Error {
    /// A file could not be read, written, sought or sized.
    Io(io::Error),
    /// The bytes are not shaped like the format that was claimed.
    Shape(String),
    /// The key was wrong. The label says which check caught it: the two-byte
    /// verifier before any ciphertext was touched, or the authentication code after.
    Auth(&'static str),
    /// A zip member could not be decompressed.
    Deflate(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(cause) => write!(formatter, "{cause}"),
            Error::Shape(detail) => write!(formatter, "{detail}"),
            Error::Auth(check) => write!(formatter, "key rejected the archive ({check})"),
            Error::Deflate(detail) => write!(formatter, "{detail}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(cause) => Some(cause),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(cause: io::Error) -> Self {
        Error::Io(cause)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Fill a buffer from the operating system. A failure here is not a soft failure:
/// a salt reused across two archives is the one mistake this format cannot survive.
pub fn random_bytes(buffer: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buffer).map_err(|cause| Error::Shape(format!("no entropy: {cause}")))
}

/// Length-independent comparison for short authenticators.
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}
