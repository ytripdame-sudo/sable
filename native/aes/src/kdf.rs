//! Key derivation, both flavours.
//!
//! The container stretches with PBKDF2-HMAC-SHA256 at 200,000 rounds. WinZip stretches
//! with PBKDF2-HMAC-SHA1 at 1,000 rounds and asks for 66 bytes in one pass — 32 of
//! encryption key, 32 of authentication key, and a 2-byte verifier that lets a wrong
//! password fail before any ciphertext is touched. The round counts are not tunable
//! here because they are not ours: they are what the format says and what the files out
//! in the world already use.

use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::Sha256;

pub const SALT_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const KEY_BYTES: usize = 32;
pub const CONTAINER_ITERATIONS: u32 = 200_000;

pub const WINZIP_ITERATIONS: u32 = 1_000;
pub const WINZIP_MATERIAL: usize = 66;

/// The 32-byte AES-256-GCM key the SABL container uses.
pub fn container_key(password: &str, salt: &[u8]) -> [u8; KEY_BYTES] {
    let mut material = [0u8; KEY_BYTES];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt,
        CONTAINER_ITERATIONS,
        &mut material,
    );
    material
}

/// The three values WinZip's AES extra field implies.
pub struct WinZipKeys {
    pub encrypt: [u8; 32],
    pub auth: [u8; 32],
    /// The first two bytes of the derived material, written into the file so a wrong
    /// password fails on a cheap comparison instead of a full decrypt.
    pub verifier: [u8; 2],
}

pub fn winzip_keys(password: &str, salt: &[u8]) -> WinZipKeys {
    let mut material = [0u8; WINZIP_MATERIAL];
    pbkdf2_hmac::<Sha1>(password.as_bytes(), salt, WINZIP_ITERATIONS, &mut material);

    let mut encrypt = [0u8; 32];
    let mut auth = [0u8; 32];
    encrypt.copy_from_slice(&material[0..32]);
    auth.copy_from_slice(&material[32..64]);

    WinZipKeys {
        encrypt,
        auth,
        verifier: [material[64], material[65]],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Values produced by `pycryptodome` with the same inputs:
    ///
    /// ```text
    /// PBKDF2(b"correct horse battery staple", bytes([0x11])*16, dkLen=66,
    ///        count=1000, hmac_hash_module=SHA1)
    ///   [0:8]   = 58 7e 5f c6 de 98 e3 e7
    ///   [32:40] = 45 77 f6 c6 53 ce da f0
    ///   [64:66] = f2 be
    /// ```
    ///
    /// If these move, every archive sealed by either side becomes unopenable by the
    /// other, so the numbers are pinned rather than recomputed.
    #[test]
    fn winzip_material_matches_pycryptodome() {
        let keys = winzip_keys("correct horse battery staple", &[0x11; SALT_SIZE]);
        assert_eq!(keys.verifier, [0xf2, 0xbe]);
        assert_eq!(&keys.encrypt[..4], &[0x58, 0x7e, 0x5f, 0xc6]);
        assert_eq!(&keys.auth[..4], &[0x45, 0x77, 0xf6, 0xc6]);
    }

    #[test]
    fn container_key_is_stable() {
        let key = container_key("k-3f9a-test-key", &[0x22; SALT_SIZE]);
        assert_eq!(key.len(), 32);
        // Two calls with the same salt agree; that is the whole point of a KDF.
        let again = container_key("k-3f9a-test-key", &[0x22; SALT_SIZE]);
        assert_eq!(key, again);
    }
}
