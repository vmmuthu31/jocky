/// AES-256-GCM encrypt/decrypt (FIPS 140-2 compliant).
///
/// All forensic evidence is encrypted in 64 KiB chunks before transmission.
/// The nonce is 12 random bytes prepended to each ciphertext blob so the
/// receiver can reconstruct it without separate channel.
///
/// Wire format per chunk:
///   [ 12 bytes nonce ][ N bytes ciphertext + 16-byte GCM tag ]

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::aead::rand_core::RngCore;

pub struct AesGcmCipher {
    cipher: Aes256Gcm,
}

impl AesGcmCipher {
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        Self { cipher: Aes256Gcm::new(key) }
    }

    /// Encrypt `plaintext` → `nonce(12) || ciphertext+tag(N+16)`
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("AES-GCM encrypt: {}", e))?;

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt `nonce(12) || ciphertext+tag` → plaintext
    pub fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        if blob.len() < 12 {
            return Err("ciphertext too short: missing nonce".into());
        }
        let nonce = Nonce::from_slice(&blob[..12]);
        self.cipher
            .decrypt(nonce, &blob[12..])
            .map_err(|e| format!("AES-GCM decrypt: {}", e))
    }

    pub fn algorithm() -> &'static str { "AES-256-GCM" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hsm::HsmKeyStore;
    use crate::test_util::with_dev_key;

    #[test]
    fn test_roundtrip() {
        with_dev_key(|| {
            let key = HsmKeyStore::derive_key("aes256", "NTRO-2026-CYBER-0421").bytes;
            let cipher = AesGcmCipher::new(&key);
            let plaintext = b"NTRO forensic payload - classified";
            let enc = cipher.encrypt(plaintext).unwrap();
            let dec = cipher.decrypt(&enc).unwrap();
            assert_eq!(dec.as_slice(), plaintext);
        });
    }

    #[test]
    fn test_different_encryptions_produce_different_ciphertexts() {
        with_dev_key(|| {
            let key = HsmKeyStore::derive_key("aes256", "NTRO-2026-CYBER-0421").bytes;
            let cipher = AesGcmCipher::new(&key);
            let pt = b"same plaintext";
            let c1 = cipher.encrypt(pt).unwrap();
            let c2 = cipher.encrypt(pt).unwrap();
            assert_ne!(c1, c2);
        });
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        with_dev_key(|| {
            let key = HsmKeyStore::derive_key("aes256", "NTRO-2026-CYBER-0421").bytes;
            let cipher = AesGcmCipher::new(&key);
            let mut enc = cipher.encrypt(b"secret").unwrap();
            *enc.last_mut().unwrap() ^= 0xff;
            assert!(cipher.decrypt(&enc).is_err(), "tampered ciphertext must fail");
        });
    }

    #[test]
    fn test_wrong_key_fails() {
        with_dev_key(|| {
            let key1 = HsmKeyStore::derive_key("aes256", "NTRO-2026-CYBER-0421").bytes;
            let key2 = HsmKeyStore::derive_key("aes256", "NTRO-2026-LINUX-0089").bytes;
            let c1 = AesGcmCipher::new(&key1);
            let c2 = AesGcmCipher::new(&key2);
            let enc = c1.encrypt(b"secret").unwrap();
            assert!(c2.decrypt(&enc).is_err(), "wrong key must fail");
        });
    }
}
