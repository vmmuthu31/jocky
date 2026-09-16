/// ChaCha20-Poly1305 encrypt/decrypt.
///
/// Used when `encrypt chacha20(key: hsm_derived)` is specified in the DSL.
/// Preferred for Linux field agents where AES-NI may not be available.
/// Same wire format as AES-GCM: nonce(12) || ciphertext+tag.

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::aead::rand_core::RngCore;

pub struct ChaCha20Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Cipher {
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        let key = Key::from_slice(key_bytes);
        Self { cipher: ChaCha20Poly1305::new(key) }
    }

    /// Encrypt plaintext → `nonce(12) || ciphertext+tag`
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("ChaCha20-Poly1305 encrypt: {}", e))?;

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
            .map_err(|e| format!("ChaCha20-Poly1305 decrypt: {}", e))
    }

    pub fn algorithm() -> &'static str { "ChaCha20-Poly1305" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hsm::HsmKeyStore;
    use crate::test_util::with_dev_key;

    #[test]
    fn test_roundtrip() {
        with_dev_key(|| {
            let key = HsmKeyStore::derive_key("chacha20", "NTRO-2026-LINUX-0089").bytes;
            let cipher = ChaCha20Cipher::new(&key);
            let pt = b"eBPF telemetry - 256 process events";
            let enc = cipher.encrypt(pt).unwrap();
            let dec = cipher.decrypt(&enc).unwrap();
            assert_eq!(dec.as_slice(), pt);
        });
    }

    #[test]
    fn test_tampered_fails() {
        with_dev_key(|| {
            let key = HsmKeyStore::derive_key("chacha20", "NTRO-2026-LINUX-0089").bytes;
            let cipher = ChaCha20Cipher::new(&key);
            let mut enc = cipher.encrypt(b"secret").unwrap();
            enc[12] ^= 0x01;
            assert!(cipher.decrypt(&enc).is_err());
        });
    }

    #[test]
    fn test_random_nonces() {
        with_dev_key(|| {
            let key = HsmKeyStore::derive_key("chacha20", "NTRO-2026-LINUX-0089").bytes;
            let cipher = ChaCha20Cipher::new(&key);
            let c1 = cipher.encrypt(b"x").unwrap();
            let c2 = cipher.encrypt(b"x").unwrap();
            assert_ne!(c1[..12], c2[..12], "nonces must differ per encryption");
        });
    }
}
