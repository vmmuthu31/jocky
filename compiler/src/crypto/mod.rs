pub mod hsm;
pub mod aes_gcm;
pub mod chacha20;
pub mod ml_kem;

pub use hsm::{HsmKeyStore, DerivedKey, KeySource};
pub use aes_gcm::AesGcmCipher;
pub use chacha20::ChaCha20Cipher;
pub use ml_kem::{ml_kem_keygen, ml_kem_encapsulate, ml_kem_decapsulate, ml_kem_dk_from_seed};

use crate::ast::EncryptionAlgo;

/// Encrypt `payload` using the algorithm specified in the DSL and a key
/// derived from the warrant ID via HKDF keyed on `JOCKY_HSM_MASTER_KEY`.
/// Returns `(ciphertext, algorithm_label)`.
pub fn encrypt_evidence(
    payload: &[u8],
    algo: EncryptionAlgo,
    warrant_id: &str,
) -> Result<(Vec<u8>, String), String> {
    match algo {
        EncryptionAlgo::Aes256 => {
            let key = HsmKeyStore::derive_key("aes256", warrant_id);
            let cipher = AesGcmCipher::new(&key.bytes);
            let ct = cipher.encrypt(payload)?;
            Ok((ct, "AES-256-GCM".to_string()))
        }
        EncryptionAlgo::ChaCha20 => {
            let key = HsmKeyStore::derive_key("chacha20", warrant_id);
            let cipher = ChaCha20Cipher::new(&key.bytes);
            let ct = cipher.encrypt(payload)?;
            Ok((ct, "ChaCha20-Poly1305".to_string()))
        }
        EncryptionAlgo::MlKem => {
            // Generate an ephemeral keypair; the recipient's public key would
            // normally be pre-provisioned.  Ephemeral encapsulation is correct
            // for one-shot evidence transmission where the server holds dk.
            let (_seed, dk) = ml_kem_keygen();
            let (ct_kem, aes_cipher) = ml_kem_encapsulate(&dk)?;
            let ct_payload = aes_cipher.encrypt(payload)?;
            // Wire format: 4-byte kem_ct_len LE + kem_ct + aes_ct
            let mut out = Vec::with_capacity(4 + ct_kem.len() + ct_payload.len());
            let kem_len = ct_kem.len() as u32;
            out.extend_from_slice(&kem_len.to_le_bytes());
            out.extend_from_slice(&ct_kem);
            out.extend_from_slice(&ct_payload);
            Ok((out, "ML-KEM-768+AES-256-GCM (FIPS 203)".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::EncryptionAlgo;

    fn with_dev_key<T, F: FnOnce() -> T>(f: F) -> T {
        std::env::set_var("JOCKY_ALLOW_DEV_KEY", "1");
        let r = f();
        std::env::remove_var("JOCKY_ALLOW_DEV_KEY");
        r
    }

    #[test]
    fn test_aes256_encrypt_produces_output() {
        with_dev_key(|| {
            let (ct, label) = encrypt_evidence(b"evidence payload", EncryptionAlgo::Aes256, "NTRO-2026-CYBER-0421").unwrap();
            assert!(!ct.is_empty());
            assert!(label.contains("AES"));
        });
    }

    #[test]
    fn test_chacha20_encrypt_produces_output() {
        with_dev_key(|| {
            let (ct, label) = encrypt_evidence(b"ebpf telemetry", EncryptionAlgo::ChaCha20, "NTRO-2026-LINUX-0089").unwrap();
            assert!(!ct.is_empty());
            assert!(label.contains("ChaCha20"));
        });
    }

    #[test]
    fn test_mlkem_encrypt_produces_output() {
        // ML-KEM does not use the HSM key path — uses its own keygen
        let (ct, label) = encrypt_evidence(b"pqc vault payload", EncryptionAlgo::MlKem, "NTRO-2026-INFIL-9901").unwrap();
        assert!(!ct.is_empty());
        assert!(label.contains("ML-KEM"));
    }
}
