/// HSM key derivation module.
///
/// In production, set `JOCKY_HSM_MASTER_KEY` to a 256-bit (32-byte) hex or
/// base64 master key loaded from AWS CloudHSM / Thales Luna via PKCS#11.
/// When the env var is present we use HKDF-SHA-256 over it.
///
/// If `JOCKY_HSM_MASTER_KEY` is absent and `JOCKY_ALLOW_DEV_KEY=1` is set the
/// module falls back to a built-in dev IKM and tags the key `DevFallback`.
/// Neither fallback mode is permitted at runtime without explicit opt-in; any
/// other case is a hard error so key material is never silently weakened.
///
/// Key hierarchy:
///   IKM  = master key bytes (env var or dev fallback)
///   Salt = warrant_id bytes
///   Info = "jocky-aes256" | "jocky-chacha20" | "jocky-mlkem"
///
/// All derived keys are 32 bytes (256 bits).

use hkdf::Hkdf;
use sha2::Sha256;

const DEV_IKM: &[u8] = b"JOCKY-NTRO-DEV-ONLY-KEY-26148!!!";

pub struct HsmKeyStore;

#[derive(Debug, Clone)]
pub struct DerivedKey {
    pub bytes: [u8; 32],
    pub source: KeySource,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeySource {
    /// Key derived from `JOCKY_HSM_MASTER_KEY` (production).
    HsmDerived,
    /// Key derived from built-in dev IKM (`JOCKY_ALLOW_DEV_KEY=1`). Never use in production.
    DevFallback,
}

impl HsmKeyStore {
    /// Derive a 32-byte key for the given algorithm and warrant.
    ///
    /// # Panics
    /// Panics if neither `JOCKY_HSM_MASTER_KEY` nor `JOCKY_ALLOW_DEV_KEY=1` is set,
    /// ensuring production deployments cannot accidentally run keyless.
    pub fn derive_key(algorithm: &str, warrant_id: &str) -> DerivedKey {
        let (ikm, source) = match std::env::var("JOCKY_HSM_MASTER_KEY") {
            Ok(v) => (v.into_bytes(), KeySource::HsmDerived),
            Err(_) => {
                let allow_dev = std::env::var("JOCKY_ALLOW_DEV_KEY")
                    .map(|v| v == "1")
                    .unwrap_or(false);
                if !allow_dev {
                    panic!(
                        "JOCKY_HSM_MASTER_KEY is not set and JOCKY_ALLOW_DEV_KEY is not '1'. \
                         Set JOCKY_HSM_MASTER_KEY to a production master key, \
                         or set JOCKY_ALLOW_DEV_KEY=1 for development/CI only."
                    );
                }
                eprintln!("WARNING: using dev fallback IKM — not for production use");
                (DEV_IKM.to_vec(), KeySource::DevFallback)
            }
        };

        let salt = warrant_id.as_bytes();
        let info = format!("jocky-{}", algorithm.to_lowercase());
        let hkdf = Hkdf::<Sha256>::new(Some(salt), &ikm);

        let mut okm = [0u8; 32];
        hkdf.expand(info.as_bytes(), &mut okm)
            .expect("HKDF expand: 32 bytes always fits");

        DerivedKey { bytes: okm, source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{with_dev_key, with_prod_key};

    #[test]
    fn test_derive_produces_32_bytes() {
        with_dev_key(|| {
            let key = HsmKeyStore::derive_key("aes256", "NTRO-2026-CYBER-0421");
            assert_eq!(key.bytes.len(), 32);
            assert_eq!(key.source, KeySource::DevFallback);
        });
    }

    #[test]
    fn test_different_algorithms_produce_different_keys() {
        with_dev_key(|| {
            let k1 = HsmKeyStore::derive_key("aes256",   "NTRO-2026-CYBER-0421");
            let k2 = HsmKeyStore::derive_key("chacha20", "NTRO-2026-CYBER-0421");
            assert_ne!(k1.bytes, k2.bytes);
        });
    }

    #[test]
    fn test_different_warrants_produce_different_keys() {
        with_dev_key(|| {
            let k1 = HsmKeyStore::derive_key("aes256", "NTRO-2026-CYBER-0421");
            let k2 = HsmKeyStore::derive_key("aes256", "NTRO-2026-LINUX-0089");
            assert_ne!(k1.bytes, k2.bytes);
        });
    }

    #[test]
    fn test_derivation_is_deterministic() {
        with_dev_key(|| {
            let k1 = HsmKeyStore::derive_key("aes256", "NTRO-2026-CYBER-0421");
            let k2 = HsmKeyStore::derive_key("aes256", "NTRO-2026-CYBER-0421");
            assert_eq!(k1.bytes, k2.bytes);
        });
    }

    #[test]
    fn test_env_key_reported_as_hsm_derived() {
        with_prod_key("test-production-key-32bytes!!!!", || {
            let k = HsmKeyStore::derive_key("aes256", "NTRO-2026-CYBER-0421");
            assert_eq!(k.source, KeySource::HsmDerived);
        });
    }
}
