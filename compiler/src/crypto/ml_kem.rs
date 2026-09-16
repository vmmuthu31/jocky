/// ML-KEM-768 (NIST FIPS 203) post-quantum key encapsulation.
///
/// Hybrid mode: ML-KEM-768 encapsulates a 32-byte shared secret which is
/// then used as AES-256-GCM key material via HKDF-SHA-256.
///
/// Wire format: [ 4-byte LE length of ML-KEM ciphertext ]
///              [ ML-KEM-768 ciphertext (1088 bytes) ]
///              [ AES-GCM ciphertext (12-byte nonce + payload + 16-byte tag) ]

use ml_kem::{
    Decapsulate,
    DecapsulationKey, EncapsulationKey,
    Seed, B32,
    ml_kem_768::MlKem768,
    array::Array,
};
// Use OsRng from aes-gcm's aead crate (which has rand_core 0.6 compatible version)
use aes_gcm::aead::rand_core::RngCore as AeadRng;
use aes_gcm::aead::OsRng;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::aes_gcm::AesGcmCipher;

fn derive_aes_key(ss: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, ss);
    let mut key = [0u8; 32];
    hkdf.expand(b"jocky-mlkem-aes256", &mut key).unwrap();
    key
}

/// Generate a fresh ML-KEM-768 keypair from a random 64-byte seed.
/// Returns `(seed_bytes, decapsulation_key)`.
pub fn ml_kem_keygen() -> ([u8; 64], DecapsulationKey<MlKem768>) {
    let mut seed_bytes = [0u8; 64];
    OsRng.fill_bytes(&mut seed_bytes);
    let seed: Seed = Array::from(seed_bytes);
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
    (seed_bytes, dk)
}

/// Restore a `DecapsulationKey` from its 64-byte seed.
pub fn ml_kem_dk_from_seed(seed_bytes: &[u8; 64]) -> DecapsulationKey<MlKem768> {
    let seed: Seed = Array::from(*seed_bytes);
    DecapsulationKey::<MlKem768>::from_seed(seed)
}

/// Encapsulate a shared secret using `dk`'s embedded encapsulation key.
/// Returns `(kem_ciphertext_bytes, AES cipher keyed on the shared secret)`.
pub fn ml_kem_encapsulate(dk: &DecapsulationKey<MlKem768>) -> Result<(Vec<u8>, AesGcmCipher), String> {
    let ek: &EncapsulationKey<MlKem768> = dk.encapsulation_key();

    // Use encapsulate_deterministic with a fresh random 32-byte value
    let mut m_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut m_bytes);
    let m: B32 = Array::from(m_bytes);

    let (ct, ss): (ml_kem::kem::Ciphertext<MlKem768>, B32) = ek.encapsulate_deterministic(&m);
    let ct_bytes_ref: &[u8] = <ml_kem::kem::Ciphertext<MlKem768> as AsRef<[u8]>>::as_ref(&ct);
    let ct_vec: Vec<u8> = ct_bytes_ref.to_vec();
    let aes_key = derive_aes_key(ss.as_ref());
    Ok((ct_vec, AesGcmCipher::new(&aes_key)))
}

/// Decapsulate `ct_bytes` with `dk`, return the corresponding AES cipher.
pub fn ml_kem_decapsulate(dk: &DecapsulationKey<MlKem768>, ct_bytes: &[u8]) -> Result<AesGcmCipher, String> {
    const CT_SIZE: usize = 1088;
    if ct_bytes.len() != CT_SIZE {
        return Err(format!("ML-KEM-768 ciphertext must be {} bytes, got {}", CT_SIZE, ct_bytes.len()));
    }

    let ct_arr = <ml_kem::kem::Ciphertext<MlKem768>>::try_from(ct_bytes)
        .map_err(|_| "ML-KEM ciphertext parse error".to_string())?;

    let ss = dk.decapsulate(&ct_arr);
    let aes_key = derive_aes_key(ss.as_ref());
    Ok(AesGcmCipher::new(&aes_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_produces_seed() {
        let (seed, _dk) = ml_kem_keygen();
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn test_encap_decap_roundtrip() {
        let (seed, dk) = ml_kem_keygen();
        let (ct_bytes, enc_cipher) = ml_kem_encapsulate(&dk).unwrap();
        assert_eq!(ct_bytes.len(), 1088, "ML-KEM-768 ct must be 1088 bytes");

        let dk2 = ml_kem_dk_from_seed(&seed);
        let dec_cipher = ml_kem_decapsulate(&dk2, &ct_bytes).unwrap();

        let pt = b"NTRO post-quantum forensic vault";
        let encrypted = enc_cipher.encrypt(pt).unwrap();
        let decrypted  = dec_cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted.as_slice(), pt);
    }

    #[test]
    fn test_wrong_ct_size_rejected() {
        let (_seed, dk) = ml_kem_keygen();
        let bad_ct = vec![0u8; 100];
        assert!(ml_kem_decapsulate(&dk, &bad_ct).is_err());
    }
}
