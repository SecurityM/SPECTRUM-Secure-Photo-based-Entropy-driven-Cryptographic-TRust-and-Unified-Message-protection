//! Symmetric layer: AES-256-GCM authenticated encryption keyed by a 256-bit
//! subkey expanded via HKDF-SHA256 (RFC 5869) from the 1072-bit image-derived
//! master key, plus an HMAC-SHA256 authenticator used for the message's
//! signature slot.
//!
//! The master key never touches AES-GCM directly: HKDF-Extract on the master
//! (IKM) with a fixed salt, then HKDF-Expand under strict domain-separated
//! labels, yields independent encryption and authentication subkeys.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
#[cfg(feature = "pq")]
use zeroize::Zeroizing;

use crate::error::{Result, SpectrumError};
#[cfg(test)]
use crate::utils::hashing::compute_sha256;
use crate::utils::hashing::hmac_sha256;

/// Fixed HKDF salt shared by every extraction from the master key (IKM).
/// A non-empty salt keeps Extract and Expand outputs independent across
/// re-derivations even if the master ever leaked partially.
const HKDF_SALT: &[u8] = b"SPECTRUM/master-kdf/salt/v1\x00";
/// Domain-separation label for expanding the encryption key.
const ENC_LABEL: &[u8] = b"spectrum/enckey/v1";
/// Domain-separation label for expanding the MAC key.
const MAC_LABEL: &[u8] = b"spectrum/mackey/v1";
/// Length of the AES-GCM nonce in bytes.
const NONCE_LEN: usize = 12;

/// Expand a master key (IKM, any length — normally the 1072-bit XOF output)
/// with a domain label into a fresh 32-byte subkey via HKDF-SHA256.
pub fn expand_key(master: &[u8], label: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), master);
    let mut okm = [0u8; 32];
    hk.expand(label, &mut okm)
        .expect("HKDF-Expand of 32 bytes cannot exceed the SHA-256 digest bounds");
    okm
}

/// Encrypt `plaintext` under `master_key`. Output layout:
/// `[ nonce(12) || ciphertext+tag ]`.
pub fn encrypt(master_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = expand_key(master_key, ENC_LABEL);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| SpectrumError::SerializationError("invalid AES key".into()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
        .map_err(|_| SpectrumError::EncapsulationFailed("AES-GCM encrypt".into()))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a blob produced by [`encrypt`].
pub fn decrypt(master_key: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN + 16 {
        return Err(SpectrumError::MalformedMessage(
            "encrypted blob too short".into(),
        ));
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let key = expand_key(master_key, ENC_LABEL);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| SpectrumError::SerializationError("invalid AES key".into()))?;

    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| SpectrumError::DecryptionFailed)
}

/// Compute an HMAC-SHA256 authenticator over `data` under the MAC subkey
/// derived from `master_key`.
pub fn authenticate(master_key: &[u8], data: &[u8]) -> [u8; 32] {
    let mac_key = expand_key(master_key, MAC_LABEL);
    hmac_sha256(&mac_key, data)
}

/// Constant-time byte equality: accumulates the XOR of every byte pair so the
/// comparison never short-circuits on the first mismatching byte. (Length is
/// public knowledge — a wrong-length tag is invalid regardless.)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Verify an HMAC-SHA256 authenticator in constant time.
pub fn verify(master_key: &[u8], data: &[u8], tag: &[u8]) -> Result<()> {
    let expect = authenticate(master_key, data);
    if constant_time_eq(tag, &expect) {
        Ok(())
    } else {
        Err(SpectrumError::VerificationFailed(
            "HMAC tag mismatch".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Hybrid post-quantum layer (feature = "pq")
//
// Hybrid messages are TRUE TWO-FACTOR: the AES-GCM key is HKDF over the
// image-derived master key ‖ a fresh NTRU-Prime shared secret encapsulated
// to the recipient's public key. Neither factor alone can open the message:
// leaking the key image does not compromise the ciphertext, and leaking the
// PQ secret key does not either. The NTRU ciphertext travels in the
// message's reserved `ntru_ciphertext` field.
// ---------------------------------------------------------------------------

/// HKDF labels for the hybrid (master ‖ NTRU shared secret) subkeys.
#[cfg(feature = "pq")]
const PQ_ENC_LABEL: &[u8] = b"spectrum/pq-enckey/v1";
#[cfg(feature = "pq")]
const PQ_MAC_LABEL: &[u8] = b"spectrum/pq-mackey/v1";

/// Expand the hybrid encryption and MAC subkeys from the image-derived
/// master key and an NTRU-Prime shared secret.
///
/// Both halves are required inputs: this is what makes a hybrid message
/// two-factor. Used identically on the send side (after encapsulation) and
/// the receive side (after decapsulation).
#[cfg(feature = "pq")]
pub fn expand_hybrid_keys(master_key: &[u8], ntru_shared_secret: &[u8]) -> ([u8; 32], [u8; 32]) {
    // The concatenated IKM (master ‖ shared secret) is secret material in its
    // own right: wipe it on drop instead of leaving the concat copy in freed
    // memory. (The inputs themselves borrow — the caller owns their lifetime.)
    let mut ikm = Vec::with_capacity(master_key.len() + ntru_shared_secret.len());
    ikm.extend_from_slice(master_key);
    ikm.extend_from_slice(ntru_shared_secret);
    let ikm = Zeroizing::new(ikm);
    let enc = expand_key(&ikm, PQ_ENC_LABEL);
    let mac = expand_key(&ikm, PQ_MAC_LABEL);
    (enc, mac)
}

/// Authenticate hybrid message data under the hybrid MAC subkey.
///
/// Same constant-time verification semantics as [`verify`]; the only
/// difference is the key expansion (see [`expand_hybrid_keys`]).
#[cfg(feature = "pq")]
pub fn authenticate_hybrid(master_key: &[u8], ntru_shared_secret: &[u8], data: &[u8]) -> [u8; 32] {
    let (_, mac) = expand_hybrid_keys(master_key, ntru_shared_secret);
    hmac_sha256(&mac, data)
}

/// Verify a hybrid authenticator in constant time.
#[cfg(feature = "pq")]
pub fn verify_hybrid(
    master_key: &[u8],
    ntru_shared_secret: &[u8],
    data: &[u8],
    tag: &[u8],
) -> Result<()> {
    let expect = authenticate_hybrid(master_key, ntru_shared_secret, data);
    if constant_time_eq(tag, &expect) {
        Ok(())
    } else {
        Err(SpectrumError::VerificationFailed(
            "hybrid HMAC tag mismatch".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = compute_sha256(b"image-pixels");
        let pt = b"hello, SPECTRUM world";
        let blob = encrypt(&key, pt).unwrap();
        assert_ne!(blob, pt);
        assert_eq!(decrypt(&key, &blob).unwrap(), pt.to_vec());
    }

    #[test]
    fn wrong_key_fails() {
        let key = compute_sha256(b"correct");
        let wrong = compute_sha256(b"wrong");
        let blob = encrypt(&key, b"secret").unwrap();
        assert!(decrypt(&wrong, &blob).is_err());
    }

    #[test]
    fn tamper_detected() {
        let key = compute_sha256(b"k");
        let blob = encrypt(&key, b"message").unwrap();
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert!(decrypt(&key, &tampered).is_err());
    }

    #[test]
    fn mac_verify() {
        let key = compute_sha256(b"k");
        let tag = authenticate(&key, b"data");
        assert!(verify(&key, b"data", &tag).is_ok());
        assert!(verify(&key, b"data2", &tag).is_err());
    }

    #[test]
    fn wrong_length_tag_is_rejected() {
        let key = compute_sha256(b"k");
        let tag = authenticate(&key, b"data");
        assert!(verify(&key, b"data", &tag[..31]).is_err());
        assert!(verify(&key, b"data", &[]).is_err());
    }

    #[test]
    fn labels_domain_separate_subkeys() {
        // Distinct labels must yield distinct AES and MAC subkeys from the
        // same master key; equal labels must be reproducible.
        let master = compute_sha256(b"master");
        assert_ne!(
            expand_key(&master, ENC_LABEL),
            expand_key(&master, MAC_LABEL)
        );
        assert_eq!(
            expand_key(&master, ENC_LABEL),
            expand_key(&master, ENC_LABEL)
        );
    }

    #[test]
    fn master_length_is_accepted_as_any_ikm() {
        // HKDF accepts an IKM of any length; the 1072-bit master key (134 B)
        // is the pipeline's normal input.
        let master: Vec<u8> = (0..crate::types::KEY_LENGTH)
            .map(|i| (i as u8).wrapping_mul(7))
            .collect();
        let blob = encrypt(&master, b"payload").unwrap();
        assert_eq!(decrypt(&master, &blob).unwrap(), b"payload".to_vec());
    }
}
