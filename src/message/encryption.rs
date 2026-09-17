//! Encrypt a plaintext into a [`SpectrumMessage`] bound to a key image.
//!
//! The key is a strict deterministic function of the key image's exact bytes
//! (see [`crate::key_derivation`]), so encryption needs nothing but the image
//! and decryption needs nothing but the *same* image — no records, no helper
//! data. The message stores the SHA-256 of the key-image file, and
//! decryption refuses any image whose bytes (hence key) differ.

use crate::crypto::symmetric;
use crate::error::{Result, SpectrumError};
use crate::key_derivation::metadata::current_timestamp;
use crate::message::SpectrumMessage;
use crate::utils::hashing::hex_to_master;

#[cfg(feature = "pq")]
use rand::RngCore;

/// Encrypt `plaintext` under the deterministic key derived from `key_image`
/// using the *default* pipeline configuration.
///
/// Instance-aware callers (e.g. [`crate::SpectrumCrypto`]) should prefer
/// [`encrypt_message_with`] so custom preprocessing/entropy settings apply —
/// previously this path always built a default pipeline, silently ignoring
/// any configuration the caller had loaded.
pub fn encrypt_message(plaintext: &str, key_image: &str) -> Result<SpectrumMessage> {
    encrypt_message_with(
        &crate::key_derivation::KeyDerivationPipeline::new(),
        plaintext,
        key_image,
    )
}

/// Encrypt `plaintext` under the key derived by `pipeline` from `key_image`.
///
/// Hybrid mode: when `pq_public_key` is `Some` (requires the `pq` feature),
/// the message becomes **two-factor** — the AES-GCM and MAC subkeys are
/// HKDF expansions of the image-derived master key ‖ a fresh NTRU-Prime
/// shared secret encapsulated to the recipient's public key. The NTRU
/// ciphertext is stored in the message's `ntru_ciphertext` field and the
/// recipient needs **both** the exact key image **and** the NTRU-Prime
/// secret key to decrypt. Without the feature, `Some` is an error.
pub fn encrypt_message_with_pq(
    pipeline: &crate::key_derivation::KeyDerivationPipeline,
    plaintext: &str,
    key_image: &str,
    pq_public_key: Option<&[u8]>,
) -> Result<SpectrumMessage> {
    #[cfg(not(feature = "pq"))]
    if pq_public_key.is_some() {
        return Err(SpectrumError::PqLayerUnavailable);
    }

    let (key_hex, metadata) = pipeline.derive_key(key_image)?;
    let key = hex_to_master(&key_hex)?;

    let image_hash: [u8; 32] = hex::decode(&metadata.image_hash)
        .map_err(|e| SpectrumError::SerializationError(e.to_string()))?
        .try_into()
        .map_err(|_| {
            SpectrumError::SerializationError(
                "image hash must be 64 hex characters (32 bytes)".into(),
            )
        })?;

    // Hybrid mode encapsulates a fresh NTRU-Prime shared secret to the
    // recipient; classic mode has no PQ factor.
    #[cfg(feature = "pq")]
    let ntru_ss: Option<(Vec<u8>, Vec<u8>)> = match pq_public_key {
        Some(pk) => {
            let (ss, ct) = crate::crypto::ntru_prime::ntru_encapsulate(pk)?;
            Some((ss, ct))
        }
        None => None,
    };
    #[cfg(not(feature = "pq"))]
    let ntru_ss: Option<(Vec<u8>, Vec<u8>)> = None;

    // Confidentiality: AES-256-GCM. Classic: under the derived master key.
    // Hybrid: under the master ‖ NTRU-secret expansion.
    let encrypted_message = match &ntru_ss {
        #[cfg(feature = "pq")]
        Some((ss, _)) => {
            let (enc, _) = symmetric::expand_hybrid_keys(&key, ss);
            encrypt_with_subkey(&enc, plaintext.as_bytes())?
        }
        _ => symmetric::encrypt(&key, plaintext.as_bytes())?,
    };

    // One timestamp for both the MAC input and the stored field: sampling the
    // clock twice could straddle a second boundary and make the stored
    // timestamp differ from the MAC'd one, rendering the message
    // permanently undecryptable.
    let timestamp = current_timestamp();

    // Authenticity/integrity: MAC over (ciphertext || image hash || timestamp).
    // Hybrid mode MACs under the hybrid subkey so the NTRU factor is bound.
    let mut auth_input = Vec::new();
    auth_input.extend_from_slice(&encrypted_message);
    auth_input.extend_from_slice(&image_hash);
    auth_input.extend_from_slice(&timestamp.to_le_bytes());
    let signature = match &ntru_ss {
        #[cfg(feature = "pq")]
        Some((ss, _)) => symmetric::authenticate_hybrid(&key, ss, &auth_input).to_vec(),
        _ => symmetric::authenticate(&key, &auth_input).to_vec(),
    };

    Ok(SpectrumMessage::new(
        timestamp,
        image_hash,
        match &ntru_ss {
            Some((_, ct)) => ct.clone(),
            None => Vec::new(),
        },
        signature,
        encrypted_message,
    ))
}

/// AES-256-GCM encrypt under an explicit 32-byte subkey (the hybrid path's
/// per-message key). Output layout identical to [`symmetric::encrypt`].
#[cfg(feature = "pq")]
fn encrypt_with_subkey(subkey: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    let cipher = Aes256Gcm::new_from_slice(subkey)
        .map_err(|_| SpectrumError::SerializationError("invalid AES key".into()))?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| SpectrumError::EncapsulationFailed("AES-GCM hybrid encrypt".into()))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn encrypt_message_with(
    pipeline: &crate::key_derivation::KeyDerivationPipeline,
    plaintext: &str,
    key_image: &str,
) -> Result<SpectrumMessage> {
    encrypt_message_with_pq(pipeline, plaintext, key_image, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_image(dir: &std::path::Path) -> std::path::PathBuf {
        let mut img = image::RgbImage::new(160, 160);
        for (x, y, p) in img.enumerate_pixels_mut() {
            *p = image::Rgb([(x * 3) as u8, (y * 5) as u8, ((x + y) * 7) as u8]);
        }
        let p = dir.join("image.png");
        img.save(&p).unwrap();
        p
    }

    #[test]
    fn instance_config_changes_the_ciphertext() {
        // The facade used to derive under a default pipeline regardless of
        // the instance's config; the _with variant must honor the config.
        let dir = tempfile::tempdir().unwrap();
        let path = sample_image(dir.path());

        let default_msg = encrypt_message("payload", path.to_str().unwrap()).unwrap();
        let mut cfg = crate::config::SpectrumConfig::default();
        cfg.entropy.texture_enabled = false;
        let custom = crate::key_derivation::KeyDerivationPipeline::with_configs(
            cfg.entropy.clone(),
            cfg.preprocessor.clone(),
        );
        let custom_msg = encrypt_message_with(&custom, "payload", path.to_str().unwrap()).unwrap();
        assert_ne!(
            default_msg.encrypted_message, custom_msg.encrypted_message,
            "different config must derive a different key"
        );

        // …and the custom pipeline decrypts its own message.
        let parsed = SpectrumMessage::deserialize(&custom_msg.serialize().unwrap()).unwrap();
        assert_eq!(
            super::super::decryption::decrypt_message_with(
                &parsed,
                &custom,
                path.to_str().unwrap()
            )
            .unwrap(),
            "payload"
        );
    }

    #[test]
    fn encrypt_binds_to_the_key_image() {
        let dir = tempfile::tempdir().unwrap();
        let path = sample_image(dir.path());
        let msg = encrypt_message("hello", path.to_str().unwrap()).unwrap();
        assert!(!msg.encrypted_message.is_empty());
        assert_eq!(msg.signature.len(), 32);
        assert_eq!(msg.image_hash.len(), 32);
        // The bound hash is the SHA-256 of the exact key-image file.
        let file_bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            msg.image_hash,
            crate::utils::hashing::compute_sha256(file_bytes)
        );
    }
}
