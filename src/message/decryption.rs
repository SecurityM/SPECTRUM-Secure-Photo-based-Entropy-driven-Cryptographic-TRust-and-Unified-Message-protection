//! Decrypt a [`SpectrumMessage`] using the exact key image it was encrypted
//! under.
//!
//! Because the master key is a strict deterministic function of the key
//! image's exact bytes, decryption re-derives the key from `key_image` and
//! verifies the message's stored image SHA-256 against it. Any other image —
//! even a near-identical re-capture — derives an unrelated key and is
//! rejected. No record is written or required.

use crate::crypto::symmetric;
use crate::error::{Result, SpectrumError};
use crate::key_derivation::metadata::current_timestamp;
use crate::message::SpectrumMessage;
use crate::utils::hashing::hex_to_master;

/// Maximum acceptable age of a message (30 days) before a replay warning.
const MAX_AGE_SECS: u64 = 86400 * 30;

/// Decrypt `message` using the exact key image at `key_image` with the
/// *default* pipeline configuration. Instance-aware callers should prefer
/// [`decrypt_message_with`].
pub fn decrypt_message(message: &SpectrumMessage, key_image: &str) -> Result<String> {
    decrypt_message_with(
        message,
        &crate::key_derivation::KeyDerivationPipeline::new(),
        key_image,
    )
}

/// Decrypt `message` using the key `pipeline` derives from `key_image`.
///
/// Hybrid messages (non-empty `ntru_ciphertext`, produced with the `pq`
/// feature) additionally require `pq_secret_key`: both factors are needed.
/// `None` on a hybrid message is an error; on classic messages it is the
/// normal path.
pub fn decrypt_message_with_pq(
    message: &SpectrumMessage,
    pipeline: &crate::key_derivation::KeyDerivationPipeline,
    key_image: &str,
    pq_secret_key: Option<&[u8]>,
) -> Result<String> {
    let (key_hex, metadata) = pipeline.derive_key(key_image)?;

    // The message is bound to the exact file bytes encrypted under. Any other
    // image — a re-capture, an edit, a recompression — has a different digest
    // (and a different key) and must be refused.
    let derived_hash: [u8; 32] = hex::decode(&metadata.image_hash)
        .map_err(|e| SpectrumError::SerializationError(e.to_string()))?
        .try_into()
        .map_err(|_| {
            SpectrumError::SerializationError(
                "image hash must be 64 hex characters (32 bytes)".into(),
            )
        })?;
    if message.image_hash != derived_hash {
        return Err(SpectrumError::ImageMismatch);
    }

    let key = hex_to_master(&key_hex)?;

    let is_hybrid = !message.ntru_ciphertext.is_empty();
    #[cfg(not(feature = "pq"))]
    if is_hybrid {
        // A hybrid message is undecryptable without the PQ layer; refuse
        // clearly instead of failing MAC verification.
        let _ = pq_secret_key; // unused in non-PQ builds
        return Err(SpectrumError::PqLayerUnavailable);
    }

    // Verify authenticator before touching the ciphertext. Hybrid messages
    // MAC under the hybrid subkey (master ‖ decapsulated NTRU secret).
    let mut auth_input = Vec::new();
    auth_input.extend_from_slice(&message.encrypted_message);
    auth_input.extend_from_slice(&message.image_hash);
    auth_input.extend_from_slice(&message.timestamp.to_le_bytes());
    #[cfg(feature = "pq")]
    let ntru_ss: Option<Vec<u8>> = if is_hybrid {
        let sk = pq_secret_key.ok_or(SpectrumError::MalformedMessage(
            "hybrid message requires the NTRU-Prime secret key in addition to the key image".into(),
        ))?;
        Some(crate::crypto::ntru_prime::ntru_decapsulate(
            sk,
            &message.ntru_ciphertext,
        )?)
    } else {
        if pq_secret_key.is_some() {
            return Err(SpectrumError::MalformedMessage(
                "message is not hybrid but an NTRU-Prime secret key was supplied".into(),
            ));
        }
        None
    };
    #[cfg(not(feature = "pq"))]
    let ntru_ss: Option<Vec<u8>> = None;

    match &ntru_ss {
        #[cfg(feature = "pq")]
        Some(ss) => symmetric::verify_hybrid(&key, ss, &auth_input, &message.signature)?,
        _ => symmetric::verify(&key, &auth_input, &message.signature)?,
    }

    // Replay guard (warning only, matching the spec's recommended behavior).
    let now = current_timestamp();
    if message.timestamp < now && now - message.timestamp > MAX_AGE_SECS {
        log::warn!("Message is older than 30 days; possible replay.");
    }

    // Ciphertext: classic messages decrypt under the master key; hybrid
    // messages under the hybrid subkey (master ‖ decapsulated NTRU secret).
    let plaintext = match &ntru_ss {
        #[cfg(feature = "pq")]
        Some(ss) => {
            let (enc, _) = symmetric::expand_hybrid_keys(&key, ss);
            decrypt_with_subkey(&enc, &message.encrypted_message)?
        }
        _ => symmetric::decrypt(&key, &message.encrypted_message)?,
    };
    String::from_utf8(plaintext).map_err(SpectrumError::from)
}

/// Decrypt [`symmetric::encrypt`]-layout output (`nonce(12) ‖ ct+tag`) under
/// an explicit 32-byte subkey (the hybrid path's per-message key).
#[cfg(feature = "pq")]
fn decrypt_with_subkey(subkey: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    if blob.len() < 12 + 16 {
        return Err(SpectrumError::MalformedMessage(
            "encrypted blob too short".into(),
        ));
    }
    let (nonce, ct) = blob.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(subkey)
        .map_err(|_| SpectrumError::SerializationError("invalid AES key".into()))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| SpectrumError::DecryptionFailed)
}

/// Decrypt `message` using the key `pipeline` derives from `key_image`.
pub fn decrypt_message_with(
    message: &SpectrumMessage,
    pipeline: &crate::key_derivation::KeyDerivationPipeline,
    key_image: &str,
) -> Result<String> {
    decrypt_message_with_pq(message, pipeline, key_image, None)
}

#[cfg(test)]
mod tests {
    use super::super::encryption::encrypt_message;
    use super::*;

    fn sample_image(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        let mut img = image::RgbImage::new(160, 160);
        for (x, y, p) in img.enumerate_pixels_mut() {
            *p = image::Rgb([(x * 7) as u8, (y * 11) as u8, ((x ^ y) * 3) as u8]);
        }
        let p = dir.join(name);
        img.save(&p).unwrap();
        p
    }

    #[test]
    fn end_to_end_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = sample_image(dir.path(), "key.png");
        let msg = encrypt_message("top secret", path.to_str().unwrap()).unwrap();
        let bytes = msg.serialize().unwrap();
        let parsed = SpectrumMessage::deserialize(&bytes).unwrap();
        assert_eq!(
            decrypt_message(&parsed, path.to_str().unwrap()).unwrap(),
            "top secret"
        );
    }

    #[test]
    fn different_image_cannot_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let a = sample_image(dir.path(), "a.png");
        let msg = encrypt_message("x", a.to_str().unwrap()).unwrap();

        // A byte-identical copy decrypts (same file, same key)…
        let copy = dir.path().join("a_copy.png");
        std::fs::copy(&a, &copy).unwrap();
        assert!(decrypt_message(&msg, copy.to_str().unwrap()).is_ok());

        // …but any other image — even a one-pixel edit of the same subject —
        // derives an unrelated key and is rejected.
        let mut edited = image::open(&a).unwrap().to_rgb8();
        let mid = (edited.width() / 2, edited.height() / 2);
        let p = edited.get_pixel_mut(mid.0, mid.1);
        p.0[0] = p.0[0].wrapping_add(1);
        let b = dir.path().join("b.png");
        edited.save(&b).unwrap();
        assert!(matches!(
            decrypt_message(&msg, b.to_str().unwrap()),
            Err(SpectrumError::ImageMismatch)
        ));

        // And a second, genuinely different image fails the same way.
        let mut other = image::RgbImage::new(160, 160);
        for (x, y, p) in other.enumerate_pixels_mut() {
            *p = image::Rgb([
                255 - (x * 7) as u8,
                (y.wrapping_mul(13)) as u8,
                (x ^ y) as u8,
            ]);
        }
        let other_path = dir.path().join("other.png");
        other.save(&other_path).unwrap();
        assert!(matches!(
            decrypt_message(&msg, other_path.to_str().unwrap()),
            Err(SpectrumError::ImageMismatch)
        ));
    }
}
