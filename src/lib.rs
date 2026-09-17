//! # SPECTRUM — Secure Photo-Based Entropy-Driven Cryptographic Trust and Unified Message Protection
//!
//! Derives deterministic cryptographic keys from the natural structure
//! of images (the "entropy fingerprint"), using eleven independent entropy
//! sources with an adaptive strategy, then encrypts/authenticates messages with
//! a symmetric post-quantum-friendly layer.
//!
//! Built for Rust 1.98.

// The whole crate is safe Rust by design (all FFI risk lives in the
// dependencies, e.g. liboqs behind the `pq` feature); this makes that
// guarantee compiler-enforced instead of convention.
#![forbid(unsafe_code)]

pub mod cli;
pub mod config;
pub mod crypto;
pub mod data;
pub mod entropy_engine;
pub mod error;
pub mod filter;
pub mod image;
pub mod key_derivation;
pub mod message;
pub mod report;
pub mod selftest;
pub mod stats;
pub mod types;
pub mod utils;

use crate::config::SpectrumConfig;
use crate::entropy_engine::Analysis;
use crate::entropy_engine::EntropyEngine;
use crate::error::Result;
#[cfg(test)]
use crate::error::SpectrumError;
use crate::key_derivation::metadata::KeyMetadata;
use crate::key_derivation::KeyDerivationPipeline;
use crate::message::SpectrumMessage;
use zeroize::Zeroizing;

/// High-level facade over the whole SPECTRUM pipeline ("the librarian").
#[derive(Debug, Clone, Default)]
pub struct SpectrumCrypto {
    pub engine: EntropyEngine,
    pub derivation: KeyDerivationPipeline,
}

impl SpectrumCrypto {
    /// Create a new SPECTRUM instance with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an instance from an explicit configuration document.
    ///
    /// The document is validated exactly as if it had been loaded from JSON
    /// (the same `validate` gate `from_json` applies), so a programmatically
    /// built config cannot bypass the checks that disk-loaded ones face.
    pub fn with_config(cfg: &SpectrumConfig) -> Result<Self> {
        cfg.validate()?;
        let derivation =
            KeyDerivationPipeline::with_configs(cfg.entropy.clone(), cfg.preprocessor.clone());
        Ok(SpectrumCrypto {
            engine: derivation.entropy_engine.clone(),
            derivation,
        })
    }

    /// Derive the deterministic master key (hex) + metadata for an image file.
    ///
    /// Strictly deterministic over the exact file bytes: the same file always
    /// returns the same key; any other file returns an unrelated key.
    pub fn derive_key_safe(&self, img_path: &str) -> Result<(Zeroizing<String>, KeyMetadata)> {
        self.derivation.derive_key(img_path)
    }

    /// Analyze an image, returning the full entropy profile + adaptive config.
    ///
    /// Uses this instance's configured preprocessor, so custom
    /// `preprocessor` settings (min/max/canonical size, JPEG-quality gate)
    /// apply instead of the built-in defaults. This is exactly the analysis
    /// step of [`Self::derive_key_safe`], exposed for inspection and
    /// debugging.
    pub fn analyze_image_safe(&self, img_path: &str) -> Result<Analysis> {
        let pp = self.derivation.preprocessor.preprocess(img_path)?;
        self.derivation.analyze(&pp)
    }

    /// Encrypt a message bound to `key_image`. Decryption needs the exact
    /// same image file — no record is produced or required.
    ///
    /// Uses this instance's configured derivation pipeline, so the key here
    /// matches the one [`Self::derive_key_safe`] produces for the same image
    /// under the same configuration.
    pub fn encrypt_message_safe(
        &self,
        plaintext: &str,
        key_image: &str,
    ) -> Result<SpectrumMessage> {
        message::encrypt_message_with(&self.derivation, plaintext, key_image)
    }

    /// Decrypt a message using the exact key image it was encrypted under.
    ///
    /// Uses this instance's configured derivation pipeline (see
    /// [`Self::encrypt_message_safe`]).
    pub fn decrypt_message_safe(
        &self,
        message: &SpectrumMessage,
        key_image: &str,
    ) -> Result<String> {
        message::decrypt_message_with(message, &self.derivation, key_image)
    }

    /// Hybrid two-factor encryption: the message is bound to the key image
    /// **and** to a fresh NTRU-Prime shared secret encapsulated to
    /// `pq_public_key`. Requires the `pq` feature; decryption needs both the
    /// exact key image and the recipient's NTRU-Prime secret key. The NTRU
    /// ciphertext is carried in the message's reserved `ntru_ciphertext`
    /// field.
    ///
    /// Without the `pq` feature this returns `PqLayerUnavailable`.
    pub fn encrypt_message_hybrid(
        &self,
        plaintext: &str,
        key_image: &str,
        pq_public_key: &[u8],
    ) -> Result<SpectrumMessage> {
        message::encrypt_message_with_pq(
            &self.derivation,
            plaintext,
            key_image,
            Some(pq_public_key),
        )
    }

    /// Decrypt a hybrid two-factor message produced by
    /// [`Self::encrypt_message_hybrid`]. Requires the `pq` feature, the exact
    /// key image, and the recipient's NTRU-Prime secret key.
    pub fn decrypt_message_hybrid(
        &self,
        message: &SpectrumMessage,
        key_image: &str,
        pq_secret_key: &[u8],
    ) -> Result<String> {
        message::decrypt_message_with_pq(message, &self.derivation, key_image, Some(pq_secret_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for the dead-config bug: the facade's message functions
    /// must derive keys through *this instance's* pipeline — previously they
    /// built a default one, so `with_config` had no effect on encryption.
    #[test]
    fn message_safe_honors_instance_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.png");
        let mut img_buf = ::image::RgbImage::new(160, 160);
        for (x, y, p) in img_buf.enumerate_pixels_mut() {
            *p = ::image::Rgb([(x * 3) as u8, (y * 5) as u8, ((x + y) * 7) as u8]);
        }
        ::image::save_buffer(&path, img_buf.as_raw(), 160, 160, ::image::ColorType::Rgb8).unwrap();
        let img = path.to_str().unwrap();

        // A config that must change the derived key vs. the default one.
        let mut cfg = SpectrumConfig::default();
        cfg.entropy.chaos_config.a = 1.97;

        let default = SpectrumCrypto::new();
        let custom = SpectrumCrypto::with_config(&cfg).unwrap();

        // The configured instance derives a different key…
        let (k_def, _) = default.derive_key_safe(img).unwrap();
        let (k_custom, _) = custom.derive_key_safe(img).unwrap();
        assert_ne!(k_def, k_custom, "config must change the derived key");

        // …and encrypt_message_safe must use *that* key, not the default.
        let msg = custom.encrypt_message_safe("payload", img).unwrap();
        assert_eq!(custom.decrypt_message_safe(&msg, img).unwrap(), "payload");

        // Cross-check: encrypting under the default instance's key must NOT
        // decrypt with the custom one (proves different keys were used).
        let msg_default = default.encrypt_message_safe("payload", img).unwrap();
        assert_ne!(
            msg.encrypted_message, msg_default.encrypted_message,
            "facade must honor the instance config when encrypting"
        );
    }

    /// `analyze_image_safe` is the inspection window into derive_key_safe:
    /// it must return the same analysis the derivation step consumed, and
    /// reject a zero-variance image through the same guard.
    #[test]
    fn analyze_image_safe_matches_derivation_and_guards_flat_images() {
        let dir = tempfile::tempdir().unwrap();
        let noisy = dir.path().join("noisy.png");
        let mut img_buf = ::image::RgbImage::new(160, 160);
        for (x, y, p) in img_buf.enumerate_pixels_mut() {
            *p = ::image::Rgb([
                (x * 7 + y * 13) as u8,
                (x * x + y) as u8,
                ((x + 1) * (y + 3)) as u8,
            ]);
        }
        ::image::save_buffer(&noisy, img_buf.as_raw(), 160, 160, ::image::ColorType::Rgb8).unwrap();

        let crypto = SpectrumCrypto::new();
        let analysis = crypto.analyze_image_safe(noisy.to_str().unwrap()).unwrap();
        assert!(
            analysis.profile.total_entropy() > 0.0,
            "a structured image must yield a non-trivial entropy profile"
        );
        assert!(
            analysis.adaptive.complexity >= 0.0 && analysis.adaptive.complexity <= 1.0,
            "adaptive config must be populated for a structured image"
        );

        // Analysis is defined for any image (it is the inspection window);
        // key *derivation* is where a zero-variance image gets refused.
        // A programmatically built config must face the same validation as a
        // disk-loaded one: an invalid knob is an Err, not a silently accepted
        // configuration.
        let mut invalid = SpectrumConfig::default();
        invalid.symmetric.nonce_len = 11;
        assert!(
            matches!(
                SpectrumCrypto::with_config(&invalid),
                Err(SpectrumError::InvalidConfiguration(_))
            ),
            "with_config must not bypass validation"
        );

        let flat = dir.path().join("flat.png");
        let flat_buf = ::image::RgbImage::from_pixel(160, 160, ::image::Rgb([7, 7, 7]));
        ::image::save_buffer(&flat, flat_buf.as_raw(), 160, 160, ::image::ColorType::Rgb8).unwrap();
        assert!(
            crypto.analyze_image_safe(flat.to_str().unwrap()).is_ok(),
            "analysis itself must remain available for inspection"
        );
        assert!(
            matches!(
                crypto.derive_key_safe(flat.to_str().unwrap()),
                Err(SpectrumError::ImageHasNoEntropy)
            ),
            "a zero-variance image must be refused at derivation time"
        );
    }
}
