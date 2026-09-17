//! The key-derivation pipeline: image file → canonical pixels → analysis →
//! witness (deterministic byte sequence) → XOF master key.
//!
//! # Key model (v3)
//!
//! The eleven engines analyse an image into a deterministic *witness* byte
//! sequence. The 1072-bit master key is squeezed by
//! [`xof::derive_master_key`] from that witness **plus** the SHA-256 of the
//! exact source-file bytes. Key derivation is therefore a strict, pure
//! function of the image file:
//!
//! * the identical file always reproduces the identical key — on this build,
//!   on any machine, through any number of pipeline instances;
//! * any different file — a single pixel changed, a single bit edited, a
//!   recompression, or a re-capture of the same physical subject — derives an
//!   unrelated key.
//!
//! Only the exact original image file reproduces a key: modified inputs —
//! edited, recompressed or re-captured — deliberately derive unrelated keys,
//! and the library exposes no operation that maps a modified image back to
//! the original key. If you need the key again, you need the exact original
//! image bytes.

pub mod conversion;
pub mod metadata;
pub mod xof;

use crate::config::{EntropyEngineConfig, ImagePreprocessorConfig};
use crate::entropy_engine::mixer::create_byte_sequence;
use crate::entropy_engine::strategy::Strategy;
use crate::entropy_engine::{Analysis, EntropyEngine};
use crate::error::{Result, SpectrumError};
use crate::image::{ImagePreprocessor, PreprocessedImage};
use crate::key_derivation::conversion::ConversionPipeline;
use crate::key_derivation::metadata::KeyMetadata;
use crate::types::KEY_LENGTH;
use crate::utils::hashing::key_to_hex;
use zeroize::Zeroizing;

/// Deterministically derives a 1072-bit master key from an image file.
#[derive(Debug, Clone, Default)]
pub struct KeyDerivationPipeline {
    pub entropy_engine: EntropyEngine,
    pub preprocessor: ImagePreprocessor,
}

impl KeyDerivationPipeline {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the pipeline from entropy and preprocessor configs.
    pub fn with_configs(
        entropy: EntropyEngineConfig,
        preprocessor: ImagePreprocessorConfig,
    ) -> Self {
        KeyDerivationPipeline {
            entropy_engine: EntropyEngine::with_config(entropy),
            preprocessor: ImagePreprocessor::with_config(preprocessor),
        }
    }

    /// Run analysis (profile + adaptive config) on a preprocessed image.
    pub fn analyze(&self, pp: &PreprocessedImage) -> Result<Analysis> {
        let img = ImagePreprocessor::to_image(pp)?;
        self.entropy_engine.analyze_image(&img)
    }

    /// The deterministic witness byte sequence. This is the XOF pre-image's
    /// image-content half; the master key itself is
    /// [`XOF(witness ‖ file-SHA-256)`](xof::derive_master_key), so the witness
    /// alone never equals the key and reveals nothing about it.
    pub fn byte_sequence(&self, analysis: &Analysis) -> Result<Vec<u8>> {
        let strategy = Strategy::determine(&analysis.profile);
        let pipeline = ConversionPipeline::new();
        let normalized = pipeline.normalize(&analysis.profile, &strategy);
        create_byte_sequence(&normalized, &strategy)
    }

    /// Collapse an analysis into the 1072-bit master key.
    ///
    /// `image_sha256` must be the SHA-256 of the exact source-file bytes
    /// (usually [`PreprocessedImage::original_hash`]); binding it into the XOF
    /// makes the key a strict function of the file, not just of its canonical
    /// pixels.
    pub fn key_bytes(
        &self,
        analysis: &Analysis,
        image_sha256: &[u8; 32],
    ) -> Result<[u8; KEY_LENGTH]> {
        let witness = self.byte_sequence(analysis)?;
        Ok(xof::derive_master_key(&witness, image_sha256))
    }

    /// Full deterministic derivation: image file → (hex key, metadata).
    ///
    /// The same file always returns the same key; any other file returns an
    /// unrelated key. Nothing is written to disk and nothing else is needed
    /// to reproduce the key later.
    ///
    /// Zero-variance images (every canonical pixel identical) are refused
    /// with [`SpectrumError::ImageHasNoEntropy`]: they carry no information,
    /// and every such image would deterministically derive the *same* key,
    /// which anyone could recompute by running the algorithm on any equal
    /// image. The entropy engines report nonzero estimates even for flat
    /// inputs (the chaos source is deterministic over its pixel-hash seed),
    /// so the variance check is done on the canonical pixels themselves.
    ///
    /// The hex key is returned in a zeroizing buffer: it is wiped when the
    /// caller drops it instead of lingering as freeable-but-unwiped memory.
    pub fn derive_key(&self, img_path: &str) -> Result<(Zeroizing<String>, KeyMetadata)> {
        let pp = self.preprocessor.preprocess(img_path)?;
        // Empty canonical buffer → nothing to derive from; fail closed instead
        // of panicking on `data[0]`. (The preprocessor refuses degenerate
        // sizes, so this is defense in depth for non-default configs.)
        let Some(&first) = pp.data.first() else {
            return Err(SpectrumError::ImageHasNoEntropy);
        };
        if pp.data.iter().all(|&b| b == first) {
            return Err(SpectrumError::ImageHasNoEntropy);
        }
        let analysis = self.analyze(&pp)?;
        let key = self.key_bytes(&analysis, &pp.original_hash)?;
        let key_hex = Zeroizing::new(key_to_hex(&key));
        let meta = self.metadata_for(&analysis, &pp);
        Ok((key_hex, meta))
    }

    fn metadata_for(&self, analysis: &Analysis, pp: &PreprocessedImage) -> KeyMetadata {
        let strategy = Strategy::determine(&analysis.profile);
        KeyMetadata::new(
            strategy.name.as_str().to_string(),
            strategy.source_names(),
            pp.original_hash,
            metadata::current_timestamp(),
            analysis.profile.total_entropy(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static N: AtomicU32 = AtomicU32::new(0);

    fn write_sample(dir: &std::path::Path) -> std::path::PathBuf {
        let idx = N.fetch_add(1, Ordering::SeqCst);
        let mut img = image::RgbImage::new(160, 160);
        for (x, y, p) in img.enumerate_pixels_mut() {
            *p = image::Rgb([
                (x.wrapping_mul(5)) as u8,
                (y.wrapping_mul(7)) as u8,
                ((x + y) * 3) as u8,
            ]);
        }
        let p = dir.join(format!("sample_{idx}.png"));
        img.save(&p).unwrap();
        p
    }

    fn derive(path: &str) -> Zeroizing<String> {
        KeyDerivationPipeline::new().derive_key(path).unwrap().0
    }

    #[test]
    fn derive_is_deterministic_across_instances_and_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_sample(dir.path());
        // Independent pipeline instances derive the identical key…
        let key_a = KeyDerivationPipeline::new()
            .derive_key(path.to_str().unwrap())
            .unwrap()
            .0;
        let key_b = derive(path.to_str().unwrap());
        assert_eq!(key_a, key_b);
        assert_eq!(key_a.len(), KEY_LENGTH * 2); // hex
                                                 // …and a byte-identical copy in another location reproduces it: the
                                                 // key is a function of the file's bytes, not of its path.
        let copy = dir.path().join("copy.png");
        std::fs::copy(&path, &copy).unwrap();
        assert_eq!(derive(copy.to_str().unwrap()), key_a);
    }

    /// A zero-variance image (every canonical pixel identical) carries no
    /// information and would derive the same key as every other flat image;
    /// derivation must refuse it instead.
    #[test]
    fn flat_image_is_refused_as_having_no_entropy() {
        let dir = tempfile::tempdir().unwrap();
        // Solid gray PNG: survives preprocessing, has zero canonical variance.
        let path = dir.path().join("flat.png");
        image::GrayImage::from_raw(160, 160, vec![128u8; 160 * 160])
            .unwrap()
            .save(&path)
            .unwrap();
        let res = KeyDerivationPipeline::new().derive_key(path.to_str().unwrap());
        assert!(
            matches!(&res, Err(SpectrumError::ImageHasNoEntropy)),
            "flat image must be refused with ImageHasNoEntropy, got {res:?}"
        );
    }

    #[test]
    fn metadata_reflects_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_sample(dir.path());
        let (key, meta) = KeyDerivationPipeline::new()
            .derive_key(path.to_str().unwrap())
            .unwrap();
        assert_eq!(key.len(), KEY_LENGTH * 2);
        assert_eq!(meta.entropy_sources_used.len(), 11);
        // The metadata carries the exact-file digest the key is bound to.
        let data = std::fs::read(&path).unwrap();
        assert_eq!(
            meta.image_hash,
            hex::encode(crate::utils::hashing::compute_sha256(data))
        );
    }

    #[test]
    fn single_pixel_change_derives_a_different_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_sample(dir.path());
        let key = derive(path.to_str().unwrap());

        // A one-pixel, ±1-level edit is still a different file and must derive
        // an unrelated key — with no path back to the original.
        let mut img = image::open(&path).unwrap().to_rgb8();
        let mid = (img.width() / 2, img.height() / 2);
        let p = img.get_pixel_mut(mid.0, mid.1);
        p.0[0] = p.0[0].wrapping_add(1);
        let edited = dir.path().join("edited.png");
        img.save(&edited).unwrap();

        assert_ne!(key, derive(edited.to_str().unwrap()));
    }

    #[test]
    fn single_bit_change_in_witness_derives_a_different_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_sample(dir.path());
        let pipeline = KeyDerivationPipeline::new();
        let pp = ImagePreprocessor::new()
            .preprocess(path.to_str().unwrap())
            .unwrap();
        let analysis = pipeline.analyze(&pp).unwrap();
        let witness = pipeline.byte_sequence(&analysis).unwrap();
        let key = pipeline.key_bytes(&analysis, &pp.original_hash).unwrap();

        // Flip a single bit of the witness: the derived key must change and
        // there is no operation that could map it back.
        let mut flipped = witness.clone();
        flipped[0] ^= 0x01;
        let key2 = xof::derive_master_key(&flipped, &pp.original_hash);
        assert_ne!(key, key2);
        // The same single-bit flip in the *file digest* also changes the key
        // even when the witness is untouched.
        let mut hash = pp.original_hash;
        hash[0] ^= 0x01;
        let key3 = pipeline.key_bytes(&analysis, &hash).unwrap();
        assert_ne!(key, key3);
        assert_ne!(key2, key3);
    }
}
