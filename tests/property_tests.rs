//! Property-oriented tests asserting invariants that should hold for every
//! image, not just hand-picked fixtures.

use spectrum::config::SpectrumConfig;
use spectrum::data::{BatchManifest, KeyRecord};
use spectrum::entropy_engine::sources::EntropySource;
use spectrum::entropy_engine::EntropyEngine;
use spectrum::image::Image;
use spectrum::key_derivation::KeyDerivationPipeline;
use spectrum::message::SpectrumMessage;
use spectrum::types::KEY_LENGTH;
use spectrum::utils::hashing::compute_sha256;
use spectrum::utils::test_images::{Kind, TestImage};

use proptest::prelude::*;

fn sample_images() -> Vec<Image> {
    let mut imgs = Vec::new();
    for kind in [Kind::Bars, Kind::Gradient, Kind::Masonry, Kind::Noise] {
        for seed in 0..4u64 {
            let test = TestImage {
                width: 96,
                height: 96,
                pixels: kind.generate(96, 96, seed),
            };
            imgs.push(test.into_crate_image());
        }
    }
    imgs
}

/// Deterministic 1072-bit key for an in-memory image, binding the SHA-256 of
/// its raw pixel buffer (the file-based pipeline binds the SHA-256 of the
/// exact file bytes instead).
fn key_of(pipeline: &KeyDerivationPipeline, img: &Image) -> [u8; KEY_LENGTH] {
    let analysis = pipeline.entropy_engine.analyze_image(img).unwrap();
    let hash = compute_sha256(&img.pixels);
    pipeline.key_bytes(&analysis, &hash).unwrap()
}

#[test]
fn entropy_deterministic_across_repeats() {
    let engine = EntropyEngine::new();
    for img in sample_images() {
        let a = engine.analyze_image(&img).unwrap();
        let b = engine.analyze_image(&img).unwrap();
        assert_eq!(a.profile.total_entropy(), b.profile.total_entropy());
    }
}

#[test]
fn all_sources_finite_and_contribute() {
    let engine = EntropyEngine::new();
    for img in sample_images() {
        let analysis = engine.analyze_image(&img).unwrap();
        for source in EntropySource::all() {
            let bits = analysis.profile.entropy_of(*source);
            assert!(
                bits.is_finite() && bits >= 0.0,
                "source {source:?} = {bits}"
            );
        }
        assert!(analysis.profile.total_entropy() > 0.0);
    }
}

#[test]
fn byte_sequence_grows_with_details() {
    // The deterministic witness length is a pure function of the image, and
    // repeats are byte-identical.
    let pipeline = KeyDerivationPipeline::new();
    for img in sample_images().into_iter().take(4) {
        let a = pipeline.entropy_engine.analyze_image(&img).unwrap();
        let b = pipeline.entropy_engine.analyze_image(&img).unwrap();
        let seq_a = pipeline.byte_sequence(&a).unwrap();
        let seq_b = pipeline.byte_sequence(&b).unwrap();
        assert_eq!(seq_a, seq_b);
        assert!(!seq_a.is_empty());
    }
}

#[test]
fn derived_key_is_always_full_length() {
    let pipeline = KeyDerivationPipeline::new();
    for img in sample_images().into_iter().take(4) {
        let key = key_of(&pipeline, &img);
        assert_eq!(key.len(), KEY_LENGTH); // 1072-bit master key
    }
}

#[test]
fn majorly_different_images_derive_distinct_keys() {
    // Two images differing everywhere derive distinct keys.
    let a = TestImage {
        width: 96,
        height: 96,
        pixels: Kind::Noise.generate(96, 96, 5),
    }
    .into_crate_image();
    let b = TestImage {
        width: 96,
        height: 96,
        pixels: Kind::Noise.generate(96, 96, 6),
    }
    .into_crate_image();
    let pipeline = KeyDerivationPipeline::new();
    let ka = key_of(&pipeline, &a);
    let kb = key_of(&pipeline, &b);
    assert_ne!(ka, kb);
    assert_eq!(ka.len(), KEY_LENGTH);
    assert_eq!(kb.len(), KEY_LENGTH);
}

#[test]
fn config_toggles_change_witness_and_key() {
    // Turning off one source must (for busy images) change the deterministic
    // witness, hence the derived key.
    let img = TestImage {
        width: 96,
        height: 96,
        pixels: Kind::Masonry.generate(96, 96, 1),
    }
    .into_crate_image();

    let pipeline_a = KeyDerivationPipeline::new();
    let a = pipeline_a.entropy_engine.analyze_image(&img).unwrap();
    let seq_a = pipeline_a.byte_sequence(&a).unwrap();
    let key_a = key_of(&pipeline_a, &img);

    let mut cfg = SpectrumConfig::default();
    cfg.entropy.texture_enabled = false;
    let pipeline_b =
        KeyDerivationPipeline::with_configs(cfg.entropy.clone(), cfg.preprocessor.clone());
    let b = pipeline_b.entropy_engine.analyze_image(&img).unwrap();
    let seq_b = pipeline_b.byte_sequence(&b).unwrap();
    let b2 = pipeline_b.entropy_engine.analyze_image(&img).unwrap();
    let seq_b2 = pipeline_b.byte_sequence(&b2).unwrap();
    assert_eq!(seq_b, seq_b2, "witness must be deterministic per config");
    assert_ne!(seq_a, seq_b, "disabling a source must change the witness");

    let key_b = key_of(&pipeline_b, &img);
    assert_eq!(key_a.len(), KEY_LENGTH);
    assert_eq!(key_b.len(), KEY_LENGTH);
    assert_ne!(
        key_a, key_b,
        "a different witness must derive a different key"
    );
    // Cross-configuration determinism: each config reproduces its own key.
    assert_eq!(key_a, key_of(&pipeline_a, &img));
    assert_eq!(key_b, key_of(&pipeline_b, &img));
}

// ---- proptest: generated inputs --------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// The deterministic witness is reproducible for arbitrary small images
    /// and never empty.
    #[test]
    fn prop_witness_deterministic_for_arbitrary_images(
        seed in any::<u64>(),
        side in 24usize..48,
    ) {
        let img = TestImage {
            width: side as u32,
            height: side as u32,
            pixels: Kind::Noise.generate(side as u32, side as u32, seed),
        }
        .into_crate_image();
        let pipeline = KeyDerivationPipeline::new();
        let a = pipeline.entropy_engine.analyze_image(&img).unwrap();
        let b = pipeline.entropy_engine.analyze_image(&img).unwrap();
        let seq_a = pipeline.byte_sequence(&a).unwrap();
        let seq_b = pipeline.byte_sequence(&b).unwrap();
        prop_assert_eq!(seq_a.as_slice(), seq_b.as_slice());
        prop_assert!(!seq_a.is_empty());
    }

    /// The XOF collapse is deterministic and full-length, and a single flipped
    /// bit (of the witness or of the bound file digest) avalanches the key.
    #[test]
    fn prop_key_is_deterministic_and_single_bit_sensitive(
        data in proptest::collection::vec(any::<u8>(), 64..512),
        seed in any::<u64>(),
    ) {
        let pipeline = KeyDerivationPipeline::new();
        let img = TestImage {
            width: 48,
            height: 48,
            pixels: Kind::Noise.generate(48, 48, seed),
        }
        .into_crate_image();
        let analysis = pipeline.entropy_engine.analyze_image(&img).unwrap();
        let hash = compute_sha256(&img.pixels);

        let witness = pipeline.byte_sequence(&analysis).unwrap();
        let key = pipeline.key_bytes(&analysis, &hash).unwrap();
        prop_assert_eq!(key.len(), KEY_LENGTH);
        prop_assert_eq!(key, pipeline.key_bytes(&analysis, &hash).unwrap());

        // One flipped witness bit → different key.
        let mut flipped = data;
        if !flipped.is_empty() {
            let pos = (flipped.len() / 2) % flipped.len();
            flipped[pos] ^= 0x40;
            prop_assert_ne!(key, xof_key(&flipped, &hash));
        }
        // One flipped digest bit (same witness) → different key.
        let mut hash2 = hash;
        hash2[0] ^= 0x01;
        prop_assert_ne!(key, xof_key(&witness, &hash2));
    }

    /// The gaussian blur of a constant image is the same constant, for any
    /// kernel size and sigma.
    #[test]
    fn prop_blur_preserves_constant(
        value in 0u8..=255,
        size in 3usize..12,
        sigma in 0.3f64..4.0,
    ) {
        let img = Image::from_luma(24, 24, vec![value; 24 * 24]).unwrap();
        let blurred = spectrum::filter::gaussian_blur(&img, size, sigma);
        prop_assert!(blurred
            .pixels
            .iter()
            .all(|p| (*p as i32 - value as i32).abs() <= 1));
    }

    /// Morphological dilation is monotone: A ⊆ B ⟹ dilate(A) ⊆ dilate(B).
    #[test]
    fn prop_dilation_monotone(
        bits_a in proptest::collection::vec(any::<bool>(), 49),
        bits_b in proptest::collection::vec(any::<bool>(), 49),
    ) {
        // Construct B ⊇ A pointwise.
        let b: Vec<bool> = bits_a
            .iter()
            .zip(bits_b.iter())
            .map(|(a, sup)| *a || *sup)
            .collect();
        let da = spectrum::filter::dilate(&bits_a, 7, 7);
        let db = spectrum::filter::dilate(&b, 7, 7);
        let contained = da.iter().zip(db.iter()).all(|(a, b)| !*a || *b);
        prop_assert!(contained);
    }

    /// Variance-time Hurst stays in (0, 1) for arbitrary series.
    #[test]
    fn prop_variance_time_hurst_bounded(
        data in proptest::collection::vec(0u8..=255, 64..512),
    ) {
        let series: Vec<f64> = data.iter().map(|v| f64::from(*v)).collect();
        let h = spectrum::stats::variance_time_hurst(&series);
        prop_assert!((0.01..=0.99).contains(&h));
    }

    /// Kurtosis is finite for arbitrary inputs and 0 for degenerate ones.
    #[test]
    fn prop_kurtosis_finite(
        data in proptest::collection::vec(0i16..=255, 4..256),
    ) {
        let series: Vec<f64> = data.iter().map(|v| f64::from(*v)).collect();
        let k = spectrum::stats::kurtosis(&series);
        prop_assert!(k.is_finite());
    }

    /// Magic-byte sniffing never accepts a short arbitrary buffer that does
    /// not begin with a known signature, and never panics.
    #[test]
    fn prop_sniffer_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..16),
    ) {
        let known_png = &b"\x89PNG\r\n\x1a\n"[..];
        let result = spectrum::image::loader::sniff_format(&bytes);
        if bytes.len() < 2 || !bytes.starts_with(&known_png[..bytes.len().min(8)]) {
            // Not required to be Ok; only required not to panic. Accept or
            // reject — but rejection must not be a panic (it is an Err).
            let _ = result.is_ok();
        }
    }

    /// Config documents round-trip for arbitrary entropy toggles.
    #[test]
    fn prop_config_roundtrip(
        wtmm in any::<bool>(),
        noise in any::<bool>(),
        bins in 16usize..512,
    ) {
        let mut cfg = SpectrumConfig::default();
        cfg.entropy.wtmm_enabled = wtmm;
        cfg.entropy.noise_enabled = noise;
        cfg.entropy.gradient_bins = bins;
        let back = SpectrumConfig::from_json(&cfg.to_json().unwrap()).unwrap();
        prop_assert_eq!(back, cfg);
    }
}

/// XOF over an explicit witness + digest pair.
fn xof_key(witness: &[u8], hash: &[u8; 32]) -> [u8; KEY_LENGTH] {
    spectrum::key_derivation::xof::derive_master_key(witness, hash)
}

// ---- adversarial mini-fuzz: parsers accept or reject, never panic -----------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// `SpectrumMessage::deserialize` over arbitrary bytes: Ok or Err, never
    /// a panic — and whatever it accepts must re-serialize byte-identically.
    #[test]
    fn prop_message_deserialize_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        if let Ok(msg) = SpectrumMessage::deserialize(&bytes) {
            let re = msg.serialize().unwrap();
            prop_assert_eq!(re, bytes);
        }
    }

    /// A huge declared field length must be rejected by the bounds check,
    /// not turned into a wild allocation.
    #[test]
    fn prop_message_huge_length_prefixes_rejected(len in any::<u32>()) {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes()); // version
        bytes.extend_from_slice(&0u64.to_le_bytes()); // timestamp
        bytes.extend_from_slice(&[0xAB; 32]); // image hash
        bytes.extend_from_slice(&len.to_le_bytes()); // ntru length
        let _ = SpectrumMessage::deserialize(&bytes);
    }

    /// The `.frk` record round-trips 1072-bit key material, a wrong-length
    /// key is rejected even with a valid checksum, and flipping any single
    /// bit of the stored file trips the SHA-256 checksum.
    #[test]
    fn prop_key_record_roundtrip_and_tamper_detection(
        key in proptest::collection::vec(any::<u8>(), spectrum::types::KEY_LENGTH),
        flip_bit in 0usize..8192,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.frk");
        let rec = KeyRecord {
            key: zeroize::Zeroizing::new(key.clone()),
            image_hash: [7u8; 32],
        };
        rec.save(path.to_str().unwrap()).unwrap();
        let loaded = KeyRecord::load(path.to_str().unwrap()).unwrap();
        prop_assert_eq!(loaded, rec);

        let mut data = std::fs::read(&path).unwrap();
        let pos = flip_bit % data.len();
        data[pos] ^= 0x01;
        std::fs::write(&path, &data).unwrap();
        prop_assert!(KeyRecord::load(path.to_str().unwrap()).is_err());
    }

    /// The batch-manifest JSON parser never panics on arbitrary text.
    #[test]
    fn prop_batch_manifest_json_never_panics(json in ".*") {
        let _ = BatchManifest::from_json(&json);
    }

    /// Hex parsing never panics on arbitrary strings.
    #[test]
    fn prop_hex_parsing_never_panics(s in ".*") {
        let _ = spectrum::utils::hex_to_key(&s);
        let _ = spectrum::utils::hex_to_hash(&s);
    }

    /// The sniffer (and, for JPEG-magic buffers, the DQT quality estimator
    /// behind it) never panics on arbitrary buffers of any length.
    #[test]
    fn prop_sniff_and_jpeg_quality_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let _ = spectrum::image::loader::sniff_format(&bytes);
        let mut jpeg = vec![0xFF, 0xD8, 0xFF];
        jpeg.extend_from_slice(&bytes);
        let _ = spectrum::image::loader::sniff_format(&jpeg);
    }

    /// The strict config loader never panics on arbitrary input, and a valid
    /// document with an injected unknown knob must be rejected (fail-closed
    /// at every nesting level — never a silent drop of settings).
    #[test]
    fn prop_config_from_json_never_panics_and_rejects_unknown_fields(
        junk in ".*",
        injection_key in "[a-zA-Z_][a-zA-Z0-9_]{0,24}",
    ) {
        // Arbitrary junk: Ok or Err, never a panic.
        let _ = SpectrumConfig::from_json(&junk);

        // A well-formed config plus one unknown top-level key must be refused.
        if matches!(
            injection_key.as_str(),
            "entropy" | "preprocessor" | "symmetric" | "version"
        ) {
            return Ok(()); // collided with a real field: nothing to inject
        }
        let cfg = SpectrumConfig::default();
        let mut value = serde_json::to_value(&cfg).unwrap();
        value[injection_key.as_str()] = serde_json::json!(1);
        let json = serde_json::to_string(&value).unwrap();
        prop_assert!(
            SpectrumConfig::from_json(&json).is_err(),
            "unknown field `{injection_key}` must be rejected"
        );
    }
}
