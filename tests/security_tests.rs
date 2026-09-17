//! Property / security-oriented tests: derived-key uniqueness, witness and
//! key sensitivity to single-pixel / single-bit perturbations, keyless
//! reports, tamper rejection, mislabeled payload refusal, and the guarantee
//! that modifying an image (even by one pixel or one bit) yields an unrelated
//! key with no recovery path back to the original.

use std::collections::HashSet;

use rand::RngCore;
use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

use spectrum::image::ImagePreprocessor;
use spectrum::key_derivation::KeyDerivationPipeline;
use spectrum::types::KEY_LENGTH;
use spectrum::utils::hashing::compute_sha256;

/// Generate a deterministic pseudo-random grayscale image.
fn random_image(dir: &std::path::Path, name: &str, seed: u16) -> std::path::PathBuf {
    let mut rng = ChaCha8Rng::seed_from_u64(seed as u64);
    let mut buf = vec![0u8; 128 * 128];
    rng.fill_bytes(&mut buf);
    let img = image::GrayImage::from_raw(128, 128, buf).unwrap();
    let p = dir.join(name);
    img.save(&p).unwrap();
    p
}

/// Derive the deterministic hex key of an image file.
fn derive(path: &std::path::Path) -> String {
    // Deref through the zeroizing wrapper; tests only compare values.
    KeyDerivationPipeline::new()
        .derive_key(path.to_str().unwrap())
        .unwrap()
        .0
        .to_string()
}

#[test]
fn derived_keys_are_full_length_and_unique() {
    let dir = tempfile::tempdir().unwrap();
    let mut seen: HashSet<String> = HashSet::new();

    for seed in 0..25u16 {
        let img = random_image(dir.path(), &format!("img_{seed}.png"), seed);
        let key = derive(&img);
        // 1072-bit key must be full length and unique so far.
        assert_eq!(key.len(), KEY_LENGTH * 2);
        assert!(seen.insert(key), "collision on seed {seed}");
    }
    assert_eq!(seen.len(), 25);
}

#[test]
fn derived_keys_are_never_degenerate() {
    let dir = tempfile::tempdir().unwrap();
    let mut keys: Vec<String> = Vec::new();
    for seed in 0..8u16 {
        let img = random_image(dir.path(), &format!("k_{seed}.png"), seed);
        let key = derive(&img);
        let bytes = hex::decode(&key).unwrap();
        assert_eq!(bytes.len(), KEY_LENGTH);
        assert!(bytes.iter().any(|b| *b != 0), "all-zero key on seed {seed}");
        assert!(
            bytes.iter().any(|b| *b != bytes[0]),
            "constant key on seed {seed}"
        );
        keys.push(key);
    }
    let unique: HashSet<&String> = keys.iter().collect();
    assert_eq!(unique.len(), keys.len());
}

#[test]
fn single_pixel_change_derives_a_different_key() {
    let dir = tempfile::tempdir().unwrap();
    // Two files differing in one channel of one pixel.
    let mut a = image::RgbImage::new(160, 160);
    for (x, y, p) in a.enumerate_pixels_mut() {
        *p = image::Rgb([(x as u8).wrapping_mul(3), (y as u8).wrapping_mul(5), 128]);
    }
    let pa = dir.path().join("ma.png");
    let pb = dir.path().join("mb.png");
    a.save(&pa).unwrap();
    a.get_pixel_mut(10, 10).0 = [200, 200, 200];
    a.save(&pb).unwrap();
    assert_ne!(
        compute_sha256(std::fs::read(&pa).unwrap()),
        compute_sha256(std::fs::read(&pb).unwrap())
    );

    let key_a = derive(&pa);
    let key_b = derive(&pb);
    assert_ne!(
        key_a, key_b,
        "a single-pixel edit must change the derived key"
    );
}

#[test]
fn single_bit_change_in_witness_derives_a_different_key() {
    // Flipping one bit of the deterministic witness must change the master
    // key, and no operation maps the new key back to the old one: the XOF is
    // the only derivation step and it is one-way.
    let dir = tempfile::tempdir().unwrap();
    let img = random_image(dir.path(), "bit.png", 4242);
    let pipeline = KeyDerivationPipeline::new();
    let pp = ImagePreprocessor::new()
        .preprocess(img.to_str().unwrap())
        .unwrap();
    let analysis = pipeline.analyze(&pp).unwrap();
    let witness = pipeline.byte_sequence(&analysis).unwrap();
    let key = pipeline.key_bytes(&analysis, &pp.original_hash).unwrap();
    assert_eq!(key.len(), KEY_LENGTH);

    let mut flipped = witness.clone();
    let bit = (witness.len() / 2) * 8 + 3;
    flipped[bit / 8] ^= 1 << (bit % 8);
    let key2 = spectrum::key_derivation::xof::derive_master_key(&flipped, &pp.original_hash);
    assert_ne!(key, key2, "one witness bit must avalanche the key");

    // The master key is bound to the exact source-file digest: re-deriving
    // the *same* witness under a different (edited) file digest also differs.
    let mut hash2 = pp.original_hash;
    hash2[0] ^= 0x01;
    let key3 = spectrum::key_derivation::xof::derive_master_key(&witness, &hash2);
    assert_ne!(key, key3);
}

#[test]
fn derived_keys_are_uniform_across_byte_positions() {
    // Across 40 derivations, every byte position must take several distinct
    // values; a stuck-at position would indicate degenerate key material.
    let dir = tempfile::tempdir().unwrap();
    let mut distinct_per_position = vec![HashSet::new(); KEY_LENGTH];
    for seed in 0..40u16 {
        let img = random_image(dir.path(), &format!("u_{seed}.png"), seed + 1000);
        let key = derive(&img);
        let bytes = hex::decode(&key).unwrap();
        assert_eq!(bytes.len(), KEY_LENGTH);
        for (i, b) in bytes.iter().enumerate() {
            distinct_per_position[i].insert(*b);
        }
    }
    for (i, set) in distinct_per_position.iter().enumerate() {
        assert!(
            set.len() >= 8,
            "byte position {i} has only {} distinct values across 40 keys",
            set.len()
        );
    }
}

#[test]
fn witness_alone_is_not_key_equivalent() {
    // The XOF input binds the exact file digest: squeezing the witness with
    // any other digest (e.g. an attacker's guess, or zero) yields a different
    // master key than the real derivation, and the real key never equals a
    // plain XOF of the witness alone.
    let dir = tempfile::tempdir().unwrap();
    let img = random_image(dir.path(), "bind.png", 9001);
    let pipeline = KeyDerivationPipeline::new();
    let pp = ImagePreprocessor::new()
        .preprocess(img.to_str().unwrap())
        .unwrap();
    let analysis = pipeline.analyze(&pp).unwrap();
    let witness = pipeline.byte_sequence(&analysis).unwrap();
    let key = pipeline.key_bytes(&analysis, &pp.original_hash).unwrap();

    let xof = spectrum::key_derivation::xof::derive_master_key;
    assert_ne!(key, xof(&witness, &[0u8; 32]));
    assert_ne!(key, xof(&witness, &compute_sha256(b"other file bytes")));
    // Deterministic on the identical (witness, digest) pair.
    assert_eq!(
        key,
        pipeline.key_bytes(&analysis, &pp.original_hash).unwrap()
    );
}

#[test]
fn tampered_key_record_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let img = random_image(dir.path(), "tamper_key.png", 5001);
    let key = derive(&img);
    let record = spectrum::data::KeyRecord {
        key: spectrum::utils::hashing::hex_to_master(&key).unwrap(),
        image_hash: [7u8; 32],
    };
    let path = dir.path().join("t.frk");
    record.save(path.to_str().unwrap()).unwrap();

    // Flip one bit in the middle of the file.
    let mut bytes = std::fs::read(&path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
    assert!(spectrum::data::KeyRecord::load(path.to_str().unwrap()).is_err());
}

#[test]
fn reports_never_contain_key_material() {
    let dir = tempfile::tempdir().unwrap();
    let img = random_image(dir.path(), "report_sec.png", 5002);
    let key = derive(&img);

    let pipeline = KeyDerivationPipeline::new();
    let pp = ImagePreprocessor::new()
        .preprocess(img.to_str().unwrap())
        .unwrap();
    let analysis = pipeline.analyze(&pp).unwrap();
    let report = spectrum::report::AnalysisReport::from_analysis(
        &analysis,
        &hex::encode(pp.original_hash),
        pp.format.name().as_str(),
        pp.dimensions,
        pp.canonical_size,
    );
    let json = report.to_json().unwrap();
    assert!(
        !json.contains(&key),
        "report must not embed the derived key"
    );
    assert!(!json.contains("key_hex"));
    assert!(!json.contains("derived_key"));
}

#[test]
fn mislabeled_and_text_payloads_refused() {
    let dir = tempfile::tempdir().unwrap();

    // Text masquerading as an image.
    let text_path = dir.path().join("payload.png");
    std::fs::write(&text_path, b"#!/bin/sh\n echo hacked ").unwrap();
    assert!(spectrum::image::loader::sniff_format_from_file(text_path.to_str().unwrap()).is_err());

    // A real PNG renamed to .jpg must not pass the preprocessor.
    let png = random_image(dir.path(), "real.png", 5003);
    let disguised = dir.path().join("renamed.jpg");
    std::fs::copy(&png, &disguised).unwrap();
    let res = spectrum::image::ImagePreprocessor::new().preprocess(disguised.to_str().unwrap());
    assert!(res.is_err());
}
