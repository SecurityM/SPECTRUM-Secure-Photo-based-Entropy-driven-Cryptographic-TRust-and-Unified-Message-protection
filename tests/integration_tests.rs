//! End-to-end integration tests: deterministic derive/encrypt/decrypt flows,
//! the CLI commands, analysis reports, magic-byte rejection and the strict
//! determinism guarantee (same bytes → same key; any perturbation → unrelated
//! key, with no recovery path).

use spectrum::data::KeyRecord;
use spectrum::image::ImagePreprocessor;
use spectrum::key_derivation::KeyDerivationPipeline;
use spectrum::message::{decrypt_message, encrypt_message, SpectrumMessage};
use spectrum::report::AnalysisReport;
use spectrum::utils::hashing::compute_sha256;
use spectrum::SpectrumCrypto;

fn write_image(dir: &std::path::Path, name: &str, seed: u8) -> std::path::PathBuf {
    let mut img = image::RgbImage::new(160, 160);
    for (x, y, p) in img.enumerate_pixels_mut() {
        let s = seed as u32;
        let r = (x.wrapping_mul(s).wrapping_add(7)) as u8;
        let g = (y.wrapping_mul(s ^ 0x55)) as u8;
        let b = ((x ^ y).wrapping_mul(s.wrapping_mul(3))) as u8;
        *p = image::Rgb([r, g, b]);
    }
    let p = dir.join(name);
    img.save(&p).unwrap();
    p
}

/// One-pixel, ±1-level perturbation of a copy of an image file.
fn perturb_one_pixel(src: &std::path::Path, dst: &std::path::Path) {
    let img = image::open(src).unwrap().to_rgb8();
    let (w, h) = img.dimensions();
    let mut out = img.clone();
    let x = (w * 3 / 7).min(w - 1);
    let y = (h * 5 / 7).min(h - 1);
    let p = out.get_pixel_mut(x, y);
    p.0[0] = p.0[0].wrapping_add(1);
    out.save(dst).unwrap();
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
fn full_encrypt_decrypt_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let img = write_image(dir.path(), "key.png", 42);
    let spectrum = SpectrumCrypto::new();

    let msg = spectrum
        .encrypt_message_safe("integration secret", img.to_str().unwrap())
        .unwrap();
    let bytes = msg.serialize().unwrap();
    let parsed = SpectrumMessage::deserialize(&bytes).unwrap();
    assert_eq!(parsed, msg);

    let out = spectrum
        .decrypt_message_safe(&parsed, img.to_str().unwrap())
        .unwrap();
    assert_eq!(out, "integration secret");
}

#[test]
fn derive_is_deterministic_across_instances() {
    let dir = tempfile::tempdir().unwrap();
    let img = write_image(dir.path(), "det.png", 9);

    // Two independent pipelines derive the identical key from the same file.
    let pa = KeyDerivationPipeline::new();
    let pb = KeyDerivationPipeline::new();
    let ka = pa.derive_key(img.to_str().unwrap()).unwrap().0;
    let kb = pb.derive_key(img.to_str().unwrap()).unwrap().0;
    assert_eq!(ka, kb);
    assert_eq!(hex::decode(&ka).unwrap().len(), spectrum::types::KEY_LENGTH);
}

#[test]
fn byte_identical_copy_derives_the_same_key() {
    let dir = tempfile::tempdir().unwrap();
    let img = write_image(dir.path(), "orig.png", 1);
    let copy = dir.path().join("copy.png");
    std::fs::copy(&img, &copy).unwrap();

    assert_eq!(derive(&img), derive(&copy));
    assert_eq!(
        compute_sha256(std::fs::read(&img).unwrap()),
        compute_sha256(std::fs::read(&copy).unwrap())
    );
}

#[test]
fn distinct_images_give_distinct_keys() {
    let dir = tempfile::tempdir().unwrap();
    let img1 = write_image(dir.path(), "one.png", 1);
    let img2 = write_image(dir.path(), "two.png", 2);

    let k1 = derive(&img1);
    let k2 = derive(&img2);
    assert_ne!(k1, k2);
    assert_eq!(k1.len(), spectrum::types::KEY_LENGTH * 2);
    assert_eq!(k2.len(), spectrum::types::KEY_LENGTH * 2);
}

#[test]
fn single_pixel_change_derives_a_different_key_and_cannot_be_unlocked() {
    let dir = tempfile::tempdir().unwrap();
    let img = write_image(dir.path(), "base.png", 77);
    let key = derive(&img);

    // A one-pixel, ±1-level re-render must derive an unrelated key…
    let rerender = dir.path().join("edited.png");
    perturb_one_pixel(&img, &rerender);
    assert_ne!(
        compute_sha256(std::fs::read(&img).unwrap()),
        compute_sha256(std::fs::read(&rerender).unwrap()),
        "perturbed copy must actually differ from the original file"
    );
    let edited_key = derive(&rerender);
    assert_ne!(
        edited_key, key,
        "a 1-pixel edit must change the derived key"
    );

    // …and a message encrypted under the original cannot be opened with the
    // edited image: there is no recovery path back to the original key.
    let spectrum = SpectrumCrypto::new();
    let msg = spectrum
        .encrypt_message_safe("bound to the original", img.to_str().unwrap())
        .unwrap();
    let res = spectrum.decrypt_message_safe(&msg, rerender.to_str().unwrap());
    assert!(res.is_err(), "edited image must not decrypt the message");

    // The original image still decrypts it.
    let plain = spectrum
        .decrypt_message_safe(&msg, img.to_str().unwrap())
        .unwrap();
    assert_eq!(plain, "bound to the original");
}

#[test]
fn tampered_message_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let img = write_image(dir.path(), "tamper.png", 3);

    let msg = encrypt_message("data", img.to_str().unwrap()).unwrap();
    let mut bytes = msg.serialize().unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01; // corrupt the encrypted payload

    let parsed = SpectrumMessage::deserialize(&bytes).unwrap();
    assert!(decrypt_message(&parsed, img.to_str().unwrap()).is_err());
}

#[test]
fn analyze_returns_full_profile() {
    let dir = tempfile::tempdir().unwrap();
    let img = write_image(dir.path(), "analyze.png", 11);
    let spectrum = SpectrumCrypto::new();
    let analysis = spectrum.analyze_image_safe(img.to_str().unwrap()).unwrap();
    let p = &analysis.profile;
    assert!(p.total_entropy() > 0.0);
    assert_eq!(
        p.wtmm.values.len(),
        analysis.wtmm_config.num_scales as usize
    );
}

// ---- CLI-level flows through the library API ----------------------------------

#[test]
fn export_then_verify_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let img = write_image(dir.path(), "export.png", 21);
    let frk = dir.path().join("out.frk");

    spectrum::cli::cmd_export(
        &spectrum::SpectrumCrypto::new(),
        img.to_str().unwrap(),
        frk.to_str().unwrap(),
    )
    .unwrap();
    assert!(frk.exists());

    // The exported key is exactly the deterministic derive of the image.
    let record = KeyRecord::load(frk.to_str().unwrap()).unwrap();
    let (derived, meta) = KeyDerivationPipeline::new()
        .derive_key(img.to_str().unwrap())
        .unwrap();
    assert_eq!(hex::encode(record.key.as_slice()), derived.as_str());
    assert_eq!(hex::encode(record.image_hash), meta.image_hash);

    // And the verify command agrees.
    assert!(spectrum::cli::cmd_verify(
        &spectrum::SpectrumCrypto::new(),
        frk.to_str().unwrap(),
        img.to_str().unwrap()
    )
    .unwrap());
}

#[test]
fn verify_detects_swapped_or_edited_image() {
    let dir = tempfile::tempdir().unwrap();
    let img_a = write_image(dir.path(), "va.png", 22);
    let img_b = write_image(dir.path(), "vb.png", 23);
    let frk_a = dir.path().join("va.frk");
    let frk_b = dir.path().join("vb.frk");

    spectrum::cli::cmd_export(
        &spectrum::SpectrumCrypto::new(),
        img_a.to_str().unwrap(),
        frk_a.to_str().unwrap(),
    )
    .unwrap();
    spectrum::cli::cmd_export(
        &spectrum::SpectrumCrypto::new(),
        img_b.to_str().unwrap(),
        frk_b.to_str().unwrap(),
    )
    .unwrap();

    // Each image verifies against its own record…
    assert!(spectrum::cli::cmd_verify(
        &spectrum::SpectrumCrypto::new(),
        frk_a.to_str().unwrap(),
        img_a.to_str().unwrap()
    )
    .unwrap());
    assert!(spectrum::cli::cmd_verify(
        &spectrum::SpectrumCrypto::new(),
        frk_b.to_str().unwrap(),
        img_b.to_str().unwrap()
    )
    .unwrap());
    // …A's record does not match B (different image)…
    assert!(!spectrum::cli::cmd_verify(
        &spectrum::SpectrumCrypto::new(),
        frk_a.to_str().unwrap(),
        img_b.to_str().unwrap()
    )
    .unwrap());
    // …and an edited copy of A does not match A's record either.
    let edited = dir.path().join("va_edited.png");
    perturb_one_pixel(&img_a, &edited);
    assert!(!spectrum::cli::cmd_verify(
        &spectrum::SpectrumCrypto::new(),
        frk_a.to_str().unwrap(),
        edited.to_str().unwrap()
    )
    .unwrap());
}

#[test]
fn batch_manifest_keys_match_direct_derivation() {
    let dir = tempfile::tempdir().unwrap();
    write_image(dir.path(), "b1.png", 24);
    write_image(dir.path(), "b2.png", 25);
    let manifest_path = dir.path().join("batch.json");

    let manifest = spectrum::cli::cmd_batch(
        &spectrum::SpectrumCrypto::new(),
        dir.path().to_str().unwrap(),
        &[],
        Some(manifest_path.to_str().unwrap()),
    )
    .unwrap();
    assert_eq!(manifest.entries.len(), 2);
    assert_eq!(manifest.success_count(), 2);

    // Each manifest key equals a direct deterministic derive of the image, and
    // re-running the batch reproduces the identical keys (nothing to skip or
    // overwrite — derivation is a pure function of each file).
    for entry in &manifest.entries {
        let direct = KeyDerivationPipeline::new()
            .derive_key(&entry.image)
            .unwrap()
            .0
            .to_string();
        assert_eq!(direct, entry.key_hex, "manifest key for {}", entry.image);
    }
    let re_run = spectrum::cli::cmd_batch(
        &spectrum::SpectrumCrypto::new(),
        dir.path().to_str().unwrap(),
        &[],
        None,
    )
    .unwrap();
    // Deterministic derivation: identical entries on a re-run (only the
    // manifest creation timestamp differs).
    assert_eq!(
        re_run.entries, manifest.entries,
        "batch must be deterministic"
    );

    let loaded = spectrum::data::BatchManifest::load(manifest_path.to_str().unwrap()).unwrap();
    assert_eq!(loaded, manifest);
}

#[test]
fn analyze_report_written_and_keyless() {
    let dir = tempfile::tempdir().unwrap();
    let img = write_image(dir.path(), "report.png", 26);
    let report_path = dir.path().join("analysis.json");
    let spectrum = SpectrumCrypto::new();

    spectrum::cli::cmd_analyze(
        &spectrum,
        img.to_str().unwrap(),
        false,
        Some(report_path.to_str().unwrap()),
    )
    .unwrap();

    let report = AnalysisReport::load(report_path.to_str().unwrap()).unwrap();
    assert_eq!(report.sources.len(), 11);
    assert!(
        (report.total_entropy_bits - report.sources.iter().map(|s| s.entropy_bits).sum::<f64>())
            .abs()
            < 1e-9
    );
    let json = report.to_json().unwrap().to_lowercase();
    assert!(!json.contains("key_hex"));
}

#[test]
fn selftest_cli_battery_green() {
    spectrum::cli::cmd_selftest(false).unwrap();
}

// ---- preprocessor: mislabeled files are refused --------------------------------

#[test]
fn mislabeled_image_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let png = write_image(dir.path(), "real.png", 31);
    let disguised = dir.path().join("fake.bmp");
    std::fs::copy(&png, &disguised).unwrap();

    let res = ImagePreprocessor::new().preprocess(disguised.to_str().unwrap());
    assert!(matches!(
        res.err(),
        Some(spectrum::error::SpectrumError::ImageFormatNotSupported(_))
    ));
}
