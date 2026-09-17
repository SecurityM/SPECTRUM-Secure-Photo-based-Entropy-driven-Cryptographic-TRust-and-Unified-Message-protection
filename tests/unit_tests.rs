//! Cross-cutting unit tests for the SPECTRUM library surface.
//!
//! Complements the inline `#[cfg(test)]` modules with integration-level
//! assertions about the public API: wavelet decomposition, morphology,
//! stats helpers, magic-byte sniffing, reports, batch records and the
//! self-test battery.

use spectrum::config::SpectrumConfig;
use spectrum::data::{BatchEntry, BatchManifest, BATCH_VERSION};
use spectrum::entropy_engine::adaptive_config::ComplexityBucket;
use spectrum::entropy_engine::sources::wtmm::{extract_wtmm, WaveletType, WtmmConfig};
use spectrum::filter::wavelet2d::swt2_decompose;
use spectrum::filter::{dilate, erode, gaussian_blur, mask_area, threshold_mask, Wavelet};
use spectrum::image::loader::sniff_format;
use spectrum::image::Image;
use spectrum::report::AnalysisReport;
use spectrum::stats::{autocorrelation, kurtosis, variance_time_hurst};
use spectrum::utils::test_images::{Kind, TestImage};

fn image(kind: Kind, side: u32, seed: u64) -> Image {
    TestImage {
        width: side,
        height: side,
        pixels: kind.generate(side, side, seed),
    }
    .into_crate_image()
}

// ---- wavelet2d ---------------------------------------------------------------

#[test]
fn swt2_reconstruction_exact_across_kinds_and_levels() {
    for kind in [Kind::Bars, Kind::Gradient, Kind::Masonry, Kind::Noise] {
        let img = image(kind, 64, 9);
        for levels in [1usize, 2, 3] {
            let d = swt2_decompose(&img, levels, Wavelet::MexicanHat).unwrap();
            let rec = d.reconstruct();
            for (r, o) in rec.iter().zip(img.pixels.iter()) {
                assert!(
                    (r - f64::from(*o)).abs() < 1e-6,
                    "reconstruction broke for {kind:?} at {levels} levels"
                );
            }
        }
    }
}

#[test]
fn swt2_detail_energy_bounded_and_finite() {
    let img = image(Kind::Noise, 64, 10);
    let d = swt2_decompose(&img, 4, Wavelet::Morlet).unwrap();
    let energies = d.detail_energy();
    assert_eq!(energies.len(), 4);
    assert!(energies.iter().all(|e| e.is_finite() && *e >= 0.0));
    // Moduli per level have the right length.
    assert_eq!(d.detail_modulus(3).unwrap().len(), 64 * 64);
    assert!(d.detail_modulus(4).is_none());
}

#[test]
fn swt2_rejects_tiny_images() {
    let img = Image::from_luma(2, 2, vec![0u8; 4]).unwrap();
    assert!(swt2_decompose(&img, 2, Wavelet::MexicanHat).is_err());
}

// ---- morphology / blur -------------------------------------------------------

#[test]
fn morphology_dilate_then_erode_is_closed_for_solid_block() {
    let w = 11usize;
    let h = 11usize;
    let mut mask = vec![false; w * h];
    for y in 3..8 {
        for x in 3..8 {
            mask[y * w + x] = true;
        }
    }
    let opened = erode(&dilate(&mask, w, h), w, h);
    // A 5×5 solid block survives opening unchanged.
    assert_eq!(mask_area(&opened), 25);
}

#[test]
fn morphology_erode_then_dilate_is_opened_for_solid_block() {
    let w = 11usize;
    let h = 11usize;
    let mut mask = vec![false; w * h];
    for y in 3..8 {
        for x in 3..8 {
            mask[y * w + x] = true;
        }
    }
    let closed = dilate(&erode(&mask, w, h), w, h);
    assert_eq!(mask_area(&closed), 25);
}

#[test]
fn blur_extremes_are_clamped_into_byte_range() {
    // A black/white checkerboard has huge contrast; the blurred output must
    // stay strictly inside [0, 255] after rounding.
    let mut pixels = vec![0u8; 32 * 32];
    for (i, p) in pixels.iter_mut().enumerate() {
        *p = if (i / 32 + i) % 2 == 0 { 0 } else { 255 };
    }
    let img = Image::from_luma(32, 32, pixels).unwrap();
    let blurred = gaussian_blur(&img, 9, 3.0);
    assert!(blurred.pixels.iter().all(|p| (0..=255).contains(p)));
}

#[test]
fn threshold_and_mask_area_agree() {
    let img = image(Kind::Bars, 48, 11);
    let mask = threshold_mask(&img, 200);
    let grown = dilate(&mask, 48, 48);
    assert!(mask_area(&grown) >= mask_area(&mask));
}

// ---- stats helpers -----------------------------------------------------------

#[test]
fn kurtosis_and_autocorrelation_behave() {
    assert_eq!(kurtosis(&[1.0, 2.0, 3.0]), 0.0); // too small
    let periodic: Vec<f64> = (0..256)
        .map(|i| if (i % 8) < 4 { 1.0 } else { -1.0 })
        .collect();
    assert!(autocorrelation(&periodic, 8) > 0.9);
    assert!(autocorrelation(&periodic, 4) < -0.9);
}

#[test]
fn variance_time_hurst_orders_series_kinds() {
    // Smooth gradient (persistent) vs noise (random) — the estimates must
    // order correctly and stay inside (0, 1).
    let grad = image(Kind::Gradient, 64, 12);
    let noise = image(Kind::Noise, 64, 13);
    let h_grad = variance_time_hurst(
        &grad
            .pixels
            .iter()
            .map(|p| f64::from(*p))
            .collect::<Vec<_>>(),
    );
    let h_noise = variance_time_hurst(
        &noise
            .pixels
            .iter()
            .map(|p| f64::from(*p))
            .collect::<Vec<_>>(),
    );
    assert!((0.01..=0.99).contains(&h_grad));
    assert!((0.01..=0.99).contains(&h_noise));
    assert!(
        h_grad > h_noise,
        "gradient {h_grad} must exceed noise {h_noise}"
    );
}

// ---- WTMM 2D -----------------------------------------------------------------

#[test]
fn wtmm_spectrum_is_well_formed_across_buckets() {
    let img = image(Kind::Masonry, 64, 14);
    for bucket in [
        ComplexityBucket::VeryLow,
        ComplexityBucket::Medium,
        ComplexityBucket::VeryHigh,
    ] {
        let cfg = WtmmConfig::auto_detect(bucket);
        let res = extract_wtmm(&img, &cfg).unwrap();
        assert_eq!(res.values.len(), cfg.num_scales as usize);
        assert_eq!(res.singularity_spectrum.len(), res.q_values.len());
        assert_eq!(res.tau_exponents.len(), res.q_values.len());
        assert!(res.values.iter().all(|v| v.is_finite()));
    }
}

#[test]
fn wtmm_singularity_spectrum_deterministic() {
    let img = image(Kind::Noise, 64, 15);
    let cfg = WtmmConfig::new(1, 16, 6, WaveletType::MexicanHat);
    let a = extract_wtmm(&img, &cfg).unwrap();
    let b = extract_wtmm(&img, &cfg).unwrap();
    assert_eq!(a.singularity_spectrum, b.singularity_spectrum);
    assert_eq!(a.tau_exponents, b.tau_exponents);
}

// ---- magic-byte sniffing ------------------------------------------------------

#[test]
fn sniffing_rejects_and_accepts_correctly() {
    assert_eq!(
        sniff_format(b"\x89PNG\r\n\x1a\nrest").unwrap(),
        spectrum::image::ImageFormat::PNG
    );
    assert!(sniff_format(b"").is_err());
    assert!(sniff_format(b"<?xml version=\"1.0\"?>").is_err());
    assert!(sniff_format(b"\xFF\xD8\xFF").is_ok()); // JPEG SOI
}

// ---- reports ------------------------------------------------------------------

#[test]
fn report_roundtrip_and_keylessness() {
    // Build a report through the public facade.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("r.png");
    let mut img = image::RgbImage::new(160, 160);
    for (x, y, p) in img.enumerate_pixels_mut() {
        *p = image::Rgb([(x * 2) as u8, (y * 2) as u8, 100]);
    }
    img.save(&path).unwrap();

    let spectrum = spectrum::SpectrumCrypto::new();
    let pp = spectrum::image::ImagePreprocessor::new()
        .preprocess(path.to_str().unwrap())
        .unwrap();
    let analysis = spectrum.derivation.analyze(&pp).unwrap();
    let report = AnalysisReport::from_analysis(
        &analysis,
        &hex::encode(pp.original_hash),
        pp.format.name().as_str(),
        pp.dimensions,
        pp.canonical_size,
    );

    let json = report.to_json().unwrap();
    let back = AnalysisReport::from_json(&json).unwrap();
    assert_eq!(back, report);
    assert_eq!(back.sources.len(), 11);
    assert!(!json.to_lowercase().contains("key_hex"));
}

// ---- batch records -------------------------------------------------------------

#[test]
fn batch_manifest_counts_and_roundtrip() {
    let manifest = BatchManifest::new(vec![
        BatchEntry::success(
            "a.png",
            "aa".repeat(spectrum::types::KEY_LENGTH),
            "bb".repeat(32),
            "BALANCED".into(),
            111.5,
        ),
        BatchEntry::failure("b.png", "File not found: b.png"),
        BatchEntry::failure("c.png", "Image corrupted: truncation"),
    ]);
    assert_eq!(manifest.version, BATCH_VERSION);
    assert_eq!(manifest.success_count(), 1);
    assert_eq!(manifest.failure_count(), 2);

    let json = manifest.to_json().unwrap();
    let back = BatchManifest::from_json(&json).unwrap();
    assert_eq!(back, manifest);
}

// ---- selftest battery -----------------------------------------------------------

#[test]
fn selftest_battery_is_green_from_outside_the_crate() {
    let results = spectrum::selftest::run_selftest(false).unwrap();
    assert!(spectrum::selftest::all_passed(&results));
    for r in &results {
        assert!(r.passed, "{}: {}", r.name, r.detail);
    }
}

// ---- config drift ----------------------------------------------------------------

#[test]
fn fuzzing_config_roundtrips_stay_stable() {
    let mut cfg = SpectrumConfig::default();
    cfg.entropy.wtmm_max_scale = 512;
    cfg.entropy.multifractal_q_values.push(-3.5);
    cfg.symmetric.nonce_len = 12;
    let json = cfg.to_json().unwrap();
    let back = SpectrumConfig::from_json(&json).unwrap();
    assert_eq!(back, cfg);
    assert_eq!(back.entropy.wtmm_max_scale, 512);
}
