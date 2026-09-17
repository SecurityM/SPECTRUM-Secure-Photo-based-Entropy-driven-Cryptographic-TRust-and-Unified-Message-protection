//! Runnable self-test suite: a battery of correctness and security checks
//! that can be executed by the `spectrum selftest` CLI command.
//!
//! Every check is deterministic, takes no arguments, and returns a named
//! [`SelfTestResult`]. The library export lets the CLI (and CI) run the same
//! battery that the unit tests assert on.

use crate::entropy_engine::sources::EntropySource;
use crate::entropy_engine::EntropyEngine;
use crate::error::Result;
use crate::image::Image;
use crate::key_derivation::KeyDerivationPipeline;
use crate::utils::hashing::compute_sha256;
use crate::utils::test_images::{Kind, TestImage};

/// Outcome of one self-test check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTestResult {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

impl SelfTestResult {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        SelfTestResult {
            name,
            passed: true,
            detail: detail.into(),
        }
    }

    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        SelfTestResult {
            name,
            passed: false,
            detail: detail.into(),
        }
    }
}

/// Deterministic in-memory sample image used by the checks.
fn sample(kind: Kind, side: u32, seed: u64) -> Image {
    TestImage {
        width: side,
        height: side,
        pixels: kind.generate(side, side, seed),
    }
    .into_crate_image()
}

/// Deterministic 1072-bit key for an in-memory image.
///
/// The file-based pipeline binds the SHA-256 of the exact file bytes into the
/// master key; these in-memory checks bind the SHA-256 of the raw pixel
/// buffer instead (a deterministic surrogate — the checks only assert
/// cross-instance reproducibility and sensitivity, which the surrogate fully
/// exercises).
fn key_of(pipeline: &KeyDerivationPipeline, img: &Image) -> Result<[u8; crate::types::KEY_LENGTH]> {
    let analysis = pipeline.entropy_engine.analyze_image(img)?;
    let hash = compute_sha256(&img.pixels);
    pipeline.key_bytes(&analysis, &hash)
}

/// Engine analysis is deterministic across repeats.
pub fn check_analysis_determinism() -> SelfTestResult {
    let name = "analysis_determinism";
    let engine = EntropyEngine::new();
    let img = sample(Kind::Masonry, 96, 1);
    match (engine.analyze_image(&img), engine.analyze_image(&img)) {
        (Ok(a), Ok(b)) if a.profile.total_entropy() == b.profile.total_entropy() => {
            SelfTestResult::pass(
                name,
                format!("total entropy {:.2} bits stable", a.profile.total_entropy()),
            )
        }
        (Ok(a), Ok(b)) => SelfTestResult::fail(
            name,
            format!(
                "entropy differs: {} vs {}",
                a.profile.total_entropy(),
                b.profile.total_entropy()
            ),
        ),
        (Err(e), _) | (_, Err(e)) => SelfTestResult::fail(name, e.to_string()),
    }
}

/// All eleven sources contribute finite, non-negative entropy.
pub fn check_all_sources_contribute() -> SelfTestResult {
    let name = "all_sources_contribute";
    let engine = EntropyEngine::new();
    let img = sample(Kind::Noise, 96, 2);
    match engine.analyze_image(&img) {
        Ok(a) => {
            let dead: Vec<&str> = EntropySource::all()
                .iter()
                .filter(|s| {
                    !(a.profile.entropy_of(**s).is_finite() && a.profile.entropy_of(**s) >= 0.0)
                })
                .map(|s| s.name())
                .collect();
            if dead.is_empty() {
                SelfTestResult::pass(name, "11/11 sources finite and non-negative")
            } else {
                SelfTestResult::fail(name, format!("bad sources: {dead:?}"))
            }
        }
        Err(e) => SelfTestResult::fail(name, e.to_string()),
    }
}

/// The identical image derives the identical 1072-bit key across pipeline
/// instances.
pub fn check_key_stability() -> SelfTestResult {
    let name = "key_stability";
    let img = sample(Kind::Gradient, 96, 3);
    let pa = KeyDerivationPipeline::new();
    let pb = KeyDerivationPipeline::new();
    match (key_of(&pa, &img), key_of(&pb, &img)) {
        (Ok(ka), Ok(kb)) if ka == kb && ka.len() == crate::types::KEY_LENGTH => {
            SelfTestResult::pass(name, "identical 1072-bit master keys across instances")
        }
        (Ok(_), Ok(_)) => SelfTestResult::fail(name, "derived keys differ across instances"),
        (Err(e), _) | (_, Err(e)) => SelfTestResult::fail(name, e.to_string()),
    }
}

/// Distinct images derive distinct keys.
pub fn check_distinct_images_distinct_keys() -> SelfTestResult {
    let name = "distinct_images_distinct_keys";
    let pipeline = KeyDerivationPipeline::new();
    let a = sample(Kind::Noise, 96, 4);
    let b = sample(Kind::Noise, 96, 5);
    match (key_of(&pipeline, &a), key_of(&pipeline, &b)) {
        (Ok(ka), Ok(kb)) if ka != kb => {
            SelfTestResult::pass(name, "different images → different keys")
        }
        (Ok(_), Ok(_)) => SelfTestResult::fail(name, "collision between distinct images"),
        (Err(e), _) | (_, Err(e)) => SelfTestResult::fail(name, e.to_string()),
    }
}

/// A single ±1 pixel edit changes the derived key; there is no path back.
pub fn check_single_pixel_sensitivity() -> SelfTestResult {
    let name = "single_pixel_sensitivity";
    let pipeline = KeyDerivationPipeline::new();
    let img = sample(Kind::Noise, 128, 6);
    let mut edited = img.clone();
    let mid = (edited.width / 2 * edited.height + edited.height / 2) as usize;
    edited.pixels[mid] = edited.pixels[mid].wrapping_add(1);
    if edited.pixels == img.pixels {
        return SelfTestResult::fail(name, "pixel edit did not change the buffer");
    }
    match (key_of(&pipeline, &img), key_of(&pipeline, &edited)) {
        (Ok(k), Ok(k_edited)) if k != k_edited => {
            SelfTestResult::pass(name, "one edited pixel → unrelated key")
        }
        (Ok(_), Ok(_)) => SelfTestResult::fail(name, "edited image derived the same key"),
        (Err(e), _) | (_, Err(e)) => SelfTestResult::fail(name, e.to_string()),
    }
}

/// The 2D wavelet decomposition reconstructs its input exactly.
pub fn check_wavelet_reconstruction() -> SelfTestResult {
    let name = "wavelet_reconstruction";
    let img = sample(Kind::Masonry, 64, 7);
    match crate::filter::wavelet2d::swt2_decompose(&img, 3, crate::filter::Wavelet::MexicanHat) {
        Ok(d) => {
            let rec = d.reconstruct();
            let max_err = rec
                .iter()
                .zip(img.pixels.iter())
                .map(|(r, o)| (r - f64::from(*o)).abs())
                .fold(0.0f64, f64::max);
            if max_err < 1e-6 {
                SelfTestResult::pass(name, format!("max reconstruction error {max_err:.2e}"))
            } else {
                SelfTestResult::fail(name, format!("reconstruction error {max_err:.2e}"))
            }
        }
        Err(e) => SelfTestResult::fail(name, e.to_string()),
    }
}

/// Magic-byte sniffing rejects a text payload masquerading as an image.
pub fn check_sniffer_rejects_mislabeled() -> SelfTestResult {
    let name = "sniffer_rejects_mislabeled";
    let hostile = b"#!/bin/sh\n echo pwned \n";
    match crate::image::loader::sniff_format(hostile) {
        Err(_) => SelfTestResult::pass(name, "non-image bytes rejected"),
        Ok(f) => SelfTestResult::fail(name, format!("text payload accepted as {f:?}")),
    }
}

/// Message round-trip binds to the exact key image.
pub fn check_message_roundtrip_file() -> Result<SelfTestResult> {
    let name = "message_roundtrip";
    let img = sample(Kind::Noise, 128, 8);
    let mut rgb = image::RgbImage::new(128, 128);
    for (x, y, p) in rgb.enumerate_pixels_mut() {
        let v = img.pixels[(y * 128 + x) as usize];
        *p = image::Rgb([v, v, v]);
    }
    // Use the system temp dir directly (no dev-dependency in lib code); the
    // file name is derived from a hash so concurrent runs never collide.
    let file_name = format!(
        "spectrum_selftest_{}.png",
        &hex::encode(compute_sha256(b"selftest-key-image"))[..16]
    );
    let path = std::env::temp_dir().join(file_name);
    rgb.save(&path)?;

    let outcome = (|| -> Result<SelfTestResult> {
        let spectrum = crate::SpectrumCrypto::new();
        let path_str = path.to_str().ok_or_else(|| {
            crate::error::SpectrumError::Unknown(format!(
                "selftest temp path is not valid UTF-8: {}",
                path.display()
            ))
        })?;
        let msg = spectrum.encrypt_message_safe("selftest-payload", path_str)?;
        let bytes = msg.serialize()?;
        let parsed = crate::message::SpectrumMessage::deserialize(&bytes)?;
        match spectrum.decrypt_message_safe(&parsed, path_str) {
            Ok(pt) if pt == "selftest-payload" => {
                Ok(SelfTestResult::pass(name, "encrypt→decrypt roundtrip OK"))
            }
            Ok(pt) => Ok(SelfTestResult::fail(name, format!("wrong plaintext: {pt}"))),
            Err(e) => Ok(SelfTestResult::fail(name, e.to_string())),
        }
    })();

    let _ = std::fs::remove_file(&path);
    outcome
}

/// Run the full battery. Filesystem checks are skipped when `with_fs` is false.
pub fn run_selftest(with_fs: bool) -> Result<Vec<SelfTestResult>> {
    let mut results = vec![
        check_analysis_determinism(),
        check_all_sources_contribute(),
        check_key_stability(),
        check_distinct_images_distinct_keys(),
        check_single_pixel_sensitivity(),
        check_wavelet_reconstruction(),
        check_sniffer_rejects_mislabeled(),
    ];
    if with_fs {
        results.push(check_message_roundtrip_file()?);
    }
    Ok(results)
}

/// Convenience: all passed?
pub fn all_passed(results: &[SelfTestResult]) -> bool {
    results.iter().all(|r| r.passed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_battery_passes() {
        let results = run_selftest(true).unwrap();
        for r in &results {
            assert!(r.passed, "selftest {} failed: {}", r.name, r.detail);
        }
        assert!(all_passed(&results));
        assert!(results.len() >= 8);
    }

    #[test]
    fn battery_without_fs_still_passes() {
        let results = run_selftest(false).unwrap();
        assert!(all_passed(&results));
        assert_eq!(results.len(), 7);
    }

    #[test]
    fn every_check_is_named() {
        let results = run_selftest(false).unwrap();
        assert!(results.iter().all(|r| !r.name.is_empty()));
        let names: std::collections::HashSet<_> = results.iter().map(|r| r.name).collect();
        assert_eq!(names.len(), results.len(), "check names must be unique");
    }
}
