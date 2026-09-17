//! Library-side CLI command implementations.
//!
//! The binary (`src/bin/spectrum.rs`) only parses arguments and delegates here, so
//! every command — including `batch`, `verify` and `selftest` — is callable
//! and testable as library API without spawning a process.

use std::fs;
use std::path::Path;

use crate::config::SpectrumConfig;
use crate::data::{BatchEntry, BatchManifest, KeyRecord};
use crate::entropy_engine::sources::EntropySource;
use crate::error::{Result, SpectrumError};
use crate::report::AnalysisReport;
use crate::selftest::{self, SelfTestResult};
use crate::types::PQ_ENABLED;
use crate::utils::hashing::{hex_to_hash, hex_to_master};
use crate::SpectrumCrypto;

/// Print the effective post-quantum status banner.
pub fn print_banner() {
    println!(
        "Post-quantum layer: {}",
        if PQ_ENABLED {
            "enabled"
        } else {
            "disabled (symmetric AES-256-GCM)"
        }
    );
}

/// `spectrum derive` — deterministically derive the 1072-bit key of an image
/// and print it with its metadata.
///
/// The key is a pure function of the exact file bytes: the same image always
/// produces the same key, and any other image produces an unrelated key.
/// Nothing is written and nothing is required to reproduce the key later.
pub fn cmd_derive(spectrum: &SpectrumCrypto, image: &str, detailed: bool) -> Result<()> {
    print_banner();
    let (key, meta) = spectrum.derive_key_safe(image)?;

    // Intentional disclosure: `spectrum derive` exists to show the key.
    println!("Key: {}", key.as_str());
    println!("Strategy: {}", meta.strategy_name);
    println!("Sources: {:?}", meta.entropy_sources_used);
    println!("Entropy: {:.0} bits", meta.total_entropy);
    println!("Image hash: {}", meta.image_hash);
    println!("Timestamp: {}", meta.creation_timestamp);

    if detailed {
        println!("\nMetadata (JSON):");
        println!("{}", meta.to_json()?);
    }
    Ok(())
}

/// `spectrum analyze` — dump the entropy profile of an image; with `report_path`,
/// write the structured JSON report (spec: `analyze --detailed`).
pub fn cmd_analyze(
    spectrum: &SpectrumCrypto,
    image: &str,
    detailed: bool,
    report_path: Option<&str>,
) -> Result<()> {
    // Honor the instance's configured preprocessor (custom size/quality
    // settings), not a fresh default one.
    let pp = spectrum.derivation.preprocessor.preprocess(image)?;
    let analysis = spectrum.derivation.analyze(&pp)?;
    let p = &analysis.profile;
    let total = EntropySource::all()
        .iter()
        .map(|s| p.entropy_of(*s))
        .sum::<f64>();

    println!("Image Analysis: {image}");
    println!("  Complexity: {:.2}", analysis.adaptive.complexity);
    println!("  Edge strength: {:.3}", analysis.adaptive.edge_strength);
    println!(
        "  Oscillations: {:.3}",
        analysis.adaptive.oscillation_strength
    );
    println!("  WTMM entropy: {:.0} bits", p.wtmm.entropy_bits);
    println!(
        "  Lacunarity entropy: {:.0} bits",
        p.lacunarity.entropy_bits
    );
    println!("  Total entropy: {total:.0} bits");

    if detailed {
        println!("\nDetailed Breakdown:");
        println!(
            "  WTMM: scales {}-{} ({} steps), {:.0} bits",
            analysis.wtmm_config.min_scale,
            analysis.wtmm_config.max_scale,
            analysis.wtmm_config.num_scales,
            p.wtmm.entropy_bits
        );
        println!(
            "  Lacunarity: scales {:?}, {:.0} bits",
            analysis.lacunarity_config.scales, p.lacunarity.entropy_bits
        );
        println!("  Multifractal: {:.0} bits", p.multifractal.entropy_bits);
        println!(
            "  Hurst: R/S={:.3}, variance-time={:.3}, disagreement={:.3}",
            p.hurst.value, p.hurst.value_variance_time, p.hurst.disagreement
        );
        println!("  Gradient entropy: {:.3}", p.gradient.value);
        println!("  Texture features: {:.0} bits", p.texture.entropy_bits);
        println!(
            "  Noise: type={}, magnitude={:.4}, {:.0} bits",
            p.noise.profile.noise_type.name(),
            p.noise.profile.magnitude,
            p.noise.entropy_bits
        );
        println!(
            "  Chaos: {} Hénon iterations, {:.0} bits (Ascon-Hash256 signature {})",
            p.chaos.config.iterations,
            p.chaos.entropy_bits,
            hex::encode(p.chaos.signature)
        );
        println!(
            "  QuantumDensityMatrix: d={}, {} blocks, {:.0} bits (Ascon-Hash256 signature {})",
            p.quantum_density.hilbert_dimension,
            p.quantum_density.block_count,
            p.quantum_density.entropy_bits,
            hex::encode(p.quantum_density.signature)
        );
        println!(
            "  CoupledMapLattice: {} sweeps, spectral {:.0} + KL {:.1} = {:.0} bits (512-bit dual signature {})",
            p.coupled_map_lattice.config.lattice_sweeps,
            p.coupled_map_lattice.final_shannon_bits,
            p.coupled_map_lattice.cumulative_kl_bits,
            p.coupled_map_lattice.entropy_bits,
            hex::encode(p.coupled_map_lattice.signature)
        );
        println!(
            "  FractalAware: class={}, D={:.3}, self-similar={}, width={:.3}, {:.0} bits (Ascon-Hash256 signature {})",
            p.fractal_aware.classification.fractal_type.name(),
            p.fractal_aware.classification.hausdorff_dimension,
            p.fractal_aware.classification.is_self_similar,
            p.fractal_aware.multifractal_width,
            p.fractal_aware.entropy_bits,
            hex::encode(p.fractal_aware.signature)
        );
    }

    if let Some(path) = report_path {
        let report = AnalysisReport::from_analysis(
            &analysis,
            &hex::encode(pp.original_hash),
            pp.format.name().as_str(),
            pp.dimensions,
            pp.canonical_size,
        );
        report.save(path)?;
        println!("\nReport written to {path}");
    }
    Ok(())
}

/// `spectrum batch` — deterministically derive a key for every image in a
/// directory/list and record each result in a JSON [`BatchManifest`].
///
/// Collects `*.png|jpg|jpeg|bmp|tif|tiff|gif` from `input_dir` (or the
/// explicit `files` list when non-empty) and derives each with the provided
/// instance's pipeline (honoring `-C config.json`). Derivation is
/// deterministic, so re-running a batch for the same
/// files reproduces the same keys; failures (unreadable images, …) are
/// recorded in the manifest rather than aborting the run.
///
/// Batch output contains the derived keys: treat the manifest (and stdout)
/// as secret material.
pub fn cmd_batch(
    spectrum: &SpectrumCrypto,
    input_dir: &str,
    files: &[String],
    manifest_out: Option<&str>,
) -> Result<BatchManifest> {
    let paths: Vec<String> = if files.is_empty() {
        collect_images(input_dir)?
    } else {
        files.to_vec()
    };
    if paths.is_empty() {
        return Err(SpectrumError::FileNotFound(format!(
            "no images found in {input_dir}"
        )));
    }

    let mut entries = Vec::with_capacity(paths.len());
    for path in &paths {
        match spectrum.derive_key_safe(path) {
            Ok((key_hex, meta)) => {
                entries.push(BatchEntry::success(
                    path,
                    key_hex.to_string(),
                    meta.image_hash,
                    meta.strategy_name,
                    meta.total_entropy,
                ));
            }
            Err(e) => {
                log::warn!("batch: {path}: {e}");
                entries.push(BatchEntry::failure(path, e.to_string()));
            }
        }
    }

    let manifest = BatchManifest::new(entries);
    if let Some(out) = manifest_out {
        manifest.save(out)?;
    }
    println!(
        "Batch complete: {} ok, {} failed ({} total)",
        manifest.success_count(),
        manifest.failure_count(),
        manifest.entries.len()
    );
    Ok(manifest)
}

/// Collect image files from a directory (deterministic sorted order).
fn collect_images(dir: &str) -> Result<Vec<String>> {
    let entries = fs::read_dir(dir).map_err(|_| SpectrumError::FileNotFound(dir.to_string()))?;
    let mut paths: Vec<String> = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| SpectrumError::Unknown(e.to_string()))?
            .path();
        if !path.is_file() {
            continue;
        }
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            const IMAGE_EXTS: [&str; 7] = ["png", "jpg", "jpeg", "bmp", "tif", "tiff", "gif"];
            if IMAGE_EXTS.contains(&ext.to_ascii_lowercase().as_str()) {
                paths.push(path.to_string_lossy().into_owned());
            }
        }
    }
    paths.sort();
    Ok(paths)
}

/// `spectrum verify` — check a `.frk` key record against its key image.
///
/// Re-derives the key deterministically from `image` and compares it to the
/// exported `.frk` record: success means the file at `image` is byte-exactly
/// the one that was exported (same key, same image hash). Any edit,
/// recompression or re-capture is detected.
pub fn cmd_verify(spectrum: &SpectrumCrypto, key_file: &str, image: &str) -> Result<bool> {
    let record = KeyRecord::load(key_file)?;
    let (key_hex, meta) = spectrum.derive_key_safe(image)?;

    let derived = hex_to_master(&key_hex)?;
    let matches_key = derived.as_slice() == record.key.as_slice();
    let matches_hash = hex_to_hash(&meta.image_hash)
        .map(|h| h == record.image_hash)
        .unwrap_or(false);

    if matches_key && matches_hash {
        println!("VERIFIED: {key_file} matches {image}");
        Ok(true)
    } else {
        println!("MISMATCH: {key_file} does not match {image}");
        if !matches_hash {
            println!("  image hash differs (file changed?)");
        }
        if !matches_key {
            println!("  derived key differs");
        }
        Ok(false)
    }
}

/// `spectrum selftest` — run the built-in correctness battery.
pub fn cmd_selftest(with_fs: bool) -> Result<()> {
    let results: Vec<SelfTestResult> = selftest::run_selftest(with_fs)?;
    for r in &results {
        println!(
            "[{}] {} — {}",
            if r.passed { "PASS" } else { "FAIL" },
            r.name,
            r.detail
        );
    }
    let failed = results.iter().filter(|r| !r.passed).count();
    if failed == 0 {
        println!("\nSelftest: all {} checks passed.", results.len());
        Ok(())
    } else {
        println!("\nSelftest: {failed} of {} checks FAILED.", results.len());
        Err(SpectrumError::EntropyExtractionFailed)
    }
}

/// `spectrum export` — derive the deterministic key of `image` and write it,
/// together with the image's SHA-256, to a secret, checksummed `.frk` file.
///
/// Re-running export for the same image reproduces the identical record
/// (derivation is deterministic), so the output is safe to overwrite.
pub fn cmd_export(spectrum: &SpectrumCrypto, image: &str, output: &str) -> Result<()> {
    let (key_hex, meta) = spectrum.derive_key_safe(image)?;
    let key = hex_to_master(&key_hex)?;
    let image_hash = hex_to_hash(&meta.image_hash)
        .map_err(|_| SpectrumError::SerializationError("bad image hash".into()))?;
    let rec = KeyRecord { key, image_hash };
    rec.save(output)?;
    println!(
        "Exported key for {image} to {output}, sha256={}",
        meta.image_hash
    );
    Ok(())
}

/// `spectrum config` — print or write the default config document.
pub fn cmd_config(output: Option<&str>) -> Result<()> {
    let cfg = SpectrumConfig::default();
    let json = cfg.to_json()?;
    match output {
        Some(path) => {
            cfg.save(path)?;
            println!("Wrote default config to {path}");
        }
        None => println!("{json}"),
    }
    Ok(())
}

/// Whether a path exists and is a file (used by the binary for nice errors).
pub fn file_exists(path: &str) -> bool {
    Path::new(path).is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static N: AtomicU32 = AtomicU32::new(0);

    fn make_image(dir: &std::path::Path, name: &str, seed: u8) -> String {
        let idx = N.fetch_add(1, Ordering::SeqCst);
        let mut img = image::RgbImage::new(160, 160);
        for (x, y, p) in img.enumerate_pixels_mut() {
            let s = u32::from(seed).wrapping_add(idx);
            *p = image::Rgb([
                (x.wrapping_mul(5) ^ s) as u8,
                (y.wrapping_mul(7)) as u8,
                ((x + y) * 3) as u8,
            ]);
        }
        let p = dir.join(format!("{name}_{idx}.png"));
        img.save(&p).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn derive_prints_the_deterministic_key() {
        let dir = tempfile::tempdir().unwrap();
        let img = make_image(dir.path(), "dv", 10);
        let spectrum = SpectrumCrypto::new();
        cmd_derive(&spectrum, &img, false).unwrap();

        // Deterministic: a second derive prints the same key (capture by
        // re-deriving through the pipeline directly).
        let (k1, _) = spectrum.derive_key_safe(&img).unwrap();
        let (k2, _) = spectrum.derive_key_safe(&img).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), crate::types::KEY_LENGTH * 2);
    }

    #[test]
    fn batch_derives_directory_and_writes_manifest() {
        let dir = tempfile::tempdir().unwrap();
        make_image(dir.path(), "one", 1);
        make_image(dir.path(), "two", 2);
        // A non-image file must be skipped.
        std::fs::write(dir.path().join("notes.txt"), "ignore me").unwrap();

        let manifest_path = dir.path().join("manifest.json");
        let manifest = cmd_batch(
            &SpectrumCrypto::new(),
            dir.path().to_str().unwrap(),
            &[],
            Some(manifest_path.to_str().unwrap()),
        )
        .unwrap();

        assert_eq!(manifest.entries.len(), 2);
        assert_eq!(manifest.success_count(), 2);
        assert!(manifest_path.exists());
        for e in &manifest.entries {
            assert_eq!(e.key_hex.len(), crate::types::KEY_LENGTH * 2);
        }
    }

    #[test]
    fn batch_explicit_file_list() {
        let dir = tempfile::tempdir().unwrap();
        let a = make_image(dir.path(), "a", 3);
        let b = make_image(dir.path(), "b", 4);
        let manifest = cmd_batch(&SpectrumCrypto::new(), "unused-dir", &[a, b], None).unwrap();
        assert_eq!(manifest.success_count(), 2);
    }

    #[test]
    fn batch_collects_failures_without_aborting() {
        let dir = tempfile::tempdir().unwrap();
        let good = make_image(dir.path(), "good", 5);
        let manifest = cmd_batch(
            &SpectrumCrypto::new(),
            "unused",
            &[good, "/nonexistent/nope.png".into()],
            None,
        )
        .unwrap();
        assert_eq!(manifest.success_count(), 1);
        assert_eq!(manifest.failure_count(), 1);
        assert!(manifest.entries[1].error.contains("not found"));
    }

    #[test]
    fn batch_empty_dir_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(cmd_batch(
            &SpectrumCrypto::new(),
            dir.path().to_str().unwrap(),
            &[],
            None
        )
        .is_err());
    }

    #[test]
    fn batch_is_deterministic_across_runs() {
        let dir = tempfile::tempdir().unwrap();
        make_image(dir.path(), "det", 6);
        let m1 = cmd_batch(
            &SpectrumCrypto::new(),
            dir.path().to_str().unwrap(),
            &[],
            None,
        )
        .unwrap();
        let m2 = cmd_batch(
            &SpectrumCrypto::new(),
            dir.path().to_str().unwrap(),
            &[],
            None,
        )
        .unwrap();
        // Deterministic derivation: re-running reproduces identical keys,
        // hashes and metadata (only the manifest timestamp differs).
        assert_eq!(m1.entries.len(), m2.entries.len());
        for (e1, e2) in m1.entries.iter().zip(m2.entries.iter()) {
            assert_eq!(e1.key_hex, e2.key_hex);
            assert_eq!(e1.image_hash, e2.image_hash);
            assert_eq!(e1.strategy, e2.strategy);
            assert_eq!(e1.total_entropy, e2.total_entropy);
        }
    }

    #[test]
    fn export_then_verify_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let img = make_image(dir.path(), "keyimg", 6);
        let frk = dir.path().join("key.frk");
        cmd_export(&SpectrumCrypto::new(), &img, frk.to_str().unwrap()).unwrap();
        assert!(frk.exists());

        // Right image verifies.
        assert!(cmd_verify(&SpectrumCrypto::new(), frk.to_str().unwrap(), &img).unwrap());
        // A different image does not.
        let other = make_image(dir.path(), "other", 7);
        assert!(!cmd_verify(&SpectrumCrypto::new(), frk.to_str().unwrap(), &other).unwrap());
    }

    #[test]
    fn verify_rejects_missing_record() {
        let dir = tempfile::tempdir().unwrap();
        let img = make_image(dir.path(), "img", 8);
        let frk = dir.path().join("missing.frk");
        assert!(cmd_verify(&SpectrumCrypto::new(), frk.to_str().unwrap(), &img).is_err());
    }

    #[test]
    fn selftest_command_passes() {
        cmd_selftest(false).unwrap();
    }

    #[test]
    fn analyze_writes_report_file() {
        let dir = tempfile::tempdir().unwrap();
        let img = make_image(dir.path(), "rep", 9);
        let report_path = dir.path().join("report.json");
        let spectrum = SpectrumCrypto::new();
        cmd_analyze(&spectrum, &img, true, Some(report_path.to_str().unwrap())).unwrap();
        let loaded = AnalysisReport::load(report_path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.sources.len(), 11);
    }
}
