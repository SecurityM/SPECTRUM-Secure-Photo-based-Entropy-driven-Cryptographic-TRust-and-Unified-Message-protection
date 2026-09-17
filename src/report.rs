//! Structured JSON analysis reports (`analyze --detailed`).
//!
//! A report captures the complete picture of one image's entropy analysis in
//! a stable, versioned, serializable document: adaptive properties, per-source
//! entropy contributions, a per-source detail block for every engine (WTMM
//! singularity spectrum, Hurst estimates, noise profile, Chaos orbit metrics,
//! QuantumDensityMatrix Hilbert data, CoupledMapLattice flow terms, FractalAware
//! classification) and the strategy that would be selected. Reports are
//! intentionally keyless — they describe the image, never the derived key or
//! the engines' raw signature digests.

use serde::{Deserialize, Serialize};

use crate::entropy_engine::strategy::Strategy;
use crate::entropy_engine::Analysis;
use crate::error::{Result, SpectrumError};
use crate::types::STRATEGY_VERSION;

/// Current report schema version. v2 adds per-source detail blocks for the
/// four signature engines: Chaos, QuantumDensityMatrix, CoupledMapLattice and
/// FractalAware.
pub const REPORT_VERSION: u32 = 2;

/// Per-source entropy contribution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceReport {
    pub name: String,
    pub entropy_bits: f64,
    /// Share of the total entropy in [0, 1].
    pub weight: f64,
}

/// WTMM-specific details.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct WtmmReport {
    pub min_scale: u32,
    pub max_scale: u32,
    pub num_scales: u32,
    pub wavelet: String,
    /// τ(q) per moment order (empty when WTMM was disabled).
    pub tau_exponents: Vec<f64>,
    /// f(α) singularity spectrum per moment order.
    pub singularity_spectrum: Vec<f64>,
    pub q_values: Vec<f64>,
}

/// Chaos (Hénon-map / Ascon-Hash256) details.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ChaosReport {
    /// Number of chaotic Hénon iterations that produced the orbit.
    pub iterations: usize,
    /// Hénon control parameter `a`.
    pub a: f64,
    /// Hénon control parameter `b`.
    pub b: f64,
    /// Shannon entropy (bits per byte, 0..=8) of the raw orbit buffer.
    pub orbit_entropy: f64,
}

/// QuantumDensityMatrix (Hermitian density operators) details.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct QuantumDensityReport {
    /// Hilbert-space dimension `d` of each density operator.
    pub hilbert_dimension: usize,
    /// Number of independent block operators accumulated.
    pub block_count: usize,
    /// Whether each operator was trace-normalised to `Tr ρ = 1`.
    pub enforce_unit_trace: bool,
    /// Whether the full spectrum of every block was analysed.
    pub hard_entropy_floor: bool,
}

/// CoupledMapLattice (spatiotemporal chaos) details.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CoupledMapLatticeReport {
    /// Number of full-lattice sweeps (time steps).
    pub lattice_sweeps: usize,
    /// Nearest-neighbour diffusion factor ε.
    pub diffusion_factor: f64,
    /// Logistic growth rate `r` of the local map.
    pub map_growth_rate: f64,
    /// Spectral Shannon entropy (bits) over the final lattice sub-blocks.
    pub final_shannon_bits: f64,
    /// Cumulative spatiotemporal KL divergence (bits) across all sweeps.
    pub cumulative_kl_bits: f64,
}

/// FractalAware (fractal detection + adaptive WTMM + `f(α)`) details.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct FractalAwareReport {
    /// Geometrical family assigned by the detector (`Regular`,
    /// `NaturalFractal`, `JuliaSet`, `MandelbrotBoundary`).
    pub fractal_type: String,
    /// Box-counting dimension estimate, clamped to `[1.0, 2.0]`.
    pub hausdorff_dimension: f64,
    /// Detector confidence in `[0, 1]`.
    pub confidence: f64,
    /// Whether the structure repeats across the probed scales.
    pub is_self_similar: bool,
    /// Width of the multifractal `f(α)` singularity spectrum.
    pub multifractal_width: f64,
    /// Goodness-of-fit of the box-counting power law.
    pub log_log_r2: f64,
    /// Fraction of pixels flagged as edges in `[0, 1]`.
    pub edge_fraction: f64,
}

/// A complete, versioned analysis report for one image.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalysisReport {
    pub report_version: u32,
    /// SHA-256 of the original image file, hex-encoded.
    pub image_hash: String,
    pub image_format: String,
    pub dimensions: (u32, u32),
    pub canonical_size: (u32, u32),

    // Adaptive properties.
    pub complexity: f64,
    pub complexity_bucket: String,
    pub edge_strength: f64,
    pub oscillation_strength: f64,
    pub pixel_density: f64,
    pub cluster_presence: bool,

    // Per-source contributions, canonical source order.
    pub sources: Vec<SourceReport>,
    pub total_entropy_bits: f64,

    // Strategy that would be selected.
    pub strategy: String,
    pub strategy_version: u32,
    /// Sources ordered most-weighted first.
    pub ranked_sources: Vec<String>,

    // Details.
    pub wtmm: WtmmReport,
    pub hurst_rescaled_range: f64,
    pub hurst_variance_time: f64,
    pub hurst_disagreement: f64,
    pub noise_type: String,
    pub noise_magnitude: f64,

    // Per-source detail blocks for the signature engines.
    pub chaos: ChaosReport,
    pub quantum_density: QuantumDensityReport,
    pub coupled_map_lattice: CoupledMapLatticeReport,
    pub fractal_aware: FractalAwareReport,
}

impl AnalysisReport {
    /// Build a report from an analysis plus the preprocessed-image context.
    pub fn from_analysis(
        analysis: &Analysis,
        image_hash: &str,
        image_format: &str,
        dimensions: (u32, u32),
        canonical_size: (u32, u32),
    ) -> Self {
        let profile = &analysis.profile;
        let total = profile.total_entropy();
        let sources = crate::entropy_engine::sources::EntropySource::all()
            .iter()
            .map(|s| {
                let bits = profile.entropy_of(*s);
                SourceReport {
                    name: s.name().to_string(),
                    entropy_bits: bits,
                    weight: if total > 0.0 { bits / total } else { 0.0 },
                }
            })
            .collect();

        let strategy = Strategy::determine(profile);

        AnalysisReport {
            report_version: REPORT_VERSION,
            image_hash: image_hash.to_string(),
            image_format: image_format.to_string(),
            dimensions,
            canonical_size,
            complexity: analysis.adaptive.complexity,
            complexity_bucket: format!("{:?}", analysis.adaptive.bucket()),
            edge_strength: analysis.adaptive.edge_strength,
            oscillation_strength: analysis.adaptive.oscillation_strength,
            pixel_density: analysis.adaptive.pixel_density,
            cluster_presence: analysis.adaptive.cluster_presence,
            sources,
            total_entropy_bits: total,
            strategy: strategy.name.as_str().to_string(),
            strategy_version: STRATEGY_VERSION,
            ranked_sources: strategy.source_names(),
            wtmm: WtmmReport {
                min_scale: analysis.wtmm_config.min_scale,
                max_scale: analysis.wtmm_config.max_scale,
                num_scales: analysis.wtmm_config.num_scales,
                wavelet: format!("{:?}", analysis.wtmm_config.wavelet),
                tau_exponents: profile.wtmm.tau_exponents.clone(),
                singularity_spectrum: profile.wtmm.singularity_spectrum.clone(),
                q_values: profile.wtmm.q_values.clone(),
            },
            hurst_rescaled_range: profile.hurst.value,
            hurst_variance_time: profile.hurst.value_variance_time,
            hurst_disagreement: profile.hurst.disagreement,
            noise_type: profile.noise.profile.noise_type.name().to_string(),
            noise_magnitude: profile.noise.profile.magnitude,
            chaos: ChaosReport {
                iterations: profile.chaos.config.iterations,
                a: profile.chaos.config.a,
                b: profile.chaos.config.b,
                orbit_entropy: profile.chaos.orbit_entropy,
            },
            quantum_density: QuantumDensityReport {
                hilbert_dimension: profile.quantum_density.hilbert_dimension,
                block_count: profile.quantum_density.block_count,
                enforce_unit_trace: profile.quantum_density.config.enforce_unit_trace,
                hard_entropy_floor: profile.quantum_density.config.hard_entropy_floor,
            },
            coupled_map_lattice: CoupledMapLatticeReport {
                lattice_sweeps: profile.coupled_map_lattice.config.lattice_sweeps,
                diffusion_factor: profile.coupled_map_lattice.config.diffusion_factor,
                map_growth_rate: profile.coupled_map_lattice.config.map_growth_rate,
                final_shannon_bits: profile.coupled_map_lattice.final_shannon_bits,
                cumulative_kl_bits: profile.coupled_map_lattice.cumulative_kl_bits,
            },
            fractal_aware: FractalAwareReport {
                fractal_type: profile
                    .fractal_aware
                    .classification
                    .fractal_type
                    .name()
                    .to_string(),
                hausdorff_dimension: profile.fractal_aware.classification.hausdorff_dimension,
                confidence: profile.fractal_aware.classification.confidence,
                is_self_similar: profile.fractal_aware.classification.is_self_similar,
                multifractal_width: profile.fractal_aware.multifractal_width,
                log_log_r2: profile.fractal_aware.classification.log_log_r2,
                edge_fraction: profile.fractal_aware.classification.edge_fraction,
            },
        }
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| SpectrumError::SerializationError(e.to_string()))
    }

    /// Parse a report from JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| SpectrumError::SerializationError(e.to_string()))
    }

    /// Write the report to a file (pretty JSON + newline).
    pub fn save(&self, path: &str) -> Result<()> {
        let mut json = self.to_json()?;
        json.push('\n');
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load a report from a file.
    ///
    /// Read under the global [`crate::data::MAX_INPUT_FILE_BYTES`] cap so a
    /// pathologically large file fails closed instead of exhausting memory.
    pub fn load(path: &str) -> Result<Self> {
        let raw = String::from_utf8(crate::data::read_capped(path)?)?;
        Self::from_json(&raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SpectrumConfig;
    use crate::image::ImagePreprocessor;
    use crate::key_derivation::KeyDerivationPipeline;
    use std::sync::atomic::{AtomicU32, Ordering};

    static N: AtomicU32 = AtomicU32::new(0);

    fn sample_image(dir: &std::path::Path) -> std::path::PathBuf {
        let idx = N.fetch_add(1, Ordering::SeqCst);
        let mut img = image::RgbImage::new(160, 160);
        for (x, y, p) in img.enumerate_pixels_mut() {
            *p = image::Rgb([
                (x.wrapping_mul(5)) as u8,
                (y.wrapping_mul(7)) as u8,
                ((x + y) * 3) as u8,
            ]);
        }
        let p = dir.join(format!("report_{idx}.png"));
        img.save(&p).unwrap();
        p
    }

    fn build_report(dir: &std::path::Path) -> (AnalysisReport, std::path::PathBuf) {
        let path = sample_image(dir);
        let cfg = SpectrumConfig::default();
        let pipeline =
            KeyDerivationPipeline::with_configs(cfg.entropy.clone(), cfg.preprocessor.clone());
        let pp = ImagePreprocessor::with_config(cfg.preprocessor.clone())
            .preprocess(path.to_str().unwrap())
            .unwrap();
        let analysis = pipeline.analyze(&pp).unwrap();
        let hash = hex::encode(pp.original_hash);
        let report = AnalysisReport::from_analysis(
            &analysis,
            &hash,
            pp.format.name().as_str(),
            pp.dimensions,
            pp.canonical_size,
        );
        (report, path)
    }

    #[test]
    fn report_json_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let (report, _) = build_report(dir.path());
        let json = report.to_json().unwrap();
        let back = AnalysisReport::from_json(&json).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn report_has_eleven_sources_and_strategy() {
        let dir = tempfile::tempdir().unwrap();
        let (report, _) = build_report(dir.path());
        assert_eq!(report.sources.len(), 11);
        assert!(!report.strategy.is_empty());
        assert_eq!(report.strategy_version, STRATEGY_VERSION);
        assert_eq!(report.report_version, REPORT_VERSION);
        let weight_sum: f64 = report.sources.iter().map(|s| s.weight).sum();
        assert!((weight_sum - 1.0).abs() < 1e-9);
    }

    #[test]
    fn report_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let (report, _) = build_report(dir.path());
        let path = dir.path().join("report.json");
        report.save(path.to_str().unwrap()).unwrap();
        let loaded = AnalysisReport::load(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded, report);
    }

    #[test]
    fn wtmm_details_are_captured() {
        let dir = tempfile::tempdir().unwrap();
        let (report, _) = build_report(dir.path());
        assert!(report.wtmm.num_scales > 0);
        assert_eq!(
            report.wtmm.singularity_spectrum.len(),
            report.wtmm.q_values.len()
        );
        assert_eq!(report.wtmm.tau_exponents.len(), report.wtmm.q_values.len());
    }

    #[test]
    fn detailed_blocks_cover_the_signature_sources() {
        // The four engines whose digests enter the key pre-image must each
        // expose a diagnostic detail block in the report.
        let dir = tempfile::tempdir().unwrap();
        let (report, _) = build_report(dir.path());

        // Chaos ran with the configured orbit and measured its entropy.
        assert!(report.chaos.iterations > 0);
        assert!(
            (0.0..=8.0).contains(&report.chaos.orbit_entropy),
            "orbit entropy out of range: {}",
            report.chaos.orbit_entropy
        );

        // QuantumDensityMatrix operated over at least one block operator.
        assert!(report.quantum_density.hilbert_dimension > 0);
        assert!(
            report.quantum_density.block_count > 0,
            "QDM must accumulate at least one density operator"
        );

        // CoupledMapLattice reports finite spectral + flow terms for the
        // configured sweeps.
        assert!(report.coupled_map_lattice.lattice_sweeps > 0);
        assert!(report.coupled_map_lattice.final_shannon_bits.is_finite());
        assert!(report.coupled_map_lattice.cumulative_kl_bits.is_finite());

        // FractalAware reports a bounded classification.
        assert!(!report.fractal_aware.fractal_type.is_empty());
        assert!(
            (1.0..=2.0).contains(&report.fractal_aware.hausdorff_dimension),
            "fractal dimension out of range: {}",
            report.fractal_aware.hausdorff_dimension
        );
        assert!((0.0..=1.0).contains(&report.fractal_aware.confidence));
        assert!(report.fractal_aware.multifractal_width.is_finite());
        assert!(report.fractal_aware.multifractal_width >= 0.0);
    }

    #[test]
    fn load_refuses_oversized_file() {
        // Untrusted-path hygiene: a huge "report" fails closed under the
        // global input cap instead of being slurped into memory. A sparse
        // file gives an over-cap logical size without touching that many
        // disk blocks, exercising the real shipped cap (128 MiB).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.json");
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(crate::data::MAX_INPUT_FILE_BYTES + 1).unwrap();
        drop(f);

        let err = AnalysisReport::load(path.to_str().unwrap())
            .expect_err("oversized report must be refused");
        assert!(
            err.to_string().contains("refusing unbounded read"),
            "expected the capped-read failure, got {err}"
        );
    }

    #[test]
    fn reports_are_keyless() {
        // The serialized document must not leak any key material field — nor
        // the raw source signatures that enter the key-derivation pre-image.
        let dir = tempfile::tempdir().unwrap();
        let (report, _) = build_report(dir.path());
        let json = report.to_json().unwrap().to_lowercase();
        for banned in [
            "\"key\"",
            "key_hex",
            "keyhash",
            "derived_key",
            "\"signature\"",
        ] {
            assert!(!json.contains(banned), "report must not contain {banned}");
        }
    }
}
