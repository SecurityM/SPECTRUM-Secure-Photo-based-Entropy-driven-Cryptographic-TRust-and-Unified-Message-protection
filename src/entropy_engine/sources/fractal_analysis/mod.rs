//! Fractal-aware universal image analysis — the "FractalAware" source.
//!
//! The ten existing engines are calibrated for ordinary photography. This
//! source makes SPECTRUM *universal*: images that are themselves fractals —
//! Mandelbrot-boundary zooms, Julia sets, natural fractals such as ferns and
//! coastlines, or deep synthetic noise — are analyzed through a pipeline that
//! first *detects* their fractal character and then adapts to it:
//!
//! 1. [`detection`] measures the box-counting dimension, lacunarity spectrum
//!    and scale-invariance of the image and assigns a [`FractalType`];
//! 2. [`adaptive_wtmm`] runs a complex-Morlet modulus-maxima analysis whose
//!    significance thresholds follow the measured dimension and which stops
//!    early once the maxima counts converge (fractal plateau);
//! 3. [`multifractal_spectrum`] computes the real `f(α)` singularity
//!    spectrum via partition functions and a Legendre transform;
//! 4. [`normalization`] adaptively quantizes each measured series to its own
//!    observed dynamic range, so Mandelbrot-scale magnitudes never clip.
//!
//! Every stage is a pure, deterministic function of the pixels — no fitted
//! constants, no RNG — so the resulting 32-byte Ascon-Hash256 signature and
//! its entropy estimate reproduce exactly for the same image. Classification
//! is metadata for byte/report purposes, never a gate: all stages always see
//! the full measurement set, which keeps the math honest for mislabelled
//! boundary cases too.

pub mod adaptive_wtmm;
pub mod detection;
pub mod multifractal_spectrum;
pub mod normalization;
pub mod utils;

pub use adaptive_wtmm::{
    AdaptiveWTMM, DEFAULT_CONVERGENCE_THRESHOLD, DEFAULT_MAX_SCALE, DEFAULT_MORLET_THRESHOLD,
};
pub use detection::{DetectorOutput, FractalClassification, FractalDetector, FractalType};
pub use multifractal_spectrum::{MultifractalAnalyzer, MultifractalSpectrum};
pub use normalization::{AdaptiveNormalizer, AdaptiveRange};

use ascon_hash256::{AsconHash256, Digest};
use serde::{Deserialize, Serialize};

use crate::entropy_engine::sources::fractal_analysis::utils::{
    byte_entropy, to_luma_f64, validate_lattice,
};
use crate::error::{Result, SpectrumError};
use crate::image::Image;

/// Ascon-Hash256 output length in bytes (256 bits).
pub const SIGNATURE_LEN: usize = 32;

/// Smallest image side the fractal stages will analyze (a 16px plane leaves
/// enough room for meaningful multi-scale ladders).
pub const MIN_SIDE: usize = 16;

/// Default largest box side probed by the box-counting/lacunarity stages.
pub const DEFAULT_DETECTION_MAX_SCALE: usize = 256;
/// Default largest dyadic scale of the adaptive WTMM (bounded kernel cost).
pub const DEFAULT_WTMM_MAX_SCALE: usize = DEFAULT_MAX_SCALE;
/// Default q-moment ladder of the multifractal partition function.
pub const DEFAULT_Q_VALUES: [f64; 7] = [-5.0, -3.0, -1.0, 0.0, 1.0, 3.0, 5.0];

/// Configuration of the FractalAware source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FractalAwareConfig {
    /// Largest box side for the detection (box-counting/lacunarity) ladders.
    pub detection_max_scale: usize,
    /// Base significance threshold of the complex-Morlet modulus maxima.
    pub morlet_threshold: f64,
    /// Relative change below which maxima counts are "converged" (plateau).
    pub convergence_threshold: f64,
    /// Largest dyadic scale probed by the adaptive WTMM.
    pub adaptive_wtmm_max_scale: usize,
    /// Moments `q` of the multifractal partition function.
    pub multifractal_q_values: Vec<f64>,
}

impl Default for FractalAwareConfig {
    fn default() -> Self {
        FractalAwareConfig {
            detection_max_scale: DEFAULT_DETECTION_MAX_SCALE,
            morlet_threshold: DEFAULT_MORLET_THRESHOLD,
            convergence_threshold: DEFAULT_CONVERGENCE_THRESHOLD,
            adaptive_wtmm_max_scale: DEFAULT_WTMM_MAX_SCALE,
            // Built through `MultifractalAnalyzer::default_ladder`, the
            // single source of truth for the canonical moment ladder.
            multifractal_q_values: crate::entropy_engine::sources::fractal_analysis::multifractal_spectrum::MultifractalAnalyzer::default_ladder().q_values,
        }
    }
}

/// Result of the FractalAware source for one image.
#[derive(Debug, Clone)]
pub struct FractalAwareResult {
    /// Uniform 256-bit Ascon-Hash256 signature of the adaptive feature pool.
    pub signature: [u8; SIGNATURE_LEN],
    /// Raw (unnormalized) feature series: dimension, lacunarity width,
    /// confidence, lacunarity spectrum, modulus-maxima counts and `f(α)`.
    pub values: Vec<f64>,
    /// Geometric classification of the image (type, dimension, confidence…).
    pub classification: FractalClassification,
    /// Width of the multifractal `f(α)` singularity spectrum.
    pub multifractal_width: f64,
    /// Heuristic entropy contribution fed into the strategy/report.
    pub entropy_bits: f64,
    /// The configuration that produced this result (reproducibility echo).
    pub config: FractalAwareConfig,
}

/// One-shot Ascon-Hash256 over the feature pool.
fn ascon_hash(data: &[u8]) -> [u8; SIGNATURE_LEN] {
    let digest = AsconHash256::digest(data);
    let mut out = [0u8; SIGNATURE_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Sanity-check a configuration before running any stage.
fn validate_config(config: &FractalAwareConfig) -> Result<()> {
    if !(2..=512).contains(&config.detection_max_scale) {
        return Err(SpectrumError::InvalidConfiguration(format!(
            "fractal detection_max_scale must lie in 2..=512, got {}",
            config.detection_max_scale
        )));
    }
    if !config.morlet_threshold.is_finite()
        || !(0.0 < config.morlet_threshold && config.morlet_threshold <= 1.0)
    {
        return Err(SpectrumError::InvalidConfiguration(format!(
            "fractal morlet_threshold must lie in (0, 1], got {}",
            config.morlet_threshold
        )));
    }
    if !config.convergence_threshold.is_finite()
        || !(0.0..=1.0).contains(&config.convergence_threshold)
    {
        return Err(SpectrumError::InvalidConfiguration(format!(
            "fractal convergence_threshold must lie in (0, 1], got {}",
            config.convergence_threshold
        )));
    }
    if !(1..=64).contains(&config.adaptive_wtmm_max_scale) {
        return Err(SpectrumError::InvalidConfiguration(format!(
            "fractal adaptive_wtmm_max_scale must lie in 1..=64, got {}",
            config.adaptive_wtmm_max_scale
        )));
    }
    let qs = &config.multifractal_q_values;
    if !(3..=32).contains(&qs.len()) {
        return Err(SpectrumError::InvalidConfiguration(format!(
            "fractal needs 3..=32 q moments, got {}",
            qs.len()
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for &q in qs {
        if !q.is_finite() || !seen.insert(q.to_bits()) {
            return Err(SpectrumError::InvalidConfiguration(format!(
                "fractal q values must be finite and distinct, got {qs:?}"
            )));
        }
    }
    Ok(())
}

/// The fractal-aware analysis facade described in the design plan: detect the
/// image's fractal character, run the adaptive stages, quantize everything
/// into a deterministic feature pool and collapse it to a signature.
#[derive(Debug, Clone, Default)]
pub struct FractalAwareEngine {
    pub config: FractalAwareConfig,
}

impl FractalAwareEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: FractalAwareConfig) -> Self {
        FractalAwareEngine { config }
    }

    /// Analyze a normalized `[0, 1]` luminance plane with fractal awareness.
    pub fn analyze(&self, img: &[f64], width: usize, height: usize) -> Result<FractalAwareResult> {
        analyze_fractal_aware(img, width, height, &self.config)
    }
}

/// House-style extraction entry point used by the 11-source orchestrator.
pub fn extract_fractal_aware(
    img: &Image,
    config: &FractalAwareConfig,
) -> Result<FractalAwareResult> {
    validate_config(config)?;
    let width = img.width as usize;
    let height = img.height as usize;
    if width < MIN_SIDE || height < MIN_SIDE {
        return Err(SpectrumError::InvalidConfiguration(format!(
            "fractal analysis requires at least {MIN_SIDE}x{MIN_SIDE} pixels, got {width}x{height}"
        )));
    }
    let luma = to_luma_f64(img);
    analyze_fractal_aware(&luma, width, height, config)
}

/// Full fractal-aware pipeline over an f64 luminance plane.
fn analyze_fractal_aware(
    img: &[f64],
    width: usize,
    height: usize,
    config: &FractalAwareConfig,
) -> Result<FractalAwareResult> {
    validate_config(config)?;
    validate_lattice(img, width, height)?;

    // (1) Detect: box-counting dimension, lacunarity spectrum, classification.
    let detector = FractalDetector::with_max_scale(config.detection_max_scale);
    let detected = detector.analyze_lattice(img, width, height)?;
    let classification = detected.classification;

    // (2) Adaptive WTMM: complex-Morlet modulus maxima per scale.
    let wtmm = AdaptiveWTMM::new(
        config.morlet_threshold,
        config.convergence_threshold,
        config.adaptive_wtmm_max_scale,
    );
    let maxima_counts = wtmm.analyze_fractal(img, width, height, &classification)?;

    // (3) Multifractal spectrum via partition functions + Legendre transform.
    let spectrum = MultifractalAnalyzer::new(config.multifractal_q_values.clone())
        .analyze(img, width, height)?;

    // (4) Assemble the raw value pool (report + entropy estimate) and the
    //     adaptively quantized feature byte pool (signature pre-image).
    let mut values: Vec<f64> = Vec::new();
    values.push(classification.hausdorff_dimension);
    values.push(classification.multifractal_width);
    values.push(classification.confidence);
    values.extend_from_slice(&detected.lacunarity);
    values.extend_from_slice(&maxima_counts);
    values.extend_from_slice(&spectrum.f_alpha_values);

    let normalizer = AdaptiveNormalizer::new();
    let lacunarity_bytes = normalizer.bytes_for(&detected.lacunarity);
    let maxima_bytes = normalizer.bytes_for(&maxima_counts);
    let f_alpha_bytes = normalizer.bytes_for(&spectrum.f_alpha_values);

    // Signature pre-image: classification header + adaptively quantized
    // feature series + a fixed-point luminance fingerprint. The header and
    // the min/max-quantized series encode the *geometry* of the image; the
    // per-pixel fixed-point fingerprint (absolute scale, no min/max) makes
    // the signature responsive to a single-pixel edit, which the adaptive
    // statistics alone may legitimately quantize away.
    let mut pool: Vec<u8> = Vec::with_capacity(
        3 + lacunarity_bytes.len() + maxima_bytes.len() + f_alpha_bytes.len() + img.len(),
    );
    pool.push(classification.fractal_type.code());
    // Dimension lives in [1.0, 2.0] by construction → fixed 8-bit encoding.
    let dim_byte =
        (((classification.hausdorff_dimension.clamp(1.0, 2.0) - 1.0) / 1.0) * 255.0).round() as i64;
    pool.push(dim_byte.clamp(0, 255) as u8);
    let conf_byte = (classification.confidence.clamp(0.0, 1.0) * 255.0).round() as i64;
    pool.push(conf_byte.clamp(0, 255) as u8);
    pool.extend_from_slice(&lacunarity_bytes);
    pool.extend_from_slice(&maxima_bytes);
    pool.extend_from_slice(&f_alpha_bytes);
    pool.extend(
        img.iter()
            .map(|&v| (v.clamp(0.0, 1.0) * 255.0).round().clamp(0.0, 255.0) as u8),
    );

    // (5) Collapse the feature + fingerprint pool to a uniform 256-bit signature.
    let signature = ascon_hash(&pool);

    // Honest entropy estimate: Shannon bits over the count-based feature
    // series (lacunarity spectrum + modulus-maxima counts) scaled by the real
    // multifractal width (bounded, no artificial constants). The count series
    // are stable under float jitter, so flat and low-detail images score ≈ 0
    // exactly; genuinely fractal planes fan out and score proportionally. The
    // classification header and the fixed-point fingerprint are excluded: they
    // describe the image deterministically but carry no extractable entropy.
    let mut feature_bytes: Vec<u8> = lacunarity_bytes;
    feature_bytes.extend_from_slice(&maxima_bytes);
    let shannon = byte_entropy(&feature_bytes);
    let detail = spectrum.width.min(1.0);
    // Both operands are finite here: `shannon` is a byte histogram (≤ 8) and
    // `width` is guarded finite upstream, so `clamp` is well-defined (unlike
    // min/max chains, which would silently propagate NaN differently).
    let entropy_bits = (shannon * (1.0 + detail)).clamp(0.0, 16.0);

    Ok(FractalAwareResult {
        signature,
        values,
        multifractal_width: spectrum.width,
        classification,
        entropy_bits,
        config: config.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_image(seed: u8) -> Image {
        let pixels: Vec<u8> = (0..96 * 96)
            .map(|i| ((i * 31 + usize::from(seed)) % 256) as u8)
            .collect();
        Image::from_luma(96, 96, pixels).unwrap()
    }

    fn flat_image() -> Image {
        Image::from_luma(96, 96, vec![128u8; 96 * 96]).unwrap()
    }

    #[test]
    fn defaults_match_plan() {
        let cfg = FractalAwareConfig::default();
        assert_eq!(cfg.morlet_threshold, 0.1);
        assert_eq!(cfg.convergence_threshold, 0.05);
        assert_eq!(cfg.multifractal_q_values, DEFAULT_Q_VALUES.to_vec());
        assert!(cfg.adaptive_wtmm_max_scale >= 1);
    }

    #[test]
    fn deterministic_signature_and_values() {
        let img = sample_image(3);
        let cfg = FractalAwareConfig::default();
        let a = extract_fractal_aware(&img, &cfg).unwrap();
        let b = extract_fractal_aware(&img, &cfg).unwrap();
        assert_eq!(a.signature.len(), SIGNATURE_LEN);
        assert_eq!(a.signature, b.signature);
        assert_eq!(a.values, b.values);
        assert_eq!(a.classification, b.classification);
        assert_eq!(a.config, cfg);
        assert!(a.entropy_bits.is_finite() && a.entropy_bits >= 0.0);
    }

    #[test]
    fn single_pixel_flip_avalanches_signature() {
        let a = sample_image(9);
        let mut b = a.clone();
        let mid = b.pixels.len() / 2;
        b.pixels[mid] = b.pixels[mid].wrapping_add(1);
        assert_ne!(a.pixels, b.pixels);

        let cfg = FractalAwareConfig::default();
        let ra = extract_fractal_aware(&a, &cfg).unwrap();
        let rb = extract_fractal_aware(&b, &cfg).unwrap();
        let differing = ra
            .signature
            .iter()
            .zip(rb.signature.iter())
            .filter(|(x, y)| x != y)
            .count();
        assert!(
            differing >= 16,
            "expected avalanche, only {differing}/32 signature bytes differ"
        );
    }

    #[test]
    fn flat_images_report_regular_and_low_entropy() {
        let flat = flat_image();
        let cfg = FractalAwareConfig::default();
        let res = extract_fractal_aware(&flat, &cfg).unwrap();
        assert_eq!(res.classification.fractal_type, FractalType::Regular);
        assert!(
            res.entropy_bits < 0.05,
            "flat plane must score ~0, got {}",
            res.entropy_bits
        );
    }

    #[test]
    fn busy_images_outscore_flat_ones() {
        let flat = flat_image();
        let busy = sample_image(1);
        let cfg = FractalAwareConfig::default();
        let r_flat = extract_fractal_aware(&flat, &cfg).unwrap();
        let r_busy = extract_fractal_aware(&busy, &cfg).unwrap();
        assert!(
            r_busy.entropy_bits > r_flat.entropy_bits + 0.1,
            "busy={} flat={}",
            r_busy.entropy_bits,
            r_flat.entropy_bits
        );
        assert_ne!(r_flat.signature, r_busy.signature);
        assert!(r_busy.entropy_bits > 0.0);
    }

    #[test]
    fn invalid_configs_are_rejected() {
        let img = sample_image(5);
        let bad = FractalAwareConfig {
            morlet_threshold: 0.0,
            ..Default::default()
        };
        assert!(extract_fractal_aware(&img, &bad).is_err());
        let bad = FractalAwareConfig {
            convergence_threshold: f64::NAN,
            ..Default::default()
        };
        assert!(extract_fractal_aware(&img, &bad).is_err());
        let bad = FractalAwareConfig {
            multifractal_q_values: vec![0.0, 0.0, 1.0],
            ..Default::default()
        };
        assert!(extract_fractal_aware(&img, &bad).is_err());
        let bad = FractalAwareConfig {
            adaptive_wtmm_max_scale: 0,
            ..Default::default()
        };
        assert!(extract_fractal_aware(&img, &bad).is_err());
    }

    #[test]
    fn tiny_images_are_rejected() {
        let img = Image::from_luma(4, 4, vec![0u8; 16]).unwrap();
        assert!(extract_fractal_aware(&img, &FractalAwareConfig::default()).is_err());
    }

    #[test]
    fn wide_range_of_inputs_stays_finite() {
        let cfg = FractalAwareConfig::default();
        for seed in 0..8u8 {
            let img = sample_image(seed);
            let res = extract_fractal_aware(&img, &cfg).unwrap();
            assert!(res.entropy_bits.is_finite());
            assert!(res.values.iter().all(|v| v.is_finite() && *v >= 0.0));
        }
    }
}
