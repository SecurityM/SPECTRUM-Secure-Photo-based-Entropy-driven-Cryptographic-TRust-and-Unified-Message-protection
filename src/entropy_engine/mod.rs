//! The adaptive 11-source entropy engine.
//!
//! Runs the eleven independent sources over a bounded working resolution,
//! aggregates them deterministically, then lets the caller derive a strategy
//! and build the final byte sequence for key derivation.

pub mod adaptive_config;
pub mod mixer;
pub mod sources;
pub mod strategy;

use rayon::prelude::*;

use crate::config::EntropyEngineConfig;
pub use crate::entropy_engine::adaptive_config::{analyze, AdaptiveConfig, ComplexityBucket};
use crate::entropy_engine::sources::fractal_analysis::{
    self, FractalAwareResult, FractalClassification,
};
use crate::entropy_engine::sources::lacunarity::{self, LacunarityConfig};
use crate::entropy_engine::sources::wtmm::{self, WtmmConfig};
use crate::entropy_engine::sources::{
    chaos, coupled_map_lattice, gradient, hurst, multifractal, noise, quantum_density, texture,
    EntropyProfile,
};
use crate::error::{Result, SpectrumError};
use crate::image::Image;

/// Result of analyzing one image: the full entropy profile plus the adaptive
/// properties used to drive configuration.
#[derive(Debug, Clone)]
pub struct Analysis {
    pub profile: EntropyProfile,
    pub adaptive: AdaptiveConfig,
    pub wtmm_config: WtmmConfig,
    pub lacunarity_config: LacunarityConfig,
}

/// One source's computed result, tagged by kind. This lets the eleven source
/// closures run in parallel (each producing exactly one `SourceOutcome`) and
/// then be folded into a fixed-order [`EntropyProfile`].
enum SourceOutcome {
    Wtmm(wtmm::WtmmResult),
    Lacunarity(lacunarity::LacunarityResult),
    Multifractal(multifractal::MultifractalResult),
    Hurst(hurst::HurstResult),
    Gradient(gradient::GradientResult),
    Texture(texture::TextureResult),
    Noise(noise::NoiseResult),
    Chaos(chaos::ChaosResult),
    QuantumDensity(quantum_density::QuantumDensityResult),
    CoupledMapLattice(coupled_map_lattice::CoupledMapLatticeResult),
    FractalAware(fractal_analysis::FractalAwareResult),
}

impl SourceOutcome {
    fn into_wtmm(self) -> Result<wtmm::WtmmResult> {
        match self {
            SourceOutcome::Wtmm(r) => Ok(r),
            _ => Err(SpectrumError::EntropyExtractionFailed),
        }
    }
    fn into_lacunarity(self) -> Result<lacunarity::LacunarityResult> {
        match self {
            SourceOutcome::Lacunarity(r) => Ok(r),
            _ => Err(SpectrumError::EntropyExtractionFailed),
        }
    }
    fn into_multifractal(self) -> Result<multifractal::MultifractalResult> {
        match self {
            SourceOutcome::Multifractal(r) => Ok(r),
            _ => Err(SpectrumError::EntropyExtractionFailed),
        }
    }
    fn into_hurst(self) -> Result<hurst::HurstResult> {
        match self {
            SourceOutcome::Hurst(r) => Ok(r),
            _ => Err(SpectrumError::EntropyExtractionFailed),
        }
    }
    fn into_gradient(self) -> Result<gradient::GradientResult> {
        match self {
            SourceOutcome::Gradient(r) => Ok(r),
            _ => Err(SpectrumError::EntropyExtractionFailed),
        }
    }
    fn into_texture(self) -> Result<texture::TextureResult> {
        match self {
            SourceOutcome::Texture(r) => Ok(r),
            _ => Err(SpectrumError::EntropyExtractionFailed),
        }
    }
    fn into_noise(self) -> Result<noise::NoiseResult> {
        match self {
            SourceOutcome::Noise(r) => Ok(r),
            _ => Err(SpectrumError::EntropyExtractionFailed),
        }
    }
    fn into_chaos(self) -> Result<chaos::ChaosResult> {
        match self {
            SourceOutcome::Chaos(r) => Ok(r),
            _ => Err(SpectrumError::EntropyExtractionFailed),
        }
    }
    fn into_quantum_density(self) -> Result<quantum_density::QuantumDensityResult> {
        match self {
            SourceOutcome::QuantumDensity(r) => Ok(r),
            _ => Err(SpectrumError::EntropyExtractionFailed),
        }
    }
    fn into_coupled_map_lattice(self) -> Result<coupled_map_lattice::CoupledMapLatticeResult> {
        match self {
            SourceOutcome::CoupledMapLattice(r) => Ok(r),
            _ => Err(SpectrumError::EntropyExtractionFailed),
        }
    }
    fn into_fractal_aware(self) -> Result<FractalAwareResult> {
        match self {
            SourceOutcome::FractalAware(r) => Ok(r),
            _ => Err(SpectrumError::EntropyExtractionFailed),
        }
    }
}

/// Configures and runs the eleven entropy sources over an image.
#[derive(Debug, Clone, Default)]
pub struct EntropyEngine {
    pub config: EntropyEngineConfig,
}

impl EntropyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: EntropyEngineConfig) -> Self {
        EntropyEngine { config }
    }

    /// Extract all enabled entropy sources from an image, in parallel.
    pub fn analyze_image(&self, img: &Image) -> Result<Analysis> {
        // Analyze on a bounded working resolution to keep entropy extraction
        // fast (<200ms) while retaining sufficient fine detail for the key.
        let work = img.downsample_to_max(160);
        let adaptive = analyze(&work);
        let bucket = adaptive.bucket();

        // Adaptive per-source configuration.
        let mut wtmm_config = wtmm::WtmmConfig::auto_detect(bucket);
        let mut lacunarity_config =
            LacunarityConfig::auto_detect(adaptive.pixel_density, adaptive.cluster_presence);

        let cfg = &self.config;

        // The static config knobs bound the adaptive choices. Defaults are
        // no-ops (floor 1, cap 256, cap 128 steps, and the full scale
        // universe for lacunarity), so out of the box the derivation is
        // identical to the purely adaptive path — but the knobs now take
        // real effect instead of being dead config fields.
        wtmm_config.min_scale = wtmm_config.min_scale.max(cfg.wtmm_min_scale.max(1));
        wtmm_config.max_scale = wtmm_config
            .max_scale
            .min(cfg.wtmm_max_scale.max(wtmm_config.min_scale));
        wtmm_config.num_scales = wtmm_config.num_scales.min(cfg.wtmm_num_scales.max(2));
        if !cfg.lacunarity_scales.is_empty() {
            lacunarity_config
                .scales
                .retain(|s| cfg.lacunarity_scales.contains(s));
            if lacunarity_config.scales.is_empty() {
                return Err(SpectrumError::InvalidConfiguration(
                    "lacunarity_scales excludes every scale the adaptive detector can select"
                        .into(),
                ));
            }
        }

        let outcomes = (0..11)
            .into_par_iter()
            .map(|i| match i {
                0 => Ok(SourceOutcome::Wtmm(if cfg.wtmm_enabled {
                    wtmm::extract_wtmm(&work, &wtmm_config)?
                } else {
                    wtmm::WtmmResult {
                        values: vec![],
                        singularity_spectrum: vec![],
                        tau_exponents: vec![],
                        q_values: vec![],
                        config: wtmm_config.clone(),
                        entropy_bits: 0.0,
                    }
                })),

                1 => Ok(SourceOutcome::Lacunarity(if cfg.lacunarity_enabled {
                    lacunarity::extract_lacunarity(&work, &lacunarity_config)?
                } else {
                    lacunarity::LacunarityResult {
                        values: vec![],
                        config: lacunarity_config.clone(),
                        entropy_bits: 0.0,
                    }
                })),

                2 => Ok(SourceOutcome::Multifractal(if cfg.multifractal_enabled {
                    multifractal::extract_multifractal(&work, &cfg.multifractal_q_values)?
                } else {
                    multifractal::MultifractalResult {
                        values: vec![],
                        entropy_bits: 0.0,
                    }
                })),

                3 => Ok(SourceOutcome::Hurst(if cfg.hurst_enabled {
                    hurst::extract_hurst(&work)?
                } else {
                    hurst::HurstResult {
                        value: 0.5,
                        value_variance_time: 0.5,
                        disagreement: 0.0,
                        entropy_bits: 0.0,
                    }
                })),

                4 => Ok(SourceOutcome::Gradient(if cfg.gradient_enabled {
                    gradient::extract_gradient_entropy(&work, cfg.gradient_bins)?
                } else {
                    gradient::GradientResult {
                        value: 0.0,
                        directional: vec![0.0; 8],
                        entropy_bits: 0.0,
                    }
                })),

                5 => Ok(SourceOutcome::Texture(if cfg.texture_enabled {
                    texture::extract_texture_features(
                        &work,
                        &cfg.texture_orientations_deg,
                        &cfg.texture_frequencies,
                    )?
                } else {
                    texture::TextureResult {
                        values: vec![],
                        orientation_profile: vec![0.0; cfg.texture_orientations_deg.len()],
                        entropy_bits: 0.0,
                    }
                })),

                6 => Ok(SourceOutcome::Noise(if cfg.noise_enabled {
                    noise::extract_noise_characteristics(&work)?
                } else {
                    noise::NoiseResult {
                        profile: noise::NoiseProfile {
                            noise_type: noise::NoiseType::None,
                            magnitude: 0.0,
                        },
                        block_stats: (0.0, 0.0),
                        entropy_bits: 0.0,
                    }
                })),

                7 => Ok(SourceOutcome::Chaos(if cfg.chaos_enabled {
                    chaos::extract_chaos(&work, &cfg.chaos_config)?
                } else {
                    chaos::ChaosResult {
                        signature: [0u8; chaos::SIGNATURE_LEN],
                        orbit_entropy: 0.0,
                        config: cfg.chaos_config.clone(),
                        entropy_bits: 0.0,
                    }
                })),

                8 => Ok(SourceOutcome::QuantumDensity(
                    if cfg.quantum_density_enabled {
                        quantum_density::extract_quantum_density(
                            &work,
                            &cfg.quantum_density_config,
                        )?
                    } else {
                        quantum_density::QuantumDensityResult {
                            signature: [0u8; quantum_density::SIGNATURE_LEN],
                            hilbert_dimension: cfg.quantum_density_config.hilbert_dimension,
                            block_count: 0,
                            entropy_bits: 0.0,
                            config: cfg.quantum_density_config.clone(),
                        }
                    },
                )),

                9 => Ok(SourceOutcome::CoupledMapLattice(
                    if cfg.coupled_map_lattice_enabled {
                        coupled_map_lattice::extract_coupled_map_lattice(
                            &work,
                            &cfg.coupled_map_lattice_config,
                        )?
                    } else {
                        coupled_map_lattice::CoupledMapLatticeResult {
                            signature: [0u8; coupled_map_lattice::DUAL_SIGNATURE_LEN],
                            final_shannon_bits: 0.0,
                            cumulative_kl_bits: 0.0,
                            entropy_bits: 0.0,
                            config: cfg.coupled_map_lattice_config.clone(),
                        }
                    },
                )),

                _ => Ok(SourceOutcome::FractalAware(if cfg.fractal_aware_enabled {
                    fractal_analysis::extract_fractal_aware(&work, &cfg.fractal_aware_config)?
                } else {
                    FractalAwareResult {
                        signature: [0u8; fractal_analysis::SIGNATURE_LEN],
                        values: vec![],
                        classification: FractalClassification::regular_default(),
                        multifractal_width: 0.0,
                        entropy_bits: 0.0,
                        config: cfg.fractal_aware_config.clone(),
                    }
                })),
            })
            .collect::<Result<Vec<SourceOutcome>>>()?;

        // Fold the ordered outcomes into a profile. Index order is fixed by the
        // parallel iterator, so this is identical to the sequential path; the
        // Result plumbing keeps a (logically impossible) order mismatch a
        // recoverable error instead of a panic.
        let mut it = outcomes.into_iter();
        let profile = EntropyProfile {
            wtmm: it
                .next()
                .ok_or(SpectrumError::EntropyExtractionFailed)?
                .into_wtmm()?,
            lacunarity: it
                .next()
                .ok_or(SpectrumError::EntropyExtractionFailed)?
                .into_lacunarity()?,
            multifractal: it
                .next()
                .ok_or(SpectrumError::EntropyExtractionFailed)?
                .into_multifractal()?,
            hurst: it
                .next()
                .ok_or(SpectrumError::EntropyExtractionFailed)?
                .into_hurst()?,
            gradient: it
                .next()
                .ok_or(SpectrumError::EntropyExtractionFailed)?
                .into_gradient()?,
            texture: it
                .next()
                .ok_or(SpectrumError::EntropyExtractionFailed)?
                .into_texture()?,
            noise: it
                .next()
                .ok_or(SpectrumError::EntropyExtractionFailed)?
                .into_noise()?,
            chaos: it
                .next()
                .ok_or(SpectrumError::EntropyExtractionFailed)?
                .into_chaos()?,
            quantum_density: it
                .next()
                .ok_or(SpectrumError::EntropyExtractionFailed)?
                .into_quantum_density()?,
            coupled_map_lattice: it
                .next()
                .ok_or(SpectrumError::EntropyExtractionFailed)?
                .into_coupled_map_lattice()?,
            fractal_aware: it
                .next()
                .ok_or(SpectrumError::EntropyExtractionFailed)?
                .into_fractal_aware()?,
        };
        Ok(Analysis {
            profile,
            adaptive,
            wtmm_config,
            lacunarity_config,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_image() -> Image {
        let pixels: Vec<u8> = (0..128 * 128).map(|i| (i * 11 % 256) as u8).collect();
        Image::from_luma(128, 128, pixels).unwrap()
    }

    #[test]
    fn runs_all_sources_deterministically() {
        let e = EntropyEngine::new();
        let a = e.analyze_image(&sample_image()).unwrap();
        let b = e.analyze_image(&sample_image()).unwrap();
        assert_eq!(a.profile.total_entropy(), b.profile.total_entropy());
        assert!(a.profile.total_entropy() > 0.0);
    }

    #[test]
    fn default_config_is_a_noop_on_the_adaptive_choices() {
        // With the shipped defaults the knobs must not alter what the
        // adaptive detector picks — keys stay identical to the purely
        // adaptive path.
        let e = EntropyEngine::new();
        let a = e.analyze_image(&sample_image()).unwrap();
        let pure_wtmm = WtmmConfig::auto_detect(a.adaptive.bucket());
        assert_eq!(a.wtmm_config.min_scale, pure_wtmm.min_scale);
        assert_eq!(a.wtmm_config.max_scale, pure_wtmm.max_scale);
        assert_eq!(a.wtmm_config.num_scales, pure_wtmm.num_scales);
        let pure_lac =
            LacunarityConfig::auto_detect(a.adaptive.pixel_density, a.adaptive.cluster_presence);
        assert_eq!(a.lacunarity_config.scales, pure_lac.scales);
    }

    #[test]
    fn wtmm_and_lacunarity_knobs_take_effect() {
        // The knobs used to be dead: the engine ignored them entirely.
        let c = EntropyEngineConfig {
            wtmm_max_scale: 16,
            wtmm_num_scales: 8,
            lacunarity_scales: vec![2, 4],
            ..EntropyEngineConfig::default()
        };
        let e = EntropyEngine::with_config(c);
        let a = e.analyze_image(&sample_image()).unwrap();
        assert!(
            a.wtmm_config.max_scale <= 16,
            "got {}",
            a.wtmm_config.max_scale
        );
        assert!(
            a.wtmm_config.num_scales <= 8,
            "got {}",
            a.wtmm_config.num_scales
        );
        assert!(!a.lacunarity_config.scales.is_empty());
        assert!(
            a.lacunarity_config
                .scales
                .iter()
                .all(|s| *s == 2 || *s == 4),
            "got {:?}",
            a.lacunarity_config.scales
        );
    }

    #[test]
    fn disabled_sources_yield_zero() {
        let c = EntropyEngineConfig {
            wtmm_enabled: false,
            ..EntropyEngineConfig::default()
        };
        let e = EntropyEngine::with_config(c);
        let a = e.analyze_image(&sample_image()).unwrap();
        assert_eq!(a.profile.wtmm.entropy_bits, 0.0);
        assert!(a.profile.total_entropy() > 0.0);
    }

    #[test]
    fn wakes_all_sources() {
        let c = EntropyEngineConfig {
            gradient_enabled: false,
            texture_enabled: false,
            ..EntropyEngineConfig::default()
        };
        let e = EntropyEngine::with_config(c);
        let a = e.analyze_image(&sample_image()).unwrap();
        assert_eq!(a.profile.gradient.entropy_bits, 0.0);
        assert_eq!(a.profile.texture.entropy_bits, 0.0);
    }
}
