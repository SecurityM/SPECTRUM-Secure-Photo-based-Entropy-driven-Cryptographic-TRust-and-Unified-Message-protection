//! Normalizes per-source entropy values into `\[0, 255]` bytes using fixed,
//! empirically-derived ranges, interleaving them round-robin so every source
//! contributes uniformly before the weighted mixer step.

use crate::entropy_engine::sources::EntropyProfile;
use crate::entropy_engine::strategy::Strategy;

/// Fixed normalization ranges per source.
#[derive(Debug, Clone)]
pub struct NormalizationRanges {
    pub wtmm_range: (f64, f64),
    pub lacunarity_range: (f64, f64),
    pub multifractal_range: (f64, f64),
    pub hurst_range: (f64, f64),
    pub gradient_range: (f64, f64),
    pub texture_range: (f64, f64),
    pub noise_range: (f64, f64),
    pub chaos_range: (f64, f64),
    pub qdm_range: (f64, f64),
    pub cml_range: (f64, f64),
    // FractalAware metric bytes: measured box-counting dimension [1, 2],
    // multifractal spectrum width, and classification confidence [0, 1].
    pub fractal_dim_range: (f64, f64),
    pub fractal_width_range: (f64, f64),
    pub fractal_confidence_range: (f64, f64),
}

impl Default for NormalizationRanges {
    fn default() -> Self {
        NormalizationRanges {
            wtmm_range: (0.0, 2.5),
            lacunarity_range: (0.5, 3.5),
            multifractal_range: (0.0, 1.0),
            hurst_range: (0.1, 0.9),
            gradient_range: (0.0, 8.0),
            texture_range: (0.0, 1.0),
            noise_range: (0.0, 0.5),
            chaos_range: (0.0, 8.0),
            // Accumulated Von Neumann entropy of the QuantumDensityMatrix
            // source: at the default d=16 and ≤160² working resolution the
            // real total stays well below this cap.
            qdm_range: (0.0, 512.0),
            // Spectral Shannon + cumulative KL terms of the CoupledMapLattice
            // source; the cap only guards pathological lattice sizes.
            cml_range: (0.0, 8192.0),
            fractal_dim_range: (1.0, 2.0),
            fractal_width_range: (0.0, 1.5),
            fractal_confidence_range: (0.0, 1.0),
        }
    }
}

/// Converts an entropy profile + strategy into a normalized byte vector.
#[derive(Debug, Clone, Default)]
pub struct ConversionPipeline {
    pub ranges: NormalizationRanges,
}

impl ConversionPipeline {
    pub fn new() -> Self {
        Self::default()
    }

    fn to_byte(&self, value: f64, (min, max): (f64, f64)) -> u8 {
        // Defensive: `NormalizationRanges` has public fields, so an inverted
        // range must not panic the process (f64::clamp asserts min <= max).
        // Swapping is deterministic and maps an inverted range to itself
        // reversed; a NaN input normalizes to 0 exactly as the saturating
        // cast did before.
        let (min, max) = if min <= max { (min, max) } else { (max, min) };
        let clamped = if value.is_nan() {
            min
        } else {
            value.clamp(min, max)
        };
        let norm = if max - min <= 1e-12 {
            0.5
        } else {
            (clamped - min) / (max - min)
        };
        (norm.clamp(0.0, 1.0) * 255.0).round() as u8
    }

    /// Build the interleaved normalized byte vector. Ordering is fully
    /// deterministic given the same profile + strategy.
    pub fn normalize(&self, profile: &EntropyProfile, _strategy: &Strategy) -> Vec<u8> {
        let max_iter = [
            profile.wtmm.values.len(),
            profile.lacunarity.values.len(),
            profile.multifractal.values.len(),
            profile.texture.values.len(),
        ]
        .iter()
        .cloned()
        .max()
        .unwrap_or(0);

        let mut result = Vec::new();

        for i in 0..max_iter {
            if let Some(v) = profile.wtmm.values.get(i) {
                result.push(self.to_byte(*v, self.ranges.wtmm_range));
            }
            if let Some(v) = profile.lacunarity.values.get(i) {
                result.push(self.to_byte(*v, self.ranges.lacunarity_range));
            }
            if let Some(v) = profile.multifractal.values.get(i) {
                result.push(self.to_byte(*v, self.ranges.multifractal_range));
            }
            if let Some(v) = profile.texture.values.get(i) {
                result.push(self.to_byte(*v, self.ranges.texture_range));
            }
        }

        // Directional gradient energy (8 bins) — appended once, in order.
        for v in &profile.gradient.directional {
            result.push(self.to_byte(*v, self.ranges.gradient_range));
        }
        // Per-orientation Gabor energy — appended once, in order.
        for v in &profile.texture.orientation_profile {
            result.push(self.to_byte(*v, self.ranges.texture_range));
        }

        // Scalars contribute exactly one byte each.
        result.push(self.to_byte(profile.hurst.value, self.ranges.hurst_range));
        // Second Hurst estimator (variance-time) and the disagreement between
        // the two estimates add independent persistence information.
        result.push(self.to_byte(profile.hurst.value_variance_time, self.ranges.hurst_range));
        result.push(self.to_byte(profile.hurst.disagreement, self.ranges.hurst_range));
        result.push(self.to_byte(profile.gradient.value, self.ranges.gradient_range));

        // Noise contributes (type, magnitude) plus the block-stats pair.
        result.extend_from_slice(&profile.noise.profile.to_bytes());
        result.push(self.to_byte(profile.noise.block_stats.0, self.ranges.noise_range));
        result.push(self.to_byte(profile.noise.block_stats.1, self.ranges.noise_range));

        // Chaos contributes its raw 32-byte Ascon-Hash256 signature — already
        // uniform, full-entropy key material — followed by one byte that
        // summarizes the orbit's byte distribution.
        result.extend_from_slice(&profile.chaos.signature);
        result.push(self.to_byte(profile.chaos.orbit_entropy, self.ranges.chaos_range));

        // QuantumDensityMatrix contributes its raw 32-byte Ascon-Hash256
        // signature plus one byte encoding the accumulated Von Neumann
        // entropy.
        result.extend_from_slice(&profile.quantum_density.signature);
        result.push(self.to_byte(profile.quantum_density.entropy_bits, self.ranges.qdm_range));

        // CoupledMapLattice contributes its raw 64-byte dual Ascon-Hash256
        // signature (mid ‖ final states) plus one byte per real metric: the
        // spectral Shannon entropy and the cumulative KL divergence.
        result.extend_from_slice(&profile.coupled_map_lattice.signature);
        result.push(self.to_byte(
            profile.coupled_map_lattice.final_shannon_bits,
            self.ranges.cml_range,
        ));
        result.push(self.to_byte(
            profile.coupled_map_lattice.cumulative_kl_bits,
            self.ranges.cml_range,
        ));

        // FractalAware contributes its raw 32-byte Ascon-Hash256 signature of
        // the adaptive feature pool, followed by three real metric bytes: the
        // measured box-counting dimension, the multifractal spectrum width
        // and the classification confidence.
        result.extend_from_slice(&profile.fractal_aware.signature);
        result.push(self.to_byte(
            profile.fractal_aware.classification.hausdorff_dimension,
            self.ranges.fractal_dim_range,
        ));
        result.push(self.to_byte(
            profile.fractal_aware.multifractal_width,
            self.ranges.fractal_width_range,
        ));
        result.push(self.to_byte(
            profile.fractal_aware.classification.confidence,
            self.ranges.fractal_confidence_range,
        ));

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_respects_byte_range() {
        let pipeline = ConversionPipeline::new();
        let b_min = pipeline.to_byte(f64::NEG_INFINITY, (0.0, 1.0));
        let b_max = pipeline.to_byte(f64::INFINITY, (0.0, 1.0));
        assert_eq!(b_min, 0);
        assert_eq!(b_max, 255);
    }

    fn fixture_profile() -> EntropyProfile {
        use crate::entropy_engine::sources::fractal_analysis::{
            FractalAwareConfig, FractalAwareResult, FractalClassification, FractalType,
        };
        use crate::entropy_engine::sources::wtmm::WtmmConfig;
        EntropyProfile {
            wtmm: crate::entropy_engine::sources::WtmmResult {
                values: vec![1.0],
                singularity_spectrum: vec![],
                tau_exponents: vec![],
                q_values: vec![],
                config: WtmmConfig::new(1, 8, 4, crate::filter::Wavelet::Morlet),
                entropy_bits: 8.0,
            },
            lacunarity: crate::entropy_engine::sources::LacunarityResult {
                values: vec![1.0],
                config: crate::entropy_engine::sources::LacunarityConfig::new(
                    vec![2],
                    crate::entropy_engine::sources::lacunarity::LacunarityAlgorithm::BoxCounting,
                ),
                entropy_bits: 4.0,
            },
            multifractal: crate::entropy_engine::sources::MultifractalResult {
                values: vec![0.5],
                entropy_bits: 4.0,
            },
            hurst: crate::entropy_engine::sources::HurstResult {
                value: 0.7,
                value_variance_time: 0.3,
                disagreement: 0.4,
                entropy_bits: 12.0,
            },
            gradient: crate::entropy_engine::sources::GradientResult {
                value: 2.0,
                directional: vec![],
                entropy_bits: 6.0,
            },
            texture: crate::entropy_engine::sources::TextureResult {
                values: vec![],
                orientation_profile: vec![],
                entropy_bits: 4.0,
            },
            noise: crate::entropy_engine::sources::NoiseResult {
                profile: crate::entropy_engine::sources::NoiseProfile {
                    noise_type: crate::entropy_engine::sources::NoiseType::Gaussian,
                    magnitude: 0.1,
                },
                block_stats: (0.1, 0.1),
                entropy_bits: 2.0,
            },
            chaos: crate::entropy_engine::sources::ChaosResult {
                signature: [7u8; 32],
                orbit_entropy: 7.5,
                config: crate::entropy_engine::sources::ChaosConfig::default(),
                entropy_bits: 9.0,
            },
            quantum_density: crate::entropy_engine::sources::QuantumDensityResult {
                signature: [8u8; 32],
                hilbert_dimension: 16,
                block_count: 100,
                entropy_bits: 300.0,
                config: crate::entropy_engine::sources::QuantumDensityConfig::default(),
            },
            coupled_map_lattice: crate::entropy_engine::sources::CoupledMapLatticeResult {
                signature: [9u8; 64],
                final_shannon_bits: 500.0,
                cumulative_kl_bits: 40.0,
                entropy_bits: 540.0,
                config: crate::entropy_engine::sources::CoupledMapLatticeConfig::default(),
            },
            fractal_aware: FractalAwareResult {
                signature: [3u8; 32],
                values: vec![],
                classification: FractalClassification {
                    fractal_type: FractalType::MandelbrotBoundary,
                    hausdorff_dimension: 1.9,
                    confidence: 0.7,
                    is_self_similar: true,
                    multifractal_width: 0.6,
                    log_log_r2: 0.99,
                    edge_fraction: 0.05,
                },
                multifractal_width: 0.8,
                entropy_bits: 7.5,
                config: FractalAwareConfig::default(),
            },
        }
    }

    #[test]
    fn hurst_fields_are_encoded() {
        let profile = fixture_profile();
        let strategy = Strategy::determine(&profile);
        let bytes = ConversionPipeline::new().normalize(&profile, &strategy);

        // Trailing layout (fixed order): ... scalars (hurst-rs, hurst-vt,
        // disagreement, gradient) | noise (4) | chaos (33) | qdm (33)
        // | cml (66) | fractal-aware (32 + 3).
        const NOISE_BYTES: usize = 4;
        const CHAOS_BYTES: usize = 32 + 1;
        const QDM_BYTES: usize = 32 + 1;
        const CML_BYTES: usize = 64 + 2;
        const FA_BYTES: usize = 32 + 3;
        let scalars_start =
            bytes.len() - NOISE_BYTES - CHAOS_BYTES - QDM_BYTES - CML_BYTES - FA_BYTES - 4;
        // VT ≠ RS must produce distinct bytes for a 0.7/0.3 split under the
        // (0.1, 0.9) range.
        assert_ne!(
            bytes[scalars_start],
            bytes[scalars_start + 1],
            "two estimators must encode differently"
        );
        // The Chaos signature travels verbatim into the byte sequence.
        let chaos_start = bytes.len() - CHAOS_BYTES - QDM_BYTES - CML_BYTES - FA_BYTES;
        assert_eq!(&bytes[chaos_start..chaos_start + 32], &[7u8; 32]);
        // Chaos orbit-entropy byte (7.5/8.0 * 255 ≈ 239).
        assert_eq!(
            bytes[bytes.len() - QDM_BYTES - CML_BYTES - FA_BYTES - 1],
            239
        );
        // The QuantumDensityMatrix signature + entropy byte.
        let qdm_start = bytes.len() - QDM_BYTES - CML_BYTES - FA_BYTES;
        assert_eq!(&bytes[qdm_start..qdm_start + 32], &[8u8; 32]);
        assert_eq!(bytes[qdm_start + 32], 149); // 300.0/512.0 * 255 ≈ 149

        // The CoupledMapLattice 64-byte dual signature, then its metric bytes.
        let cml_start = bytes.len() - CML_BYTES - FA_BYTES;
        assert_eq!(&bytes[cml_start..cml_start + 64], &[9u8; 64]);
        assert_eq!(bytes[cml_start + 64], 16); // 500.0/8192.0 * 255 ≈ 16
        assert_eq!(bytes[cml_start + 65], 1); // 40.0/8192.0 * 255 ≈ 1

        // FractalAware closes the sequence: 32-byte signature + dimension,
        // multifractal-width and confidence metric bytes (bounds asserted to
        // stay robust against float rounding at range edges).
        let fa_start = bytes.len() - FA_BYTES;
        assert_eq!(&bytes[fa_start..fa_start + 32], &[3u8; 32]);
        let dim = bytes[fa_start + 32];
        let width = bytes[fa_start + 33];
        let conf = bytes[fa_start + 34];
        assert!((100..=255).contains(&dim), "dimension byte: {dim}");
        assert!((125..=150).contains(&width), "width byte: {width}");
        assert!((165..=195).contains(&conf), "confidence byte: {conf}");
    }
}
