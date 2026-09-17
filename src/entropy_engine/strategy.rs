//! Deterministic strategy selection: ranks sources by entropy contribution and
//! assigns normalized weights. Same image ⇒ same strategy.

use serde::{Deserialize, Serialize};

use crate::entropy_engine::sources::{EntropyProfile, EntropySource};
use crate::types::STRATEGY_VERSION;

/// Strategy archetype, chosen entirely from the entropy profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StrategyName {
    WtmmPrimary,
    LacunarityPrimary,
    Balanced,
    TextureHeavy,
    NoiseAdaptive,
}

impl StrategyName {
    /// Stable short identifier used in CLI/metadata output.
    pub fn as_str(&self) -> &'static str {
        match self {
            StrategyName::WtmmPrimary => "WTMM_PRIMARY",
            StrategyName::LacunarityPrimary => "LACUNARITY_PRIMARY",
            StrategyName::Balanced => "BALANCED",
            StrategyName::TextureHeavy => "TEXTURE_HEAVY",
            StrategyName::NoiseAdaptive => "NOISE_ADAPTIVE",
        }
    }
}

/// How to combine the eleven sources for one key derivation.
#[derive(Debug, Clone)]
pub struct Strategy {
    pub name: StrategyName,
    /// Sources ordered from most to least weighted.
    pub sources: Vec<EntropySource>,
    /// Weights aligned with `sources`, summing to 1.
    pub weights: Vec<f64>,
    pub version: u32,
}

impl Strategy {
    /// Deterministic strategy for a given entropy profile.
    pub fn determine(profile: &EntropyProfile) -> Self {
        let entropy: Vec<f64> = EntropySource::all()
            .iter()
            .map(|s| profile.entropy_of(*s))
            .collect();
        let total: f64 = entropy.iter().sum();

        let name = if !total.is_finite() || total <= 0.0 {
            StrategyName::Balanced
        } else if entropy[0] > total * 0.4 {
            StrategyName::WtmmPrimary
        } else if entropy[1] > total * 0.4 {
            StrategyName::LacunarityPrimary
        } else if entropy[5] > total * 0.3 {
            StrategyName::TextureHeavy
        } else if entropy[6] > 5.0 {
            StrategyName::NoiseAdaptive
        } else {
            StrategyName::Balanced
        };

        let weights: Vec<f64> = if total <= 0.0 {
            vec![1.0 / 11.0; 11]
        } else {
            entropy.iter().map(|&e| e / total).collect()
        };

        // Sources descending by weight (stable tie-break by canonical index).
        let mut indexed: Vec<(usize, f64)> =
            weights.iter().enumerate().map(|(i, w)| (i, *w)).collect();
        indexed.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.0.cmp(&b.0))
        });

        let sources: Vec<EntropySource> = indexed
            .iter()
            .map(|(i, _)| EntropySource::all()[*i])
            .collect();
        let sorted_weights: Vec<f64> = indexed.iter().map(|(_, w)| *w).collect();

        Strategy {
            name,
            sources,
            weights: sorted_weights,
            version: STRATEGY_VERSION,
        }
    }

    /// Name of each ordered source (for metadata).
    pub fn source_names(&self) -> Vec<String> {
        self.sources.iter().map(|s| s.name().to_string()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile_with(weights: [f64; 11]) -> EntropyProfile {
        use crate::entropy_engine::sources::fractal_analysis::{
            FractalAwareConfig, FractalAwareResult, FractalClassification,
        };
        use crate::entropy_engine::sources::lacunarity::LacunarityConfig;
        use crate::entropy_engine::sources::{
            ChaosConfig, ChaosResult, CoupledMapLatticeConfig, CoupledMapLatticeResult,
            GradientResult, HurstResult, LacunarityResult, MultifractalResult, NoiseProfile,
            NoiseResult, QuantumDensityConfig, QuantumDensityResult, TextureResult, WtmmConfig,
            WtmmResult,
        };
        EntropyProfile {
            wtmm: WtmmResult {
                values: vec![],
                singularity_spectrum: vec![],
                tau_exponents: vec![],
                q_values: vec![],
                config: WtmmConfig::new(
                    1,
                    2,
                    2,
                    crate::entropy_engine::sources::wtmm::WaveletType::MexicanHat,
                ),
                entropy_bits: weights[0],
            },
            lacunarity: LacunarityResult {
                values: vec![],
                config: LacunarityConfig::new(
                    vec![2],
                    crate::entropy_engine::sources::lacunarity::LacunarityAlgorithm::BoxCounting,
                ),
                entropy_bits: weights[1],
            },
            multifractal: MultifractalResult {
                values: vec![],
                entropy_bits: weights[2],
            },
            hurst: HurstResult {
                value: 0.5,
                value_variance_time: 0.5,
                disagreement: 0.0,
                entropy_bits: weights[3],
            },
            gradient: GradientResult {
                value: 0.0,
                directional: vec![0.0; 8],
                entropy_bits: weights[4],
            },
            texture: TextureResult {
                values: vec![],
                orientation_profile: vec![0.0; 4],
                entropy_bits: weights[5],
            },
            noise: NoiseResult {
                profile: NoiseProfile {
                    noise_type: crate::entropy_engine::sources::NoiseType::None,
                    magnitude: 0.0,
                },
                block_stats: (0.0, 0.0),
                entropy_bits: weights[6],
            },
            chaos: ChaosResult {
                signature: [0u8; 32],
                orbit_entropy: 0.0,
                config: ChaosConfig::default(),
                entropy_bits: weights[7],
            },
            quantum_density: QuantumDensityResult {
                signature: [0u8; 32],
                hilbert_dimension: 16,
                block_count: 0,
                entropy_bits: weights[8],
                config: QuantumDensityConfig::default(),
            },
            coupled_map_lattice: CoupledMapLatticeResult {
                signature: [0u8; 64],
                final_shannon_bits: 0.0,
                cumulative_kl_bits: 0.0,
                entropy_bits: weights[9],
                config: CoupledMapLatticeConfig::default(),
            },
            fractal_aware: FractalAwareResult {
                signature: [0u8; 32],
                values: vec![],
                classification: FractalClassification::regular_default(),
                multifractal_width: 0.0,
                entropy_bits: weights[10],
                config: FractalAwareConfig::default(),
            },
        }
    }

    #[test]
    fn weights_sum_to_one() {
        let p = profile_with([2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0, 2.0]);
        let s = Strategy::determine(&p);
        let sum: f64 = s.weights.iter().sum();
        assert!((sum - 1.0).abs() < 1e-9);
        assert_eq!(s.sources.len(), 11);
        assert!(matches!(s.name, StrategyName::Balanced));
    }

    #[test]
    fn wtmm_heavy_is_detected() {
        let p = profile_with([10.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0]);
        let s = Strategy::determine(&p);
        assert!(matches!(s.name, StrategyName::WtmmPrimary));
    }
}
