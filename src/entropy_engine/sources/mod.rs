//! The eleven independent entropy sources.

pub mod chaos;
pub mod coupled_map_lattice;
pub mod fractal_analysis;
pub mod gradient;
pub mod hurst;
pub mod lacunarity;
pub mod multifractal;
pub mod noise;
pub mod quantum_density;
pub mod texture;
pub mod wtmm;

use serde::{Deserialize, Serialize};

pub use chaos::{ChaosConfig, ChaosResult};
pub use coupled_map_lattice::{CoupledMapLatticeConfig, CoupledMapLatticeResult};
pub use fractal_analysis::{FractalAwareConfig, FractalAwareResult, FractalType};
pub use gradient::GradientResult;
pub use hurst::HurstResult;
pub use lacunarity::{LacunarityConfig, LacunarityResult};
pub use multifractal::MultifractalResult;
pub use noise::{NoiseProfile, NoiseResult, NoiseType};
pub use quantum_density::{QuantumDensityConfig, QuantumDensityResult};
pub use texture::TextureResult;
pub use wtmm::{WtmmConfig, WtmmResult};

/// Identifies one of the eleven entropy sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntropySource {
    Wtmm,
    Lacunarity,
    Multifractal,
    Hurst,
    Gradient,
    Texture,
    Noise,
    Chaos,
    QuantumDensity,
    CoupledMapLattice,
    FractalAware,
}

impl EntropySource {
    /// All sources in canonical order.
    pub fn all() -> &'static [EntropySource; 11] {
        &[
            EntropySource::Wtmm,
            EntropySource::Lacunarity,
            EntropySource::Multifractal,
            EntropySource::Hurst,
            EntropySource::Gradient,
            EntropySource::Texture,
            EntropySource::Noise,
            EntropySource::Chaos,
            EntropySource::QuantumDensity,
            EntropySource::CoupledMapLattice,
            EntropySource::FractalAware,
        ]
    }

    /// Canonical name used in strategy metadata.
    pub fn name(&self) -> &'static str {
        match self {
            EntropySource::Wtmm => "WTMM",
            EntropySource::Lacunarity => "Lacunarity",
            EntropySource::Multifractal => "Multifractal",
            EntropySource::Hurst => "Hurst",
            EntropySource::Gradient => "Gradient",
            EntropySource::Texture => "Texture",
            EntropySource::Noise => "Noise",
            EntropySource::Chaos => "Chaos",
            EntropySource::QuantumDensity => "QuantumDensityMatrix",
            EntropySource::CoupledMapLattice => "CoupledMapLattice",
            EntropySource::FractalAware => "FractalAware",
        }
    }
}

/// Shannon entropy (bits) of a value distribution, binning into 256 buckets.
/// Used to gauge each source's contribution to the final key.
pub fn compute_entropy_bits(values: &[f64]) -> f64 {
    if values.len() < 2 || values.iter().all(|v| !v.is_finite()) {
        return 0.0;
    }
    let finite: Vec<f64> = values.iter().cloned().filter(|v| v.is_finite()).collect();
    if finite.is_empty() {
        return 0.0;
    }
    let min = finite.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = finite.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let range = (max - min).max(1e-9);

    let mut hist = vec![0usize; 256];
    for &v in &finite {
        let n = (v - min) / range;
        let idx = ((n * 255.0).round() as usize).clamp(0, 255);
        hist[idx] += 1;
    }
    let total = finite.len() as f64;
    let entropy = -hist
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            p * p.log2()
        })
        .sum::<f64>();
    entropy
}
/// The complete set of entropy analyses for one image.
#[derive(Debug, Clone)]
pub struct EntropyProfile {
    pub wtmm: WtmmResult,
    pub lacunarity: LacunarityResult,
    pub multifractal: MultifractalResult,
    pub hurst: HurstResult,
    pub gradient: GradientResult,
    pub texture: TextureResult,
    pub noise: NoiseResult,
    pub chaos: ChaosResult,
    pub quantum_density: QuantumDensityResult,
    pub coupled_map_lattice: CoupledMapLatticeResult,
    pub fractal_aware: FractalAwareResult,
}

impl EntropyProfile {
    /// Entropy bits contributed by a specific source.
    pub fn entropy_of(&self, source: EntropySource) -> f64 {
        match source {
            EntropySource::Wtmm => self.wtmm.entropy_bits,
            EntropySource::Lacunarity => self.lacunarity.entropy_bits,
            EntropySource::Multifractal => self.multifractal.entropy_bits,
            EntropySource::Hurst => self.hurst.entropy_bits,
            EntropySource::Gradient => self.gradient.entropy_bits,
            EntropySource::Texture => self.texture.entropy_bits,
            EntropySource::Noise => self.noise.entropy_bits,
            EntropySource::Chaos => self.chaos.entropy_bits,
            EntropySource::QuantumDensity => self.quantum_density.entropy_bits,
            EntropySource::CoupledMapLattice => self.coupled_map_lattice.entropy_bits,
            EntropySource::FractalAware => self.fractal_aware.entropy_bits,
        }
    }

    /// Total estimated entropy across all sources.
    pub fn total_entropy(&self) -> f64 {
        EntropySource::all()
            .iter()
            .map(|s| self.entropy_of(*s))
            .sum()
    }
}
