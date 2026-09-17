//! Deterministic mixing of per-source bytes using the strategy's source order
//! and weights. The output byte sequence is the XOF pre-image that the
//! key-derivation layer collapses with SHAKE256 into the 1072-bit master key.

use crate::entropy_engine::strategy::Strategy;
use crate::error::Result;

/// Interleave + weight-normalize an already-joined normalized byte vector.
///
/// `normalized` is produced by
/// [`ConversionPipeline::normalize`](crate::key_derivation::conversion::ConversionPipeline)
/// as a round-robin interleave of every source's bytes. Here we carve it into
/// contiguous spans proportional to each source's weight, preserving the global
/// ordering established by `strategy.sources`.
pub fn create_byte_sequence(normalized: &[u8], strategy: &Strategy) -> Result<Vec<u8>> {
    if normalized.is_empty() {
        return crate::error::bad("cannot create byte sequence from empty input");
    }

    let n = normalized.len();
    let k = strategy.sources.len().max(1);
    let mut result = Vec::with_capacity(n);

    // Cumulative weight boundaries in [0, 1]. `Strategy` has public fields, so
    // a caller may pass fewer weights than sources (or none); missing
    // boundaries mean "no span" rather than an out-of-bounds panic.
    let mut cum = 0.0f64;
    let mut cuts: Vec<f64> = Vec::with_capacity(k + 1);
    cuts.push(0.0);
    for w in &strategy.weights {
        cum += w;
        cuts.push(cum);
    }
    let cut = |i: usize| cuts.get(i).copied().unwrap_or(1.0);

    for idx in 0..k {
        let lo = (cut(idx).clamp(0.0, 1.0) * n as f64).round() as usize;
        let hi = (cut(idx + 1).clamp(0.0, 1.0) * n as f64).round() as usize;
        let lo = lo.min(n);
        let hi = hi.min(n).max(lo);
        result.extend_from_slice(&normalized[lo..hi]);
    }

    // Append a strategy tag so the same image with different-but-rare
    // strategies still diverges immediately.
    result.push(strategy.name.as_str().as_bytes()[0]);
    result.extend_from_slice(strategy.version.to_le_bytes().as_slice());

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy_engine::sources::EntropySource;
    use crate::entropy_engine::strategy::{Strategy, StrategyName};

    fn sample_strategy() -> Strategy {
        Strategy {
            name: StrategyName::Balanced,
            sources: vec![
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
            ],
            weights: vec![1.0 / 11.0; 11],
            version: 1,
        }
    }

    #[test]
    fn mismatched_weights_do_not_panic() {
        let mut s = sample_strategy();
        s.weights = vec![0.5]; // fewer weights than sources
        let input = vec![9u8; 64];
        let out = create_byte_sequence(&input, &s).unwrap();
        // All bytes must still be accounted for exactly once.
        assert_eq!(out[..64], input[..]);
    }

    #[test]
    fn deterministic_and_nonempty() {
        let s = sample_strategy();
        let input = vec![7u8; 64];
        let a = create_byte_sequence(&input, &s).unwrap();
        let b = create_byte_sequence(&input, &s).unwrap();
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }
}
