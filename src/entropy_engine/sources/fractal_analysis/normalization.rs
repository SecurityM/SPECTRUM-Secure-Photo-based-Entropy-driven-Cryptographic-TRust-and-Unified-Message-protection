//! Adaptive normalization for the fractal-aware feature pool.
//!
//! The classical fixed-range normalization of [`crate::key_derivation`] is
//! calibrated for *regular* photography; fractal images (Mandelbrot zooms,
//! Julia sets) push the same features to very different magnitudes. This
//! stage derives each feature series' `[min, max]` from the image actually
//! being analyzed, so quantization always spans the observed dynamic range —
//! while remaining a pure, deterministic function of the image (no external
//! calibration state), which keeps key derivation reproducible.

/// A per-series `[min, max]` range discovered from real feature values.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AdaptiveRange {
    pub min: f64,
    pub max: f64,
}

impl AdaptiveRange {
    /// Infer the range from a value series, growing it by a small symmetric
    /// margin so boundary samples never clip. A constant series yields a
    /// degenerate range that maps every value to the neutral byte 128.
    pub fn from_values(values: &[f64]) -> AdaptiveRange {
        let mut min = f64::INFINITY;
        let mut max = f64::NEG_INFINITY;
        for &v in values {
            if v.is_finite() {
                min = min.min(v);
                max = max.max(v);
            }
        }
        if !min.is_finite() || !max.is_finite() {
            return AdaptiveRange { min: 0.0, max: 0.0 };
        }
        if max <= min {
            // Constant series: keep a degenerate range so `normalize` maps
            // every value (in- or out-of-series) to the neutral 0.5 → 128.
            return AdaptiveRange { min, max: min };
        }
        // 2% headroom on each side keeps the observed extrema interior.
        let span = max - min;
        AdaptiveRange {
            min: min - 0.02 * span,
            max: max + 0.02 * span,
        }
    }

    /// Map a value into `[0, 1]`; degenerate ranges return the neutral 0.5.
    pub fn normalize(&self, value: f64) -> f64 {
        if self.max <= self.min {
            return 0.5;
        }
        ((value - self.min) / (self.max - self.min)).clamp(0.0, 1.0)
    }

    /// Quantize a value to a byte in `0..=255`.
    pub fn to_byte(&self, value: f64) -> u8 {
        (self.normalize(value) * 255.0).round().clamp(0.0, 255.0) as u8
    }
}

/// Stateless adaptive normalizer: discovers ranges and quantizes series.
///
/// Kept as a struct (matching the project's engine style) but carries no
/// mutable state, so instances are freely shareable across threads.
#[derive(Debug, Clone, Default)]
pub struct AdaptiveNormalizer;

impl AdaptiveNormalizer {
    pub fn new() -> Self {
        AdaptiveNormalizer
    }

    /// Quantize a whole series using its own inferred range.
    pub fn bytes_for(&self, values: &[f64]) -> Vec<u8> {
        let range = AdaptiveRange::from_values(values);
        values.iter().map(|&v| range.to_byte(v)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_range_spans_observed_values() {
        let range = AdaptiveRange::from_values(&[0.1, 0.9]);
        assert!(range.to_byte(0.1) > 0);
        assert!(range.to_byte(0.9) < 255);
        // Monotone: larger input → larger byte.
        assert!(range.to_byte(0.9) > range.to_byte(0.1));
    }

    #[test]
    fn constant_series_maps_to_neutral_byte() {
        let range = AdaptiveRange::from_values(&[0.42, 0.42, 0.42]);
        assert_eq!(range.to_byte(0.42), 128);
        // Out-of-range values still normalize through the degenerate range.
        assert_eq!(range.to_byte(1.0), 128);
    }

    #[test]
    fn empty_and_non_finite_series_are_safe() {
        let r1 = AdaptiveRange::from_values(&[]);
        assert_eq!(r1.to_byte(0.5), 128);
        let r2 = AdaptiveRange::from_values(&[f64::NAN, f64::INFINITY]);
        assert_eq!(r2.to_byte(0.5), 128);
    }

    #[test]
    fn series_bytes_are_deterministic_and_bounded() {
        let n = AdaptiveNormalizer::new();
        let vals: Vec<f64> = (0..64).map(|i| (i % 7) as f64 * 0.13).collect();
        let a = n.bytes_for(&vals);
        let b = n.bytes_for(&vals);
        assert_eq!(a, b);
        assert_eq!(a.len(), vals.len());
    }
}
