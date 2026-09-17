//! Source 5 — Gradient entropy.
//!
//! Edge energy from a Sobel filter, summarized as (a) the Shannon entropy of
//! the gradient-magnitude histogram and (b) a directional energy profile across
//! eight orientation bins. Both feed the key material.

use crate::error::Result;
use crate::filter::{gradient_orientations, sobel_components, sobel_magnitudes};
use crate::image::Image;

/// Result of the gradient source.
#[derive(Debug, Clone)]
pub struct GradientResult {
    /// Shannon entropy (bits) of the gradient-magnitude histogram.
    pub value: f64,
    /// Normalized energy per each of 8 orientation bins (0..=1 mean brightness).
    pub directional: Vec<f64>,
    pub entropy_bits: f64,
}

/// Compute gradient magnitudes for all interior pixels (normalized [0, 1]).
pub fn gradient_magnitudes(img: &Image) -> Vec<f64> {
    sobel_magnitudes(img)
}

/// Mean gradient magnitude in [0, 1].
pub fn mean_gradient_magnitude(img: &Image) -> f64 {
    let mags = gradient_magnitudes(img);
    if mags.is_empty() {
        0.0
    } else {
        mags.iter().sum::<f64>() / mags.len() as f64
    }
}

/// Histogram Shannon entropy of a set of values, binned into `bins`.
///
/// `bins` comes from public config, so it is floored at 2: with 0 or 1 bins
/// the original `bins - 1` multiplier underflowed and indexed the histogram
/// out of bounds, panicking the whole derivation.
pub fn histogram_entropy(values: &[f64], bins: usize) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let bins = bins.max(2);
    let mut hist = vec![0usize; bins];
    for &v in values {
        let v = v.clamp(0.0, 1.0);
        let idx = ((v * (bins as f64 - 1.0)).round() as usize).min(bins - 1);
        hist[idx] += 1;
    }
    let total = values.len() as f64;
    -hist
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Directional energy profile across 8 orientation bins.
///
/// Bins cover 180° (unsigned orientations): each gradient orientation is folded
/// into [0, π) and assigned to one of 8 bins; the bin value is the mean
/// magnitude of gradients assigned to it. This captures edge *direction*
/// richness that a global magnitude histogram misses.
pub fn directional_energy(img: &Image, bins: usize) -> Vec<f64> {
    let bins = bins.max(2);
    let (gx, gy) = sobel_components(img);
    let mags = sobel_magnitudes(img);
    let ori = gradient_orientations(&mags, &gx, &gy);

    let mut accum = vec![0.0f64; bins];
    let mut count = vec![0usize; bins];
    for (o, m) in ori.iter().zip(mags.iter()) {
        // Fold to [0, π).
        let mut a = *o % std::f64::consts::PI;
        if a < 0.0 {
            a += std::f64::consts::PI;
        }
        let idx = ((a / std::f64::consts::PI) * bins as f64) as usize;
        let idx = idx.min(bins - 1);
        accum[idx] += m;
        count[idx] += 1;
    }

    // Per-bin mean, then normalize the whole profile to [0, 1].
    let mean: Vec<f64> = accum
        .iter()
        .zip(count.iter())
        .map(|(s, c)| if *c > 0 { s / *c as f64 } else { 0.0 })
        .collect();
    let max = mean.iter().cloned().fold(0.0f64, f64::max);
    if max <= 1e-9 {
        mean
    } else {
        mean.iter().map(|v| v / max).collect()
    }
}

/// Extract gradient entropy + directional profile.
pub fn extract_gradient_entropy(img: &Image, bins: usize) -> Result<GradientResult> {
    let mags = gradient_magnitudes(img);
    let value = histogram_entropy(&mags, bins);
    let directional = directional_energy(img, 8);
    let entropy_bits = (value * 3.0).clamp(2.0, 20.0);
    Ok(GradientResult {
        value,
        directional,
        entropy_bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

    #[test]
    fn degenerate_bins_do_not_panic() {
        // bins = 0/1 used to underflow `bins - 1` and index out of bounds.
        // Both are now floored to 2 bins, so they behave identically.
        let values = [0.1f64, 0.9, 0.5, 0.7];
        let zero = histogram_entropy(&values, 0);
        let one = histogram_entropy(&values, 1);
        let two = histogram_entropy(&values, 2);
        assert!(zero > 0.0);
        assert_eq!(zero, one);
        assert_eq!(one, two);
    }

    #[test]
    fn flat_image_zero_gradient_entropy() {
        let img = Image::from_luma(64, 64, vec![128u8; 64 * 64]).unwrap();
        let res = extract_gradient_entropy(&img, 256).unwrap();
        assert_eq!(res.value, 0.0); // single bin → 0 entropy
    }

    #[test]
    fn textured_image_more_entropy() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let mut buf = vec![0u8; 64 * 64];
        rng.fill_bytes(&mut buf);
        let img = Image::from_luma(64, 64, buf).unwrap();
        let res = extract_gradient_entropy(&img, 256).unwrap();
        assert!(res.value > 0.0);
        assert_eq!(res.directional.len(), 8);
        assert!(res.directional.iter().all(|v| (0.0..=1.0).contains(v)));
    }

    #[test]
    fn directional_profile_normalized() {
        // Pure vertical edges (strong in y) concentrate in two bins.
        let mut img = Image::from_luma(48, 48, vec![0u8; 48 * 48]).unwrap();
        for y in 0..48u32 {
            for x in 0..48u32 {
                // left half dark, right half light: vertical edge everywhere.
                img.pixels[(y * 48 + x) as usize] = if x < 24 { 30 } else { 220 };
            }
        }
        let d = directional_energy(&img, 8);
        let sum: f64 = d.iter().sum();
        assert!(sum > 0.0, "a strong edge must register direction energy");
    }
}
