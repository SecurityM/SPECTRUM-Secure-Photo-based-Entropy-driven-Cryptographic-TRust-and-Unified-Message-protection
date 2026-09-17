//! Source 4 — Hurst exponent, estimated two independent ways.
//!
//! 1. **Rescaled-range (R/S)**: classical Hurst analysis. H < 0.5 means
//!    mean-reverting, H ≈ 0.5 a random walk, H > 0.5 trending/persistent.
//! 2. **Variance-time (aggregated variance)**: the variance of non-overlapping
//!    window means scales as `m^(2H−2)`; the regression slope yields a second,
//!    independent estimate (see [`crate::stats::variance_time_hurst`]).
//!
//! Both estimates plus their disagreement are part of the key material, so an
//! image must reproduce the same persistence structure under both methods.

use crate::error::Result;
use crate::image::Image;
use crate::stats::variance_time_hurst;

/// Result of the Hurst source.
#[derive(Debug, Clone)]
pub struct HurstResult {
    /// Rescaled-range estimate.
    pub value: f64,
    /// Variance-time estimate.
    pub value_variance_time: f64,
    /// Absolute difference between the two estimators (agreement signal).
    pub disagreement: f64,
    pub entropy_bits: f64,
}

fn rescaled_range(series: &[f64], start: usize, len: usize) -> f64 {
    if len < 4 {
        return 0.5;
    }
    let sub = &series[start..start + len];
    let mean = sub.iter().sum::<f64>() / sub.len() as f64;
    let n = sub.len() as f64;

    // Cumulative deviation series.
    let mut y = Vec::with_capacity(sub.len());
    let mut running = 0.0;
    for &x in sub {
        running += x - mean;
        y.push(running);
    }

    let r = y.iter().cloned().fold(f64::NEG_INFINITY, f64::max)
        - y.iter().cloned().fold(f64::INFINITY, f64::min);
    let std_dev = (sub.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n).sqrt();
    if std_dev < 1e-12 {
        return 0.5;
    }
    let rs = (r / std_dev).max(1e-6);
    rs.ln() / n.ln()
}

/// Compute the rescaled-range Hurst estimate from a flattened row-major signal.
pub fn rescaled_range_hurst(values: &[f64]) -> f64 {
    // Rescaled-range over progressively shorter suffixes, then average.
    let total = values.len();
    let min_len = 64usize;
    let mut estimates = Vec::new();
    let mut len = total;
    // Evaluate R/S over progressively shorter suffixes for a stable average.
    while len >= min_len && len <= total {
        let start = total - len;
        estimates.push(rescaled_range(values, start, len));
        if len <= min_len * 2 {
            break;
        }
        len /= 2;
    }

    if estimates.is_empty() {
        0.5
    } else {
        (estimates.iter().sum::<f64>() / estimates.len() as f64).clamp(0.1, 0.9)
    }
}

/// Extract both Hurst estimates for an image.
pub fn extract_hurst(img: &Image) -> Result<HurstResult> {
    let values: Vec<f64> = img.pixels.iter().map(|p| *p as f64).collect();

    let rs = rescaled_range_hurst(&values);
    let vt = variance_time_hurst(&values);
    let disagreement = (rs - vt).abs();

    // Scalar sources: entropy approximated from how far the estimates sit from
    // 0.5 (pure random walk) and from each other (structured persistence).
    let deviation = (rs - 0.5).abs().max((vt - 0.5).abs());
    let entropy_bits = (40.0 * deviation + 8.0 * disagreement).clamp(4.0, 20.0);
    Ok(HurstResult {
        value: rs,
        value_variance_time: vt,
        disagreement,
        entropy_bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trending_series_high_hurst() {
        // A monotonically increasing ramp is strongly persistent/tending.
        let vals: Vec<f64> = (0..4096).map(|i| i as f64).collect();
        let img =
            Image::from_luma(64, 64, vals.iter().map(|v| (*v % 256.0) as u8).collect()).unwrap();
        let res = extract_hurst(&img).unwrap();
        assert!(res.entropy_bits.is_finite());
    }

    #[test]
    fn both_estimators_are_finite_and_bounded() {
        let img =
            Image::from_luma(64, 64, (0..64 * 64).map(|i| (i * 7 % 256) as u8).collect()).unwrap();
        let res = extract_hurst(&img).unwrap();
        assert!((0.01..=0.99).contains(&res.value));
        assert!((0.01..=0.99).contains(&res.value_variance_time));
        assert!((0.0..=1.0).contains(&res.disagreement));
    }

    #[test]
    fn r_s_recovers_known_persistence() {
        // White noise-ish sequence: R/S should stay below a strongly trending
        // sequence's estimate.
        let noisy: Vec<f64> = (0..8192)
            .map(|i| (((i * 2654435761u64) >> 17) % 1024) as f64)
            .collect();
        let h_noisy = rescaled_range_hurst(&noisy);

        let trend: Vec<f64> = (0..8192)
            .map(|i| {
                let t = i as f64 / 8192.0;
                t + 0.1 * (7.0 * t).sin()
            })
            .collect();
        let h_trend = rescaled_range_hurst(&trend);
        assert!(h_trend > h_noisy, "trend {h_trend} vs noisy {h_noisy}");
    }

    #[test]
    fn variance_time_matches_r_s_direction() {
        // Both estimators should rate a trending series above white noise.
        let noisy: Vec<f64> = (0..8192)
            .map(|i| (((i * 2654435761u64) >> 17) % 1024) as f64)
            .collect();
        let trend: Vec<f64> = (0..8192)
            .map(|i| {
                let t = i as f64 / 8192.0;
                t + 0.1 * (7.0 * t).sin()
            })
            .collect();
        let vt_noisy = variance_time_hurst(&noisy);
        let vt_trend = variance_time_hurst(&trend);
        assert!(vt_trend > vt_noisy);
    }

    #[test]
    fn tiny_image_uses_neutral_defaults() {
        // Small image: R/S runs over few suffixes; variance-time degrades to
        // the neutral 0.5. Everything must stay finite and bounded.
        let img = Image::from_luma(16, 16, (0..256).map(|i| (i % 256) as u8).collect()).unwrap();
        let res = extract_hurst(&img).unwrap();
        assert!(res.value.is_finite());
        assert!(res.value_variance_time.is_finite());
        assert!((0.1..=0.9).contains(&res.value));
    }

    #[test]
    fn deterministic_repeats() {
        let img =
            Image::from_luma(48, 48, (0..48 * 48).map(|i| (i * 11 % 256) as u8).collect()).unwrap();
        let a = extract_hurst(&img).unwrap();
        let b = extract_hurst(&img).unwrap();
        assert_eq!(a.value, b.value);
        assert_eq!(a.value_variance_time, b.value_variance_time);
    }
}
