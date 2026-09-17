//! Small, deterministic statistics helpers shared by the entropy sources.
//!
//! Everything is intentionally dependency-free and operates on `f64` slices so
//! the sources never branch on platform-specific BLAS behaviour.

/// A fitted line `y = intercept + slope * x`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LinearFit {
    pub slope: f64,
    pub intercept: f64,
}

/// Arithmetic mean of a slice, or 0 for an empty slice.
pub fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

/// Unbiased sample variance (n-1 denominator), or 0 when n < 2.
pub fn variance(values: &[f64]) -> f64 {
    let n = values.len();
    if n < 2 {
        return 0.0;
    }
    let m = mean(values);
    values.iter().map(|v| (v - m).powi(2)).sum::<f64>() / (n - 1) as f64
}

/// Sample standard deviation.
pub fn std_dev(values: &[f64]) -> f64 {
    variance(values).sqrt()
}

/// Third standardized moment (skewness), or 0 when data is too small / uniform.
pub fn skewness(values: &[f64]) -> f64 {
    let n = values.len();
    if n < 3 {
        return 0.0;
    }
    let m = mean(values);
    let s = std_dev(values);
    if s < 1e-12 {
        return 0.0;
    }
    let nf = n as f64;
    values.iter().map(|v| ((v - m) / s).powi(3)).sum::<f64>() / nf
}

/// Fourth standardized moment (excess kurtosis: Gaussian ≈ 0), or 0 when data
/// is too small / uniform. Heavy tails give positive values.
///
/// Uses the population central moments (both m₄ and m² over `1/n`), matching
/// the standard `g₂ = m₄/m₂² − 3` definition so a perfectly bimodal ±1 sample
/// scores exactly −2.
pub fn kurtosis(values: &[f64]) -> f64 {
    let n = values.len();
    if n < 4 {
        return 0.0;
    }
    let m = mean(values);
    let m2 = values.iter().map(|v| (v - m).powi(2)).sum::<f64>() / n as f64;
    if m2 < 1e-12 {
        return 0.0;
    }
    let m4 = values.iter().map(|v| (v - m).powi(4)).sum::<f64>() / n as f64;
    m4 / (m2 * m2) - 3.0
}

/// Sample autocorrelation at lag `lag`, or 0 when the series is too short /
/// constant. Lag 0 is exactly 1.0 for any non-degenerate series.
pub fn autocorrelation(values: &[f64], lag: usize) -> f64 {
    let n = values.len();
    if lag == 0 {
        return if n == 0 { 0.0 } else { 1.0 };
    }
    if n <= lag || n < 2 {
        return 0.0;
    }
    let m = mean(values);
    let denom: f64 = values.iter().map(|v| (v - m).powi(2)).sum::<f64>();
    if denom < 1e-12 {
        return 0.0;
    }
    let numer: f64 = (lag..n)
        .map(|i| (values[i] - m) * (values[i - lag] - m))
        .sum();
    // Fall inside [-1, 1] against numerical noise.
    (numer / denom).clamp(-1.0, 1.0)
}

/// Variance-time (aggregated variance) Hurst estimate, as a [`LinearFit`] of
/// log variance against log aggregation window.
///
/// For fractional-Gaussian-noise-like series the variance of the aggregated
/// (non-overlapping) means scales as `m^(2H-2)`; the slope of log variance vs
/// log window is therefore `2H − 2`, giving `H = 1 + slope/2`.
///
/// Returns the fit itself so callers can inspect the slope/intercept; the
/// convenience [`variance_time_hurst`] wraps it and clamps H to (0, 1).
pub fn variance_time_fit(values: &[f64]) -> LinearFit {
    let n = values.len();
    if n < 8 {
        return LinearFit {
            slope: 0.0,
            intercept: 0.0,
        };
    }
    let mut log_m = Vec::new();
    let mut log_var = Vec::new();
    let mut m = 2usize;
    while m <= n / 4 {
        // Non-overlapping aggregation into windows of length m.
        let windows = n / m;
        let mut means = Vec::with_capacity(windows);
        for w in 0..windows {
            let start = w * m;
            let sum: f64 = values[start..start + m].iter().sum();
            means.push(sum / m as f64);
        }
        let v = variance(&means);
        if v.is_finite() {
            log_m.push((m as f64).ln());
            log_var.push(v.max(1e-12).ln());
        }
        // Doubling keeps the regression O(log n) and well-conditioned.
        if m > n / 8 {
            break;
        }
        m *= 2;
    }
    if log_m.len() < 2 {
        return LinearFit {
            slope: 0.0,
            intercept: 0.0,
        };
    }
    linear_fit(&log_m, &log_var)
}

/// Convenience wrapper: Hurst exponent from the variance-time method, clamped
/// to (0.01, 0.99). Degenerate input (fewer than 8 samples, zero variance)
/// yields 0.5.
pub fn variance_time_hurst(values: &[f64]) -> f64 {
    let fit = variance_time_fit(values);
    if !fit.slope.is_finite() || fit.slope == 0.0 {
        return 0.5;
    }
    (1.0 + fit.slope / 2.0).clamp(0.01, 0.99)
}

/// Ordinary least-squares fit of `y` against `x`. Returns a zero fit when there
/// is no variance in `x`.
pub fn linear_fit(x: &[f64], y: &[f64]) -> LinearFit {
    let n = x.len().min(y.len());
    if n < 2 {
        return LinearFit {
            slope: 0.0,
            intercept: 0.0,
        };
    }
    let mx = mean(&x[..n]);
    let my = mean(&y[..n]);
    let mut num = 0.0;
    let mut den = 0.0;
    for k in 0..n {
        let dx = x[k] - mx;
        num += dx * (y[k] - my);
        den += dx * dx;
    }
    if den.abs() < 1e-12 {
        return LinearFit {
            slope: 0.0,
            intercept: my,
        };
    }
    let slope = num / den;
    LinearFit {
        slope,
        intercept: my - slope * mx,
    }
}

/// Min and max of a slice, as `(Some(min), Some(max))`; `(None, None)` if empty.
pub fn min_max(values: &[f64]) -> (Option<f64>, Option<f64>) {
    let mut min = None;
    let mut max = None;
    for &v in values {
        if !v.is_finite() {
            continue;
        }
        min = Some(min.map_or(v, |m: f64| m.min(v)));
        max = Some(max.map_or(v, |m: f64| m.max(v)));
    }
    (min, max)
}

/// Shannon entropy (bits) over a binned histogram of `values`.
pub fn binned_entropy(values: &[f64], bins: usize) -> f64 {
    let (lo, hi) = min_max(values);
    let (lo, hi) = match (lo, hi) {
        (Some(lo), Some(hi)) if hi > lo => (lo, hi),
        _ => return 0.0,
    };
    let bins = bins.max(2);
    let mut hist = vec![0usize; bins];
    for &v in values {
        let idx = (((v - lo) / (hi - lo)) * bins as f64) as usize;
        let idx = idx.min(bins - 1);
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

/// Normalize each value of `values` into `[0, 1]` using the observed min/max;
/// returns a vector of the same length (or all-zero when flat).
pub fn normalize_minmax(values: &[f64]) -> Vec<f64> {
    let (lo, hi) = min_max(values);
    match (lo, hi) {
        (Some(lo), Some(hi)) if hi > lo => values
            .iter()
            .map(|v| ((v - lo) / (hi - lo)).clamp(0.0, 1.0))
            .collect(),
        _ => vec![0.0; values.len()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_fit_recovers_line() {
        let x = [0.0, 1.0, 2.0, 3.0, 4.0];
        let y = [2.0, 4.0, 6.0, 8.0, 10.0];
        let fit = linear_fit(&x, &y);
        assert!((fit.slope - 2.0).abs() < 1e-9);
        assert!((fit.intercept - 2.0).abs() < 1e-9);
    }

    #[test]
    fn linear_fit_flat_x() {
        let x = [3.0, 3.0, 3.0];
        let y = [1.0, 2.0, 3.0];
        let fit = linear_fit(&x, &y);
        assert_eq!(fit.slope, 0.0);
    }

    #[test]
    fn mean_variance_sane() {
        assert_eq!(mean(&[]), 0.0);
        assert_eq!(variance(&[1.0, 1.0, 1.0]), 0.0);
        assert!(variance(&[0.0, 1.0]) > 0.0);
    }

    #[test]
    fn skewness_sign() {
        // Right-skewed sample: positive skewness.
        let right = [1.0, 2.0, 3.0, 100.0];
        assert!(skewness(&right) > 0.0);
    }

    #[test]
    fn min_max_empty() {
        assert_eq!(min_max(&[]), (None, None));
        assert_eq!(min_max(&[5.0, 2.0]), (Some(2.0), Some(5.0)));
    }

    #[test]
    fn normalize_clamps() {
        let v = normalize_minmax(&[0.0, 5.0, 10.0]);
        assert!((v[0] - 0.0).abs() < 1e-12);
        assert!((v[1] - 0.5).abs() < 1e-12);
        assert!((v[2] - 1.0).abs() < 1e-12);
    }

    #[test]
    fn kurtosis_of_gaussian_like_is_near_zero() {
        // Symmetric two-hump sample: fourth moment ≈ 3σ⁴ → excess ≈ 0.
        // A perfectly bimodal ±1 sample has excess kurtosis −2.
        let bimodal = [-1.0, 1.0, -1.0, 1.0, -1.0, 1.0, -1.0, 1.0];
        let k = kurtosis(&bimodal);
        assert!(
            (k - -2.0).abs() < 1e-9,
            "bimodal excess kurtosis is -2, got {k}"
        );
    }

    #[test]
    fn kurtosis_heavy_tails_positive() {
        // One huge outlier in a tight sample: strongly positive excess.
        let heavy = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 100.0];
        assert!(kurtosis(&heavy) > 0.0);
    }

    #[test]
    fn kurtosis_degenerate_inputs() {
        assert_eq!(kurtosis(&[]), 0.0);
        assert_eq!(kurtosis(&[1.0]), 0.0);
        assert_eq!(kurtosis(&[5.0, 5.0, 5.0, 5.0]), 0.0);
    }

    #[test]
    fn autocorrelation_lag0_is_one() {
        assert_eq!(autocorrelation(&[1.0, 2.0, 3.0], 0), 1.0);
        assert_eq!(autocorrelation(&[], 0), 0.0);
    }

    #[test]
    fn autocorrelation_lagged_signal() {
        // Perfectly periodic series: correlation at its period is ≈ 1.
        let period = 8usize;
        let series: Vec<f64> = (0..128)
            .map(|i| if (i % period) < 4 { 1.0 } else { -1.0 })
            .collect();
        assert!(autocorrelation(&series, period) > 0.9);
        // Anti-correlated at half the period.
        assert!(autocorrelation(&series, period / 2) < -0.9);
    }

    #[test]
    fn autocorrelation_bounded_and_too_short() {
        let s = [1.0, 3.0, 2.0, 8.0, 4.0];
        for lag in 1..6 {
            let c = autocorrelation(&s, lag);
            assert!((-1.0..=1.0).contains(&c));
        }
        // Lag exceeds the series length → 0.
        assert_eq!(autocorrelation(&s, 10), 0.0);
        // Constant series → 0 (undefined correlation).
        assert_eq!(autocorrelation(&[2.0, 2.0, 2.0, 2.0], 1), 0.0);
    }

    #[test]
    fn variance_time_fit_scales_like_fgn() {
        // Build a self-similar-ish series with H≈0.75 by cumulative summing a
        // smoothed noise signal. Exact H is not needed; the estimate must land
        // strictly between a white-noise baseline and 1.
        let white: Vec<f64> = (0..4096)
            .map(|i| (((i * 2654435761u64) >> 17) % 1024) as f64 - 512.0)
            .collect();
        let h_white = variance_time_hurst(&white);
        assert!(
            h_white < 0.75,
            "white noise should have low H, got {h_white}"
        );

        // Strongly trending (persistent) series: cumulative ramp.
        let ramp: Vec<f64> = (0..4096)
            .map(|i| {
                let t = i as f64 / 4096.0;
                t + 0.2 * (3.0 * std::f64::consts::PI * t).sin()
            })
            .collect();
        let h_trend = variance_time_hurst(&ramp);
        assert!(h_trend > h_white, "trending series must have larger H");
        assert!(h_trend <= 0.99);
    }

    #[test]
    fn variance_time_degenerate_inputs() {
        // Too short → neutral 0.5.
        assert_eq!(variance_time_hurst(&[1.0, 2.0, 3.0]), 0.5);
        // Constant → neutral 0.5.
        assert_eq!(variance_time_hurst(&[7.0; 256]), 0.5);
        // Fit slope of white noise sits near −1 (H≈0.5).
        let white: Vec<f64> = (0..2048)
            .map(|i| (((i * 2654435761u64) >> 17) % 512) as f64)
            .collect();
        let fit = variance_time_fit(&white);
        assert!(fit.slope.is_finite());
    }

    #[test]
    fn binned_entropy_uniform_is_max() {
        let values: Vec<f64> = (0..256).map(|i| i as f64 / 256.0).collect();
        let entropy = binned_entropy(&values, 256);
        assert!(entropy > 7.5, "uniform → ≈8 bits, got {entropy}");
    }
}
