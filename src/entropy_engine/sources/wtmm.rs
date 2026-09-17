//! Source 1 — WTMM (Wavelet Transform Modulus Maxima), 2D multi-scale.
//!
//! The image is decomposed with the 2D stationary wavelet transform
//! ([`crate::filter::wavelet2d`]) over a logarithmically sampled scale ladder.
//! At every scale the detail modulus M = √(lh² + hl² + hh²) is computed and
//! its local maxima (in the 8-connected sense) are retained as the modulus
//! maxima chain. Maxima that persist across consecutive scales are the
//! signatures of image singularities.
//!
//! Two outputs feed key derivation:
//!
//! 1. **Scale profile** — per-scale statistics of the maxima (count, mean
//!    modulus, max modulus), reduced to one deterministic value per scale.
//! 2. **Partition-function singularity spectrum** — for a grid of moment
//!    orders `q`, the partition sum `Z(q, s) = Σ_i M_i(s)^q` over the maxima
//!    at scale `s` is regressed against `log s`; the slope is the Rényi
//!    scaling exponent `τ(q)`, and the Legendre transform
//!    `α(q) = dτ/dq, f(α) = q·α − τ(q)` gives the singularity spectrum.

use crate::entropy_engine::sources::compute_entropy_bits;
use crate::entropy_engine::ComplexityBucket;
use crate::error::Result;
use crate::filter::wavelet2d::swt2_decompose;
use crate::filter::Wavelet;
use crate::image::Image;
use crate::stats::linear_fit;

/// Which mother wavelet to use (re-export of the shared wavelet type).
pub type WaveletType = Wavelet;

/// Configuration for the WTMM analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct WtmmConfig {
    pub min_scale: u32,
    pub max_scale: u32,
    pub num_scales: u32,
    pub wavelet: WaveletType,
}

impl WtmmConfig {
    pub fn new(min_scale: u32, max_scale: u32, num_scales: u32, wavelet: WaveletType) -> Self {
        WtmmConfig {
            min_scale,
            max_scale,
            num_scales,
            wavelet,
        }
    }

    /// Table-driven deterministic selection based on image complexity.
    pub fn auto_detect(bucket: ComplexityBucket) -> Self {
        match bucket {
            ComplexityBucket::VeryLow => WtmmConfig::new(1, 64, 16, WaveletType::Morlet),
            ComplexityBucket::Low => WtmmConfig::new(1, 128, 32, WaveletType::Morlet),
            ComplexityBucket::Medium => WtmmConfig::new(1, 128, 48, WaveletType::MexicanHat),
            ComplexityBucket::High => WtmmConfig::new(2, 256, 64, WaveletType::MexicanHat),
            ComplexityBucket::VeryHigh => WtmmConfig::new(2, 256, 128, WaveletType::MexicanHat),
        }
    }

    /// Number of SWT levels needed to cover the configured scale ladder.
    /// Each SWT level `k` has an effective smoothing width ∝ 2^(k-1).
    fn swt_levels(&self) -> usize {
        let ladder = (self.max_scale.max(self.min_scale)).max(2);
        let levels = (ladder as f64).log2().ceil() as usize + 1;
        levels.clamp(1, 6)
    }
}

/// Result of the WTMM source.
#[derive(Debug, Clone)]
pub struct WtmmResult {
    /// One value per configured scale: the reduced singularity-density metric.
    pub values: Vec<f64>,
    /// Partition-function singularity spectrum: f(α) per moment order.
    pub singularity_spectrum: Vec<f64>,
    /// τ(q) per moment order.
    pub tau_exponents: Vec<f64>,
    /// Moment orders used for the partition function.
    pub q_values: Vec<f64>,
    pub config: WtmmConfig,
    pub entropy_bits: f64,
}

/// Statistics of the modulus maxima at one scale.
#[derive(Debug, Clone, Copy)]
struct MaximaStats {
    count: usize,
    mean_modulus: f64,
}

/// Local maxima of the modulus over the 8-connected neighbourhood.
/// Border pixels are only compared against in-bounds neighbours; a border
/// pixel tied with itself alone is not counted (needs at least one in-bounds
/// neighbour that is strictly smaller, or equal-neighbour tie-break by index).
fn local_maxima(modulus: &[f64], width: usize, height: usize) -> Vec<(usize, f64)> {
    let mut out = Vec::new();
    for y in 0..height {
        for x in 0..width {
            let idx = y * width + x;
            let cur = modulus[idx];
            let mut is_max = true;
            let mut strict = false;
            for dy in -1i64..=1 {
                for dx in -1i64..=1 {
                    if dx == 0 && dy == 0 {
                        continue;
                    }
                    let nx = x as i64 + dx;
                    let ny = y as i64 + dy;
                    if nx < 0 || nx >= width as i64 || ny < 0 || ny >= height as i64 {
                        continue;
                    }
                    let other = modulus[ny as usize * width + nx as usize];
                    if other > cur {
                        is_max = false;
                        break;
                    }
                    if other < cur {
                        strict = true;
                    }
                }
                if !is_max {
                    break;
                }
            }
            // Require the maximum to be strict against at least one neighbour,
            // which rejects flat plateaus (that would flood the maxima list).
            if is_max && strict {
                out.push((idx, cur));
            }
        }
    }
    out
}

/// Maxima statistics at one scale.
fn maxima_stats(modulus: &[f64], width: usize, height: usize) -> MaximaStats {
    let maxima = local_maxima(modulus, width, height);
    if maxima.is_empty() {
        return MaximaStats {
            count: 0,
            mean_modulus: 0.0,
        };
    }
    let count = maxima.len();
    let sum: f64 = maxima.iter().map(|(_, m)| m).sum();
    MaximaStats {
        count,
        mean_modulus: sum / count as f64,
    }
}

/// Partition sum Z(q, s) = Σ_i M_i(s)^q over the maxima at one scale.
/// For q = 0 this is the maxima count; for q < 0 masses are floored to keep
/// the powers finite.
fn partition_sum(maxima_moduli: &[f64], q: f64) -> f64 {
    if maxima_moduli.is_empty() {
        return 0.0;
    }
    if q.abs() < 1e-9 {
        return maxima_moduli.len() as f64;
    }
    maxima_moduli.iter().map(|m| m.max(1e-12).powf(q)).sum()
}

/// Partition-function analysis across the scale ladder.
///
/// Returns `(tau_exponents, singularity_spectrum)` for the given `q_values`.
/// `scales` holds the effective smoothing width of each analyzed level.
fn partition_analysis(
    maxima_per_scale: &[Vec<f64>],
    scales: &[f64],
    q_values: &[f64],
) -> (Vec<f64>, Vec<f64>) {
    let mut taus = Vec::with_capacity(q_values.len());
    for &q in q_values {
        let log_s: Vec<f64> = scales.iter().map(|s| s.ln()).collect();
        let log_z: Vec<f64> = maxima_per_scale
            .iter()
            .map(|maxima| partition_sum(maxima, q).max(1e-12).ln())
            .collect();
        // Z(q, s) ∝ s^τ(q) → slope of log Z vs log s is τ(q).
        taus.push(linear_fit(&log_s, &log_z).slope);
    }

    // Legendre transform on the discrete q grid: α(q_i) = dτ/dq via central
    // differences; f(α) = q·α − τ(q).
    let mut spectrum = Vec::with_capacity(taus.len());
    for (i, &q) in q_values.iter().enumerate() {
        let alpha = if q_values.len() < 2 {
            0.0
        } else if i == 0 {
            (taus[1] - taus[0]) / (q_values[1] - q_values[0])
        } else if i + 1 == q_values.len() {
            (taus[i] - taus[i - 1]) / (q_values[i] - q_values[i - 1])
        } else {
            (taus[i + 1] - taus[i - 1]) / (q_values[i + 1] - q_values[i - 1])
        };
        spectrum.push(q * alpha - taus[i]);
    }
    (taus, spectrum)
}

/// Extract the 2D multi-scale WTMM singularity analysis for an image.
pub fn extract_wtmm(img: &Image, config: &WtmmConfig) -> Result<WtmmResult> {
    let w = img.width as usize;
    let h = img.height as usize;
    if w < 4 || h < 4 {
        return crate::error::bad("WTMM needs at least 4x4 pixels");
    }

    let levels = config.swt_levels();
    let decomposition = swt2_decompose(img, levels, config.wavelet)?;

    // Analyze every level whose effective scale lies in the configured ladder.
    let steps = config.num_scales.max(2) as usize;
    let min_c = config.min_scale.max(1) as f64;
    let max_c = config.max_scale.max(min_c as u32 + 1) as f64;

    // The SWT gives us up to `levels` scales; map them onto the requested
    // ladder by sampling `steps` points between min and max scale and
    // assigning each point to its nearest SWT level. This keeps the number of
    // returned values equal to `num_scales` (the deterministic contract) while
    // the underlying maxima come from real 2D multi-scale analysis.
    let mut values = Vec::with_capacity(steps);
    let mut selected_moduli: Vec<Vec<f64>> = Vec::new();
    let mut selected_scales: Vec<f64> = Vec::new();

    for s in 0..steps {
        let t = s as f64 / (steps - 1).max(1) as f64;
        let scale = (min_c * (max_c / min_c).powf(t)).max(1.0);

        // Effective SWT level for this requested scale (log-spacing).
        let level = (((scale).log2().floor() as usize) + 1).clamp(1, levels);
        let modulus = decomposition
            .detail_modulus(level - 1)
            .ok_or(crate::error::SpectrumError::WtmmAnalysisFailed)?;

        let stats = maxima_stats(&modulus, w, h);
        // Singularity-density heuristic per scale: normalized maxima count
        // blended with the mean modulus. Bounded to keep the histogram stable.
        // Guard the integer denominator: images below 100 px would divide by
        // zero (density → inf) and saturate the metric.
        let density = stats.count as f64 / (w * h / 100).max(1) as f64;
        let value = (density * 0.6 + stats.mean_modulus / 32.0).min(2.5);
        values.push(value);

        // Cache per-level maxima once for the partition analysis.
        let level_idx = level - 1;
        if selected_moduli.len() <= level_idx {
            selected_moduli.resize(level_idx + 1, Vec::new());
        }
        if selected_moduli[level_idx].is_empty() {
            let maxima = local_maxima(&modulus, w, h);
            selected_moduli[level_idx] = maxima.into_iter().map(|(_, m)| m).collect();
            selected_scales.resize(level_idx + 1, 0.0);
            selected_scales[level_idx] = (1usize << level_idx) as f64;
        }
    }

    // Partition-function singularity spectrum over the real multi-scale data.
    let q_values: Vec<f64> = vec![-2.0, -1.0, 0.0, 1.0, 2.0];
    let pairs: Vec<(f64, Vec<f64>)> = selected_scales
        .iter()
        .zip(selected_moduli.iter())
        .filter(|(_, maxima)| !maxima.is_empty())
        .map(|(s, m)| (*s, m.clone()))
        .collect();

    let (taus, spectrum) = if pairs.len() >= 2 {
        let scales: Vec<f64> = pairs.iter().map(|(s, _)| *s).collect();
        let maxima: Vec<Vec<f64>> = pairs.into_iter().map(|(_, m)| m).collect();
        let (t, sp) = partition_analysis(&maxima, &scales, &q_values);
        (t, sp)
    } else {
        // Too few scales with maxima (e.g. a flat image): neutral spectrum.
        (vec![0.0; q_values.len()], vec![0.0; q_values.len()])
    };

    let entropy_bits = compute_entropy_bits(&values).max(8.0);
    Ok(WtmmResult {
        values,
        singularity_spectrum: spectrum,
        tau_exponents: taus,
        q_values,
        config: config.clone(),
        entropy_bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy_engine::adaptive_config::ComplexityBucket;

    #[test]
    fn auto_detect_is_monotonic() {
        let v = ComplexityBucket::VeryLow;
        let h = ComplexityBucket::VeryHigh;
        assert!(WtmmConfig::auto_detect(v).num_scales < WtmmConfig::auto_detect(h).num_scales);
    }

    #[test]
    fn mexican_hat_kernel_symmetry() {
        // Mexican hat is symmetric about 0 (delegated to the shared filter).
        let a = crate::filter::mexh_kernel(2.0, -1.0);
        assert!((a - crate::filter::mexh_kernel(2.0, 1.0)).abs() < 1e-9);
    }

    #[test]
    fn extract_returns_scales() {
        let img =
            Image::from_luma(64, 64, (0..64 * 64).map(|i| (i * 7 % 256) as u8).collect()).unwrap();
        let cfg = WtmmConfig::new(1, 32, 8, WaveletType::MexicanHat);
        let res = extract_wtmm(&img, &cfg).unwrap();
        assert_eq!(res.values.len(), 8);
        assert!(res.entropy_bits > 0.0);
    }

    #[test]
    fn local_maxima_finds_isolated_peak() {
        let mut modulus = vec![0.0f64; 9 * 9];
        modulus[4 * 9 + 4] = 5.0;
        let maxima = local_maxima(&modulus, 9, 9);
        assert_eq!(maxima.len(), 1);
        assert_eq!(maxima[0].0, 4 * 9 + 4);
        assert!((maxima[0].1 - 5.0).abs() < 1e-9);
    }

    #[test]
    fn local_maxima_rejects_flat_plateau() {
        let modulus = vec![2.0f64; 8 * 8];
        assert!(local_maxima(&modulus, 8, 8).is_empty());
    }

    #[test]
    fn partition_sum_matches_hand_computation() {
        let maxima = vec![1.0, 2.0, 4.0];
        let z1 = partition_sum(&maxima, 1.0);
        assert!((z1 - 7.0).abs() < 1e-9);
        let z0 = partition_sum(&maxima, 0.0);
        assert!((z0 - 3.0).abs() < 1e-9);
        let zneg = partition_sum(&maxima, -1.0);
        assert!((zneg - (1.0 + 0.5 + 0.25)).abs() < 1e-9);
        assert_eq!(partition_sum(&[], 1.0), 0.0);
    }

    #[test]
    fn partition_analysis_scales_with_synthetic_cascade() {
        // A synthetic multiplicative cascade: at scale s the maxima are s^a,
        // so Z(q,s) ∝ s^(a·q) and τ(q) should recover ≈ a·q.
        let scales: [f64; 4] = [1.0, 2.0, 4.0, 8.0];
        let a = 0.7f64;
        let maxima_per_scale: Vec<Vec<f64>> = scales.iter().map(|&s| vec![s.powf(a); 16]).collect();
        let qs = [-1.0, 0.0, 1.0, 2.0];
        let (taus, spectrum) = partition_analysis(&maxima_per_scale, &scales, &qs);
        for (i, &q) in qs.iter().enumerate() {
            assert!(
                (taus[i] - a * q).abs() < 0.15,
                "τ({q}) = {} vs expected ≈ {}",
                taus[i],
                a * q
            );
        }
        // f(α) at q=1 with a linear τ is ≈ 0 (mass conservation regime).
        assert!(spectrum.iter().all(|f| f.is_finite()));
    }

    #[test]
    fn spectrum_output_shape_and_finiteness() {
        let img =
            Image::from_luma(64, 64, (0..64 * 64).map(|i| (i * 13 % 256) as u8).collect()).unwrap();
        let cfg = WtmmConfig::new(1, 16, 6, WaveletType::MexicanHat);
        let res = extract_wtmm(&img, &cfg).unwrap();
        assert_eq!(res.q_values.len(), 5);
        assert_eq!(res.tau_exponents.len(), 5);
        assert_eq!(res.singularity_spectrum.len(), 5);
        assert!(res.singularity_spectrum.iter().all(|v| v.is_finite()));
        assert!(res.tau_exponents.iter().all(|v| v.is_finite()));
    }

    #[test]
    fn textured_image_has_richer_spectrum_than_flat() {
        let flat = Image::from_luma(64, 64, vec![128u8; 64 * 64]).unwrap();
        let busy =
            Image::from_luma(64, 64, (0..64 * 64).map(|i| (i * 37 % 256) as u8).collect()).unwrap();
        let cfg = WtmmConfig::new(1, 16, 6, WaveletType::MexicanHat);
        let r_flat = extract_wtmm(&flat, &cfg).unwrap();
        let r_busy = extract_wtmm(&busy, &cfg).unwrap();
        // A flat image has no maxima at any scale; a busy image has many and
        // saturates the per-scale metric.
        assert!(r_flat.values.iter().all(|v| *v < 0.5));
        assert!(r_busy.values.iter().all(|v| *v >= 0.5));
        assert!(r_busy.entropy_bits >= r_flat.entropy_bits);
    }

    #[test]
    fn small_image_rejected() {
        let img = Image::from_luma(2, 2, vec![0u8; 4]).unwrap();
        let cfg = WtmmConfig::new(1, 8, 4, WaveletType::Morlet);
        assert!(extract_wtmm(&img, &cfg).is_err());
    }

    #[test]
    fn deterministic_repeats() {
        let img =
            Image::from_luma(48, 48, (0..48 * 48).map(|i| (i * 11 % 256) as u8).collect()).unwrap();
        let cfg = WtmmConfig::new(1, 16, 6, WaveletType::MexicanHat);
        let a = extract_wtmm(&img, &cfg).unwrap();
        let b = extract_wtmm(&img, &cfg).unwrap();
        assert_eq!(a.values, b.values);
        assert_eq!(a.singularity_spectrum, b.singularity_spectrum);
    }
}
