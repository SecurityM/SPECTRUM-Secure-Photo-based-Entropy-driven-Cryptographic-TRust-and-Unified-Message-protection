//! Adaptive Wavelet-Transform Modulus Maxima (WTMM) stage.
//!
//! A complex-Morlet continuous wavelet transform is applied at a ladder of
//! dyadic scales; at every scale we keep the *modulus maxima* — pixels whose
//! wavelet modulus is locally maximal and significant relative to that scale
//! plane. Two adaptive mechanisms make the stage behave correctly on both
//! regular and fractal imagery:
//!
//! * **Scale-relative significance.** The acceptance threshold is a fraction
//!   of the scale's own peak modulus (plus a small boost for high measured
//!   fractal dimension), so bright, cluttered fractal planes do not drown out
//!   the boundary singularities and flat regions do not produce spurious
//!   chains.
//! * **Plateau convergence.** When the modulus-maxima count stops changing
//!   between consecutive scales (`< convergence_threshold` for three scales
//!   in a row), the structure has converged and remaining scales are skipped —
//!   the fractal-aware early exit that also keeps runtime bounded.
//!
//! The analysis is fully deterministic: the complex Morlet kernels are
//! zero-mean (constant planes yield exactly zero response), the row-parallel
//! convolution writes disjoint outputs, and no ordering-dependent reductions
//! are used.

use num_complex::Complex64;
use rayon::prelude::*;

use crate::entropy_engine::sources::fractal_analysis::detection::FractalClassification;
use crate::error::{Result, SpectrumError};

/// Default base significance threshold on the normalized modulus plane.
pub const DEFAULT_MORLET_THRESHOLD: f64 = 0.1;
/// Default relative change below which modulus-maxima counts are "converged".
pub const DEFAULT_CONVERGENCE_THRESHOLD: f64 = 0.05;
/// Default largest dyadic scale probed (kernel cost stays bounded).
pub const DEFAULT_MAX_SCALE: usize = 8;
/// Boosts the significance threshold for high-dimension (fractal) planes.
const DIM_THRESHOLD_GAIN: f64 = 0.2;

/// Complex-Morlet WTMM analyzer with fractal-aware convergence detection.
#[derive(Debug, Clone)]
pub struct AdaptiveWTMM {
    /// Base fraction of a scale plane's peak modulus that a maximum must
    /// exceed to count.
    pub morlet_threshold: f64,
    /// Plateau detection: relative change below this for three consecutive
    /// scales stops the analysis.
    pub convergence_threshold: f64,
    /// Largest dyadic scale to probe.
    pub max_scale: usize,
}

impl AdaptiveWTMM {
    pub fn new(morlet_threshold: f64, convergence_threshold: f64, max_scale: usize) -> Self {
        AdaptiveWTMM {
            morlet_threshold,
            convergence_threshold,
            max_scale,
        }
    }

    /// Default analyzer (plan defaults: 0.1 / 0.05 / scale ladder ≤ 8).
    pub fn defaults() -> Self {
        AdaptiveWTMM::new(
            DEFAULT_MORLET_THRESHOLD,
            DEFAULT_CONVERGENCE_THRESHOLD,
            DEFAULT_MAX_SCALE,
        )
    }

    /// Dyadic scale ladder `1, 2, 4, …` bounded by `max_scale` and the image.
    pub fn scales_for(&self, min_side: usize) -> Vec<usize> {
        let cap = self.max_scale.min(min_side / 2).max(1);
        let mut scales = Vec::new();
        let mut s = 1usize;
        while s <= cap && scales.len() < 16 {
            scales.push(s);
            s = s.saturating_mul(2);
        }
        scales
    }
    /// Analyze an image whose fractal class (hence measured dimension) is
    /// known — the dimension only nudges the significance threshold.
    pub fn analyze_fractal(
        &self,
        img: &[f64],
        width: usize,
        height: usize,
        classification: &FractalClassification,
    ) -> Result<Vec<f64>> {
        self.analyze(img, width, height, Some(classification))
    }

    /// Unified adaptive WTMM: one modulus-maxima count per probed scale.
    pub fn analyze(
        &self,
        img: &[f64],
        width: usize,
        height: usize,
        classification: Option<&FractalClassification>,
    ) -> Result<Vec<f64>> {
        if img.len() != width * height {
            return Err(SpectrumError::InvalidConfiguration(format!(
                "adaptive WTMM buffer length {} does not match {width}x{height}",
                img.len()
            )));
        }
        if width < 4 || height < 4 {
            return Err(SpectrumError::InvalidConfiguration(format!(
                "adaptive WTMM requires at least 4x4 pixels, got {width}x{height}"
            )));
        }
        if !self.morlet_threshold.is_finite()
            || !(0.0..=1.0).contains(&self.morlet_threshold)
            || !self.convergence_threshold.is_finite()
            || !(0.0..=1.0).contains(&self.convergence_threshold)
            || self.max_scale == 0
        {
            return Err(SpectrumError::InvalidConfiguration(format!(
                "adaptive WTMM thresholds must lie in (0, 1] and max_scale >= 1, got {:?}",
                (
                    self.morlet_threshold,
                    self.convergence_threshold,
                    self.max_scale
                )
            )));
        }

        let dim = classification
            .map(|c| c.hausdorff_dimension.clamp(1.0, 2.0))
            .unwrap_or(1.5);
        let scales = self.scales_for(width.min(height));

        let mut features = Vec::new();
        let mut prev: Option<f64> = None;
        let mut plateau = 0usize;
        for &scale in &scales {
            if plateau >= 3 {
                break;
            }
            let modulus = self.cwt_modulus(img, width, height, scale)?;
            let count = self.count_maxima(&modulus, width, height, scale, dim) as f64;

            if let Some(p) = prev {
                let change = (count - p).abs() / (p + 1.0);
                if change < self.convergence_threshold {
                    plateau += 1;
                } else {
                    plateau = 0;
                }
            }
            prev = Some(count);
            features.push(count);
        }
        Ok(features)
    }

    /// Complex-Morlet modulus plane at one dyadic scale.
    ///
    /// The kernel is a zero-mean Morlet wavelet (DC removed), so a constant
    /// plane produces a zero response everywhere. Rows are convolved in
    /// parallel; every output pixel is written by exactly one worker.
    fn cwt_modulus(
        &self,
        img: &[f64],
        width: usize,
        height: usize,
        scale: usize,
    ) -> Result<Vec<f64>> {
        let kernel = self.morlet_kernel(scale);
        let size = kernel.len();
        let hw = size / 2;

        if hw >= height.min(width) {
            // Kernel cannot fit: no interior pixels → empty plane.
            return Ok(vec![0.0; width * height]);
        }

        // Each worker owns a private clone of the (small) kernel and writes a
        // disjoint row, so the parallel output is bit-for-bit deterministic.
        let interior: Vec<(usize, Vec<(usize, f64)>)> = (hw..height - hw)
            .into_par_iter()
            .map(|y| {
                let kernel = kernel.clone();
                let row: Vec<(usize, f64)> = (hw..width - hw)
                    .map(|x| {
                        let mut re = 0.0f64;
                        let mut im = 0.0f64;
                        for (ky, kr) in kernel.iter().enumerate() {
                            let iy = y + ky - hw;
                            for (kx, tap) in kr.iter().enumerate() {
                                let ix = x + kx - hw;
                                let v = img[iy * width + ix];
                                re += v * tap.re;
                                im += v * tap.im;
                            }
                        }
                        let m = (re * re + im * im).sqrt();
                        (x, if m.is_finite() { m } else { 0.0 })
                    })
                    .collect();
                (y, row)
            })
            .collect();

        let mut modulus = vec![0.0f64; width * height];
        for (y, row) in interior {
            for (x, m) in row {
                modulus[y * width + x] = m;
            }
        }
        Ok(modulus)
    }

    /// Zero-mean complex Morlet kernel of side `(3·scale) | 1` (odd), Gaussian
    /// envelope `σ = scale/5`, carrier `ω = 2π/scale` along `x`.
    fn morlet_kernel(&self, scale: usize) -> Vec<Vec<Complex64>> {
        let size = (((scale * 3).max(3)) | 1).max(3);
        let hw = size / 2;
        let sigma = scale as f64 / 5.0;
        let omega = 2.0 * std::f64::consts::PI / scale as f64;
        let denom = 2.0 * sigma * sigma;

        let mut kernel = vec![vec![Complex64::new(0.0, 0.0); size]; size];
        let mut acc = Complex64::new(0.0, 0.0);
        for (ky, row) in kernel.iter_mut().enumerate() {
            let dy = ky as f64 - hw as f64;
            for (kx, cell) in row.iter_mut().enumerate() {
                let dx = kx as f64 - hw as f64;
                let g = (-(dx * dx + dy * dy) / denom).exp();
                let k = Complex64::new(g * (omega * dx).cos(), g * (omega * dx).sin());
                *cell = k;
                acc += k;
            }
        }
        // DC removal: subtract the complex mean so constant planes vanish.
        let mean = acc / (size * size) as f64;
        for row in &mut kernel {
            for tap in row {
                *tap -= mean;
            }
        }
        kernel
    }

    /// Count modulus maxima above a scale-relative significance threshold.
    fn count_maxima(
        &self,
        modulus: &[f64],
        width: usize,
        height: usize,
        scale: usize,
        dim: f64,
    ) -> usize {
        let size = ((scale * 3).max(3)) | 1;
        let hw = size / 2;
        // The interior slice per row is [y*width + hw + 1 .. y*width + width
        // - hw - 1]; it requires hw + 1 < width - hw - 1 (else start > end and
        // slicing panics). scale ≈ min_side/2 from the ladder makes hw reach
        // 3·min_side/4, so a mere `hw + 1 >= width` guard is insufficient
        // (e.g. 8×16 at scale 4: start = +7, end = +1).
        if width < 2 * hw + 3 || height < 2 * hw + 3 {
            return 0;
        }

        // Interior significance: a fraction of the plane's own peak modulus,
        // boosted slightly for high-dimension (fractal) planes.
        let mut peak = 0.0f64;
        for y in hw + 1..height - hw - 1 {
            let row = &modulus[y * width + hw + 1..y * width + (width - hw - 1)];
            if let Some(&m) = row
                .iter()
                .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            {
                peak = peak.max(m);
            }
        }
        if peak <= 1e-9 {
            return 0;
        }
        let dim_gain = 1.0 + DIM_THRESHOLD_GAIN * (dim - 1.0).max(0.0);
        let threshold = self.morlet_threshold * peak * dim_gain;

        let mut count = 0usize;
        for y in hw + 1..height - hw - 1 {
            for x in hw + 1..width - hw - 1 {
                let idx = y * width + x;
                let v = modulus[idx];
                if v < threshold {
                    continue;
                }
                // 8-connected local maximum (ties count once per plateau pixel
                // — non-strict comparison keeps ridge pixels on the chain).
                let is_max = (0..=2).all(|dy| {
                    (0..=2).all(|dx| {
                        if dy == 1 && dx == 1 {
                            return true;
                        }
                        let nidx = (y + dy - 1) * width + (x + dx - 1);
                        modulus[nidx] <= v
                    })
                });
                if is_max {
                    count += 1;
                }
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise_buffer(w: usize, h: usize, seed: u64) -> Vec<f64> {
        // Deterministic low-discrepancy-ish pseudo noise in [0, 1].
        (0..w * h)
            .map(|i| {
                let v = (i as u64)
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add(seed);
                let v = v ^ (v >> 30);
                (v.wrapping_mul(0xBF58_476D_1CE4_E5B9) >> 33) as f64 / (1u64 << 31) as f64
            })
            .collect()
    }

    #[test]
    fn flat_image_yields_zero_maxima_at_every_scale() {
        let img = vec![0.5f64; 64 * 64];
        let a = AdaptiveWTMM::defaults();
        let feats = a.analyze(&img, 64, 64, None).unwrap();
        assert!(!feats.is_empty());
        assert!(
            feats.iter().all(|&c| c == 0.0),
            "zero-mean Morlet must not fire on a flat plane: {feats:?}"
        );
    }

    #[test]
    fn busy_image_has_maxima_and_is_deterministic() {
        let img = noise_buffer(64, 64, 42);
        let a = AdaptiveWTMM::defaults();
        let f1 = a.analyze(&img, 64, 64, None).unwrap();
        let f2 = a.analyze(&img, 64, 64, None).unwrap();
        assert_eq!(f1, f2);
        assert!(f1.iter().any(|&c| c > 0.0), "noise must produce maxima");
        assert!(f1.iter().all(|c| c.is_finite() && *c >= 0.0));
    }

    #[test]
    fn classified_and_standard_paths_agree_on_determinism() {
        // Classification is metadata for thresholding only; results must stay
        // deterministic and finite either way.
        let img = noise_buffer(48, 48, 7);
        let a = AdaptiveWTMM::defaults();
        let plain = a.analyze(&img, 48, 48, None).unwrap();
        let cls = crate::entropy_engine::sources::fractal_analysis::detection::FractalClassification::regular_default();
        let aware = a.analyze_fractal(&img, 48, 48, &cls).unwrap();
        assert_eq!(plain, aware);
    }

    #[test]
    fn dimensions_are_checked() {
        let a = AdaptiveWTMM::defaults();
        assert!(a.analyze(&[0.5; 10], 3, 3, None).is_err());
        assert!(a.analyze(&[0.5; 10], 5, 5, None).is_err(), "len mismatch");
        assert!(AdaptiveWTMM::new(1.5, 0.05, 8)
            .analyze(&[0.5; 25], 5, 5, None)
            .is_err());
    }

    #[test]
    fn scale_ladder_respects_cap_and_image() {
        let a = AdaptiveWTMM::defaults();
        assert_eq!(a.scales_for(160), vec![1, 2, 4, 8]);
        assert_eq!(a.scales_for(64), vec![1, 2, 4, 8]);
        assert_eq!(a.scales_for(10), vec![1, 2, 4]);
        assert_eq!(
            AdaptiveWTMM::new(0.1, 0.05, 32).scales_for(160),
            vec![1, 2, 4, 8, 16, 32]
        );
    }

    #[test]
    fn largest_ladder_scale_never_panics_on_small_planes() {
        // Asymmetric regression: width < 2*hw+2 <= height makes the row slice
        // [hw+1 .. width-hw-1] start past its end (8x16 at scale 4: hw=6,
        // slice y*8+7..y*8+1) while the y-loop stays non-empty. This test was
        // verified to panic with the old guard before this fix.
        // Regression: at scale = min_side/2 the Morlet kernel support reaches
        // 3·min_side/4, so the row-interior slice [hw+1 .. width-hw-1] used to
        // have start > end and panicked the derivation (e.g. 16×16 at scale 8:
        // start offset 13, end offset 3).
        for side in [8usize, 16, 20, 32, 64] {
            let img = noise_buffer(side, side, 11);
            let a = AdaptiveWTMM::defaults();
            let feats = a.analyze(&img, side, side, None).unwrap();
            assert!(feats.iter().all(|c| c.is_finite() && *c >= 0.0));
        }

        // The asymmetric shape that actually tripped the old guard: the
        // y-loop is non-empty while the row slice is inverted.
        let wide_tall = noise_buffer(8, 16, 12);
        let feats = AdaptiveWTMM::defaults()
            .analyze(&wide_tall, 8, 16, None)
            .unwrap();
        assert!(feats.iter().all(|c| c.is_finite() && *c >= 0.0));
    }
}
