//! Multifractal spectrum analysis: the `f(α)` singularity spectrum.
//!
//! Following the standard partition-function route:
//!
//! ```text
//! Z(q, r) = Σᵢ μᵢ(r)^q        (box measure μᵢ = box intensity / total)
//! τ(q)    = slope of log Z(q, r) vs log r     (linear regression)
//! α(q)    = dτ/dq            (Legendre transform parameter)
//! f(q)    = q·α(q) − τ(q)     (Legendre transform of τ)
//! ```
//!
//! The spread of `α` over the probed `q` range — the *spectrum width* — is a
//! real, data-driven measure of how multifractal (scale-interleaved) an image
//! is: monofractals collapse to a single `α`, while Mandelbrot-boundary and
//! natural-fractal images fan out into a wide `f(α)` curve. The values are
//! deterministic functions of the pixels and carry no fitted constants.

use crate::entropy_engine::sources::fractal_analysis::utils::{least_squares, power_of_two_sizes};
use crate::error::{Result, SpectrumError};

/// Result of a partition-function multifractal analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct MultifractalSpectrum {
    /// Singularity exponents `α` (one per interior `q`, sorted by `q`).
    pub alpha_values: Vec<f64>,
    /// Spectrum `f(α)` aligned with `alpha_values`.
    pub f_alpha_values: Vec<f64>,
    /// `(q, τ(q))` for every probed moment (used by callers for detail).
    pub tau_q: Vec<(f64, f64)>,
    /// `α_max − α_min`: how wide the singularity spectrum is.
    pub width: f64,
    /// Peak of `f(α)`, an estimate of the Hausdorff dimension of the measure.
    pub hausdorff_estimate: f64,
}

impl MultifractalSpectrum {
    /// An empty spectrum (used when the image carries no usable measure).
    fn empty() -> Self {
        MultifractalSpectrum {
            alpha_values: Vec::new(),
            f_alpha_values: Vec::new(),
            tau_q: Vec::new(),
            width: 0.0,
            hausdorff_estimate: 0.0,
        }
    }
}

/// Computes `Z(q, r)` partition functions and their Legendre spectrum.
#[derive(Debug, Clone)]
pub struct MultifractalAnalyzer {
    /// Moments `q` to probe. Must be finite, distinct values; the canonical
    /// ladder is `[-5, -3, -1, 0, 1, 3, 5]`.
    pub q_values: Vec<f64>,
}

impl MultifractalAnalyzer {
    pub fn new(q_values: Vec<f64>) -> Self {
        MultifractalAnalyzer { q_values }
    }

    /// Default analyzer over the canonical moment ladder.
    ///
    /// The single source of truth for the default `q` ladder: both the
    /// `FractalAwareConfig` default and the unit tests construct their
    /// analyzer through here, so the ladder cannot drift between config and
    /// analysis.
    pub fn default_ladder() -> Self {
        MultifractalAnalyzer {
            q_values: super::DEFAULT_Q_VALUES.to_vec(),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.q_values.len() < 3 {
            return Err(SpectrumError::InvalidConfiguration(
                "multifractal analysis needs at least 3 distinct q moments".into(),
            ));
        }
        if self.q_values.len() > 32 {
            return Err(SpectrumError::InvalidConfiguration(
                "multifractal q ladder is capped at 32 moments".into(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for &q in &self.q_values {
            if !q.is_finite() || !seen.insert(q.to_bits()) {
                return Err(SpectrumError::InvalidConfiguration(format!(
                    "multifractal q values must be finite and distinct, got {:?}",
                    self.q_values
                )));
            }
        }
        Ok(())
    }

    /// Analyze a normalized `[0, 1]` luminance buffer.
    pub fn analyze(
        &self,
        img: &[f64],
        width: usize,
        height: usize,
    ) -> Result<MultifractalSpectrum> {
        self.validate()?;
        if img.len() != width * height {
            return Err(SpectrumError::InvalidConfiguration(format!(
                "multifractal buffer length {} does not match {width}x{height}",
                img.len()
            )));
        }
        let min_side = width.min(height);
        let mut scales = power_of_two_sizes(min_side / 2, 32);
        scales.retain(|&r| r >= 2 && r * 2 <= min_side.max(4));
        if scales.len() < 2 {
            return Ok(MultifractalSpectrum::empty());
        }

        // Normalized box measures: μᵢ = box intensity / total intensity. A
        // zero-intensity image carries no measure → empty spectrum.
        let total: f64 = img.iter().sum();
        if total <= 0.0 || !total.is_finite() {
            return Ok(MultifractalSpectrum::empty());
        }

        // q moments, ascending & deduplicated for the Legendre derivative.
        let mut qs: Vec<f64> = self.q_values.clone();
        qs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        qs.dedup_by(|a, b| (*a - *b).abs() < 1e-12);

        let mut tau_q: Vec<(f64, f64)> = Vec::with_capacity(qs.len());
        for &q in &qs {
            if let Some(tau) = self.tau_of_moment(img, width, height, &scales, total, q) {
                tau_q.push((q, tau));
            }
        }
        if tau_q.len() < 3 {
            return Ok(MultifractalSpectrum::empty());
        }

        // Legendre transform via central differences on the interior q values.
        let mut alpha_values = Vec::with_capacity(tau_q.len());
        let mut f_alpha_values = Vec::with_capacity(tau_q.len());
        for i in 1..tau_q.len() - 1 {
            let (q_prev, tau_prev) = tau_q[i - 1];
            let (q_cur, tau_cur) = tau_q[i];
            let (q_next, tau_next) = tau_q[i + 1];
            if (q_next - q_prev).abs() < 1e-12 {
                continue;
            }
            let alpha = (tau_next - tau_prev) / (q_next - q_prev);
            if !alpha.is_finite() {
                continue;
            }
            let f_alpha = q_cur * alpha - tau_cur;
            alpha_values.push(alpha);
            f_alpha_values.push(f_alpha);
        }

        let width = if alpha_values.is_empty() {
            0.0
        } else {
            let min_a = alpha_values.iter().cloned().fold(f64::INFINITY, f64::min);
            let max_a = alpha_values
                .iter()
                .cloned()
                .fold(f64::NEG_INFINITY, f64::max);
            (max_a - min_a).max(0.0)
        };
        let hausdorff_estimate = f_alpha_values
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);

        Ok(MultifractalSpectrum {
            alpha_values,
            f_alpha_values,
            tau_q,
            width,
            hausdorff_estimate,
        })
    }

    /// Log-log slope of `Z(q, r)` against `r` (the exponent `τ(q)`).
    fn tau_of_moment(
        &self,
        img: &[f64],
        width: usize,
        height: usize,
        scales: &[usize],
        total: f64,
        q: f64,
    ) -> Option<f64> {
        let mut log_r = Vec::with_capacity(scales.len());
        let mut log_z = Vec::with_capacity(scales.len());
        for &r in scales {
            let z = self.partition(img, width, height, r, total, q);
            if z.is_finite() && z > 0.0 {
                log_r.push((r as f64).ln());
                log_z.push(z.ln());
            }
        }
        let (slope, _, _) = least_squares(&log_r, &log_z)?;
        if !slope.is_finite() {
            return None;
        }
        Some(slope)
    }

    /// `Z(q, r) = Σᵢ μᵢ^q` over the full tiling (including clipped edge
    /// boxes, so boundary content is never dropped).
    fn partition(
        &self,
        img: &[f64],
        width: usize,
        height: usize,
        r: usize,
        total: f64,
        q: f64,
    ) -> f64 {
        let mut z = 0.0;
        let mut y0 = 0usize;
        while y0 < height {
            let y1 = (y0 + r).min(height);
            let mut x0 = 0usize;
            while x0 < width {
                let x1 = (x0 + r).min(width);
                let mut mass = 0.0f64;
                for y in y0..y1 {
                    let row = &img[y * width + x0..y * width + x1];
                    for &v in row {
                        mass += v;
                    }
                }
                let mu = mass / total;
                if mu > 0.0 {
                    if q.abs() < 1e-12 {
                        // q = 0: Z counts occupied boxes (each contributes 1).
                        z += 1.0;
                    } else {
                        z += mu.powf(q);
                    }
                }
                x0 += r;
            }
            y0 += r;
        }
        z
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffer_from(f: impl Fn(usize, usize) -> f64, w: usize, h: usize) -> Vec<f64> {
        (0..h * w)
            .map(|i| f(i / w, i % w).clamp(0.0, 1.0))
            .collect()
    }

    #[test]
    fn tau_of_unity_is_zero_for_normalized_measure() {
        // Deterministic pseudo-noise so the measure spans many boxes.
        let img: Vec<f64> = (0..128 * 128)
            .map(|i| ((i * 31 + 7) % 251) as f64 / 250.0)
            .collect();
        let a = MultifractalAnalyzer::default_ladder();
        let spec = a.analyze(&img, 128, 128).unwrap();
        let tau1 = spec
            .tau_q
            .iter()
            .find(|(q, _)| (q - 1.0).abs() < 1e-9)
            .map(|(_, t)| *t);
        assert!(tau1.is_some(), "q=1 must be probed");
        assert!(tau1.unwrap().abs() < 1e-6, "τ(1) = 0 got {}", tau1.unwrap());
    }

    #[test]
    fn spectrum_width_is_zero_for_uniform_image() {
        let img = vec![0.5f64; 128 * 128];
        let a = MultifractalAnalyzer::default_ladder();
        let spec = a.analyze(&img, 128, 128).unwrap();
        // Uniform measure is monofractal: every box mass identical → α flat.
        assert!(
            spec.width < 1e-9,
            "uniform measure must collapse the spectrum, got width {}",
            spec.width
        );
    }

    #[test]
    fn empty_and_zero_images_are_safe() {
        let a = MultifractalAnalyzer::default_ladder();
        assert!(
            a.analyze(&[], 8, 8).is_err(),
            "buffer must match dimensions"
        );
        let zero = vec![0.0f64; 64 * 64];
        let spec = a.analyze(&zero, 64, 64).unwrap();
        assert_eq!(spec.width, 0.0);
        assert!(spec.alpha_values.is_empty());
    }

    #[test]
    fn analysis_is_deterministic() {
        let img: Vec<f64> = (0..96 * 96)
            .map(|i| ((i * 17) % 256) as f64 / 255.0)
            .collect();
        let a = MultifractalAnalyzer::default_ladder();
        let s1 = a.analyze(&img, 96, 96).unwrap();
        let s2 = a.analyze(&img, 96, 96).unwrap();
        assert_eq!(s1.tau_q, s2.tau_q);
        assert_eq!(s1.alpha_values, s2.alpha_values);
        assert_eq!(s1.width, s2.width);
    }

    #[test]
    fn interior_multiplicative_structure_yields_positive_width() {
        // Concentric intensity rings create a genuinely multi-scale measure
        // (different scaling behaviour at different radii), so the spectrum
        // must not collapse to a single α.
        let w = 128usize;
        let h = 128usize;
        let img = buffer_from(
            |x, y| {
                let dx = (x as f64 - 63.5) / 63.5;
                let dy = (y as f64 - 63.5) / 63.5;
                let rad = (dx * dx + dy * dy).sqrt();
                if rad < 0.25 {
                    0.9
                } else if rad < 0.5 {
                    0.4
                } else if rad < 0.75 {
                    0.8
                } else {
                    0.2
                }
            },
            w,
            h,
        );
        let a = MultifractalAnalyzer::default_ladder();
        let spec = a.analyze(&img, w, h).unwrap();
        assert!(
            spec.width > 1e-3,
            "multi-scale rings must widen the spectrum"
        );
    }

    #[test]
    fn invalid_q_ladders_are_rejected() {
        assert!(MultifractalAnalyzer::new(vec![-1.0, 1.0])
            .analyze(&[0.5; 64 * 64], 64, 64)
            .is_err());
        assert!(MultifractalAnalyzer::new(vec![f64::NAN, 0.0, 1.0])
            .analyze(&[0.5; 64 * 64], 64, 64)
            .is_err());
        // Duplicates are rejected.
        assert!(MultifractalAnalyzer::new(vec![0.0, 0.0, 1.0])
            .analyze(&[0.5; 64 * 64], 64, 64)
            .is_err());
    }
}
