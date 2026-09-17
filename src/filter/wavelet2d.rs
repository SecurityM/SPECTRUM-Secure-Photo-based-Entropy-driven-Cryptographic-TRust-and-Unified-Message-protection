//! 2D stationary wavelet transform (à trous / undecimated DWT).
//!
//! The decomposition convolves the image with a separable 1D low-pass filter
//! (three-point binomial B(2)) at every scale, without any downsampling, and
//! forms each detail band by subtraction (high-pass = identity − low-pass),
//! i.e. the "starlet" scheme. Each level therefore yields four same-size
//! coefficient blocks (LL kept as the running low-pass remainder, plus
//! LH/HL/HH details), and the sum of all detail blocks plus the final LL
//! reconstructs the original image *exactly* — by construction, not just
//! approximately.
//!
//! This is used by the WTMM source, which needs modulus maxima tracked across
//! scales *at the same resolution* — exactly what the undecimated transform
//! provides and the decimated DWT does not.

use super::kernels::Wavelet;
use crate::error::Result;
use crate::image::Image;

/// One level of the 2D stationary wavelet decomposition.
#[derive(Debug, Clone)]
pub struct SwtLevel {
    /// Approximation (low-pass) coefficients after this level.
    pub ll: Vec<f64>,
    /// Horizontal-detail coefficients (low-pass along x, high-pass along y).
    pub lh: Vec<f64>,
    /// Vertical-detail coefficients (high-pass along x, low-pass along y).
    pub hl: Vec<f64>,
    /// Diagonal-detail coefficients.
    pub hh: Vec<f64>,
}

/// Full decomposition: `levels` detail levels plus the final approximation.
#[derive(Debug, Clone)]
pub struct SwtDecomposition {
    pub width: usize,
    pub height: usize,
    pub levels: Vec<SwtLevel>,
}

impl SwtDecomposition {
    /// Number of decomposition levels.
    pub fn num_levels(&self) -> usize {
        self.levels.len()
    }

    /// Exact reconstruction: sum of all detail blocks plus the final LL.
    ///
    /// The starlet scheme guarantees `idwt(decompose(x)) == x` by construction:
    /// each detail is identity − low-pass on a shared branch, so the four
    /// blocks of a level always sum back to the level's input.
    pub fn reconstruct(&self) -> Vec<f64> {
        let n = self.width * self.height;
        let mut out = vec![0.0; n];
        for level in &self.levels {
            for ((o, &lh), (&hl, &hh)) in out
                .iter_mut()
                .zip(level.lh.iter())
                .zip(level.hl.iter().zip(level.hh.iter()))
            {
                *o += lh + hl + hh;
            }
        }
        if let Some(last) = self.levels.last() {
            for (o, l) in out.iter_mut().zip(last.ll.iter()) {
                *o += *l;
            }
        }
        out
    }

    /// Modulus of the detail coefficients at a level: `√(lh² + hl² + hh²)`.
    pub fn detail_modulus(&self, level: usize) -> Option<Vec<f64>> {
        let lvl = self.levels.get(level)?;
        let n = self.width * self.height;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let m = (lvl.lh[i] * lvl.lh[i] + lvl.hl[i] * lvl.hl[i] + lvl.hh[i] * lvl.hh[i]).sqrt();
            out.push(m);
        }
        Some(out)
    }

    /// Total energy (sum of squares) of the detail coefficients per level.
    pub fn detail_energy(&self) -> Vec<f64> {
        self.levels
            .iter()
            .map(|l| {
                l.lh.iter()
                    .chain(l.hl.iter())
                    .chain(l.hh.iter())
                    .map(|v| v * v)
                    .sum::<f64>()
            })
            .collect()
    }
}

/// Normalized 1D low-pass (smoothing) kernel: three-point binomial B(2),
/// (¼, ½, ¼), which sums to exactly 1 and is symmetric (zero-phase).
fn lowpass_kernel() -> [f64; 3] {
    [0.25, 0.5, 0.25]
}

/// Separable à-trous convolution of a row-major buffer along x at a given gap.
fn convolve_x(data: &[f64], width: usize, height: usize, gap: usize) -> Vec<f64> {
    let mut out = vec![0.0; width * height];
    let k = lowpass_kernel();
    for y in 0..height {
        for x in 0..width {
            let mut acc = 0.0;
            for (t, &kt) in k.iter().enumerate() {
                let off = (t as i64 - 1) * gap as i64;
                let sx = (x as i64 + off).clamp(0, width as i64 - 1) as usize;
                acc += kt * data[y * width + sx];
            }
            out[y * width + x] = acc;
        }
    }
    out
}

/// Separable à-trous convolution of a row-major buffer along y at a given gap.
fn convolve_y(data: &[f64], width: usize, height: usize, gap: usize) -> Vec<f64> {
    let mut out = vec![0.0; width * height];
    let k = lowpass_kernel();
    for y in 0..height {
        for x in 0..width {
            let mut acc = 0.0;
            for (t, &kt) in k.iter().enumerate() {
                let off = (t as i64 - 1) * gap as i64;
                let sy = (y as i64 + off).clamp(0, height as i64 - 1) as usize;
                acc += kt * data[sy * width + x];
            }
            out[y * width + x] = acc;
        }
    }
    out
}

/// Dilation by zero insertion: the effective gap between taps at level
/// `level` (1-indexed) is `2^(level-1)`.
fn gap_for_level(level: usize) -> usize {
    1usize << level.saturating_sub(1)
}

/// Decompose an image into `levels` stationary-wavelet scales.
///
/// The `wavelet` parameter selects the smoothing used for the approximation
/// branch (both supported wavelets share the same binomial low-pass; the
/// parameter is kept so callers can express intent and so future asymmetric
/// kernels can be slotted in without an API break).
pub fn swt2_decompose(img: &Image, levels: usize, wavelet: Wavelet) -> Result<SwtDecomposition> {
    let _ = wavelet; // reserved for future kernel asymmetry; see module docs
    let w = img.width as usize;
    let h = img.height as usize;
    if w < 4 || h < 4 {
        return crate::error::bad("SWT needs at least 4x4 pixels");
    }
    let levels = levels.clamp(1, 8);

    let mut current: Vec<f64> = img.pixels.iter().map(|p| f64::from(*p)).collect();
    let mut out_levels = Vec::with_capacity(levels);

    for level in 1..=levels {
        let gap = gap_for_level(level);

        // Low-pass each axis (à-trous: taps spread by the gap).
        let lx = convolve_x(&current, w, h, gap);
        let ly = convolve_y(&current, w, h, gap);
        let ll = convolve_y(&lx, w, h, gap);

        // Starlet detail definition: high-pass = identity − low-pass. Details
        // are formed by subtraction, which makes the reconstruction identity
        // ll + lh + hl + hh == input exact by construction.
        let mut lh = vec![0.0; w * h];
        let mut hl = vec![0.0; w * h];
        let mut hh = vec![0.0; w * h];
        for i in 0..w * h {
            lh[i] = lx[i] - ll[i];
            hl[i] = ly[i] - ll[i];
            hh[i] = current[i] - lx[i] - ly[i] + ll[i];
        }

        // Move the approximation band forward for the next level without a
        // unwrap: `ll` is moved out of the level we just pushed.
        current = ll;
        out_levels.push(SwtLevel {
            ll: current.clone(),
            lh,
            hl,
            hh,
        });
    }

    Ok(SwtDecomposition {
        width: w,
        height: h,
        levels: out_levels,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::WAVELET_MEXICAN_HAT;

    fn gradient_image(w: u32, h: u32) -> Image {
        let pixels: Vec<u8> = (0..w * h)
            .map(|i| {
                let x = i % w;
                let y = i / w;
                ((x * 200 / w.max(1)).min(255) as u8).wrapping_add((y % 7) as u8)
            })
            .collect();
        Image::from_luma(w, h, pixels).unwrap()
    }

    #[test]
    fn decomposition_has_requested_levels() {
        let img = gradient_image(64, 64);
        let d = swt2_decompose(&img, 3, WAVELET_MEXICAN_HAT).unwrap();
        assert_eq!(d.num_levels(), 3);
        for lvl in &d.levels {
            assert_eq!(lvl.ll.len(), 64 * 64);
            assert_eq!(lvl.lh.len(), 64 * 64);
            assert_eq!(lvl.hl.len(), 64 * 64);
            assert_eq!(lvl.hh.len(), 64 * 64);
        }
    }

    #[test]
    fn reconstruction_is_exact_on_smooth_image() {
        // The à-trous scheme with binomial B(2) low-pass and (−½,½) high-pass
        // satisfies idwt(dwt(x)) == x up to floating-point error for any input.
        let img = gradient_image(64, 64);
        let d = swt2_decompose(&img, 2, WAVELET_MEXICAN_HAT).unwrap();
        let rec = d.reconstruct();
        for (i, r) in rec.iter().enumerate() {
            let orig = f64::from(img.pixels[i]);
            assert!(
                (r - orig).abs() < 1e-6,
                "reconstruction error at {i}: {r} vs {orig}"
            );
        }
    }

    #[test]
    fn detail_energies_are_finite_and_positive() {
        let img = gradient_image(48, 48);
        let d = swt2_decompose(&img, 3, WAVELET_MEXICAN_HAT).unwrap();
        let energies = d.detail_energy();
        assert_eq!(energies.len(), 3);
        assert!(energies.iter().all(|e| e.is_finite() && *e > 0.0));
    }

    #[test]
    fn detail_modulus_bounded() {
        let img = gradient_image(32, 32);
        let d = swt2_decompose(&img, 2, WAVELET_MEXICAN_HAT).unwrap();
        let m = d.detail_modulus(0).unwrap();
        assert_eq!(m.len(), 32 * 32);
        assert!(m.iter().all(|v| v.is_finite() && *v >= 0.0));
        assert!(d.detail_modulus(5).is_none());
    }

    #[test]
    fn small_image_rejected() {
        let img = Image::from_luma(3, 3, vec![0u8; 9]).unwrap();
        assert!(swt2_decompose(&img, 2, WAVELET_MEXICAN_HAT).is_err());
    }

    #[test]
    fn flat_image_has_zero_details() {
        let img = Image::from_luma(32, 32, vec![90u8; 32 * 32]).unwrap();
        let d = swt2_decompose(&img, 2, WAVELET_MEXICAN_HAT).unwrap();
        for lvl in &d.levels {
            assert!(lvl.lh.iter().all(|v| v.abs() < 1e-9));
            assert!(lvl.hl.iter().all(|v| v.abs() < 1e-9));
            assert!(lvl.hh.iter().all(|v| v.abs() < 1e-9));
        }
    }
}
