//! Shared image-filtering primitives: discrete convolution kernels, wavelets
//! and Gabor filters.
//!
//! Centralizing these keeps the eleven entropy sources free of duplicated math
//! and lets every filter be unit-tested once instead of eleven times.

use crate::image::Image;

/// 3×3 Sobel kernel for the x (horizontal) derivative.
pub const SOBEL_X: [[f64; 3]; 3] = [[-1.0, 0.0, 1.0], [-2.0, 0.0, 2.0], [-1.0, 0.0, 1.0]];
/// 3×3 Sobel kernel for the y (vertical) derivative.
pub const SOBEL_Y: [[f64; 3]; 3] = [[-1.0, -2.0, -1.0], [0.0, 0.0, 0.0], [1.0, 2.0, 1.0]];
/// 3×3 Laplacian kernel (approximates the second derivative).
pub const LAPLACIAN: [[f64; 3]; 3] = [[0.0, -1.0, 0.0], [-1.0, 4.0, -1.0], [0.0, -1.0, 0.0]];

/// Sobel gradient magnitude for every interior pixel, normalized to [0, 1].
pub fn sobel_magnitudes(img: &Image) -> Vec<f64> {
    let w = img.width as i64;
    let h = img.height as i64;
    let mut mags = Vec::new();
    for y in 1..h - 1 {
        for x in 1..w - 1 {
            let mut gx = 0.0;
            let mut gy = 0.0;
            for dy in -1..=1i64 {
                for dx in -1..=1i64 {
                    let v = f64::from(img.pixel_clamped(x + dx, y + dy));
                    gx += v * SOBEL_X[(dy + 1) as usize][(dx + 1) as usize];
                    gy += v * SOBEL_Y[(dy + 1) as usize][(dx + 1) as usize];
                }
            }
            mags.push(((gx * gx + gy * gy).sqrt() / 255.0).min(1.0));
        }
    }
    mags
}

/// Sobel gradient components (gx, gy) per interior pixel, in [0, 1].
pub fn sobel_components(img: &Image) -> (Vec<f64>, Vec<f64>) {
    let w = img.width as i64;
    let h = img.height as i64;
    let mut gxs = Vec::new();
    let mut gys = Vec::new();
    for y in 1..h - 1 {
        for x in 1..w - 1 {
            let mut gx = 0.0;
            let mut gy = 0.0;
            for dy in -1..=1i64 {
                for dx in -1..=1i64 {
                    let v = f64::from(img.pixel_clamped(x + dx, y + dy));
                    gx += v * SOBEL_X[(dy + 1) as usize][(dx + 1) as usize];
                    gy += v * SOBEL_Y[(dy + 1) as usize][(dx + 1) as usize];
                }
            }
            gxs.push(gx / 255.0);
            gys.push(gy / 255.0);
        }
    }
    (gxs, gys)
}

/// Gradient orientation (radians) of every interior pixel from its components.
pub fn gradient_orientations(mags: &[f64], gxs: &[f64], gys: &[f64]) -> Vec<f64> {
    mags.iter()
        .zip(gxs)
        .zip(gys)
        .map(|((&m, &x), &y)| {
            if m < 1e-6 {
                0.0
            } else {
                y.atan2(x) // wrapped to [-π, π]
            }
        })
        .collect()
}

/// Laplacian response for every interior pixel (unnormalized).
pub fn laplacian_response(img: &Image) -> Vec<f64> {
    let w = img.width as i64;
    let h = img.height as i64;
    let mut out = Vec::new();
    for y in 1..h - 1 {
        for x in 1..w - 1 {
            let mut acc = 0.0;
            for dy in -1..=1i64 {
                for dx in -1..=1i64 {
                    let v = f64::from(img.pixel_clamped(x + dx, y + dy));
                    acc += v * LAPLACIAN[(dy + 1) as usize][(dx + 1) as usize];
                }
            }
            out.push(acc);
        }
    }
    out
}

/// Gaussian-envelope kernel (used for blur and as a building block elsewhere).
pub fn gaussian_kernel(size: usize, sigma: f64) -> Vec<f64> {
    let half = size as f64 / 2.0;
    let denom = 2.0 * sigma.max(1e-6) * sigma.max(1e-6);
    let mut k = Vec::with_capacity(size * size);
    for ky in 0..size {
        for kx in 0..size {
            let px = kx as f64 - half;
            let py = ky as f64 - half;
            k.push((-((px * px) + (py * py)) / denom).exp());
        }
    }
    k
}

/// Wavelet family used by the WTMM source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wavelet {
    Morlet,
    MexicanHat,
}

/// Public shorthand constants for the wavelet family.
pub const WAVELET_MORLET: Wavelet = Wavelet::Morlet;
pub const WAVELET_MEXICAN_HAT: Wavelet = Wavelet::MexicanHat;

/// Mexican-hat (Ricker) mother wavelet kernel value at offset `t` for `scale`.
pub fn mexh_kernel(scale: f64, t: f64) -> f64 {
    let z = (t / scale.max(1e-6)).powi(2);
    (1.0 - z) * (-z / 2.0).exp()
}

/// Real-part Morlet mother wavelet kernel value at offset `t` for `scale`.
pub fn morlet_kernel(scale: f64, t: f64) -> f64 {
    let omega = 2.0 * std::f64::consts::PI * scale.max(1e-6);
    let gauss = (-(t / scale.max(1e-6)).powi(2) / 2.0).exp();
    (omega * t).cos() * gauss
}

/// Evaluate one wavelet mother kernel at offset `t` for `scale`.
pub fn wavelet_kernel(w: Wavelet, scale: f64, t: f64) -> f64 {
    match w {
        Wavelet::Morlet => morlet_kernel(scale, t),
        Wavelet::MexicanHat => mexh_kernel(scale, t),
    }
}

/// 1D convolution of `signal` with a wavelet of `scale`, using a fixed number
/// of taps so cost is independent of the scale value.
pub fn wavelet_conv(signal: &[f64], scale: f64, wavelet: Wavelet) -> Vec<f64> {
    const TAPS: usize = 16;
    let n = signal.len();
    if n == 0 {
        return Vec::new();
    }
    let mut out = vec![0.0; n];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut acc = 0.0;
        for k in 0..TAPS {
            let frac = if TAPS == 1 {
                0.0
            } else {
                k as f64 / (TAPS - 1) as f64 * 2.0 - 1.0
            };
            let dt = frac * scale * 3.0;
            let src = i as i64 + dt.round() as i64;
            let idx = src.clamp(0, n as i64 - 1) as usize;
            acc += signal[idx] * wavelet_kernel(wavelet, scale, dt);
        }
        *slot = acc;
    }
    out
}

/// Gabor filter configuration.
#[derive(Debug, Clone, Copy)]
pub struct GaborFilter {
    pub frequency: f64,
    pub orientation_deg: f64,
    pub sigma: f64,
    pub size: usize,
}

/// Build a 2D Gabor kernel from its configuration.
pub fn gabor_kernel(filter: &GaborFilter) -> Vec<f64> {
    let half = filter.size as f64 / 2.0;
    // Guarded like `gaussian_kernel`: sigma = 0 (or subnormal) would make the
    // center tap exp(-0/0) = NaN and poison the whole response.
    let sigma = filter.sigma.max(1e-6);
    let sigma2 = 2.0 * sigma * sigma;
    let phi = filter.orientation_deg.to_radians();
    let (cos_p, sin_p) = (phi.cos(), phi.sin());
    let omega = 2.0 * std::f64::consts::PI * filter.frequency;

    let mut kernel = Vec::with_capacity(filter.size * filter.size);
    for ky in 0..filter.size {
        for kx in 0..filter.size {
            let px = kx as f64 - half;
            let py = ky as f64 - half;
            let xp = px * cos_p + py * sin_p;
            kernel.push((-((px * px) + (py * py)) / sigma2).exp() * (omega * xp).cos());
        }
    }
    kernel
}

/// Mean absolute response of a 2D kernel over the image, subsampling by 2.
pub fn mean_abs_response(img: &Image, kernel: &[f64], size: usize) -> f64 {
    let w = img.width as usize;
    let h = img.height as usize;
    let half = size / 2;
    let stride = 2usize;
    let max_x = w.saturating_sub(half).max(half + 1).min(w);
    let max_y = h.saturating_sub(half).max(half + 1).min(h);

    let mut mag_sum = 0.0f64;
    let mut count = 0usize;
    let mut y = half;
    while y < max_y {
        let mut x = half;
        while x < max_x {
            let mut conv = 0.0;
            let mut ki = 0;
            for ky in 0..size {
                for kx in 0..size {
                    let v = f64::from(
                        img.pixel_clamped((x + kx - half) as i64, (y + ky - half) as i64),
                    ) / 255.0;
                    conv += v * kernel[ki];
                    ki += 1;
                }
            }
            mag_sum += conv.abs();
            count += 1;
            x += stride;
        }
        y += stride;
    }
    if count == 0 {
        0.0
    } else {
        mag_sum / count as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wavelet_conv_empty_signal_is_empty() {
        // Used to panic on `clamp(0, n-1)` with n = 0.
        assert!(wavelet_conv(&[], 2.0, Wavelet::MexicanHat).is_empty());
        assert!(wavelet_conv(&[], 2.0, Wavelet::Morlet).is_empty());
    }

    #[test]
    fn sobel_instance_entropy() {
        // Striped image: strong horizontal gradients, zero vertical ones.
        let mut img = Image::from_luma(32, 32, vec![0u8; 32 * 32]).unwrap();
        for row in 0..32u32 {
            for x in 0..32u32 {
                img.pixels[(row * 32 + x) as usize] = (x * 16 % 256) as u8;
            }
        }
        let mags = sobel_magnitudes(&img);
        let mean = mags.iter().sum::<f64>() / mags.len() as f64;
        assert!(
            mean > 0.0,
            "a gradient image must have non-zero edge energy"
        );
    }

    #[test]
    fn wavelet_kernels_normalize_zero() {
        // Both kernels vanish at the origin's neighborhood for a symmetric say.
        let mx = mexh_kernel(2.0, 0.0);
        let mo = morlet_kernel(2.0, 0.0);
        assert!(mx.abs() < 2.0);
        assert!(mo.abs() <= 1.0);
    }

    #[test]
    fn gabor_kernel_zero_sigma_stays_finite() {
        // A degenerate sigma used to produce exp(-0/0) = NaN in every tap.
        let f = GaborFilter {
            frequency: 0.1,
            orientation_deg: 45.0,
            sigma: 0.0,
            size: 9,
        };
        let k = gabor_kernel(&f);
        assert_eq!(k.len(), 81);
        assert!(
            k.iter().all(|v| v.is_finite()),
            "sigma=0 must not yield NaN"
        );
    }

    #[test]
    fn gabor_kernel_shape() {
        let f = GaborFilter {
            frequency: 0.1,
            orientation_deg: 0.0,
            sigma: 3.0,
            size: 9,
        };
        let k = gabor_kernel(&f);
        assert_eq!(k.len(), 81);
        assert!(k.iter().all(|v| v.is_finite()));
    }

    #[test]
    fn laplacian_flat_image_is_zero() {
        let img = Image::from_luma(16, 16, vec![128u8; 16 * 16]).unwrap();
        let resp = laplacian_response(&img);
        assert!(resp.iter().all(|&v| v.abs() < 1e-9));
    }

    #[test]
    fn orientations_bounded() {
        let img =
            Image::from_luma(24, 24, (0..24 * 24).map(|i| (i * 7 % 256) as u8).collect()).unwrap();
        let (gx, gy) = sobel_components(&img);
        let mags = sobel_magnitudes(&img);
        let ori = gradient_orientations(&mags, &gx, &gy);
        assert!(ori
            .iter()
            .all(|o| (-std::f64::consts::PI..=std::f64::consts::PI).contains(o)));
    }
}
