//! Shared image-filtering primitives.
//!
//! * [`kernels`] — convolution kernels (Sobel/Laplacian), wavelets, Gabor.
//! * [`wavelet2d`] — 2D stationary wavelet decomposition (undecimated, so it
//!   keeps the input resolution and is translation-covariant).
//! * Morphological dilate/erode over masks — used by the adaptive-config layer
//!   to measure cluster geometry. Masks are structural metadata only: they
//!   never touch derived key material, so no cryptographic determinism depends
//!   on tie-breaking inside these ops.
//! * [`gaussian_blur`] — separable convolution used to build difference
//!   measures for the adaptive configuration.

pub mod kernels;
pub mod wavelet2d;

pub use self::kernels::{
    gabor_kernel, gradient_orientations, laplacian_response, mean_abs_response, mexh_kernel,
    morlet_kernel, sobel_components, sobel_magnitudes, wavelet_conv, wavelet_kernel, GaborFilter,
    LAPLACIAN, SOBEL_X, SOBEL_Y,
};
pub use self::kernels::{Wavelet, WAVELET_MEXICAN_HAT, WAVELET_MORLET};

use crate::image::Image;

/// A binary mask over an image: one bool per pixel, row-major.
pub type Mask = Vec<bool>;

/// Build a mask of pixels brighter than `threshold`.
pub fn threshold_mask(img: &Image, threshold: u8) -> Mask {
    img.pixels.iter().map(|p| *p > threshold).collect()
}

/// Morphological dilation with the 8-connected (3×3) structuring element:
/// a pixel is set if any neighbour in the mask is set. Border pixels are
/// treated as empty (no implicit padding growth).
pub fn dilate(mask: &Mask, width: usize, height: usize) -> Mask {
    let mut out = vec![false; mask.len()];
    for y in 0..height {
        for x in 0..width {
            let mut set = false;
            for dy in -1i64..=1 {
                for dx in -1i64..=1 {
                    let ny = y as i64 + dy;
                    let nx = x as i64 + dx;
                    if ny < 0 || ny >= height as i64 || nx < 0 || nx >= width as i64 {
                        continue;
                    }
                    if mask[ny as usize * width + nx as usize] {
                        set = true;
                        break;
                    }
                }
                if set {
                    break;
                }
            }
            out[y * width + x] = set;
        }
    }
    out
}

/// Morphological erosion with the 3×3 structuring element: a pixel survives
/// only if every in-bounds neighbour (itself included) is set. Borders erode.
pub fn erode(mask: &Mask, width: usize, height: usize) -> Mask {
    let mut out = vec![false; mask.len()];
    for y in 0..height {
        for x in 0..width {
            let mut all = true;
            'outer: for dy in -1i64..=1 {
                for dx in -1i64..=1 {
                    let ny = y as i64 + dy;
                    let nx = x as i64 + dx;
                    if ny < 0 || ny >= height as i64 || nx < 0 || nx >= width as i64 {
                        // Out-of-bounds neighbours count as empty → erosion.
                        all = false;
                        break 'outer;
                    }
                    if !mask[ny as usize * width + nx as usize] {
                        all = false;
                        break 'outer;
                    }
                }
            }
            out[y * width + x] = all;
        }
    }
    out
}

/// Count set pixels in a mask.
pub fn mask_area(mask: &Mask) -> usize {
    mask.iter().filter(|b| **b).count()
}

/// 1D gaussian weights for `sigma` over a kernel of the given (odd) size.
fn gaussian_weights(size: usize, sigma: f64) -> Vec<f64> {
    let size = size.max(3) | 1; // force odd
    let half = (size / 2) as f64;
    let denom = 2.0 * sigma.max(1e-6) * sigma.max(1e-6);
    let mut w: Vec<f64> = (0..size)
        .map(|i| {
            let d = i as f64 - half;
            (-(d * d) / denom).exp()
        })
        .collect();
    let sum: f64 = w.iter().sum();
    for v in &mut w {
        *v /= sum;
    }
    w
}

/// Gaussian blur with a separable convolution over an odd-sized square kernel.
/// Edges are handled by clamping to the nearest pixel, so the output has the
/// same dimensions and no energy leaks in from outside.
pub fn gaussian_blur(img: &Image, size: usize, sigma: f64) -> Image {
    let w = img.width as usize;
    let h = img.height as usize;
    let weights = gaussian_weights(size, sigma);
    let half = weights.len() / 2;

    // Horizontal pass into f64 accumulation space.
    let mut tmp = vec![0.0f64; w * h];
    for y in 0..h {
        for x in 0..w {
            let mut acc = 0.0f64;
            for (k, &wt) in weights.iter().enumerate() {
                let sx = (x as i64 + k as i64 - half as i64).clamp(0, w as i64 - 1) as usize;
                acc += wt * f64::from(img.pixels[y * w + sx]);
            }
            tmp[y * w + x] = acc;
        }
    }

    // Vertical pass back into u8.
    let mut out = vec![0u8; w * h];
    for y in 0..h {
        for x in 0..w {
            let mut acc = 0.0f64;
            for (k, &wt) in weights.iter().enumerate() {
                let sy = (y as i64 + k as i64 - half as i64).clamp(0, h as i64 - 1) as usize;
                acc += wt * tmp[sy * w + x];
            }
            out[y * w + x] = acc.round().clamp(0.0, 255.0) as u8;
        }
    }

    Image {
        width: img.width,
        height: img.height,
        pixels: out,
    }
}

/// Mean absolute difference between an image and its blur — a high-frequency
/// energy measure used by the adaptive configuration.
pub fn high_frequency_energy(img: &Image, size: usize, sigma: f64) -> f64 {
    let blurred = gaussian_blur(img, size, sigma);
    let n = img.pixels.len().max(1);
    let sum: f64 = img
        .pixels
        .iter()
        .zip(blurred.pixels.iter())
        .map(|(a, b)| ((*a as i32 - *b as i32).abs() as f64) / 255.0)
        .sum();
    sum / n as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dilate_grows_region() {
        let w = 7usize;
        let h = 7usize;
        let mut mask = vec![false; w * h];
        mask[3 * w + 3] = true;
        let grown = dilate(&mask, w, h);
        assert_eq!(mask_area(&mask), 1);
        assert_eq!(mask_area(&grown), 9, "3×3 dilation of one pixel");
    }

    #[test]
    fn erode_shrinks_region() {
        let w = 7usize;
        let h = 7usize;
        let mut mask = vec![false; w * h];
        for y in 2..5 {
            for x in 2..5 {
                mask[y * w + x] = true;
            }
        }
        let eroded = erode(&mask, w, h);
        assert_eq!(mask_area(&eroded), 1, "3×3 block erodes to its centre");
        // Dilation is not generally an inverse, but on a solid interior block
        // of ≥3×3 the centre survives and grows back to the same area here.
        let regrown = dilate(&eroded, w, h);
        assert_eq!(mask_area(&regrown), 9);
    }

    #[test]
    fn dilation_idempotence_bound() {
        // Dilation can grow an irregular shape on the first pass; a second
        // dilation of an already-dilated blob is monotone non-decreasing.
        let w = 9usize;
        let h = 9usize;
        let mut mask = vec![false; w * h];
        for (i, slot) in mask.iter_mut().enumerate() {
            *slot = i % 4 == 0;
        }
        let once = dilate(&mask, w, h);
        let twice = dilate(&once, w, h);
        assert!(mask_area(&twice) >= mask_area(&once));
    }

    #[test]
    fn erode_empty_and_full() {
        let w = 4usize;
        let h = 4usize;
        assert!(erode(&vec![false; 16], w, h).iter().all(|b| !b));
        // A full image erodes to false on the borders (they see out-of-bounds).
        let eroded = erode(&vec![true; 16], w, h);
        assert!(!eroded[0]);
        assert!(eroded[w + 1]);
    }

    #[test]
    fn blur_preserves_flat_image_and_dimensions() {
        let img = Image::from_luma(16, 16, vec![100u8; 16 * 16]).unwrap();
        let blurred = gaussian_blur(&img, 5, 1.5);
        assert_eq!(blurred.dimensions(), (16, 16));
        assert!(blurred.pixels.iter().all(|p| (*p as i32 - 100).abs() <= 1));
    }

    #[test]
    fn blur_smooths_an_impulse() {
        let mut pixels = vec![0u8; 15 * 15];
        pixels[7 * 15 + 7] = 255;
        let img = Image::from_luma(15, 15, pixels).unwrap();
        let blurred = gaussian_blur(&img, 5, 1.4);
        // Centre keeps most of the energy; neighbours receive some.
        let centre = blurred.pixels[7 * 15 + 7];
        assert!(centre > 0 && centre < 255);
        assert!(blurred.pixels[7 * 15 + 8] > 0, "blur spreads energy");
        assert!(blurred.pixels[0] == 0, "far corner receives nothing");
    }

    #[test]
    fn blur_normalization_is_energy_preserving_on_constant() {
        // For a constant image the blur must return the same constant, proving
        // the kernel sums to 1.
        for sigma in [0.5, 1.0, 2.0] {
            let img = Image::from_luma(12, 12, vec![200u8; 144]).unwrap();
            let blurred = gaussian_blur(&img, 7, sigma);
            assert!(
                blurred.pixels.iter().all(|p| (*p as i32 - 200).abs() <= 1),
                "sigma={sigma}"
            );
        }
    }

    #[test]
    fn high_frequency_energy_separates_image_classes() {
        let flat = Image::from_luma(64, 64, vec![128u8; 64 * 64]).unwrap();
        let noisy =
            Image::from_luma(64, 64, (0..64 * 64).map(|i| (i * 37 % 256) as u8).collect()).unwrap();
        let e_flat = high_frequency_energy(&flat, 5, 1.5);
        let e_noisy = high_frequency_energy(&noisy, 5, 1.5);
        assert!(e_flat < 1e-6, "flat image has no high-frequency energy");
        assert!(e_noisy > e_flat * 10.0);
    }

    #[test]
    fn threshold_mask_basics() {
        let img = Image::from_luma(
            4,
            4,
            vec![
                10, 200, 30, 250, 0, 0, 0, 0, 255, 255, 255, 255, 7, 8, 9, 10,
            ],
        )
        .unwrap();
        let mask = threshold_mask(&img, 128);
        assert_eq!(mask.iter().filter(|b| **b).count(), 6);
    }
}
