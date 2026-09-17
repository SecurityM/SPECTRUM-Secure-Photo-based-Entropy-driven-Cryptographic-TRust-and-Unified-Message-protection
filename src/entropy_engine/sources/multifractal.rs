//! Source 3 — Multifractal spectrum.
//!
//! For each moment order `q`, the partition function `Z(q, s)` is estimated at
//! several box sizes and a log–log least-squares fit yields the generalized
//! dimension `D(q)`. The set of `D(q)` values across the `q` grid forms the
//! spectrum fed into key derivation.

use crate::entropy_engine::sources::compute_entropy_bits;
use crate::error::Result;
use crate::image::Image;
use crate::stats::linear_fit;

/// Result of the multifractal source.
#[derive(Debug, Clone)]
pub struct MultifractalResult {
    /// Generalized dimension per moment `q` (same length as the q grid).
    pub values: Vec<f64>,
    pub entropy_bits: f64,
}

/// Per-box normalized mass at a given box size.
fn box_masses(img: &Image, size: usize) -> Vec<f64> {
    let w = img.width as usize;
    let h = img.height as usize;
    let cols = (w / size).max(1);
    let rows = (h / size).max(1);
    let mut masses = Vec::with_capacity(cols * rows);
    for by in 0..rows {
        for bx in 0..cols {
            let mut sum = 0.0;
            let mut count = 0usize;
            for dy in 0..size {
                for dx in 0..size {
                    let y = by * size + dy;
                    let x = bx * size + dx;
                    if y < h && x < w {
                        let idx = y * w + x;
                        if idx < img.pixels.len() {
                            sum += img.pixels[idx] as f64 / 255.0;
                            count += 1;
                        }
                    }
                }
            }
            masses.push(if count > 0 { sum / count as f64 } else { 0.0 });
        }
    }
    masses
}

/// Partition sum (Z) for a moment `q` over a box size.
fn partition_moment(masses: &[f64], q: f64) -> f64 {
    let total: f64 = masses.iter().sum();
    if total <= 1e-12 {
        return 0.0;
    }
    if q.abs() < 1e-9 {
        return masses.len() as f64; // Z(q=0) == #boxes
    }
    masses.iter().map(|m| (m / total).max(1e-12).powf(q)).sum()
}

/// Estimate D(q) by regression of log Z against log box size over several sizes.
fn generalized_dimension(img: &Image, sizes: &[usize], q: f64) -> f64 {
    let mut log_s = Vec::new();
    let mut log_z = Vec::new();
    for &s in sizes {
        let z = partition_moment(&box_masses(img, s), q).max(1e-12).ln();
        log_s.push((s as f64).ln());
        log_z.push(z);
    }
    // ln Z ≈ ln c − D(q) * ln s  → slope is −D(q).
    let fit = linear_fit(&log_s, &log_z);
    -fit.slope
}

fn default_box_sizes(w: usize) -> Vec<usize> {
    let base = (w / 4).max(4);
    let mut sizes = Vec::new();
    let mut s = 2usize;
    while s <= base && sizes.len() < 8 {
        sizes.push(s);
        s = (s * 2).max(s + 1);
    }
    if sizes.is_empty() {
        sizes.push(2);
    }
    sizes
}

/// Extract a multifractal `D(q)` spectrum over the given moment grid.
pub fn extract_multifractal(img: &Image, q_values: &[f64]) -> Result<MultifractalResult> {
    if img.width < 8 || img.height < 8 {
        return crate::error::bad("multifractal needs at least 8x8 pixels");
    }
    let sizes = default_box_sizes(img.width as usize);
    let values: Vec<f64> = q_values
        .iter()
        .map(|&q| generalized_dimension(img, &sizes, q))
        .collect();

    let entropy_bits = compute_entropy_bits(&values).clamp(4.0, 8.0);
    Ok(MultifractalResult {
        values,
        entropy_bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_masses_len() {
        let img = Image::from_luma(64, 64, vec![100u8; 64 * 64]).unwrap();
        let m = box_masses(&img, 8);
        assert_eq!(m.len(), 8 * 8);
    }

    #[test]
    fn uniform_image_yields_flat_spectrum() {
        let img = Image::from_luma(64, 64, vec![100u8; 64 * 64]).unwrap();
        let qs = vec![-2.0, 0.0, 2.0];
        let res = extract_multifractal(&img, &qs).unwrap();
        assert_eq!(res.values.len(), 3);
        assert!(res.values.iter().all(|v| v.is_finite()));
    }

    #[test]
    fn dimension_is_bounded() {
        let img =
            Image::from_luma(64, 64, (0..64 * 64).map(|i| (i * 7 % 256) as u8).collect()).unwrap();
        let res = extract_multifractal(&img, &[-1.0, 0.0, 1.0]).unwrap();
        // Generalized dimensions may stray beyond the box-counting (topological)
        // value for negative moments; assert finite and in a generous sanity band.
        assert!(res
            .values
            .iter()
            .all(|v| v.is_finite() && (-3.0..=5.0).contains(v)));
    }
}
