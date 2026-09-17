//! Source 2 — Lacunarity analysis.
//!
//! Measured as Λ = mean(r²)/mean(r)² over gap distributions computed with a
//! gliding-box-style sampling at multiple box sizes.

use crate::entropy_engine::sources::compute_entropy_bits;
use crate::error::{Result, SpectrumError};
use crate::image::Image;

/// Algorithm for computing lacunarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LacunarityAlgorithm {
    /// Gliding box — counts per-box occupied mass.
    GlidingBox,
    /// Box counting — boolean occupancy ratio.
    BoxCounting,
}

/// Configuration for lacunarity analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct LacunarityConfig {
    pub scales: Vec<u32>,
    pub algorithm: LacunarityAlgorithm,
}

impl LacunarityConfig {
    pub fn new(scales: Vec<u32>, algorithm: LacunarityAlgorithm) -> Self {
        LacunarityConfig { scales, algorithm }
    }

    /// Heuristic, deterministic selection based on pixel density.
    pub fn auto_detect(density: f64, clustered: bool) -> Self {
        let scales = match density {
            d if d < 0.3 => vec![2, 4, 8, 16, 32],
            d if d < 0.7 => vec![2, 4, 8, 16, 32, 64, 128],
            _ => vec![4, 8, 16, 32, 64, 128, 256],
        };
        let algorithm = if clustered {
            LacunarityAlgorithm::GlidingBox
        } else {
            LacunarityAlgorithm::BoxCounting
        };
        LacunarityConfig { scales, algorithm }
    }
}

/// Result of the lacunarity source.
#[derive(Debug, Clone)]
pub struct LacunarityResult {
    pub values: Vec<f64>,
    pub config: LacunarityConfig,
    pub entropy_bits: f64,
}

/// Mean density of pixels above a fixed threshold; 0.0 for an empty image
/// (a 0/0 division would otherwise leak a NaN into downstream comparisons,
/// where it silently fails every `<` arm and picks arbitrary defaults).
pub fn pixel_density(img: &Image) -> f64 {
    let count = img.pixel_count();
    if count == 0 {
        return 0.0;
    }
    let filled = img.pixels.iter().filter(|p| **p > 128).count();
    filled as f64 / count as f64
}

/// Crude cluster heuristic: whether dilation grows occupied area significantly.
pub fn has_clusters(img: &Image) -> bool {
    let w = img.width as usize;
    let h = img.height as usize;
    let occupied: Vec<bool> = img.pixels.iter().map(|p| *p > 128).collect();
    let original = occupied.iter().filter(|b| **b).count();
    if original == 0 {
        return false;
    }

    let mut dilated = vec![false; occupied.len()];
    for y in 0..h as i64 {
        for x in 0..w as i64 {
            if occupied[y as usize * w + x as usize] {
                for dy in -1..=1i64 {
                    for dx in -1..=1i64 {
                        let ny = y + dy;
                        let nx = x + dx;
                        if ny >= 0 && ny < h as i64 && nx >= 0 && nx < w as i64 {
                            dilated[ny as usize * w + nx as usize] = true;
                        }
                    }
                }
            }
        }
    }
    let grown = dilated.iter().filter(|b| **b).count();
    grown as f64 / original as f64 > 2.0
}

fn compute_lacunarity(gaps: &[f64]) -> f64 {
    if gaps.is_empty() {
        return 0.0;
    }
    let n = gaps.len() as f64;
    let mean = gaps.iter().sum::<f64>() / n;
    let mean_sq = gaps.iter().map(|g| g * g).sum::<f64>() / n;
    mean_sq / (mean * mean + 1e-12)
}
/// Extract lacunarity values across the configured box scales.
pub fn extract_lacunarity(img: &Image, config: &LacunarityConfig) -> Result<LacunarityResult> {
    let w = img.width as usize;
    let h = img.height as usize;
    if w == 0 || h == 0 {
        // The gliding-box sampling below uses `% w` / `% h` for wraparound;
        // a zero dimension would panic on modulo-by-zero (and the loop
        // guards are floored to 1, so the loop is always entered).
        return Err(SpectrumError::InvalidConfiguration(
            "lacunarity requires a non-empty image (zero dimension)".into(),
        ));
    }
    let mut values = Vec::with_capacity(config.scales.len());

    for &side in &config.scales {
        let side = (side as usize).max(2);
        let mut gaps: Vec<f64> = Vec::new();

        match config.algorithm {
            LacunarityAlgorithm::GlidingBox => {
                // Sample overlapping boxes.
                let end_x = w.saturating_sub(side).min(w).max(1);
                let end_y = h.saturating_sub(side).min(h).max(1);
                let mut x = 0;
                let mut y = 0;
                let step = side;
                while y < end_y && gaps.len() < 256 {
                    let mut mass = 0usize;
                    for dy in 0..side {
                        for dx in 0..side {
                            let px = (x + dx) % w;
                            let py = (y + dy) % h;

                            let idx = py * w + px;
                            if idx < img.pixels.len() && img.pixels[idx] > 128 {
                                mass += 1;
                            }
                        }
                    }
                    gaps.push(mass as f64 / (side * side) as f64);
                    if x + step >= end_x && y + step >= end_y {
                        break;
                    }
                    x = (x + step) % end_x;
                    if x < step {
                        y += step;
                    }
                }
            }
            LacunarityAlgorithm::BoxCounting => {
                let cols = (w / side).max(1);
                let rows = (h / side).max(1);
                for by in 0..rows {
                    for bx in 0..cols {
                        let mut mass = 0usize;
                        for dy in 0..side {
                            for dx in 0..side {
                                let y = by * side + dy;
                                let x = bx * side + dx;
                                if y < h && x < w {
                                    let idx = y * w + x;
                                    if idx < img.pixels.len() && img.pixels[idx] > 128 {
                                        mass += 1;
                                    }
                                }
                            }
                        }
                        gaps.push(mass as f64 / (side * side) as f64);
                    }
                }
            }
        }
        values.push(compute_lacunarity(&gaps));
    }

    let entropy_bits = compute_entropy_bits(&values).clamp(4.0, 8.0);
    Ok(LacunarityResult {
        values,
        config: config.clone(),
        entropy_bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_image_has_low_lacunarity() {
        let img = Image::from_luma(128, 128, vec![255u8; 128 * 128]).unwrap();
        let cfg = LacunarityConfig::auto_detect(1.0, false);
        let res = extract_lacunarity(&img, &cfg).unwrap();
        // ~1.0 for homogeneous occupancy.
        for v in &res.values {
            assert!((v - 1.0).abs() < 1e-6, "got {v}");
        }
    }

    #[test]
    fn zero_dimension_image_is_rejected_not_panic() {
        // Regression: the gliding-box path computed `(x + dx) % w`; with a
        // zero dimension that is a modulo-by-zero panic on a public API
        // (`Image::from_luma(0, n, …)` is a legal constructor).
        let cfg = LacunarityConfig::new(vec![2, 4], LacunarityAlgorithm::GlidingBox);
        let img_w0 = Image::from_luma(0, 2, vec![]).unwrap();
        assert!(extract_lacunarity(&img_w0, &cfg).is_err());
        let img_h0 = Image::from_luma(2, 0, vec![]).unwrap();
        assert!(extract_lacunarity(&img_h0, &cfg).is_err());
        // Density of an empty image is an honest 0.0, not NaN.
        assert_eq!(pixel_density(&Image::from_luma(0, 0, vec![]).unwrap()), 0.0);
    }
}
