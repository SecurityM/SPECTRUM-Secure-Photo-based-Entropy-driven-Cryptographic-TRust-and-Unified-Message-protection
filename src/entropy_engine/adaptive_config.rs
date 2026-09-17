//! Adaptive image-property analysis that steers per-source configuration.

use crate::entropy_engine::sources::gradient::{gradient_magnitudes, mean_gradient_magnitude};
use crate::entropy_engine::sources::lacunarity::{has_clusters, pixel_density};
use crate::image::Image;

/// Coarse complexity bands used by table-driven configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplexityBucket {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Aggregate adaptive properties of an image.
#[derive(Debug, Clone)]
pub struct AdaptiveConfig {
    /// Global complexity in [0, 1].
    pub complexity: f64,
    pub edge_strength: f64,
    pub oscillation_strength: f64,
    pub pixel_density: f64,
    pub cluster_presence: bool,
}

impl AdaptiveConfig {
    /// Complexity divided into a bucket.
    pub fn bucket(&self) -> ComplexityBucket {
        match self.complexity {
            c if c < 0.2 => ComplexityBucket::VeryLow,
            c if c < 0.4 => ComplexityBucket::Low,
            c if c < 0.6 => ComplexityBucket::Medium,
            c if c < 0.8 => ComplexityBucket::High,
            _ => ComplexityBucket::VeryHigh,
        }
    }
}

/// Analyze image properties used for adaptive configuration.
pub fn analyze(img: &Image) -> AdaptiveConfig {
    let complexity = measure_complexity(img);
    let edge_strength = measure_edge_strength(img);
    let oscillation_strength = measure_oscillations(img);
    let density = pixel_density(img);
    let cluster_presence = has_clusters(img);

    AdaptiveConfig {
        complexity,
        edge_strength,
        oscillation_strength,
        pixel_density: density,
        cluster_presence,
    }
}

/// Coefficient-of-variation of gradient magnitudes, normalized to [0, 1].
pub fn measure_complexity(img: &Image) -> f64 {
    let mags = gradient_magnitudes(img);
    if mags.len() < 16 {
        return 0.0;
    }
    let mean = mags.iter().sum::<f64>() / mags.len() as f64;
    let variance = mags.iter().map(|m| (m - mean).powi(2)).sum::<f64>() / mags.len() as f64;
    let std_dev = variance.sqrt();
    (std_dev / (mean + 1e-6)).clamp(0.0, 1.0)
}

/// Mean gradient magnitude in [0, 1].
pub fn measure_edge_strength(img: &Image) -> f64 {
    mean_gradient_magnitude(img)
}

/// Zero-crossing density taken along the first image row.
pub fn measure_oscillations(img: &Image) -> f64 {
    let w = img.width as usize;
    // The scan reads the first row (pixels[0..w]); a buffer shorter than the
    // row (e.g. width > 0 with height 0 — legal via Image::from_luma) must
    // yield a neutral 0 instead of indexing out of bounds.
    if w < 4 || img.pixels.len() < w {
        return 0.0;
    }
    let mut crossings = 0usize;
    for i in 2..w {
        let a = f64::from(img.pixels[i - 2]);
        let b = f64::from(img.pixels[i - 1]);
        let c = f64::from(img.pixels[i]);
        if (b - a).signum() * (c - b).signum() < 0.0 {
            crossings += 1;
        }
    }
    (crossings as f64 / w as f64).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_image_low_complexity() {
        let img = Image::from_luma(128, 128, vec![128u8; 128 * 128]).unwrap();
        let c = measure_complexity(&img);
        assert!(c < 0.1);
    }

    #[test]
    fn textured_image_higher_complexity() {
        let noise: Vec<u8> = (0..128 * 128).map(|i| (i * 17 % 256) as u8).collect();
        let img = Image::from_luma(128, 128, noise).unwrap();
        assert!(measure_complexity(&img) > 0.1);
    }

    #[test]
    fn degenerate_dimensions_never_panic() {
        // width > 0 with an empty buffer (height 0) used to index out of
        // bounds in measure_oscillations; the whole adaptive analysis must
        // tolerate it now.
        let img = Image::from_luma(64, 0, vec![]).unwrap();
        assert_eq!(measure_oscillations(&img), 0.0);
        let cfg = analyze(&img);
        assert_eq!(cfg.complexity, 0.0);
        assert!(!cfg.cluster_presence);
        // Zero width too.
        let img = Image::from_luma(0, 8, vec![]).unwrap();
        let cfg = analyze(&img);
        assert_eq!(cfg.oscillation_strength, 0.0);
    }
}
