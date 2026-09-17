//! Source 7 — Noise characteristics.
//!
//! Estimates the sensor noise magnitude via a Laplacian filter and classifies
//! the dominant noise type (Gaussian / Poisson / salt-and-pepper / none).

use crate::error::Result;
use crate::filter::laplacian_response;
use crate::image::Image;

/// Classified noise type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseType {
    Gaussian,
    Poisson,
    SaltAndPepper,
    Uniform,
    None,
}

impl NoiseType {
    pub fn name(self) -> &'static str {
        match self {
            NoiseType::Gaussian => "gaussian",
            NoiseType::Poisson => "poisson",
            NoiseType::SaltAndPepper => "salt-and-pepper",
            NoiseType::Uniform => "uniform",
            NoiseType::None => "none",
        }
    }
}

/// Noise profile result.
#[derive(Debug, Clone, PartialEq)]
pub struct NoiseProfile {
    pub noise_type: NoiseType,
    pub magnitude: f64,
}

/// Result of the noise source.
#[derive(Debug, Clone)]
pub struct NoiseResult {
    pub profile: NoiseProfile,
    /// (mean block std-dev, block-std coefficient of variation).
    pub block_stats: (f64, f64),
    pub entropy_bits: f64,
}

/// Estimated global noise magnitude (RMS of Laplacian response) in [0, 1].
pub fn estimate_noise_variance(img: &Image) -> f64 {
    let resp = laplacian_response(img);
    if resp.is_empty() {
        return 0.0;
    }
    let sum_sq: f64 = resp.iter().map(|v| v * v).sum::<f64>() / resp.len() as f64;
    (sum_sq / 16.0).sqrt() / 64.0
}

/// Block-wise noise statistics: per-block standard deviation and the spread of
/// those block stats across the image (higher spread ⇒ spatially varying noise).
///
/// Divides the image into a grid of `side×side` blocks and reports:
/// - mean block std-dev (overall noise energy),
/// - coefficient of variation of block std-dev (textural non-uniformity).
pub fn block_noise_stats(img: &Image, side: usize) -> (f64, f64) {
    let side = side.max(2);
    let w = img.width as usize;
    let h = img.height as usize;
    let cols = (w as f64 / side as f64).ceil() as usize;
    let rows = (h as f64 / side as f64).ceil() as usize;

    let mut block_stds = Vec::new();
    for br in 0..rows {
        for bc in 0..cols {
            let x0 = bc * side;
            let y0 = br * side;
            let x1 = (x0 + side).min(w);
            let y1 = (y0 + side).min(h);
            let mut sum = 0.0f64;
            let mut n = 0usize;
            for y in y0..y1 {
                for x in x0..x1 {
                    sum += img.pixels[y * w + x] as f64;
                    n += 1;
                }
            }
            if n == 0 {
                continue;
            }
            let mean = sum / n as f64;
            let var = (y0..y1)
                .flat_map(|y| (x0..x1).map(move |x| (img.pixels[y * w + x] as f64 - mean).powi(2)))
                .sum::<f64>()
                / n as f64;
            block_stds.push(var.sqrt() / 255.0);
        }
    }

    if block_stds.is_empty() {
        return (0.0, 0.0);
    }
    let mean_std = block_stds.iter().sum::<f64>() / block_stds.len() as f64;
    let variance = block_stds
        .iter()
        .map(|s| (s - mean_std).powi(2))
        .sum::<f64>()
        / block_stds.len() as f64;
    let cov = if mean_std <= 1e-9 {
        0.0
    } else {
        variance.sqrt() / mean_std
    };
    (mean_std.clamp(0.0, 1.0), cov.clamp(0.0, 1.0))
}

fn detect_noise_type(img: &Image, variance: f64) -> NoiseType {
    if variance < 0.01 {
        return NoiseType::None;
    }
    // Skewness of the normalized histogram discriminates salt-and-pepper.
    let n = img.pixels.len();
    let mean: f64 = img
        .pixels
        .iter()
        .map(|p| f64::from(*p) / 255.0)
        .sum::<f64>()
        / n as f64;
    let skewness = img
        .pixels
        .iter()
        .map(|p| {
            let v = f64::from(*p) / 255.0 - mean;
            v * v * v
        })
        .sum::<f64>()
        / n as f64;

    if skewness.abs() > 0.5 {
        NoiseType::SaltAndPepper
    } else if variance > 0.1 {
        NoiseType::Poisson
    } else if variance > 0.02 {
        NoiseType::Uniform
    } else {
        NoiseType::Gaussian
    }
}

impl NoiseProfile {
    /// Deterministic byte representation (type tag + quantized magnitude).
    pub fn to_bytes(&self) -> Vec<u8> {
        let tag = match self.noise_type {
            NoiseType::None => 0u8,
            NoiseType::Gaussian => 1,
            NoiseType::Poisson => 2,
            NoiseType::SaltAndPepper => 3,
            NoiseType::Uniform => 4,
        };
        let mag = (self.magnitude.clamp(0.0, 1.0) * 255.0).round() as u8;
        vec![tag, mag]
    }
}

/// Extract the noise profile of an image.
pub fn extract_noise_characteristics(img: &Image) -> Result<NoiseResult> {
    let magnitude = estimate_noise_variance(img);
    let noise_type = detect_noise_type(img, magnitude);
    let profile = NoiseProfile {
        noise_type,
        magnitude,
    };
    let block_stats = block_noise_stats(img, 8);

    let base_entropy = match profile.noise_type {
        NoiseType::None => 0.0,
        NoiseType::Gaussian => (profile.magnitude * 20.0).clamp(0.0, 10.0),
        NoiseType::Poisson => (profile.magnitude * 15.0).clamp(0.0, 8.0),
        NoiseType::SaltAndPepper => (profile.magnitude * 10.0).clamp(0.0, 6.0),
        NoiseType::Uniform => (profile.magnitude * 12.0).clamp(0.0, 7.0),
    };
    // Spatially non-uniform noise carries a little extra information.
    let entropy_bits = base_entropy + block_stats.1 * 4.0;

    Ok(NoiseResult {
        profile,
        block_stats,
        entropy_bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noise_profile_bytes() {
        let p = NoiseProfile {
            noise_type: NoiseType::Gaussian,
            magnitude: 0.5,
        };
        assert_eq!(p.to_bytes(), vec![1, 128]);
    }

    #[test]
    fn clean_image_has_low_noise() {
        let img = Image::from_luma(64, 64, vec![100u8; 64 * 64]).unwrap();
        let res = extract_noise_characteristics(&img).unwrap();
        assert_eq!(res.profile.noise_type, NoiseType::None);
    }
}
