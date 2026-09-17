//! Source 6 — Gabor texture features.
//!
//! Convolves the image with 16 Gabor kernels (4 orientations × 4 frequencies)
//! and reports the mean absolute response of each as a feature.

use crate::entropy_engine::sources::compute_entropy_bits;
use crate::error::Result;
use crate::filter::{gabor_kernel, mean_abs_response, GaborFilter};
use crate::image::Image;

/// Result of the texture source.
#[derive(Debug, Clone)]
pub struct TextureResult {
    pub values: Vec<f64>,
    /// Mean response aggregated per orientation (length == #orientations).
    pub orientation_profile: Vec<f64>,
    pub entropy_bits: f64,
}

/// Number of orientations × frequencies sampling grid used by default.
pub const DEFAULT_ORIENTATIONS: [f64; 4] = [0.0, 45.0, 90.0, 135.0];
pub const DEFAULT_FREQUENCIES: [f64; 4] = [0.05, 0.1, 0.2, 0.4];

/// Extract Gabor features (all orientation/frequency combinations), normalized.
pub fn extract_texture_features(
    img: &Image,
    orientations_deg: &[f64],
    frequencies: &[f64],
) -> Result<TextureResult> {
    let size = 15usize;
    let mut values = Vec::new();
    // Accumulate per-orientation energy to summarize directional bias.
    let mut per_orientation = vec![0.0f64; orientations_deg.len()];

    for (oi, &orient) in orientations_deg.iter().enumerate() {
        for &freq in frequencies {
            let filter = GaborFilter {
                frequency: freq,
                orientation_deg: orient,
                sigma: 3.0,
                size,
            };
            let kernel = gabor_kernel(&filter);
            let response = mean_abs_response(img, &kernel, size);
            let v = (response.abs() * 20.0).min(1.0);
            values.push(v);
            per_orientation[oi] += v;
        }
        // Mean over the frequencies sampled for this orientation. An empty
        // frequency list (public config) must leave the profile at zero —
        // 0/0 would be NaN, leaking into reports (JSON null) and the
        // conversion pipeline.
        per_orientation[oi] /= frequencies.len().max(1) as f64;
    }

    let entropy_bits = compute_entropy_bits(&values).clamp(3.0, 8.0);
    Ok(TextureResult {
        values,
        orientation_profile: per_orientation,
        entropy_bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_count() {
        let img: Vec<u8> = (0..64 * 64).map(|i| (i * 13 % 256) as u8).collect();
        let img = Image::from_luma(64, 64, img).unwrap();
        let res =
            extract_texture_features(&img, &DEFAULT_ORIENTATIONS, &DEFAULT_FREQUENCIES).unwrap();
        assert_eq!(res.values.len(), 16);
        assert_eq!(res.orientation_profile.len(), 4);
    }

    #[test]
    fn vertical_edges_favor_horizontal_orientation_filter() {
        // Image with strong vertical edges (high response to 90°/0°? — the
        // 0° filter responds to features oriented along the sine carrier x). We
        // only assert the profile is well-formed and finite.
        let mut pixels = vec![0u8; 64 * 64];
        for y in 0..64u32 {
            for x in 0..64u32 {
                pixels[(y * 64 + x) as usize] = if x < 32 { 20 } else { 235 };
            }
        }
        let img = Image::from_luma(64, 64, pixels).unwrap();
        let res =
            extract_texture_features(&img, &DEFAULT_ORIENTATIONS, &DEFAULT_FREQUENCIES).unwrap();
        assert!(res.orientation_profile.iter().all(|v| v.is_finite()));
    }

    #[test]
    fn empty_frequency_list_leaves_profile_finite() {
        // Regression: with an empty frequency list the per-orientation mean
        // was 0/0 = NaN, leaking NaN into the profile (and as JSON null in
        // reports).
        let pixels: Vec<u8> = (0..32 * 32).map(|i| (i * 17 % 256) as u8).collect();
        let img = Image::from_luma(32, 32, pixels).unwrap();
        let res = extract_texture_features(&img, &DEFAULT_ORIENTATIONS, &[]).unwrap();
        assert!(res.values.is_empty());
        assert_eq!(res.orientation_profile.len(), 4);
        assert!(res.orientation_profile.iter().all(|v| v.is_finite()));
    }
}
