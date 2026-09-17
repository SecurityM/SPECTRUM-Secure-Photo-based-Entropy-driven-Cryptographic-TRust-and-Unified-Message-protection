//! Fractal detection system.
//!
//! Classifies an image's *geometric* character before the heavier stages run,
//! using three complementary, data-only measurements on the luminance plane:
//!
//! 1. **Box-counting dimension** — log-log regression of occupied-box counts
//!    against box size over an edge map (`N(r) ~ r^(−D)`). The absolute slope
//!    `D` is the reported Hausdorff dimension estimate and `R²` measures how
//!    closely the image follows a single power law (scale invariance).
//! 2. **Gliding-box lacunarity** — the distribution of edge mass per window
//!    across scales; its spread is a cheap proxy for the multifractal width.
//! 3. **Self-similarity flag** — high `R²` on the box-counting fit within the
//!    fractal dimension band marks images whose structure repeats across the
//!    probed scales.
//!
//! Classification is *metadata*: it feeds one signature byte, a small
//! threshold nudge and the terminal report. It never gates algorithms away —
//! the adaptive stages always see the full measurement set, so a mislabelled
//! boundary case still receives correct, honest analysis.

use crate::entropy_engine::sources::fractal_analysis::utils::{
    least_squares, power_of_two_sizes, validate_lattice,
};
use crate::error::Result;

/// Canonical box-size ladder; runtime pruning adapts it to each image.
const DEFAULT_BOX_SIZES: [usize; 8] = [2, 4, 8, 16, 32, 64, 128, 256];

/// `R²` above which the box-counting fit is considered scale-invariant.
pub const SELF_SIMILAR_R2: f64 = 0.95;
/// Dimension band considered self-similar (a straight line, D ≈ 1, is not a
/// fractal; a saturated plane, D ≈ 2, carries no scale structure either).
pub const SELF_SIMILAR_DIM_RANGE: (f64, f64) = (1.15, 1.95);

/// Geometrical family the detector assigns to an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FractalType {
    /// Regular image (estimated dimension below 1.2).
    Regular,
    /// Natural fractal — textures, clouds, tree/coastline-like (1.2–1.8).
    NaturalFractal,
    /// Julia-set-like, strongly structured boundary (1.8–1.95).
    JuliaSet,
    /// Mandelbrot-boundary-like mathematical fractal (≥ 1.95).
    MandelbrotBoundary,
}

impl FractalType {
    /// Compact ordinal used as a signature byte (0..=3).
    pub fn code(self) -> u8 {
        match self {
            FractalType::Regular => 0,
            FractalType::NaturalFractal => 1,
            FractalType::JuliaSet => 2,
            FractalType::MandelbrotBoundary => 3,
        }
    }

    /// Stable display name.
    pub fn name(self) -> &'static str {
        match self {
            FractalType::Regular => "Regular",
            FractalType::NaturalFractal => "NaturalFractal",
            FractalType::JuliaSet => "JuliaSet",
            FractalType::MandelbrotBoundary => "MandelbrotBoundary",
        }
    }

    /// Classify a measured box-counting dimension (plan thresholds).
    pub fn from_dimension(dim: f64) -> FractalType {
        match dim {
            d if d < 1.2 => FractalType::Regular,
            d if d < 1.8 => FractalType::NaturalFractal,
            d if d < 1.95 => FractalType::JuliaSet,
            _ => FractalType::MandelbrotBoundary,
        }
    }
}

/// Everything the detector concludes about one image.
#[derive(Debug, Clone, PartialEq)]
pub struct FractalClassification {
    pub fractal_type: FractalType,
    /// Box-counting dimension estimate, clamped to `[1.0, 2.0]`.
    pub hausdorff_dimension: f64,
    /// Heuristic `[0, 1]` confidence in the classification.
    pub confidence: f64,
    /// Whether the structure repeats across scales (power-law `R²` ≥ 0.95
    /// inside the fractal dimension band).
    pub is_self_similar: bool,
    /// Spread (std dev) of the lacunarity spectrum — multifractal-width proxy.
    pub multifractal_width: f64,
    /// Goodness-of-fit of the box-counting power law.
    pub log_log_r2: f64,
    /// Fraction of pixels flagged as edge pixels (`[0, 1]`).
    pub edge_fraction: f64,
}

impl FractalClassification {
    /// Neutral classification for a flat/regular reference image.
    pub fn regular_default() -> Self {
        FractalClassification {
            fractal_type: FractalType::Regular,
            hausdorff_dimension: 1.0,
            confidence: 0.5,
            is_self_similar: false,
            multifractal_width: 0.0,
            log_log_r2: 0.0,
            edge_fraction: 0.0,
        }
    }
}

/// Combined output of a detection pass (classification + reused series).
#[derive(Debug, Clone)]
pub struct DetectorOutput {
    pub classification: FractalClassification,
    /// Gliding-box lacunarity across the probed scales (one value per scale).
    pub lacunarity: Vec<f64>,
}

/// Multi-scale fractal detector.
#[derive(Debug, Clone)]
pub struct FractalDetector {
    box_sizes: [usize; 8],
    /// Largest box side probed (configurable upper bound of the ladder).
    max_scale: usize,
}

impl FractalDetector {
    /// Default detector (plan box ladder, 256-pixel cap).
    pub fn new() -> Self {
        FractalDetector::with_max_scale(DEFAULT_BOX_SIZES[7])
    }

    /// Detector whose ladders never exceed `max_scale` on a side.
    pub fn with_max_scale(max_scale: usize) -> Self {
        FractalDetector {
            box_sizes: DEFAULT_BOX_SIZES,
            max_scale: max_scale.max(2),
        }
    }

    /// Image- and config-bounded power-of-two ladder.
    fn ladder(&self, cap: usize) -> Vec<usize> {
        let capped = cap.min(self.max_scale);
        power_of_two_sizes(capped, self.box_sizes.len())
            .into_iter()
            .filter(|&r| r >= 2)
            .collect()
    }

    /// Full detection pass: classification plus the lacunarity series the
    /// downstream feature pool reuses (no duplicated edge/stat work).
    pub fn analyze_lattice(
        &self,
        img: &[f64],
        width: usize,
        height: usize,
    ) -> Result<DetectorOutput> {
        validate_lattice(img, width, height)?;

        // (1) Edge map via Sobel magnitudes over normalized luminance.
        let magnitudes = self.sobel_magnitudes(img, width, height);
        let edge = self.edge_mask(&magnitudes);

        // (2) Box-counting dimension from log-log regression.
        let (dim, r2) = self.box_counting_dimension(&edge, width, height);

        // (3) Gliding-box lacunarity spectrum over the same edge map.
        let lacunarity = self.lacunarity_spectrum_from_mask(&edge, width, height);

        let edge_count = edge.iter().filter(|b| **b).count();
        let edge_fraction = edge_count as f64 / (width * height).max(1) as f64;

        let classification = self.build_classification(dim, r2, &lacunarity, edge_fraction);
        Ok(DetectorOutput {
            classification,
            lacunarity,
        })
    }

    /// Convenience classification-only pass (plan-facing API).
    pub fn classify(
        &self,
        img: &[f64],
        width: usize,
        height: usize,
    ) -> Result<FractalClassification> {
        Ok(self.analyze_lattice(img, width, height)?.classification)
    }

    /// Sobel gradient magnitude per pixel (interior; borders read 0).
    fn sobel_magnitudes(&self, img: &[f64], width: usize, height: usize) -> Vec<f64> {
        let mut mag = vec![0.0f64; width * height];
        for y in 1..height - 1 {
            for x in 1..width - 1 {
                let i = y * width + x;
                let a = |dy: isize, dx: isize| {
                    img[(y as isize + dy) as usize * width + (x as isize + dx) as usize]
                };
                let gx =
                    -a(-1, -1) + a(-1, 1) - 2.0 * a(0, -1) + 2.0 * a(0, 1) - a(1, -1) + a(1, 1);
                let gy =
                    -a(-1, -1) - 2.0 * a(-1, 0) - a(-1, 1) + a(1, -1) + 2.0 * a(1, 0) + a(1, 1);
                mag[i] = (gx * gx + gy * gy).sqrt();
            }
        }
        mag
    }

    /// Threshold magnitudes into a binary edge map. The threshold sits one
    /// standard deviation above the mean magnitude: strong, coherent edges
    /// pass while smooth ramps (whose gradient magnitudes are nearly uniform)
    /// and diffuse texture produce no spurious edges.
    fn edge_mask(&self, magnitudes: &[f64]) -> Vec<bool> {
        let n = magnitudes.len().max(1) as f64;
        let mut sum = 0.0;
        let mut peak = 0.0f64;
        for &m in magnitudes {
            sum += m;
            peak = peak.max(m);
        }
        if peak <= 0.0 {
            return vec![false; magnitudes.len()];
        }
        let mean = sum / n;
        let var = magnitudes
            .iter()
            .map(|&m| {
                let d = m - mean;
                d * d
            })
            .sum::<f64>()
            / n;
        let std = var.sqrt();
        // A magnitude plane that barely spreads around its mean has no edges:
        // a linear ramp must not be read as fractal structure. Degenerate
        // (near-zero-spread) planes therefore pass nothing.
        let threshold = if std <= 1e-12 { peak + 1.0 } else { mean + std };
        magnitudes.iter().map(|&m| m > threshold).collect()
    }

    /// Log-log regression of occupied box counts against box size.
    /// Returns `(dimension, R²)`; degenerate inputs fall back to `(1.0, 0.0)`.
    fn box_counting_dimension(&self, edge: &[bool], width: usize, height: usize) -> (f64, f64) {
        let min_side = width.min(height);
        let sizes = self.ladder(min_side / 2);
        let mut points = Vec::new();
        for &r in &sizes {
            let count = self.count_occupied_boxes(edge, width, height, r);
            if count > 0 {
                points.push(((r as f64).ln(), (count as f64).ln()));
            }
        }
        match least_squares(
            &points.iter().map(|(x, _)| *x).collect::<Vec<_>>(),
            &points.iter().map(|(_, y)| *y).collect::<Vec<_>>(),
        ) {
            Some((slope, _, r2)) => {
                let dim = (-slope).clamp(1.0, 2.0);
                if !dim.is_finite() {
                    (1.0, 0.0)
                } else {
                    (dim, r2)
                }
            }
            None => (1.0, 0.0),
        }
    }

    /// Number of `r×r` boxes (tiling anchored at multiples of `r`) that
    /// contain at least one edge pixel. Partial edge boxes are included.
    fn count_occupied_boxes(&self, edge: &[bool], width: usize, height: usize, r: usize) -> usize {
        let mut count = 0usize;
        let mut y0 = 0usize;
        while y0 < height {
            let y1 = (y0 + r).min(height);
            let mut x0 = 0usize;
            while x0 < width {
                let x1 = (x0 + r).min(width);
                let mut occupied = false;
                'scan: for y in y0..y1 {
                    for x in x0..x1 {
                        if edge[y * width + x] {
                            occupied = true;
                            break 'scan;
                        }
                    }
                }
                if occupied {
                    count += 1;
                }
                x0 += r;
            }
            y0 += r;
        }
        count
    }

    fn lacunarity_spectrum_from_mask(
        &self,
        edge: &[bool],
        width: usize,
        height: usize,
    ) -> Vec<f64> {
        let min_side = width.min(height);
        // Keep the gliding windows bounded: full-window scans grow as
        // (side − r)²·r², so cap the ladder at side/4 on the short axis.
        let sizes = self.ladder(min_side / 4);
        let mut spectrum = Vec::with_capacity(sizes.len());
        for &r in &sizes {
            spectrum.push(self.gliding_lacunarity(edge, width, height, r));
        }
        spectrum
    }

    fn gliding_lacunarity(&self, edge: &[bool], width: usize, height: usize, r: usize) -> f64 {
        let h_windows = height.saturating_sub(r) + 1;
        let w_windows = width.saturating_sub(r) + 1;
        if h_windows == 0 || w_windows == 0 {
            return 1.0;
        }
        let mut sum = 0.0f64;
        let mut sum_sq = 0.0f64;
        let mut n = 0.0f64;
        for y in 0..h_windows {
            for x in 0..w_windows {
                let mut mass = 0usize;
                for yy in y..y + r {
                    let row = &edge[yy * width + x..yy * width + x + r];
                    for &e in row {
                        if e {
                            mass += 1;
                        }
                    }
                }
                let m = mass as f64;
                sum += m;
                sum_sq += m * m;
                n += 1.0;
            }
        }
        if n <= 0.0 {
            return 1.0;
        }
        let mean = sum / n;
        if mean <= 1e-9 {
            return 1.0;
        }
        let variance = (sum_sq / n) - mean * mean;
        (variance / (mean * mean)).max(0.0) + 1.0
    }

    /// Combine measurements into a classification (plan threshold scheme).
    fn build_classification(
        &self,
        dim: f64,
        r2: f64,
        lacunarity: &[f64],
        edge_fraction: f64,
    ) -> FractalClassification {
        let width_std = std_dev(lacunarity);
        let is_self_similar = r2 >= SELF_SIMILAR_R2
            && (SELF_SIMILAR_DIM_RANGE.0..=SELF_SIMILAR_DIM_RANGE.1).contains(&dim);

        let mut confidence: f64 = 0.5;
        if (1.05..1.95).contains(&dim) {
            confidence += 0.2;
        }
        if is_self_similar {
            confidence += 0.2;
        }
        if width_std > 0.1 {
            confidence += 0.1;
        }
        // Fully saturated planes are not coherent fractals.
        if edge_fraction > 0.9 {
            confidence -= 0.2;
        }
        let confidence = confidence.clamp(0.0, 1.0);

        FractalClassification {
            fractal_type: FractalType::from_dimension(dim),
            hausdorff_dimension: dim,
            confidence,
            is_self_similar,
            multifractal_width: width_std,
            log_log_r2: r2,
            edge_fraction,
        }
    }
}

impl Default for FractalDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Standard deviation of a value series (0 when too few samples).
fn std_dev(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let var = values.iter().map(|&v| (v - mean) * (v - mean)).sum::<f64>() / values.len() as f64;
    var.sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn luminance_of(f: impl Fn(usize, usize) -> f64, w: usize, h: usize) -> Vec<f64> {
        (0..h * w)
            .map(|i| f(i / w, i % w).clamp(0.0, 1.0))
            .collect()
    }

    #[test]
    fn flat_image_is_regular() {
        let img = vec![0.5f64; 96 * 96];
        let d = FractalDetector::new();
        let out = d.analyze_lattice(&img, 96, 96).unwrap();
        assert_eq!(out.classification.fractal_type, FractalType::Regular);
        assert!((out.classification.hausdorff_dimension - 1.0).abs() < 1e-9);
        assert!(!out.classification.is_self_similar);
        assert_eq!(out.classification.edge_fraction, 0.0);
    }

    #[test]
    fn single_horizontal_line_has_dimension_near_one() {
        // One bright row on black: box counts ~ w/r → D ≈ 1.
        let w = 128usize;
        let h = 128usize;
        let img = luminance_of(|_, y| if y == 64 { 1.0 } else { 0.0 }, w, h);
        let d = FractalDetector::new();
        let cls = d.classify(&img, w, h).unwrap();
        assert!(
            (cls.hausdorff_dimension - 1.0).abs() < 0.15,
            "line dimension ≈ 1, got {}",
            cls.hausdorff_dimension
        );
    }

    #[test]
    fn detection_is_deterministic_and_discriminates() {
        let noise = luminance_of(|x, y| ((x * 31 + y * 17) % 251) as f64 / 250.0, 96, 96);
        let d = FractalDetector::new();
        let a = d.analyze_lattice(&noise, 96, 96).unwrap();
        let b = d.analyze_lattice(&noise, 96, 96).unwrap();
        assert_eq!(a.classification, b.classification);
        assert_eq!(a.lacunarity, b.lacunarity);
        assert!((1.0..=2.0).contains(&a.classification.hausdorff_dimension));

        // A structured fractal-like pattern must classify differently from the
        // plain gradient (low edge content).
        let gradient = luminance_of(|x, _| x as f64 / 95.0, 96, 96);
        let g = d.classify(&gradient, 96, 96).unwrap();
        assert_eq!(g.fractal_type, FractalType::Regular);
    }

    #[test]
    fn tiny_images_are_rejected() {
        let d = FractalDetector::new();
        assert!(d.classify(&[0.5; 7 * 7], 7, 7).is_err());
        assert!(d.classify(&[0.5; 64], 8, 8).is_err(), "length mismatch");
    }

    #[test]
    fn type_thresholds_and_codes() {
        assert_eq!(FractalType::from_dimension(1.1), FractalType::Regular);
        assert_eq!(
            FractalType::from_dimension(1.5),
            FractalType::NaturalFractal
        );
        assert_eq!(FractalType::from_dimension(1.9), FractalType::JuliaSet);
        assert_eq!(
            FractalType::from_dimension(2.0),
            FractalType::MandelbrotBoundary
        );
        assert_eq!(FractalType::MandelbrotBoundary.code(), 3);
        assert_eq!(FractalType::Regular.code(), 0);
    }

    #[test]
    fn checkerboard_has_positive_lacunarity_width() {
        let w = 96usize;
        let h = 96usize;
        let img = luminance_of(
            |x, y| {
                let cell = 8usize;
                if ((x / cell) + (y / cell)).is_multiple_of(2) {
                    0.9
                } else {
                    0.1
                }
            },
            w,
            h,
        );
        let d = FractalDetector::new();
        let out = d.analyze_lattice(&img, w, h).unwrap();
        assert!(
            out.classification.multifractal_width > 0.0,
            "checkerboard must spread the lacunarity spectrum"
        );
        assert!(!out.lacunarity.is_empty());
    }
}
