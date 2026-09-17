//! Small deterministic helpers shared by the fractal-analysis stages.
//!
//! Everything here is a pure function of its inputs (no RNG, no filesystem),
//! mirroring the determinism guarantee the whole entropy engine relies on.

use crate::error::{Result, SpectrumError};
use crate::image::Image;

/// Convert an 8-bit grayscale image into `f64` luminance normalized to
/// `[0, 1]`. The buffer is assumed to be row-major (`pixels[y * width + x]`).
pub fn to_luma_f64(img: &Image) -> Vec<f64> {
    img.pixels.iter().map(|&p| f64::from(p) / 255.0).collect()
}

/// Validate that the luminance buffer matches its declared dimensions and is
/// large enough for multi-scale analysis (box-size ladders need headroom:
/// sub-16px planes leave fewer than two usable box sizes per stage).
pub fn validate_lattice(buf: &[f64], width: usize, height: usize) -> Result<()> {
    if buf.len() != width * height {
        return Err(SpectrumError::InvalidConfiguration(format!(
            "fractal analysis buffer length {} does not match {width}x{height}",
            buf.len()
        )));
    }
    if width < 16 || height < 16 {
        return Err(SpectrumError::InvalidConfiguration(format!(
            "fractal analysis requires at least 16x16 pixels, got {width}x{height}"
        )));
    }
    Ok(())
}

/// Powers of two from `2` up to and including `cap`, pruned to `max_sizes`
/// entries at most. Used to build the multi-scale ladder of the box-counting,
/// lacunarity and multifractal stages.
pub fn power_of_two_sizes(cap: usize, max_sizes: usize) -> Vec<usize> {
    let mut sizes = Vec::new();
    let mut s = 2usize;
    while s <= cap.max(1) && sizes.len() < max_sizes.max(1) {
        sizes.push(s);
        s = s.saturating_mul(2);
    }
    sizes
}

/// Ordinary-least-squares fit of `ys` against `xs`, returning the slope,
/// intercept and coefficient of determination `R²`. `None` when there are
/// fewer than two usable points or the denominator collapses.
pub fn least_squares(xs: &[f64], ys: &[f64]) -> Option<(f64, f64, f64)> {
    let n = xs.len().min(ys.len());
    if n < 2 {
        return None;
    }
    let mean_x = xs[..n].iter().sum::<f64>() / n as f64;
    let mean_y = ys[..n].iter().sum::<f64>() / n as f64;
    let mut s_xx = 0.0;
    let mut s_xy = 0.0;
    for i in 0..n {
        let dx = xs[i] - mean_x;
        let dy = ys[i] - mean_y;
        s_xx += dx * dx;
        s_xy += dx * dy;
    }
    if s_xx <= 1e-12 {
        return None;
    }
    let slope = s_xy / s_xx;
    let intercept = mean_y - slope * mean_x;

    let mut s_res = 0.0;
    let mut s_tot = 0.0;
    for i in 0..n {
        let fit = slope * xs[i] + intercept;
        let d_res = ys[i] - fit;
        let d_tot = ys[i] - mean_y;
        s_res += d_res * d_res;
        s_tot += d_tot * d_tot;
    }
    let r2 = if s_tot <= 1e-12 {
        // All ys identical: the fit is perfect, but the relation carries no
        // information; report a neutral 0.5.
        0.5
    } else {
        (1.0 - s_res / s_tot).clamp(0.0, 1.0)
    };
    Some((slope, intercept, r2))
}

/// Shannon entropy (bits per symbol, `0..=8`) of a byte distribution.
pub fn byte_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut hist = [0usize; 256];
    for &b in bytes {
        hist[b as usize] += 1;
    }
    let total = bytes.len() as f64;
    -hist
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            p * p.log2()
        })
        .sum::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luma_normalization_bounds() {
        let img = Image::from_luma(4, 4, (0u8..=15).collect()).unwrap();
        let g = to_luma_f64(&img);
        assert_eq!(g.len(), 16);
        assert!(g.iter().all(|&v| (0.0..=1.0).contains(&v)));
        assert_eq!(g[0], 0.0);
        assert!((g[15] - 15.0 / 255.0).abs() < 1e-12);
    }

    #[test]
    fn least_squares_exact_line() {
        let xs: Vec<f64> = (0..10).map(f64::from).collect();
        let ys: Vec<f64> = xs.iter().map(|x| 2.0 * x + 1.0).collect();
        let (slope, intercept, r2) = least_squares(&xs, &ys).unwrap();
        assert!((slope - 2.0).abs() < 1e-9);
        assert!((intercept - 1.0).abs() < 1e-9);
        assert!(r2 > 0.999);
    }

    #[test]
    fn least_squares_rejects_short_inputs() {
        assert!(least_squares(&[1.0], &[1.0]).is_none());
        assert!(least_squares(&[1.0, 2.0], &[3.0, 3.0]).is_some());
    }

    #[test]
    fn power_of_two_ladder_is_bounded() {
        assert_eq!(
            power_of_two_sizes(256, 32),
            vec![2, 4, 8, 16, 32, 64, 128, 256]
        );
        assert_eq!(power_of_two_sizes(200, 32), vec![2, 4, 8, 16, 32, 64, 128]);
        assert_eq!(power_of_two_sizes(100, 3), vec![2, 4, 8]);
    }

    #[test]
    fn byte_entropy_extremes() {
        assert_eq!(byte_entropy(&[7u8; 64]), 0.0);
        let uniform: Vec<u8> = (0..256u16).map(|v| v as u8).collect();
        let e = byte_entropy(&uniform);
        assert!((e - 8.0).abs() < 0.01, "got {e}");
    }
}
