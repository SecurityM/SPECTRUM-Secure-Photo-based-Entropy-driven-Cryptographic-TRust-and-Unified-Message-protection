//! Source 8 — "Chaos": chaotic diffusion via the Hénon map + Ascon-Hash256.
//!
//! The whole pixel buffer is first condensed into the map's initial
//! conditions `(x₀, y₀)` (so every pixel steers the seed). The Hénon map
//!
//! ```text
//! xₙ₊₁ = 1 − a·xₙ² + yₙ
//! yₙ₊₁ = b·xₙ
//! ```
//!
//! is then iterated `config.iterations` times with pixel-derived *modifiers*
//! injected into each step; the resulting orbit is a deterministic, chaotic
//! re-mixing of the image bytes. Each step's state is folded back into the
//! attractor's trapping box (a sawtooth wrap) so the orbit can never diverge
//! to ±∞/NaN while still amplifying tiny pixel differences. The full orbit
//! buffer is finally compressed by Ascon-Hash256 into a uniform 256-bit
//! signature, giving ideal avalanche and diffusion of the image bytes.
//!
//! With the default parameters (`a = 1.4`, `b = 0.3`) the map is in its
//! classical chaotic regime.

use ascon_hash256::{AsconHash256, Digest};

use crate::error::{Result, SpectrumError};
use crate::image::Image;

/// Ascon-Hash256 output length in bytes (256 bits).
pub const SIGNATURE_LEN: usize = 32;

/// Default number of Hénon iterations.
pub const DEFAULT_ITERATIONS: usize = 1000;
/// Default Hénon control parameter `a` (classical chaotic value).
pub const DEFAULT_A: f64 = 1.4;
/// Default Hénon control parameter `b`.
pub const DEFAULT_B: f64 = 0.3;

/// Upper bound on `iterations`: keeps the orbit buffer (16 B/iteration) and
/// the hashing cost bounded even under hostile configuration.
pub const MAX_ITERATIONS: usize = 1_000_000;

/// Upper bound on the Hénon control parameters `a`/`b`. The classical chaotic
/// regime lives around a = 1.4; anything past this bound would overflow
/// `a·x²` to ∞ inside the fold and NaN-poison the orbit.
pub const MAX_CHAOS_PARAM: f64 = 1_000.0;

/// Folding interval for the `x` state; it contains the classical attractor.
const X_LO: f64 = -1.3;
const X_SPAN: f64 = 2.6;
/// Folding interval for the `y` state.
const Y_LO: f64 = -0.4;
const Y_SPAN: f64 = 0.8;

/// Peak amplitude of the pixel-derived perturbation injected into `x`.
const PERTURB_X: f64 = 0.05;
/// Peak amplitude of the pixel-derived perturbation injected into `y`.
const PERTURB_Y: f64 = 0.02;
/// State bytes appended to the orbit buffer per iteration (x and y as f64 bits).
const ORBIT_BYTES_PER_ITERATION: usize = 16;
/// Multiplicative stride used to pick the second (y-tap) pixel so the two taps
/// decorrelate even on small images.
const PIXEL_TAP_STRIDE: usize = 31;
/// Fixed offset for the y-tap (co-prime with 256, so taps drift).
const PIXEL_TAP_OFFSET: usize = 17;

/// Configuration of the Hénon-map engine.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ChaosConfig {
    /// Number of chaotic iterations; each step ingests pixel modifiers.
    pub iterations: usize,
    /// Hénon control parameter `a` (default 1.4 → chaotic regime).
    pub a: f64,
    /// Hénon control parameter `b` (default 0.3 → classical attractor).
    pub b: f64,
}

impl Default for ChaosConfig {
    fn default() -> Self {
        ChaosConfig {
            iterations: DEFAULT_ITERATIONS,
            a: DEFAULT_A,
            b: DEFAULT_B,
        }
    }
}

impl ChaosConfig {
    pub fn new(iterations: usize, a: f64, b: f64) -> Self {
        ChaosConfig { iterations, a, b }
    }
}

/// Result of the Chaos source.
#[derive(Debug, Clone)]
pub struct ChaosResult {
    /// Uniform 256-bit Ascon-Hash256 signature of the chaotic orbit.
    pub signature: [u8; SIGNATURE_LEN],
    /// Shannon entropy (bits per byte, 0..=8) of the raw orbit buffer.
    pub orbit_entropy: f64,
    /// The configuration that produced this result (reproducibility echo).
    pub config: ChaosConfig,
    /// Heuristic entropy contribution fed into the strategy/report.
    pub entropy_bits: f64,
}

/// One-shot Ascon-Hash256: a uniform 256-bit digest of `data`.
fn ascon_hash(data: &[u8]) -> [u8; SIGNATURE_LEN] {
    let digest = AsconHash256::digest(data);
    let mut out = [0u8; SIGNATURE_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Sanity-check a configuration before iterating.
fn validate_config(config: &ChaosConfig) -> Result<()> {
    if !(1..=MAX_ITERATIONS).contains(&config.iterations) {
        return Err(SpectrumError::InvalidConfiguration(format!(
            "chaos iterations must be within 1..={MAX_ITERATIONS}, got {}",
            config.iterations
        )));
    }
    // Upper bounds keep every iterate finite: the state is bounded by the
    // trapping box, so a·x² + y ≤ a·1.69 + b must never approach f64::MAX —
    // otherwise `a·x²` overflows to ∞ and the fold wraps it into NaN.
    if !(config.a.is_finite() && config.a > 0.0 && config.a <= MAX_CHAOS_PARAM)
        || !(config.b.is_finite() && config.b > 0.0 && config.b <= MAX_CHAOS_PARAM)
    {
        return Err(SpectrumError::InvalidConfiguration(format!(
            "chaos Hénon parameters must be finite, positive and ≤ {MAX_CHAOS_PARAM}, got a={}, b={}",
            config.a, config.b
        )));
    }
    Ok(())
}

/// Map eight seed bytes into a uniform `[0, 1)` fraction (top 53 bits → full
/// f64 mantissa precision, no NaN/inf bit patterns can leak in).
fn unit_from_seed(seed: &[u8], offset: usize) -> f64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&seed[offset..offset + 8]);
    (u64::from_le_bytes(bytes) >> 11) as f64 / (1u64 << 53) as f64
}

/// Deterministic initial conditions inside the Hénon trapping box, derived
/// from the Ascon digest of the *whole* pixel buffer.
fn initial_conditions(seed: &[u8; SIGNATURE_LEN]) -> (f64, f64) {
    let x = X_LO + unit_from_seed(seed, 0) * X_SPAN;
    let y = Y_LO + unit_from_seed(seed, 8) * Y_SPAN;
    (x, y)
}

/// Sawtooth-fold a finite value into `[lo, lo + span)` so every iterate stays
/// bounded regardless of perturbations, while the map keeps its sensitivity.
/// Non-finite values (unreachable with validated parameters, but not worth a
/// panic) wrap to the box origin instead of poisoning the orbit with NaN.
#[inline]
fn fold_into(value: f64, lo: f64, span: f64) -> f64 {
    if !value.is_finite() {
        return lo;
    }
    lo + (value - lo).rem_euclid(span)
}

/// Shannon entropy (bits per byte) of a byte distribution.
fn byte_entropy(bytes: &[u8]) -> f64 {
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

/// Number of distinct byte values present in `bytes` (1..=32 for a signature).
fn distinct_byte_count(bytes: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut count = 0usize;
    for &b in bytes {
        if !seen[b as usize] {
            seen[b as usize] = true;
            count += 1;
        }
    }
    count
}

/// Extract the Chaos signature of an image.
///
/// 1. The Ascon-Hash256 of the raw pixels seeds `(x₀, y₀)` in the Hénon box.
/// 2. The map runs `config.iterations` times; every step absorbs two pixel
///    modifiers (deterministic taps over the buffer) and folds back into the
///    box, appending 16 raw state bytes to the orbit buffer.
/// 3. Ascon-Hash256 compresses the orbit buffer into a 32-byte signature.
pub fn extract_chaos(img: &Image, config: &ChaosConfig) -> Result<ChaosResult> {
    validate_config(config)?;
    let pixels = &img.pixels;
    if pixels.is_empty() {
        return crate::error::bad("chaos requires a non-empty pixel buffer");
    }
    let n = pixels.len();

    // (1) Seed: fold a digest of every pixel into the map's initial state.
    let seed = ascon_hash(pixels);
    let (mut x, mut y) = initial_conditions(&seed);

    // (2) Chaotic orbit with injected pixel modifiers.
    let mut orbit = Vec::with_capacity(config.iterations * ORBIT_BYTES_PER_ITERATION);
    for i in 0..config.iterations {
        let px = f64::from(pixels[i % n]) / 255.0;
        let py = f64::from(pixels[(i * PIXEL_TAP_STRIDE + PIXEL_TAP_OFFSET) % n]) / 255.0;

        let nx = 1.0 - config.a * x * x + y + (px - 0.5) * 2.0 * PERTURB_X;
        let ny = config.b * x + (py - 0.5) * 2.0 * PERTURB_Y;

        x = fold_into(nx, X_LO, X_SPAN);
        y = fold_into(ny, Y_LO, Y_SPAN);

        orbit.extend_from_slice(&x.to_bits().to_le_bytes());
        orbit.extend_from_slice(&y.to_bits().to_le_bytes());
    }

    // (3) Uniform 256-bit signature of the whole orbit.
    let signature = ascon_hash(&orbit);

    // Heuristic contribution score (mirrors the scalar-source scaling used by
    // the Hurst/gradient engines): orbit uniformity (0..=8 bits) boosted by
    // how many distinct values the 32-byte signature already exhibits.
    let orbit_entropy = byte_entropy(&orbit);
    let distinct = distinct_byte_count(&signature);
    let entropy_bits =
        (orbit_entropy + 4.0 * (distinct as f64 / SIGNATURE_LEN as f64)).clamp(4.0, 12.0);

    Ok(ChaosResult {
        signature,
        orbit_entropy,
        config: config.clone(),
        entropy_bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_image(seed: u8) -> Image {
        let pixels: Vec<u8> = (0..64 * 64)
            .map(|i| ((i * 31 + usize::from(seed)) % 256) as u8)
            .collect();
        Image::from_luma(64, 64, pixels).unwrap()
    }

    #[test]
    fn hostile_henon_parameters_are_rejected() {
        // a·x² must never overflow: an unbounded `a` used to wrap ∞ into a
        // NaN orbit inside the fold (and trip the old debug_assert).
        let img = sample_image(2);
        assert!(extract_chaos(&img, &ChaosConfig::new(10, 1e308, 0.3)).is_err());
        assert!(extract_chaos(&img, &ChaosConfig::new(10, 1.4, 1e308)).is_err());
        assert!(extract_chaos(&img, &ChaosConfig::new(10, -1.0, 0.3)).is_err());
        assert!(extract_chaos(&img, &ChaosConfig::new(10, f64::NAN, 0.3)).is_err());
        // Boundary values are accepted and produce a sane, finite orbit.
        let ok = extract_chaos(
            &img,
            &ChaosConfig::new(10, MAX_CHAOS_PARAM, MAX_CHAOS_PARAM),
        )
        .unwrap();
        assert!(ok.orbit_entropy.is_finite());
        assert!(ok.orbit_entropy >= 0.0);
    }

    #[test]
    fn defaults_match_spec() {
        let cfg = ChaosConfig::default();
        assert_eq!(cfg.iterations, 1000);
        assert_eq!(cfg.a, 1.4);
        assert_eq!(cfg.b, 0.3);
    }

    #[test]
    fn deterministic_32_byte_signature() {
        let img = sample_image(3);
        let cfg = ChaosConfig::default();
        let a = extract_chaos(&img, &cfg).unwrap();
        let b = extract_chaos(&img, &cfg).unwrap();
        assert_eq!(a.signature.len(), SIGNATURE_LEN);
        assert_eq!(a.signature, b.signature);
        assert_eq!(a.config, cfg);
        assert!(a.entropy_bits > 0.0);
        assert!((0.0..=8.0).contains(&a.orbit_entropy));
    }

    #[test]
    fn single_pixel_flip_avalanches_signature() {
        let a = sample_image(9);
        let mut b = a.clone();
        // Flip the value of one interior pixel in the copy.
        let mid = b.pixels.len() / 2;
        b.pixels[mid] = b.pixels[mid].wrapping_add(1);
        assert_ne!(a.pixels, b.pixels);

        let cfg = ChaosConfig::default();
        let ra = extract_chaos(&a, &cfg).unwrap();
        let rb = extract_chaos(&b, &cfg).unwrap();
        let differing = ra
            .signature
            .iter()
            .zip(rb.signature.iter())
            .filter(|(x, y)| x != y)
            .count();
        assert!(
            differing >= 16,
            "expected avalanche, only {differing}/32 signature bytes differ"
        );
    }

    #[test]
    fn flat_and_busy_images_stay_distinct_and_positive() {
        let flat = Image::from_luma(64, 64, vec![128u8; 64 * 64]).unwrap();
        let busy = sample_image(1);
        let cfg = ChaosConfig::default();
        let r_flat = extract_chaos(&flat, &cfg).unwrap();
        let r_busy = extract_chaos(&busy, &cfg).unwrap();
        assert!(r_flat.entropy_bits > 0.0);
        assert!(r_busy.entropy_bits > 0.0);
        assert_ne!(r_flat.signature, r_busy.signature);
    }

    #[test]
    fn invalid_configs_are_rejected() {
        let img = sample_image(5);
        assert!(extract_chaos(&img, &ChaosConfig::new(0, 1.4, 0.3)).is_err());
        assert!(extract_chaos(&img, &ChaosConfig::new(1, f64::NAN, 0.3)).is_err());
        assert!(extract_chaos(&img, &ChaosConfig::new(1, 1.4, -0.3)).is_err());
    }

    #[test]
    fn empty_image_is_rejected() {
        let img = Image::from_luma(0, 0, vec![]).unwrap();
        assert!(extract_chaos(&img, &ChaosConfig::default()).is_err());
    }

    #[test]
    fn orbit_entropy_never_exceeds_8_bits() {
        let img = sample_image(7);
        let res = extract_chaos(&img, &ChaosConfig::default()).unwrap();
        assert!((0.0..=8.0).contains(&res.orbit_entropy));
    }

    // The orbit must never diverge: whatever the seed or iteration count, the
    // extraction returns finite, deterministic results.
    #[test]
    fn wide_range_of_inputs_stays_finite() {
        let flat = Image::from_luma(64, 64, vec![128u8; 64 * 64]).unwrap();
        let busy = sample_image(2);
        for img in [flat, busy] {
            for iterations in [1usize, 16, 1000] {
                let cfg = ChaosConfig::new(iterations, DEFAULT_A, DEFAULT_B);
                let a = extract_chaos(&img, &cfg).unwrap();
                let b = extract_chaos(&img, &cfg).unwrap();
                assert_eq!(a.signature, b.signature);
                assert!(a.entropy_bits.is_finite() && a.entropy_bits > 0.0);
                assert!(a.orbit_entropy.is_finite());
            }
        }
    }
}
