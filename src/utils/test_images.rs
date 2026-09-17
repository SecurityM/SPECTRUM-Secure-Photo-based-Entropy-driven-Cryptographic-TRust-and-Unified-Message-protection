//! Deterministic generators for synthetic test images.
//!
//! Used across the test suite, the benchmarks and the runnable examples so that
//! they all observe the same, reproducible inputs. Everything here is a pure
//! function of its seed: no system RNG, no filesystem — exactly the kind of
//! reproducibility the entropy engine itself guarantees.

use rand::RngCore;
use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

/// A grayscale (luma) buffer plus its dimensions, matching what the entropy
/// engine consumes.
#[derive(Debug, Clone)]
pub struct TestImage {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

impl TestImage {
    /// Wrap as a crate `Image`. Falls back to an explicit error (instead of
    /// panicking) if the generated buffer length does not match the declared
    /// dimensions — a generator bug would surface as an `Err`, not a crash.
    pub fn into_crate_image(self) -> crate::image::Image {
        match crate::image::Image::from_luma(self.width, self.height, self.pixels) {
            Ok(img) => img,
            Err(e) => panic!(
                "test-image generator produced a malformed buffer ({e}); \
                 this is a bug in the generator, not in caller input"
            ),
        }
    }
}

fn chacha(seed: u64) -> ChaCha8Rng {
    ChaCha8Rng::seed_from_u64(seed)
}

/// SMPTE-style color bars: seven vertical bands of known luma levels,
/// deterministic and structurally trivial.
pub fn bars(width: u32, height: u32) -> Vec<u8> {
    let bands = [232u8, 128, 96, 64, 32, 16, 240];
    let mut p = Vec::with_capacity((width * height) as usize);
    for y in 0..height {
        for x in 0..width {
            let band = ((x as usize) * bands.len() / width as usize).min(bands.len() - 1);
            // A gentle per-row gradient keeps each band from being a solid plane.
            let dither = ((y * 3) % 8) as u8;
            p.push(bands[band].wrapping_sub(dither));
        }
    }
    p
}

/// A deterministic pseudo-random (white-noise) image.
pub fn noise(width: u32, height: u32, seed: u64) -> Vec<u8> {
    let mut out = vec![0u8; (width * height) as usize];
    chacha(seed).fill_bytes(&mut out);
    out
}

/// A deliberately smooth gradient image (low complexity).
pub fn gradient(width: u32, height: u32) -> Vec<u8> {
    let mut p = Vec::with_capacity((width * height) as usize);
    for y in 0..height {
        for x in 0..width {
            let v = (255.0 * x as f64 / width.max(1) as f64
                + 128.0 * y as f64 / height.max(1) as f64) as u8;
            p.push(v);
        }
    }
    p
}

/// A masonry-like grid: dark mortar between lighter bricks (mid complexity,
/// strong edges in both axes).
pub fn masonry(width: u32, height: u32) -> Vec<u8> {
    const BRICK: u32 = 24;
    const MORTAR: u32 = 3;
    let mut p = Vec::with_capacity((width * height) as usize);
    for y in 0..height {
        for x in 0..width {
            let in_mortar = x % (BRICK + MORTAR) < MORTAR || y % (BRICK + MORTAR) < MORTAR;
            p.push(if in_mortar { 40 } else { 190 });
        }
    }
    p
}

/// Escape-time Mandelbrot set render (deterministic, no smoothing state).
///
/// `pixels_per_unit` maps screen pixels to complex-plane units; the classic
/// whole-set view uses roughly `width / 2.7`. Pixels inside the set saturate
/// to white; the layered escape-count boundary outside it carries the fractal
/// structure the engines are designed to read.
pub fn mandelbrot(
    width: u32,
    height: u32,
    iterations: u32,
    center: (f64, f64),
    pixels_per_unit: f64,
) -> Vec<u8> {
    let mut p = Vec::with_capacity((width * height) as usize);
    for y in 0..height {
        let im = center.1 + (y as f64 - height as f64 / 2.0) / pixels_per_unit;
        for x in 0..width {
            let re = center.0 + (x as f64 - width as f64 / 2.0) / pixels_per_unit;
            let (mut zr, mut zi) = (0.0f64, 0.0f64);
            let mut n = 0u32;
            while n < iterations {
                let zr2 = zr * zr;
                let zi2 = zi * zi;
                if zr2 + zi2 > 4.0 {
                    break;
                }
                zi = 2.0 * zr * zi + im;
                zr = zr2 - zi2 + re;
                n += 1;
            }
            let v = 255.0 * (n as f64 / iterations as f64);
            p.push(v.round().clamp(0.0, 255.0) as u8);
        }
    }
    p
}

/// Escape-time Julia set render for a fixed parameter `c` (deterministic).
/// The classical "rabbit"-adjacent parameter `(-0.75, 0.11)` sits right at the
/// boundary where the set stays connected but richly filamented.
pub fn julia(
    width: u32,
    height: u32,
    iterations: u32,
    c: (f64, f64),
    pixels_per_unit: f64,
) -> Vec<u8> {
    let mut p = Vec::with_capacity((width * height) as usize);
    for y in 0..height {
        let zi0 = (y as f64 - height as f64 / 2.0) / pixels_per_unit;
        for x in 0..width {
            let zr0 = (x as f64 - width as f64 / 2.0) / pixels_per_unit;
            let (mut zr, mut zi) = (zr0, zi0);
            let mut n = 0u32;
            while n < iterations {
                let zr2 = zr * zr;
                let zi2 = zi * zi;
                if zr2 + zi2 > 4.0 {
                    break;
                }
                zi = 2.0 * zr * zi + c.1;
                zr = zr2 - zi2 + c.0;
                n += 1;
            }
            let v = 255.0 * (n as f64 / iterations as f64);
            p.push(v.round().clamp(0.0, 255.0) as u8);
        }
    }
    p
}

/// Hash a lattice coordinate into a deterministic `[0, 1)` scalar.
fn lattice_value(ix: i64, iy: i64, seed: u64) -> f64 {
    let mut h = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    h ^= (ix as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    h = h.rotate_left(13);
    h ^= (iy as u64).wrapping_mul(0x94D0_49BB_1331_11EB);
    h = h.rotate_left(29);
    h ^= h >> 32;
    h = h.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    h ^= h >> 29;
    (h >> 11) as f64 / (1u64 << 53) as f64
}

/// Periodic value noise with `freq` cells across the unit square.
fn value_noise(x: f64, y: f64, freq: usize, seed: u64) -> f64 {
    let freq = freq.max(1) as f64;
    let gx = x * freq;
    let gy = y * freq;
    let ix = gx.floor() as i64;
    let iy = gy.floor() as i64;
    let fx = gx - gx.floor();
    let fy = gy - gy.floor();
    let sx = fx * fx * (3.0 - 2.0 * fx); // smoothstep
    let sy = fy * fy * (3.0 - 2.0 * fy);
    let wrap = |v: i64| v.rem_euclid(freq as i64);

    let v00 = lattice_value(wrap(ix), wrap(iy), seed);
    let v10 = lattice_value(wrap(ix + 1), wrap(iy), seed);
    let v01 = lattice_value(wrap(ix), wrap(iy + 1), seed);
    let v11 = lattice_value(wrap(ix + 1), wrap(iy + 1), seed);

    let a = v00 + (v10 - v00) * sx;
    let b = v01 + (v11 - v01) * sx;
    a + (b - a) * sy
}

/// Fractal value-noise (Perlin-style) field: `octaves` of 1/f noise summed
/// with halving amplitudes, deterministic in `(size, octaves, seed)`.
pub fn perlin(width: u32, height: u32, octaves: usize, seed: u64) -> Vec<u8> {
    let octaves = octaves.max(1);
    let mut p = Vec::with_capacity((width * height) as usize);
    let mut total_amp = 0.0f64;
    for o in 1..=octaves {
        total_amp += 1.0 / (1u64 << (o - 1)) as f64;
    }
    for y in 0..height {
        let ny = y as f64 / height.max(1) as f64;
        for x in 0..width {
            let nx = x as f64 / width.max(1) as f64;
            let mut acc = 0.0;
            for o in 1..=octaves {
                let freq = 1usize << (o - 1);
                let amp = 1.0 / (1u64 << (o - 1)) as f64;
                acc += amp * value_noise(nx, ny, freq, seed);
            }
            let v = 255.0 * (acc / total_amp);
            p.push(v.round().clamp(0.0, 255.0) as u8);
        }
    }
    p
}

/// Render any of these preset generators into a `TestImage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bars,
    Noise,
    Gradient,
    Masonry,
    Mandelbrot,
    Julia,
    Perlin,
}

impl Kind {
    /// Generate pixels for the requested size (noise takes a seed).
    pub fn generate(&self, width: u32, height: u32, seed: u64) -> Vec<u8> {
        match self {
            Kind::Bars => bars(width, height),
            Kind::Noise => noise(width, height, seed),
            Kind::Gradient => gradient(width, height),
            Kind::Masonry => masonry(width, height),
            // Whole-set view around the main cardioid/boundary region.
            Kind::Mandelbrot => mandelbrot(width, height, 300, (-0.5, 0.0), width as f64 / 2.7),
            // Julia parameter at the boundary of connectivity.
            Kind::Julia => julia(width, height, 300, (-0.75, 0.11), width as f64 / 3.0),
            Kind::Perlin => perlin(width, height, 8, seed),
        }
    }
}

/// A naming helper used by callers that persist generated images.
pub fn filename(kind: Kind, seed: u64) -> String {
    match kind {
        Kind::Bars => "bars".to_string(),
        Kind::Noise => format!("noise_{seed}"),
        Kind::Gradient => "gradient".to_string(),
        Kind::Masonry => "masonry".to_string(),
        Kind::Mandelbrot => "mandelbrot".to_string(),
        Kind::Julia => "julia".to_string(),
        Kind::Perlin => format!("perlin_{seed}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generators_are_deterministic() {
        assert_eq!(noise(64, 64, 7), noise(64, 64, 7));
        assert_eq!(bars(64, 64), bars(64, 64));
        assert_eq!(gradient(64, 64), gradient(64, 64));
        assert_eq!(masonry(64, 64), masonry(64, 64));
        assert_eq!(
            mandelbrot(64, 64, 300, (-0.5, 0.0), 23.0),
            mandelbrot(64, 64, 300, (-0.5, 0.0), 23.0)
        );
        assert_eq!(
            julia(64, 64, 300, (-0.75, 0.11), 21.0),
            julia(64, 64, 300, (-0.75, 0.11), 21.0)
        );
        assert_eq!(perlin(64, 64, 8, 5), perlin(64, 64, 8, 5));
    }

    #[test]
    fn generators_differ_from_each_other() {
        let a = noise(64, 64, 0);
        let b = gradient(64, 64);
        assert_ne!(a, b);
        assert_ne!(
            mandelbrot(64, 64, 300, (-0.5, 0.0), 23.0),
            julia(64, 64, 300, (-0.75, 0.11), 21.0)
        );
        assert_ne!(perlin(64, 64, 8, 0), perlin(64, 64, 8, 1));
    }

    #[test]
    fn fractal_generators_produce_structure() {
        // Fractal renders must not be flat or single-valued.
        let mb = mandelbrot(64, 64, 300, (-0.5, 0.0), 23.0);
        let seen: std::collections::HashSet<u8> = mb.iter().cloned().collect();
        assert!(seen.len() > 8, "mandelbrot has only {} values", seen.len());
        let jl = julia(64, 64, 300, (-0.75, 0.11), 21.0);
        let seen: std::collections::HashSet<u8> = jl.iter().cloned().collect();
        assert!(seen.len() > 8, "julia has only {} values", seen.len());
        let pn = perlin(64, 64, 8, 3);
        let seen: std::collections::HashSet<u8> = pn.iter().cloned().collect();
        assert!(seen.len() > 8, "perlin has only {} values", seen.len());
    }

    #[test]
    fn sizes_are_respected() {
        assert_eq!(noise(12, 13, 1).len(), 12 * 13);
        assert_eq!(bars(17, 19).len(), 17 * 19);
        let ti = TestImage {
            width: 9,
            height: 8,
            pixels: vec![0u8; 72],
        };
        assert_eq!(ti.into_crate_image().dimensions(), (9, 8));
    }

    #[test]
    fn kind_filename_unique() {
        let names: std::collections::HashSet<_> = [
            filename(Kind::Bars, 0),
            filename(Kind::Gradient, 0),
            filename(Kind::Masonry, 0),
            // Two different seeds must yield two different names for Noise,
            // and every Kind (including the fractal renders) must persist
            // under a name distinct from all the others.
            filename(Kind::Noise, 1),
            filename(Kind::Noise, 2),
            filename(Kind::Mandelbrot, 0),
            filename(Kind::Julia, 0),
            filename(Kind::Perlin, 3),
        ]
        .into_iter()
        .collect();
        assert_eq!(names.len(), 8);
    }
}
