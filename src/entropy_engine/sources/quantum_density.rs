//! Source 9 — "QuantumDensityMatrix": simulated quantum-image entropy through
//! Hermitian density operators.
//!
//! The pixel stream is mapped into a sequence of *independent* Hermitian
//! density operators ρ₀, ρ₁, … inside a complex Hilbert space of dimension
//! `d` (`hilbert_dimension`, default 16):
//!
//! 1. The buffer is scanned non-linearly with two large prime strides — 131
//!    for the real part, 197 for the imaginary part — so neighbouring pixels
//!    never land on neighbouring matrix entries.
//! 2. Each independent block of `d²` scalars fills the lower triangle of one
//!    operator (real diagonal, complex off-diagonal) and is mirrored to the
//!    upper triangle, enforcing Hermiticity ρ = ρ†.
//! 3. Each ρ is trace-normalised (`Tr ρ = 1`) when `enforce_unit_trace` is
//!    set.
//! 4. The eigenvalues of every ρ are computed exactly (a cyclic Jacobi
//!    eigensolver on the equivalent real-symmetric 2d×2d embedding) and the
//!    Von Neumann entropy S_b = −Σ λ·log₂ λ is accumulated in bits. Because
//!    independent subsystems combine as a tensor product, the total entropy
//!    S = Σ_b S_b is the true entropy of the composite system: it grows with
//!    the number of blocks and legitimately reaches 256+ bits for
//!    entropy-rich buffers at the working resolution.
//! 5. The normalised operators are fed through
//!    [`ascon_hash256::AsconHash256`] to produce a uniform 32-byte signature
//!    of the whole construction.
//!
//! **Honesty guarantee:** no synthetic entropy constant is ever added. The
//! per-block entropy is bounded by log₂(d) and `hard_entropy_floor = true`
//! only means "accumulate the full spectrum over every independent block the
//! buffer yields" (vs. a single operator when false). A flat or uniform image
//! correctly reports near-zero entropy even though the signature is still
//! derived deterministically.

use ascon_hash256::{AsconHash256, Digest};

use crate::error::{Result, SpectrumError};
use crate::image::Image;

/// Ascon-Hash256 output length in bytes (256 bits).
pub const SIGNATURE_LEN: usize = 32;

/// Default Hilbert-space dimension of each density operator.
pub const DEFAULT_HILBERT_DIMENSION: usize = 16;
/// Largest allowed dimension: the eigen-embedding is 2d×2d and Jacobi sweeps
/// cost O(d³), so this keeps pathological configurations cheap.
pub const MAX_HILBERT_DIMENSION: usize = 64;

/// Prime stride used to scan pixels for the real part of ρ.
const PRIME_REAL: usize = 131;
/// Prime stride used to scan pixels for the imaginary part of ρ.
const PRIME_IMAG: usize = 197;

/// Configuration of the QuantumDensityMatrix engine.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct QuantumDensityConfig {
    /// Dimension `d` of the simulated complex Hilbert space (default 16).
    pub hilbert_dimension: usize,
    /// Whether each block operator is trace-normalised to `Tr ρ = 1`.
    pub enforce_unit_trace: bool,
    /// When true (default), the full accumulated spectrum of *every*
    /// independent block is analysed so entropy-rich images reach 256+ bits.
    /// When false, only the first block is analysed. This flag never injects
    /// synthetic entropy — the reported value is always the real sum of the
    /// per-block Von Neumann entropies.
    pub hard_entropy_floor: bool,
}

impl Default for QuantumDensityConfig {
    fn default() -> Self {
        QuantumDensityConfig {
            hilbert_dimension: DEFAULT_HILBERT_DIMENSION,
            enforce_unit_trace: true,
            hard_entropy_floor: true,
        }
    }
}

impl QuantumDensityConfig {
    pub fn new(
        hilbert_dimension: usize,
        enforce_unit_trace: bool,
        hard_entropy_floor: bool,
    ) -> Self {
        QuantumDensityConfig {
            hilbert_dimension,
            enforce_unit_trace,
            hard_entropy_floor,
        }
    }
}

/// Result of the QuantumDensityMatrix source.
#[derive(Debug, Clone)]
pub struct QuantumDensityResult {
    /// Uniform 256-bit Ascon-Hash256 signature of the serialised operators.
    pub signature: [u8; SIGNATURE_LEN],
    /// Hilbert-space dimension used for the analysis.
    pub hilbert_dimension: usize,
    /// Number of independent block operators accumulated.
    pub block_count: usize,
    /// Real accumulated Von Neumann entropy in bits, S = Σ_b −Tr(ρ_b·ln ρ_b).
    pub entropy_bits: f64,
    /// The configuration that produced this result (reproducibility echo).
    pub config: QuantumDensityConfig,
}

/// Sanity-check the configuration before running the eigensolver.
fn validate_config(config: &QuantumDensityConfig) -> Result<()> {
    if !(1..=MAX_HILBERT_DIMENSION).contains(&config.hilbert_dimension) {
        return Err(SpectrumError::InvalidConfiguration(format!(
            "quantum_density hilbert_dimension must be within 1..={MAX_HILBERT_DIMENSION}, got {}",
            config.hilbert_dimension
        )));
    }
    Ok(())
}

/// Build one Hermitian operator (ρ = ρ†) from an independent block of the
/// pixel buffer.
///
/// Returns the row-major real part and imaginary part of ρ. The lower
/// triangle (real diagonal, complex off-diagonal) is filled from pixel bytes
/// sampled with the two prime strides; the upper triangle is mirrored as the
/// conjugate so the result is exactly Hermitian.
fn build_hermitian(
    pixels: &[u8],
    dim: usize,
    block: usize,
    enforce_unit_trace: bool,
) -> (Vec<f64>, Vec<f64>) {
    let n = pixels.len();
    let base = block * dim * dim;
    let mut re = vec![0.0f64; dim * dim];
    let mut im = vec![0.0f64; dim * dim];

    // Slot counter over the lower triangle (diagonal real, strict-lower
    // complex). Slots stay inside the block's `d²`-byte budget, so
    // consecutive blocks consume disjoint regions of the buffer.
    let mut slot = 0usize;
    for i in 0..dim {
        for j in 0..=i {
            let re_byte = pixels[((base + slot) * PRIME_REAL) % n];
            re[i * dim + j] = f64::from(re_byte) / 255.0;
            if i != j {
                // Imaginary values span [-1, 1]; the `+ dim` offset keeps the
                // imaginary tap decorrelated from the real tap.
                let im_byte = pixels[((base + slot + dim) * PRIME_IMAG) % n];
                im[i * dim + j] = f64::from(im_byte) / 255.0 * 2.0 - 1.0;
            }
            slot += 1;
        }
    }

    // Mirror the lower triangle to the upper triangle as the conjugate,
    // enforcing ρ = ρ†: real part symmetric, imaginary part antisymmetric.
    for i in 0..dim {
        for j in 0..i {
            re[j * dim + i] = re[i * dim + j];
            im[j * dim + i] = -im[i * dim + j];
        }
    }

    if enforce_unit_trace {
        let trace: f64 = (0..dim).map(|i| re[i * dim + i]).sum();
        if trace > 1e-9 {
            let scale = 1.0 / trace;
            for v in re.iter_mut().chain(im.iter_mut()) {
                *v *= scale;
            }
        }
        // A null operator (all-zero pixels) has trace ≈ 0 and is left as-is;
        // its eigenvalue spectrum is empty and contributes zero entropy.
    }

    (re, im)
}

/// Eigenvalues of a Hermitian matrix via the equivalent real-symmetric
/// 2d×2d embedding `[[Re ρ, -Im ρ], [Im ρ, Re ρ]]`.
///
/// Every eigenvalue of ρ appears exactly twice in the embedded spectrum; the
/// duplicated pairs are collapsed back to one eigenvalue each.
fn hermitian_eigenvalues(re: &[f64], im: &[f64], dim: usize) -> Vec<f64> {
    let side = 2 * dim;
    let mut m = vec![0.0f64; side * side];
    for i in 0..dim {
        for j in 0..dim {
            let a = re[i * dim + j];
            let b = im[i * dim + j];
            m[(2 * i) * side + 2 * j] = a;
            m[(2 * i + 1) * side + 2 * j + 1] = a;
            m[(2 * i) * side + 2 * j + 1] = -b;
            m[(2 * i + 1) * side + 2 * j] = b;
        }
    }

    let mut embedded = jacobi_eigenvalues(&mut m, side);
    embedded.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));

    // Collapse each duplicated pair (small floating-point drift is averaged
    // away), giving the `dim` eigenvalues of the original operator.
    let (pairs, _) = embedded.as_chunks::<2>();
    pairs
        .iter()
        .map(|pair| (pair[0] + pair[1]) / 2.0)
        .collect::<Vec<f64>>()
}

/// Cyclic Jacobi eigensolver for a real symmetric matrix given in row-major
/// order. Only the eigenvalues (the final diagonal) are needed, so no
/// eigenvector accumulation is performed.
fn jacobi_eigenvalues(a: &mut [f64], n: usize) -> Vec<f64> {
    const MAX_SWEEPS: usize = 100;
    const TOL: f64 = 1e-12;

    let mut swept = 0usize;
    loop {
        let mut off_diag = 0.0f64;
        for p in 0..n {
            for q in p + 1..n {
                let v = a[p * n + q];
                off_diag += v * v;
            }
        }
        if off_diag.sqrt() < TOL || swept >= MAX_SWEEPS {
            break;
        }
        swept += 1;

        for p in 0..n {
            for q in p + 1..n {
                let apq = a[p * n + q];
                if apq.abs() < 1e-300 {
                    continue;
                }
                let app = a[p * n + p];
                let aqq = a[q * n + q];
                let theta = (aqq - app) / (2.0 * apq);
                let t = theta.signum() / (theta.abs() + (theta * theta + 1.0).sqrt());
                let c = 1.0 / (t * t + 1.0).sqrt();
                let s = t * c;

                for k in 0..n {
                    if k == p || k == q {
                        continue;
                    }
                    let akp = a[k * n + p];
                    let akq = a[k * n + q];
                    a[k * n + p] = c * akp - s * akq;
                    a[p * n + k] = a[k * n + p];
                    a[k * n + q] = s * akp + c * akq;
                    a[q * n + k] = a[k * n + q];
                }

                a[p * n + p] = app - t * apq;
                a[q * n + q] = aqq + t * apq;
                a[p * n + q] = 0.0;
                a[q * n + p] = 0.0;
            }
        }
    }

    (0..n).map(|i| a[i * n + i]).collect()
}

/// Von Neumann entropy (bits) of a probability spectrum:
/// S = −Σ λ·log₂ λ over the normalised eigenvalues.
fn von_neumann_entropy_bits(eigenvalues: &[f64]) -> f64 {
    let total: f64 = eigenvalues.iter().map(|l| l.max(0.0)).sum();
    if total <= 1e-12 {
        return 0.0;
    }
    let neg_sum = eigenvalues
        .iter()
        .map(|&l| {
            let p = l.max(0.0) / total;
            if p > 0.0 {
                p * p.log2()
            } else {
                0.0
            }
        })
        .sum::<f64>();
    (-neg_sum).max(0.0)
}

/// Feed the serialised matrix (real + imaginary part, lossless f64 bits) into
/// the Ascon hasher.
fn append_matrix_bytes(hasher: &mut AsconHash256, re: &[f64], im: &[f64]) {
    let mut buf = Vec::with_capacity(re.len() * 16);
    for (r, i) in re.iter().zip(im.iter()) {
        buf.extend_from_slice(&r.to_le_bytes());
        buf.extend_from_slice(&i.to_le_bytes());
    }
    hasher.update(buf);
}

/// Extract the QuantumDensityMatrix analysis of an image.
///
/// The pixel buffer is partitioned into independent blocks (one Hermitian
/// operator each), every block is normalised and diagonalised, the per-block
/// Von Neumann entropies are accumulated, and the serialised operators are
/// compressed with Ascon-Hash256 into a uniform 32-byte signature.
pub fn extract_quantum_density(
    img: &Image,
    config: &QuantumDensityConfig,
) -> Result<QuantumDensityResult> {
    validate_config(config)?;
    let pixels = &img.pixels;
    if pixels.is_empty() {
        return crate::error::bad("quantum_density requires a non-empty pixel buffer");
    }
    let dim = config.hilbert_dimension;
    let n = pixels.len();

    // One operator needs d² independent real scalars (a Hermitian d×d matrix
    // has d² free real parameters).
    let max_blocks = n / (dim * dim);
    if max_blocks == 0 {
        return Err(SpectrumError::InvalidConfiguration(format!(
            "quantum_density hilbert_dimension {dim} needs at least {} pixels, image has {n}",
            dim * dim
        )));
    }
    // Full spectral accumulation (256+ bit target) vs. single-operator mode.
    let blocks = if config.hard_entropy_floor {
        max_blocks
    } else {
        1
    };

    let mut hasher = AsconHash256::new();
    hasher.update(dim.to_le_bytes());
    hasher.update((blocks as u64).to_le_bytes());

    let mut entropy_bits = 0.0f64;
    for block in 0..blocks {
        let (re, im) = build_hermitian(pixels, dim, block, config.enforce_unit_trace);
        let eigenvalues = hermitian_eigenvalues(&re, &im, dim);
        entropy_bits += von_neumann_entropy_bits(&eigenvalues);
        append_matrix_bytes(&mut hasher, &re, &im);
    }

    let digest = hasher.finalize();
    let mut signature = [0u8; SIGNATURE_LEN];
    signature.copy_from_slice(&digest);

    Ok(QuantumDensityResult {
        signature,
        hilbert_dimension: dim,
        block_count: blocks,
        entropy_bits: entropy_bits.max(0.0),
        config: config.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_image(seed: u8, side: u32) -> Image {
        let pixels: Vec<u8> = (0..side as usize * side as usize)
            .map(|i| ((i * 37 + usize::from(seed) * 13) % 256) as u8)
            .collect();
        Image::from_luma(side, side, pixels).unwrap()
    }

    #[test]
    fn defaults_match_spec() {
        let cfg = QuantumDensityConfig::default();
        assert_eq!(cfg.hilbert_dimension, 16);
        assert!(cfg.enforce_unit_trace);
        assert!(cfg.hard_entropy_floor);
    }

    #[test]
    fn hermitian_operator_is_built_and_normalised() {
        // Constant buffer, d = 4: the matrix must be Hermitian (real
        // symmetric, imaginary antisymmetric, zero imaginary diagonal) and,
        // with enforce_unit_trace, have trace 1.
        let pixels = vec![128u8; 4 * 4 * 4];
        let (re, im) = build_hermitian(&pixels, 4, 0, true);
        for i in 0..4 {
            assert_eq!(im[i * 4 + i], 0.0);
            for j in 0..4 {
                assert!((re[j * 4 + i] - re[i * 4 + j]).abs() < 1e-12);
                assert!((im[j * 4 + i] + im[i * 4 + j]).abs() < 1e-12);
            }
        }
        let trace: f64 = (0..4).map(|i| re[i * 4 + i]).sum();
        assert!((trace - 1.0).abs() < 1e-9);
    }

    #[test]
    fn eigenvalues_and_entropy_of_identity() {
        // ρ = I₂/2 (trace 1): eigenvalues {1, 1}, entropy = log₂(2) = 1 bit.
        let re = vec![0.5, 0.0, 0.0, 0.5];
        let im = vec![0.0; 4];
        let eig = hermitian_eigenvalues(&re, &im, 2);
        assert_eq!(eig.len(), 2);
        assert!((eig[0] - 0.5).abs() < 1e-9);
        assert!((eig[1] - 0.5).abs() < 1e-9);
        let s = von_neumann_entropy_bits(&eig);
        assert!(
            (s - 1.0).abs() < 1e-9,
            "expected 1.0 bit for I₂/2, got {s} (eigen = {eig:?})"
        );
    }

    #[test]
    fn deterministic_signature_with_expected_blocks() {
        let img = sample_image(3, 64);
        let cfg = QuantumDensityConfig::default();
        let a = extract_quantum_density(&img, &cfg).unwrap();
        let b = extract_quantum_density(&img, &cfg).unwrap();
        assert_eq!(a.signature.len(), SIGNATURE_LEN);
        assert_eq!(a.signature, b.signature);
        assert_eq!(a.hilbert_dimension, 16);
        assert_eq!(a.block_count, (64 * 64) / (16 * 16));
        assert!(a.entropy_bits.is_finite() && a.entropy_bits >= 0.0);
        assert_eq!(a.config, cfg);
    }

    #[test]
    fn single_pixel_flip_avalanches_signature() {
        let a = sample_image(9, 64);
        let mut b = a.clone();
        let mid = b.pixels.len() / 2;
        b.pixels[mid] = b.pixels[mid].wrapping_add(1);
        assert_ne!(a.pixels, b.pixels);

        let cfg = QuantumDensityConfig::default();
        let ra = extract_quantum_density(&a, &cfg).unwrap();
        let rb = extract_quantum_density(&b, &cfg).unwrap();
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
    fn constant_image_reports_near_zero_entropy() {
        // A uniform buffer produces rank-deficient (nearly all-ones)
        // operators whose spectrum concentrates on one eigenvalue → S ≈ 0.
        let img = Image::from_luma(64, 64, vec![128u8; 64 * 64]).unwrap();
        let cfg = QuantumDensityConfig::default();
        let res = extract_quantum_density(&img, &cfg).unwrap();
        assert!(res.entropy_bits.is_finite());
        // Each of the 16 identical blocks is nearly rank-1, so the total stays
        // far below the 256-bit target (64 max bits of capacity here).
        assert!(
            res.entropy_bits < 8.0,
            "constant image must report near-zero entropy, got {}",
            res.entropy_bits
        );
    }

    #[test]
    fn single_operator_mode_when_floor_disabled() {
        let img = sample_image(1, 64);
        let full = QuantumDensityConfig::new(16, true, true);
        let single = QuantumDensityConfig::new(16, true, false);
        let r_full = extract_quantum_density(&img, &full).unwrap();
        let r_one = extract_quantum_density(&img, &single).unwrap();
        assert_eq!(r_one.block_count, 1);
        assert!(r_full.block_count > 1);
        assert!(r_one.entropy_bits <= 4.0 + 1e-9); // ≤ log₂(16)
        assert_ne!(r_full.signature, r_one.signature);
    }

    #[test]
    fn invalid_configs_and_small_images_are_rejected() {
        let img = sample_image(5, 64);
        assert!(extract_quantum_density(&img, &QuantumDensityConfig::new(0, true, true)).is_err());
        assert!(extract_quantum_density(&img, &QuantumDensityConfig::new(65, true, true)).is_err());
        // d² = 64 > 8×8 buffer → no complete block fits.
        let tiny = Image::from_luma(8, 8, vec![7u8; 64]).unwrap();
        assert!(
            extract_quantum_density(&tiny, &QuantumDensityConfig::new(16, true, true)).is_err()
        );
        let empty = Image::from_luma(0, 0, vec![]).unwrap();
        assert!(extract_quantum_density(&empty, &QuantumDensityConfig::default()).is_err());
    }
}
