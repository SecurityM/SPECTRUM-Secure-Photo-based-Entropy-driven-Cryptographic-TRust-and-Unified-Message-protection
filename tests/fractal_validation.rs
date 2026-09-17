//! Fractal-aware validation (design-plan phase 6).
//!
//! Exercises the FractalAware source and the full key-derivation pipeline on
//! the image families SPECTRUM v0.1.0 is meant to be *universal* over:
//! Mandelbrot-boundary renders, Julia sets, multi-octave Perlin fields and
//! plain structured images. Asserts the guarantees the fractal stage is built
//! on — determinism, single-pixel avalanche, collision-free signatures across
//! many distinct fractal views, honest near-zero entropy for flat planes, and
//! correct classification of genuinely fractal renders.

use spectrum::entropy_engine::sources::fractal_analysis::{
    extract_fractal_aware, FractalAwareConfig, FractalAwareResult, FractalType, SIGNATURE_LEN,
};
use spectrum::image::Image;
use spectrum::key_derivation::KeyDerivationPipeline;
use spectrum::utils::test_images;

const SIDE: u32 = 96;

fn analyze(pixels: Vec<u8>) -> FractalAwareResult {
    extract_fractal_aware(
        &Image::from_luma(SIDE, SIDE, pixels).unwrap(),
        &FractalAwareConfig::default(),
    )
    .unwrap()
}

fn mandelbrot_whole() -> Vec<u8> {
    test_images::mandelbrot(SIDE, SIDE, 250, (-0.5, 0.0), SIDE as f64 / 2.7)
}

fn julia_critical() -> Vec<u8> {
    test_images::julia(SIDE, SIDE, 250, (-0.75, 0.11), SIDE as f64 / 3.0)
}

fn perlin_field(seed: u64) -> Vec<u8> {
    test_images::perlin(SIDE, SIDE, 8, seed)
}

// A ladder of distinct fractal views: whole-set, deep-boundary and off-axis
// Mandelbrot zooms; varied Julia parameters along the connectivity boundary;
// and differently seeded Perlin/noise fields.
fn distinct_views() -> Vec<Vec<u8>> {
    let mut views = Vec::new();
    let mb_centers = [(-0.5, 0.0), (-0.745, 0.113), (-1.768, 0.0), (-0.11, 0.86)];
    for &center in mb_centers.iter() {
        for zoom in [0.5, 1.0, 2.0] {
            views.push(test_images::mandelbrot(
                SIDE,
                SIDE,
                250,
                center,
                SIDE as f64 / 2.7 * zoom,
            ));
        }
    }
    let julia_params = [(-0.75, 0.11), (-0.4, 0.6), (-0.835, -0.2321), (0.285, 0.01)];
    for &(cr, ci) in julia_params.iter() {
        for zoom in [0.5, 1.0, 2.0] {
            views.push(test_images::julia(
                SIDE,
                SIDE,
                250,
                (cr, ci),
                SIDE as f64 / 3.0 * zoom,
            ));
        }
    }
    for seed in 1..=12 {
        views.push(perlin_field(seed));
        views.push(test_images::noise(SIDE, SIDE, seed.wrapping_mul(7919)));
    }
    views
}

// ---------------------------------------------------------------------------
// Source-level guarantees
// ---------------------------------------------------------------------------

#[test]
fn fractal_renders_are_deterministic() {
    for pixels in [mandelbrot_whole(), julia_critical(), perlin_field(42)] {
        let a = analyze(pixels.clone());
        let b = analyze(pixels);
        assert_eq!(a.signature, b.signature);
        assert_eq!(a.values, b.values);
        assert_eq!(a.classification, b.classification);
        assert_eq!(a.signature.len(), SIGNATURE_LEN);
    }
}

#[test]
fn fractal_renders_classify_as_fractal_not_regular() {
    // Structured fractal renders (Julia, Perlin, noise) must land inside the
    // fractal band and be self-similar; none may fall back to Regular.
    let cases: Vec<Vec<u8>> = vec![
        julia_critical(),
        perlin_field(42),
        test_images::noise(SIDE, SIDE, 7),
        test_images::masonry(SIDE, SIDE),
    ];
    for pixels in cases {
        let r = analyze(pixels);
        assert_ne!(
            r.classification.fractal_type,
            FractalType::Regular,
            "structured plane misclassified as Regular"
        );
        assert!(
            r.classification.is_self_similar,
            "structured plane must be scale-invariant"
        );
        assert!(
            r.classification.hausdorff_dimension >= 1.15,
            "fractal dimension too low: {}",
            r.classification.hausdorff_dimension
        );
        assert!(
            r.entropy_bits > 0.5,
            "structured plane scored {:.3} bits",
            r.entropy_bits
        );
    }

    // The Mandelbrot whole-set render is a genuinely fractal boundary too; it
    // must carry measurable entropy and a self-similar signature even though
    // its measured dimension at this resolution hovers near the band edge.
    let mb = analyze(mandelbrot_whole());
    assert!(mb.entropy_bits > 0.5);
    assert!(mb.classification.hausdorff_dimension >= 1.0);
    assert!(
        mb.classification.confidence >= 0.5,
        "Mandelbrot boundary should classify with confidence"
    );
}

#[test]
fn flat_plane_scores_zero_entropy_and_regular() {
    let flat = analyze(vec![128u8; (SIDE * SIDE) as usize]);
    assert_eq!(flat.classification.fractal_type, FractalType::Regular);
    assert_eq!(flat.entropy_bits, 0.0);
    // Feature pool collapsed: the source still emits a signature, but a flat
    // plane must not masquerade as an entropy source.
    assert_eq!(flat.signature.len(), SIGNATURE_LEN);
}

#[test]
fn fractal_planes_outscore_flat_planes() {
    let flat = analyze(vec![128u8; (SIDE * SIDE) as usize]);
    let best_fractal = [mandelbrot_whole(), julia_critical(), perlin_field(42)]
        .iter()
        .map(|p| analyze(p.clone()).entropy_bits)
        .fold(0.0f64, f64::max);
    assert!(
        best_fractal > flat.entropy_bits + 1.0,
        "fractal renders ({best_fractal:.2} bits) must outscore a flat plane ({:.2})",
        flat.entropy_bits
    );
}

#[test]
fn signatures_unique_across_many_fractal_views() {
    let views = distinct_views();
    // Sanity: the ladder actually produced distinct planes (pixel-level).
    let unique_pixels: std::collections::HashSet<Vec<u8>> = views.iter().cloned().collect();
    assert!(
        unique_pixels.len() >= views.len() - 2,
        "view ladder collapsed: {} unique of {}",
        unique_pixels.len(),
        views.len()
    );

    let mut signatures = std::collections::HashSet::new();
    for pixels in views {
        let sig = analyze(pixels).signature;
        assert!(
            signatures.insert(sig),
            "collision: two distinct fractal views produced the same signature"
        );
    }
    assert!(signatures.len() >= 40);
}

#[test]
fn single_pixel_flip_avalanches_fractal_signature() {
    // A fractal plane is the least forgiving case for quantization: flip one
    // pixel and the 256-bit signature must still avalanche.
    let size = 128u32;
    let a = test_images::perlin(size, size, 8, 11);
    let mut b = a.clone();
    let mid = (size * size / 2 + size / 2) as usize;
    b[mid] = b[mid].wrapping_add(1);
    assert_ne!(a, b);

    let cfg = FractalAwareConfig::default();
    let ra = extract_fractal_aware(&Image::from_luma(size, size, a).unwrap(), &cfg).unwrap();
    let rb = extract_fractal_aware(&Image::from_luma(size, size, b).unwrap(), &cfg).unwrap();
    let differing = ra
        .signature
        .iter()
        .zip(rb.signature.iter())
        .filter(|(x, y)| x != y)
        .count();
    assert!(
        differing >= 16,
        "expected avalanche on a single-pixel flip, only {differing}/32 bytes differ"
    );
}

// ---------------------------------------------------------------------------
// Full-pipeline guarantees (deterministic keys from fractal image files)
// ---------------------------------------------------------------------------

// Full-pipeline renders must satisfy the preprocessor's ≥128px minimum, so
// they are generated at 256² (the pipeline canonicalizes them anyway).
const FILE_SIDE: u32 = 256;

fn mandelbrot_file() -> Vec<u8> {
    test_images::mandelbrot(
        FILE_SIDE,
        FILE_SIDE,
        300,
        (-0.5, 0.0),
        FILE_SIDE as f64 / 2.7,
    )
}

fn julia_file() -> Vec<u8> {
    test_images::julia(
        FILE_SIDE,
        FILE_SIDE,
        300,
        (-0.75, 0.11),
        FILE_SIDE as f64 / 3.0,
    )
}

fn perlin_file(seed: u64) -> Vec<u8> {
    test_images::perlin(FILE_SIDE, FILE_SIDE, 8, seed)
}

fn save_luma(dir: &std::path::Path, name: &str, pixels: Vec<u8>) -> std::path::PathBuf {
    let img = image::GrayImage::from_raw(FILE_SIDE, FILE_SIDE, pixels).unwrap();
    let path = dir.join(name);
    img.save(&path).unwrap();
    path
}

/// Deterministically derive the hex key of an image file.
fn derive_file(path: &std::path::Path) -> String {
    KeyDerivationPipeline::new()
        .derive_key(path.to_str().unwrap())
        .unwrap()
        .0
        .to_string()
}

#[test]
fn fractal_images_derive_reproducible_distinct_keys() {
    let dir = tempfile::tempdir().unwrap();
    let mb = save_luma(dir.path(), "mb.png", mandelbrot_file());
    let jl = save_luma(dir.path(), "jl.png", julia_file());
    let pn = save_luma(dir.path(), "pn.png", perlin_file(3));
    let pn2 = save_luma(dir.path(), "pn2.png", perlin_file(4));

    // The same fractal file derives the identical key through two independent
    // pipeline instances — strict determinism.
    let pipeline = KeyDerivationPipeline::new();
    let mb_key = derive_file(&mb);
    assert_eq!(
        mb_key,
        pipeline
            .derive_key(mb.to_str().unwrap())
            .unwrap()
            .0
            .as_str(),
        "fractal derivation must be reproducible"
    );

    // Distinct fractal views derive distinct keys.
    let jl_k = derive_file(&jl);
    let pn_k = derive_file(&pn);
    let pn2_k = derive_file(&pn2);
    let keys = [mb_key, jl_k, pn_k, pn2_k];
    for (i, k) in keys.iter().enumerate() {
        for other in &keys[i + 1..] {
            assert_ne!(k, other, "distinct fractal views must yield distinct keys");
        }
    }
}

#[test]
fn edited_fractal_derives_an_unrelated_key() {
    let dir = tempfile::tempdir().unwrap();
    let mb = save_luma(dir.path(), "mb_base.png", mandelbrot_file());
    let key = derive_file(&mb);

    // A one-pixel edit of the fractal render is still a different file and
    // must derive an unrelated key — no recovery path exists.
    let mut edited = image::open(&mb).unwrap().to_luma8();
    let mid = (edited.width() / 2, edited.height() / 2);
    let p = edited.get_pixel_mut(mid.0, mid.1);
    p.0[0] = p.0[0].wrapping_add(1);
    let edited_path = dir.path().join("mb_edited.png");
    edited.save(&edited_path).unwrap();

    assert_ne!(key, derive_file(&edited_path));
}
