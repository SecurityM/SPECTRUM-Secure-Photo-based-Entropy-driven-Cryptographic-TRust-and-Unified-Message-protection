//! Benchmarks for entropy extraction and the full key-derivation pipeline.
//!
//! Run with:
//!   cargo bench
//!   cargo bench --bench entropy

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use spectrum::entropy_engine::EntropyEngine;
use spectrum::image::Image;
use spectrum::key_derivation::KeyDerivationPipeline;
use spectrum::utils::test_images::{Kind, TestImage};

/// Benchmark the parallel entropy engine over four deterministic image classes.
fn entropy_suite(c: &mut Criterion) {
    let kinds = [
        (Kind::Bars, "bars"),
        (Kind::Gradient, "gradient"),
        (Kind::Masonry, "masonry"),
        (Kind::Noise, "noise"),
    ];
    for (kind, name) in kinds {
        let img: Image = TestImage {
            width: 512,
            height: 512,
            pixels: kind.generate(512, 512, 1),
        }
        .into_crate_image();
        let engine = EntropyEngine::new();
        c.bench_function(&format!("analyze_{name}_512x512"), move |b| {
            b.iter(|| engine.analyze_image(black_box(&img)))
        });
    }
}

/// Benchmark the full deterministic derivation pipeline
/// (load → canonicalize → analyze → XOF master-key collapse).
fn key_derivation_full(c: &mut Criterion) {
    // Materialize a real PNG once so the image loader + preprocessor run.
    let dir = std::env::temp_dir().join("spectrum_bench_assets");
    std::fs::create_dir_all(&dir).expect("create bench asset dir");
    let target = dir.join("masonry_512.png");
    if !target.exists() {
        let test = TestImage {
            width: 512,
            height: 512,
            pixels: Kind::Masonry.generate(512, 512, 1),
        };
        let mut out = image::RgbImage::new(512, 512);
        for (x, y, p) in out.enumerate_pixels_mut() {
            let v = test.pixels[(y * 512 + x) as usize];
            *p = image::Rgb([v, v, v]);
        }
        out.save(&target).expect("save bench image");
    }

    let pipeline = KeyDerivationPipeline::new();
    let path = target.to_str().unwrap().to_string();
    c.bench_function("key_derivation_full", move |b| {
        b.iter(|| pipeline.derive_key(black_box(&path)))
    });
}

criterion_group!(benches, entropy_suite, key_derivation_full);
criterion_main!(benches);
