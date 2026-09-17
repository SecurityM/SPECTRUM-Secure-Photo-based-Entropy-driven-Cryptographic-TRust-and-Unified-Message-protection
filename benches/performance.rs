//! Performance benchmarks.
//!
//! Run with:
//!   cargo bench --bench performance

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use spectrum::image::Image;
use spectrum::key_derivation::KeyDerivationPipeline;
use spectrum::utils::test_images::{Kind, TestImage};

fn img(kind: Kind, side: u32, seed: u64) -> Image {
    TestImage {
        width: side,
        height: side,
        pixels: kind.generate(side, side, seed),
    }
    .into_crate_image()
}

/// WTMM at multiple sizes and complexity classes.
fn bench_wtmm(c: &mut Criterion) {
    use spectrum::entropy_engine::sources::wtmm::{extract_wtmm, WaveletType, WtmmConfig};
    let simple = img(Kind::Gradient, 256, 1);
    let complex = img(Kind::Noise, 512, 2);
    let cfg = WtmmConfig::new(1, 64, 16, WaveletType::MexicanHat);
    c.bench_function("wtmm_simple_256x256", |b| {
        b.iter(|| extract_wtmm(black_box(&simple), &cfg))
    });
    c.bench_function("wtmm_complex_512x512", |b| {
        b.iter(|| extract_wtmm(black_box(&complex), &cfg))
    });
}

/// The end-to-end derivation pipeline against a real file.
fn bench_full_pipeline(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("spectrum_bench_assets");
    std::fs::create_dir_all(&dir).expect("create bench asset dir");
    let target = dir.join("gradient_512.png");
    if !target.exists() {
        let test = TestImage {
            width: 512,
            height: 512,
            pixels: Kind::Gradient.generate(512, 512, 1),
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

/// Adaptive-config + morphology overhead over four image classes.
fn bench_adaptive_and_filters(c: &mut Criterion) {
    for (kind, name) in [
        (Kind::Bars, "bars"),
        (Kind::Masonry, "masonry"),
        (Kind::Noise, "noise"),
    ] {
        let image = img(kind, 160, 3);
        c.bench_function(&format!("adaptive_{name}_160"), |b| {
            b.iter(|| spectrum::entropy_engine::adaptive_config::analyze(black_box(&image)))
        });
        c.bench_function(&format!("gaussian_blur_{name}_160"), |b| {
            b.iter(|| spectrum::filter::gaussian_blur(black_box(&image), 5, 2.0))
        });
    }
}

/// 2D stationary wavelet decomposition cost at the working resolution.
fn bench_wavelet2d(c: &mut Criterion) {
    let image = img(Kind::Masonry, 160, 4);
    c.bench_function("swt2_masonry_160_d3", |b| {
        b.iter(|| {
            spectrum::filter::wavelet2d::swt2_decompose(
                black_box(&image),
                3,
                spectrum::filter::Wavelet::MexicanHat,
            )
        })
    });
}

/// Batch derivation throughput (10 images, one pipeline).
fn bench_batch_derivation(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("spectrum_bench_assets");
    std::fs::create_dir_all(&dir).expect("create bench asset dir");
    let paths: Vec<String> = (0..10)
        .map(|i| {
            let p = dir.join(format!("batch_{i}.png"));
            if !p.exists() {
                let mut out = image::RgbImage::new(160, 160);
                for (x, y, px) in out.enumerate_pixels_mut() {
                    let v = ((x * 3 + y * 7 + i * 17) % 256) as u8;
                    *px = image::Rgb([v, v.wrapping_mul(2), v.wrapping_add(40)]);
                }
                out.save(&p).expect("save batch bench image");
            }
            p.to_str().unwrap().to_string()
        })
        .collect();

    c.bench_function("batch_derive_10_images", |b| {
        b.iter(|| {
            let pipeline = KeyDerivationPipeline::new();
            let mut keys = Vec::with_capacity(paths.len());
            for p in &paths {
                keys.push(pipeline.derive_key(p).map(|(k, _)| k));
            }
            keys
        })
    });
}

criterion_group!(
    benches,
    bench_wtmm,
    bench_full_pipeline,
    bench_adaptive_and_filters,
    bench_wavelet2d,
    bench_batch_derivation
);
criterion_main!(benches);
