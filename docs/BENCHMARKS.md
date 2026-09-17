# Benchmarks

Benchmarks use [criterion](https://crates.io/crates/criterion) and live in
`benches/`:

* `benches/performance.rs` — WTMM extraction, full pipeline, adaptive config,
  blur, 2D wavelet, batch derivation.
* `benches/entropy.rs` — engine analysis over four deterministic image
  classes plus end-to-end derivation.

## Running

```bash
cargo bench                              # all suites
cargo bench --bench performance          # main suite only
cargo bench --bench performance -- wtmm  # filter by name substring
```

Bench images are generated deterministically at first run and cached under
`$TMPDIR/spectrum_bench_assets/`.

## Suites

| Benchmark | What it measures |
|-----------|------------------|
| `wtmm_simple_256x256` / `wtmm_complex_512x512` | 2D multi-scale WTMM extraction |
| `key_derivation_full` | load → canonicalize → analyze → mix → XOF collapse (in both suites) |
| `adaptive_*_160` | adaptive property analysis per image class |
| `gaussian_blur_*_160` | separable gaussian blur |
| `swt2_masonry_160_d3` | 3-level 2D stationary wavelet decomposition |
| `batch_derive_10_images` | 10 sequential derivations through one pipeline |
| `analyze_{bars,gradient,masonry,noise}_512x512` | full engine analysis per class |

## Internal design targets

These are the targets the implementation was designed against, carried over
from the original project specification (the spec document itself is not
part of this repository). They are **targets, not published measurements** —
run the suites above to check them on your hardware:

| Component | Target |
|-----------|--------|
| Preprocessing (load + resize) | ≤ 30 ms |
| Gradient / texture extraction | ≤ 20 ms |
| WTMM | ≤ 50 ms |
| Lacunarity | ≤ 30 ms |
| Multifractal | ≤ 40 ms |
| Hurst (both estimators) | ≤ 20 ms |
| Strategy determination | ≤ 5 ms |
| Normalization + mixing | ≤ 10 ms |
| SHA-256 | ≤ 5 ms |
| **Total key derivation** | **< 200 ms** |
| **Total encryption / decryption** | **< 250 ms** |

One data point from the v0.1.0 development machine (release build,
512×512 random-noise PNG): `spectrum derive` completed end-to-end in
≈0.16 s including process startup, consistent with the < 200 ms target.
This is a single uncontrolled measurement, not a benchmark result — treat
it as a magnitude indicator only.

## Why the targets are attainable by design

* The engine analyzes a bounded 160 px working buffer, keeping every source
  O(n) in a small pixel count regardless of input resolution.
* WTMM runs over a fixed ladder of stationary-wavelet levels; maxima
  detection is a single 8-connected pass per level.
* The variance-time Hurst estimator regresses over O(log n) doubling windows.
* The eleven sources run in parallel via `rayon`; per-source configs are
  chosen table-style from the adaptive bucket, never by search.

## Reproducing

Criterion reports (median, mean, p95, slopes) are written to
`target/criterion/`. A CI-friendly one-line summary:

```bash
cargo bench --bench performance -- --save-baseline main
```

Compare later runs with `--baseline main`.
