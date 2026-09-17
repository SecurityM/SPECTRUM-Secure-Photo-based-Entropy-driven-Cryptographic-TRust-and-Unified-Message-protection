# Fractal-aware analysis

The FractalAware source (`src/entropy_engine/sources/fractal_analysis/`) is
the eleventh entropy source. It measures an image's scale behaviour
explicitly, then adapts its analysis to what it measured. Ordinary
photography passes through the same stages as fractal renders; the
classifier is metadata, never a gate.

## Why a dedicated source

The classical engines (WTMM, lacunarity, multifractal, …) are calibrated
for photographic dynamic range. A Mandelbrot render or a Julia set is
dominated by structure that repeats across scales, which pushes
fixed-normalization stages toward their clamps. The fractal pipeline:

1. measures the image's scale behaviour (box-counting dimension,
   lacunarity),
2. runs a WTMM whose significance thresholds follow the measured dimension
   and which stops early once maxima counts converge, and
3. quantizes every series against the range actually observed in that
   image, so extreme renders clip predictably instead of silently.

Every stage is a pure, deterministic function of the pixels — no fitted
constants per image, no RNG — so the 32-byte Ascon-Hash256 signature and
its entropy estimate reproduce exactly for the same image.

## Pipeline

### 1. Fractal detection (`detection.rs`)

* **Box-counting dimension** — Sobel edge magnitudes are thresholded at one
  standard deviation above the mean (smooth ramps yield no spurious edges),
  then occupied-box counts across the power-of-two ladder
  `2, 4, …, 256` are regressed in log-log space. The absolute slope is the
  reported Hausdorff-dimension estimate; `R²` measures scale invariance.
* **Gliding-box lacunarity** — window edge-mass variance across scales; its
  spread is the multifractal-width proxy.
* **Classification** — the dimension maps onto a geometric family:

  | Estimated dimension | Classification |
  |---------------------|----------------|
  | `< 1.2`             | `Regular` |
  | `1.2 – 1.8`         | `NaturalFractal` |
  | `1.8 – 1.95`        | `JuliaSet` |
  | `≥ 1.95`            | `MandelbrotBoundary` |

  Confidence is assembled from the dimension band, self-similarity
  (`R² ≥ 0.95`, bands `1.15–1.95`) and lacunarity spread.

Classification is **metadata**, not a gate: it feeds one signature byte, a
small WTMM threshold nudge and the terminal report. All stages always see
the full measurement set.

### 2. Adaptive WTMM (`adaptive_wtmm.rs`)

A complex-Morlet continuous wavelet transform (zero-mean kernels, so
constant planes respond exactly zero) runs at dyadic scales `1, 2, 4, …`.
At each scale, modulus maxima are counted above a threshold set as a
fraction of that scale's own peak modulus, boosted slightly for high
measured dimension. When the count stops changing between consecutive
scales (relative change below `convergence_threshold` for three scales in a
row), the ladder is cut short.

### 3. Multifractal spectrum (`multifractal_spectrum.rs`)

Partition functions `Z(q, r) = Σ μᵢ(r)^q` over the intensity-normalized box
measures for the moment ladder `q ∈ {−5, −3, −1, 0, 1, 3, 5}`; linear
regression of `log Z` vs `log r` yields `τ(q)`; central differences give
`α(q) = dτ/dq` and the Legendre transform `f(α) = q·α − τ(q)`. The spread
of `α` (the spectrum width) measures how multifractal the image is:
monofractals collapse to a single `α`, boundary fractals fan out.

### 4. Adaptive normalization (`normalization.rs`)

Each feature series is quantized against its own observed `[min, max]`
(with 2 % headroom). A constant series maps every value to the neutral
byte `128`, so featureless planes cannot masquerade as entropy.

### 5. Signature and entropy estimate (`mod.rs`)

The signature pre-image is the classification header (type, dimension,
confidence), the adaptively quantized series (lacunarity spectrum, WTMM
maxima counts, `f(α)`) **and a fixed-point luminance fingerprint** (one
byte per pixel at absolute scale). The fingerprint is what makes the
signature respond to a single-pixel edit that the quantized statistics may
legitimately absorb. The pool collapses through Ascon-Hash256 to 32 bytes.

The reported entropy is a Shannon estimate over the count-based series
(lacunarity + maxima counts) scaled by the multifractal width. Flat planes
score exactly `0`; fractal planes score proportionally to how far their
structure fans out.

## Guarantees (locked by tests)

`tests/fractal_validation.rs` plus module unit tests assert:

| Property | Coverage |
|----------|----------|
| Determinism | identical signature/values/keys across repeats of the same fractal file |
| Single-pixel avalanche | a one-pixel edit flips at least half of the 32 signature bytes (≥ 16 asserted) |
| Collision resistance | 48 generated fractal views (12 Mandelbrot zooms, 12 Julia sets, 12 Perlin fields, 12 noise fields) → collision-free signatures, asserted `≥ 40` distinct |
| Classification | structured renders land in the fractal bands (`NaturalFractal`/`JuliaSet`/`MandelbrotBoundary`, self-similar); flat planes report `Regular` with zero entropy |
| Edited-render sensitivity | a one-pixel edit of a Mandelbrot render derives an unrelated key (strict determinism; no recovery path) |
| Finite values | wide range of inputs (flat, noise, renders, ramps) stays finite |

Test inputs are generated deterministically in `src/utils/test_images.rs`
(`mandelbrot`, `julia`, `perlin`, plus the classical
`bars`/`gradient`/`masonry`/`noise` presets).

## What this source does not do

* It does not distinguish a *specific* fractal (which Julia parameter, which
  zoom region) — the classification is a coarse four-band family label.
* Its dimension estimate depends on the edge-threshold heuristic; a
  smooth-shaded render can measure below the band its mathematics would
  suggest. The band then only affects metadata, never key derivation.
* Its "entropy" output is a Shannon-style estimate over intermediate
  feature series — it is a profile number, not a measure of key strength
  (see [SECURITY.md](SECURITY.md)).

## Configuration

The source ships enabled by default. `EntropyEngineConfig.fractal_aware_config`
(`FractalAwareConfig`) carries: detection ladder cap, complex-Morlet
threshold, convergence threshold, WTMM scale cap and the multifractal `q`
ladder. All are validated (finite, bounded, distinct), and a configuration
change deterministically changes the signature.

## Performance

The source runs on the same ≤160 px working buffer as every other engine;
its box/lacunarity ladders are capped by image side and the WTMM exits once
the plateau converges. Measure with the criterion benches (see
[BENCHMARKS.md](BENCHMARKS.md)) rather than ad-hoc timings.

## Relationship to the rest of SPECTRUM

* Enters the engine as the eleventh source; per-source entropy feeds the
  strategy, mixer and key-derivation byte sequence exactly like the others.
* Its 32-byte Ascon-Hash256 signature is absorbed into the witness
  alongside the Chaos/QuantumDensityMatrix/CoupledMapLattice signatures.
* The classifier byte and dimension/width/confidence metrics appear in the
  CLI's detailed output and in `FractalAwareResult` (reports remain
  keyless).
