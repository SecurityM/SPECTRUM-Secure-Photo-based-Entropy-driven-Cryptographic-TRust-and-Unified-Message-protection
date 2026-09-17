# Architecture

This document describes how SPECTRUM v0.1.0 actually works, as implemented
in this repository. Every claim below is checkable against the source.

## Data flow

```
image file
   │  magic-byte sniff · extension/content cross-check · format allow-list
   │  header-only dimension probe · min/max size checks (fail before decode)
   ▼
limited decode ── strict decoder limits (width/height/max_alloc) from max_size
   │               JPEG-quality floor for lossy inputs
   ▼
canonicalize ──── aspect-preserving resize to (512,512) grayscale,
   │              metadata stripped, SHA-256 of the exact file recorded
   ▼
EntropyEngine.analyze_image ── working buffer downsampled to ≤160 px
   ├─ adaptive properties (complexity → bucket, edge, oscillation, density, clusters)
   ├─ per-source configs (wavelet type/scales, lacunarity box sizes, …)
   └─ eleven independent sources in parallel (rayon) → fixed-order profile
   ▼
Strategy::determine ── deterministic ranking + weights from the profile
   ▼
ConversionPipeline.normalize ── fixed-range byte quantization, round-robin
   ▼
mixer::create_byte_sequence ── weighted spans + strategy tag
   │     (the "witness": classical engines' feature bytes + the raw
   │      Ascon-Hash256 signatures of Chaos/QDM/CML/FractalAware)
   ▼
SHAKE256(domain ‖ len ‖ witness ‖ SHA-256(exact file))
   │     (key_derivation::xof) ──▶ 134-byte / 1072-bit master key
   ▼
HKDF-SHA256 ──▶ 256-bit AES-256-GCM subkey + HMAC-SHA256 subkey  ·  KeyMetadata
```

## What is deterministic and what is not

Deterministic (pure functions of the input bytes):

1. **Preprocessing** — sniffing, size checks, resize and grayscale conversion
   contain no RNG and no clock.
2. **Entropy values** — all wavelet/convolution/chaos math is float math over
   the same buffer; sources run in parallel but are folded into a fixed
   order, so the profile is identical run to run.
3. **Strategy + witness** — a pure sort/partition and byte interleave.
4. **The key** — SHAKE256 absorbs the witness plus the SHA-256 of the exact
   source file and squeezes 134 bytes. Same file bytes → same key.

Not deterministic:

- **`KeyMetadata.creation_timestamp`** — wall-clock seconds at derivation
  time. It is stored in metadata and batch entries and differs between runs.
  It is not an input to the key.
- **AES-GCM nonces** — fresh random 96 bits per encryption, so the
  ciphertext of the same plaintext under the same key differs between runs.
  The key, not the ciphertext, is the deterministic artifact.

Therefore: `derive(file)` returns the same *key* for the same file every
time (locked by `derive_is_deterministic_across_instances`), and an
unrelated key for any other file, because the bound file digest changes with
any byte-level difference. `single_pixel_change_derives_a_different_key` and
`single_bit_change_in_witness_derives_a_different_key` lock sensitivity in;
`tests/fractal_validation.rs` extends the same guarantees to fractal inputs
(Mandelbrot zooms, Julia sets, Perlin/noise fields).

## Message binding

The message stores the SHA-256 of the key image, MAC'd together with the
ciphertext and timestamp. Decryption re-derives the key from the presented
image and refuses a digest mismatch (`ImageMismatch`) before touching the
ciphertext. There is no tolerance: the exact encrypted-under file is
required (unit tests in `message/decryption.rs` cover the wrong-image case,
and `tampered_message_rejected` locks MAC rejection).

## Cryptography

- **Confidentiality + integrity:** AES-256-GCM keyed by an HKDF-SHA256
  (RFC 5869) subkey expanded from the 1072-bit master key under the
  `spectrum/enckey/v1` label; a second label (`spectrum/mackey/v1`) derives
  the HMAC-SHA256 key whose tag occupies the message signature slot. The
  master key never enters AES-GCM directly. MAC verification is
  constant-time and happens before any ciphertext is touched.
- **Image binding:** the image hash participates in the MAC input.
- **Post-quantum (`pq` feature):** `crypto::ntru_prime` (sntrup761 KEM) and
  `crypto::dilithium` (Dilithium3) wrap liboqs. Hybrid message mode is
  integrated: with `--pq-pubkey` (or the facade's hybrid methods) the AES
  and HMAC subkeys become HKDF expansions of the master key ‖ a fresh
  NTRU shared secret, the NTRU ciphertext is stored in the message's
  `ntru_ciphertext` field, and decryption requires both the exact image
  and the NTRU secret key. Classic builds refuse hybrid messages.
  Dilithium3 remains a standalone sign/verify operator; there is no
  message-level signature or ephemeral-key handshake.

## Design decisions and trade-offs

* **Why bound the exact file digest into the XOF?** Feature statistics are
  quantized; two different images could theoretically produce similar
  witness bytes. Absorbing `SHA-256(exact file)` makes the key a strict
  function of the bytes and gives the one-pixel avalanche property. The
  cost is zero error correction: any recompressed copy derives an unrelated
  key. That is intentional — tolerance would be a guessing oracle.
* **Why a bounded 160 px working buffer?** Every source becomes O(small
  n) regardless of input resolution, so derivation time is predictable and
  a 4096×4096 image costs nearly the same as a 512×512 one. The trade-off
  is that fine detail beyond 160 px is invisible to the sources; the exact
  file digest is what carries byte-level sensitivity, not the analysis.
* **Why rayon with a fixed-order fold?** The eleven sources are
  independent, so they run in parallel; each returns exactly one
  `SourceOutcome`, folded in a fixed order, so parallelism cannot change
  the profile.
* **Why HKDF labels instead of one key?** Domain-separated labels
  (`enckey`/`mackey`/`pq-*`) keep the AES and HMAC subkeys independent
  even though they expand from the same master.
* **Why is metadata timestamped but the key not?** The timestamp makes
  batch manifests and metadata auditable; it is excluded from every
  cryptographic input so wall-clock skew cannot break reproducibility.

## Module map (src/)

| Module | Responsibility |
|--------|----------------|
| `entropy_engine/` | 11 sources, adaptive config, strategy, mixer |
| `entropy_engine/sources/wtmm` | 2D multi-scale modulus maxima + partition-function singularity spectrum |
| `entropy_engine/sources/fractal_analysis` | fractal detection, adaptive complex-Morlet WTMM, multifractal `f(α)` spectrum, adaptive normalization — the FractalAware source (see [FRACTAL_AWARE_ANALYSIS.md](FRACTAL_AWARE_ANALYSIS.md)) |
| `entropy_engine/sources/hurst` | dual estimators: rescaled-range + variance-time |
| `entropy_engine/sources/{chaos,quantum_density,coupled_map_lattice}` | Hénon-map orbit, Hermitian density operators, spatiotemporal lattice — each fingerprinted with Ascon-Hash256 |
| `filter/` | Sobel/Laplacian/Gabor kernels, morphology, gaussian blur, 2D stationary wavelets (`wavelet2d`) |
| `image/` | loading, magic-byte sniffing, canonicalization, decoder limits, `Image` buffer |
| `key_derivation/` | normalization, mixing, XOF key collapse (witness ‖ file digest), metadata |
| `report.rs` | structured, keyless JSON analysis reports (schema v2) |
| `data.rs` | on-disk records: exported `.frk` key record, batch manifest |
| `selftest.rs` | runnable correctness battery (`spectrum selftest`) |
| `cli.rs` | library-side command implementations (thin `bin/spectrum.rs` delegates here) |
| `crypto/` | AES-256-GCM, HMAC, optional NTRU-Prime/Dilithium |
| `message/` | `SpectrumMessage` + encrypt/decrypt pipelines |
| `config.rs` | serializable config document with fail-closed parsing |
| `utils/` | SHA-256/HMAC helpers, binary I/O, logging, deterministic test images |
| `bin/spectrum.rs` | argument parsing only |

## Wavelet decomposition (`filter/wavelet2d`)

The 2D stationary wavelet transform (à-trous / starlet) is the geometric
backbone of the WTMM source. It convolves a three-point binomial B(2)
low-pass along each axis with tap gaps doubling per level (no downsampling)
and forms details by subtraction (`high = identity − low`). Each level's
four blocks (LL, LH, HL, HH) sum back to the level's input, so the
decomposition reconstructs its input exactly — the self-test battery checks
this at runtime (`check_wavelet_reconstruction`).

The WTMM source tracks local maxima of the detail modulus
`M = √(lh² + hl² + hh²)` across the scale ladder and regresses the partition
sums `Z(q, s) = Σ Mᵢ(s)^q` against `log s` to obtain `τ(q)`; the Legendre
transform yields the singularity spectrum `f(α)`. All of this is
deterministic float math over the image buffer.

## Reports and batch records

`report::AnalysisReport` (schema version 2) serializes the full analysis
into a versioned JSON document: adaptive properties, per-source
contributions, the strategy, and per-source detail blocks for every engine.
It intentionally contains no key material and no raw source signatures — a
test asserts the serialized document never contains the derived key
(`reports_never_contain_key_material`). `data::BatchManifest` records one
entry per image of a `spectrum batch` run, including failures, so a bulk
derivation is auditable afterwards. Both record writers go through a helper
that sets 0600 permissions on Unix before writing content.

## Input validation and resource limits

- `sniff_format` rejects payloads whose leading bytes do not match a known
  signature (PNG, JPEG, BMP, TIFF LE/BE, GIF87a/89a).
- The preprocessor requires sniffed content to agree with the extension
  claim; mismatches fail before decoding.
- Dimension limits are enforced three ways: a header-only probe (no pixel
  allocation) rejects out-of-range canvases with exact `width`/`height`;
  the decode itself runs under `image::Limits` (`max_image_width`,
  `max_image_height`, and a `max_alloc` budget) so a malformed file that
  misstates its header cannot drive an oversized allocation either; and the
  same limits wrap the standalone `load_image` helper.
- Config parsing rejects unknown fields at any nesting level and any
  `version` other than 1, so a written-but-ignored knob cannot diverge
  between writer and reader. A programmatically built config is validated
  by the same gate (`SpectrumCrypto::with_config` calls `validate`).

## Performance

The engine analyzes a bounded 160 px working buffer with per-source configs
chosen table-style from the adaptive bucket (no search), and sources run in
parallel via `rayon`, so derivation cost is dominated by I/O and the
canonical resize rather than by the analysis. Rough magnitude on the
development machine: a full `derive` of a 512×512 PNG completes in a few
hundred milliseconds including process startup (see [BENCHMARKS.md](BENCHMARKS.md)
for the concrete data point and how to measure on your hardware).
