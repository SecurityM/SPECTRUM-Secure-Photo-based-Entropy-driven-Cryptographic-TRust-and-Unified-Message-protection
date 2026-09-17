# SPECTRUM v0.1.0 — API reference

All fallible operations return `Result<T, SpectrumError>`
(`spectrum::error::Result`). Signatures below were checked against the
source at v0.1.0.

## `SpectrumCrypto` (public facade)

```rust
use spectrum::SpectrumCrypto;

let spectrum = SpectrumCrypto::new()?;                     // default config
// `with_config` validates exactly like a disk-loaded config (Err on an
// invalid document — a programmatic config cannot bypass the checks):
let spectrum = SpectrumCrypto::with_config(&cfg)?;         // loaded SpectrumConfig
```

| Method | Returns | Behavior |
|--------|---------|----------|
| `derive_key_safe(img_path)` | `Result<(Zeroizing<String>, KeyMetadata)>` | 268-char hex key (1072 bits) + metadata. Deterministic over the exact file bytes. The hex key is zeroized on drop. |
| `analyze_image_safe(img_path)` | `Result<Analysis>` | Full entropy profile + adaptive config. Uses the instance's preprocessor config. |
| `encrypt_message_safe(plaintext, key_image)` | `Result<SpectrumMessage>` | AES-256-GCM encrypt bound to the key image. Uses the instance's pipeline config. |
| `decrypt_message_safe(msg, key_image)` | `Result<String>` | Decrypt; re-derives the key, checks the stored image digest and the MAC against the presented image. |
| `encrypt_message_hybrid(plaintext, key_image, pq_public_key)` | `Result<SpectrumMessage>` | (`pq` feature) Two-factor: subkeys are HKDF expansions of master ‖ fresh NTRU-Prime shared secret; the ciphertext rides in the message. Without the feature, returns `PqLayerUnavailable`. |
| `decrypt_message_hybrid(msg, key_image, pq_secret_key)` | `Result<String>` | (`pq` feature) Recipient needs the exact image **and** the NTRU-Prime secret key. A classic build refuses hybrid messages. |

The facade methods run through the instance's `KeyDerivationPipeline`, so a
config loaded with `with_config` affects key derivation and message
encryption alike (locked by the `message_safe_honors_instance_config` test).

## `Analysis` / `EntropyProfile`

```rust
analysis.profile.wtmm.entropy_bits        // per-source estimate
analysis.profile.total_entropy()          // sum over the 11 sources
analysis.adaptive.complexity              // [0,1] adaptive bucket input
analysis.wtmm_config.num_scales           // adaptively chosen scale count
```

`Analysis` bundles the profile (`profile`), the adaptive config
(`adaptive`), the selected WTMM config (`wtmm_config`) and the selected
lacunarity config (`lacunarity_config`).

## Key-derivation primitives (`spectrum::key_derivation`)

```rust
KeyDerivationPipeline::new()                     // default configs
KeyDerivationPipeline::with_configs(entropy, preprocessor)

pipeline.derive_key(path)                        -> Result<(Zeroizing<String>, KeyMetadata)>
pipeline.analyze(&PreprocessedImage)             -> Result<Analysis>
pipeline.byte_sequence(&analysis)                -> Result<Vec<u8>>   // the witness
pipeline.key_bytes(&analysis, &file_sha256)      -> Result<[u8; 134]> // 1072-bit master key

// key_derivation::xof
xof::derive_master_key(&witness, &file_sha256)   -> [u8; 134]         // SHAKE256 squeeze
xof::XOF_DOMAIN_LABEL                            // public domain-separation constant
```

The master key is `SHAKE256(domain_label ‖ len(witness) ‖ witness ‖
SHA-256(exact file))` — 134 bytes squeezed by SHAKE256. The witness is a
deterministic byte sequence built from every source's normalized feature
bytes plus the raw Ascon-Hash256 signatures of the Chaos, QuantumDensityMatrix,
CoupledMapLattice (64-byte dual digest) and FractalAware sources. The witness
alone is not the key and is never persisted.

`KeyMetadata` fields: `version`, `strategy_version`, `strategy_name`,
`entropy_sources_used` (most-weighted first), `image_hash` (hex SHA-256 of
the file), `creation_timestamp` (wall-clock seconds — **not**
deterministic), `total_entropy`.

## Message container (`spectrum::message`)

```rust
msg.serialize()                          -> Result<Vec<u8>>
SpectrumMessage::deserialize(&bytes)     -> Result<SpectrumMessage>
```

Binary layout (little-endian, length-prefixed with `u32`):

```
version(u32)  timestamp(u64)  image_hash(32 bytes)
ntru_ct_len(u32)  ntru_ct    // empty in classic mode; NTRU-Prime ciphertext in hybrid mode
sig_len(u32)      signature  // 32-byte HMAC-SHA256 (hybrid: HMAC under the hybrid subkey)
payload_len(u32)  payload    // nonce(12) ‖ ciphertext+tag
```

`deserialize` rejects any `version` other than `MESSAGE_VERSION` (1),
bounds-checks every slice, and rejects trailing bytes after the payload.

`SpectrumMessage` fields: `version`, `timestamp`, `image_hash` ([u8; 32]),
`ntru_ciphertext` (empty in classic mode; carries the NTRU-Prime
ciphertext in hybrid mode), `signature`, `encrypted_message`.

The timestamp is written once and is MAC'd with the ciphertext, so the
stored value always matches the authenticated one. Message age is **not**
enforced: decryption only logs a warning for messages older than 30 days.

## Entropy sources (`spectrum::entropy_engine::sources`)

Eleven sources; each exposes a typed extractor and result struct.

```rust
wtmm::extract_wtmm(&image, &WtmmConfig)             -> WtmmResult {
    values, singularity_spectrum, tau_exponents, q_values, config, entropy_bits
}
lacunarity::extract_lacunarity(&image, &LacunarityConfig) -> LacunarityResult
multifractal::extract_multifractal(&image, &qs)     -> MultifractalResult
hurst::extract_hurst(&image)                        -> HurstResult {
    value,                 // rescaled-range estimate
    value_variance_time,   // aggregated-variance estimate
    disagreement,          // |RS − VT|
    entropy_bits
}
gradient::extract_gradient_entropy(&image, bins)    -> GradientResult
texture::extract_texture_entropy(&image, &cfg)      -> TextureResult
noise::extract_noise_characteristics(&image)        -> NoiseResult
```

The four signature engines:

```rust
chaos::extract_chaos(&image, &ChaosConfig)          -> ChaosResult {
    signature,             // 256-bit Ascon-Hash256 of the Hénon orbit
    orbit_entropy,         // Shannon bits/byte of the raw orbit buffer
    config, entropy_bits
}
quantum_density::extract_quantum_density(&image, &QuantumDensityConfig)
                                                    -> QuantumDensityResult {
    signature,             // 256-bit Ascon-Hash256 of the operators
    hilbert_dimension, block_count, entropy_bits, config
}
coupled_map_lattice::extract_coupled_map_lattice(&image, &CoupledMapLatticeConfig)
                                                    -> CoupledMapLatticeResult {
    signature,             // dual 512-bit Ascon-Hash256 (mid ‖ final)
    final_shannon_bits,    // spectral Shannon entropy over 8×8 sub-blocks
    cumulative_kl_bits,    // spatiotemporal KL flow across sweeps
    entropy_bits, config
}
fractal_analysis::extract_fractal_aware(&image, &FractalAwareConfig)
                                                    -> FractalAwareResult {
    signature,             // 256-bit Ascon-Hash256 of feature pool + fingerprint
    classification,        // fractal_type, dimension, confidence, self_similarity
    multifractal_width, entropy_bits, config
}
```

All sources run in parallel (`rayon`) over the same ≤160 px working buffer
and are folded into a fixed-order `EntropyProfile`. Per-source
`entropy_bits` values are Shannon-style estimates of feature buffers —
heuristics, not attacker-work bounds.

## Strategy + witness

```rust
Strategy::determine(&profile) -> Strategy {
    name,      // WtmmPrimary | LacunarityPrimary | Balanced | TextureHeavy | NoiseAdaptive
    sources,   // 11 sources ordered by descending weight (stable tie-break)
    weights,   // normalized entropy shares, sum to 1
    version,   // STRATEGY_VERSION = 1
}
```

Selection thresholds: WTMM or lacunarity > 40 % of total → primary strategy;
texture > 30 % → `TextureHeavy`; noise estimate > 5.0 → `NoiseAdaptive`;
otherwise `Balanced`. Zero/degenerate totals fall back to `Balanced` with
equal weights.

## Crypto (`spectrum::crypto`)

```rust
// master = 1072-bit XOF output (any IKM length accepted); subkeys are
// HKDF-SHA256 expansions under domain-separated labels
symmetric::expand_key(&master, label)    -> [u8; 32]
symmetric::encrypt(&master, plaintext)   -> Result<Vec<u8>>   // nonce(12) ‖ ct+tag
symmetric::decrypt(&master, blob)        -> Result<Vec<u8>>
symmetric::authenticate(&master, data)   -> [u8; 32]          // HMAC-SHA256
symmetric::verify(&master, data, tag)    -> Result<()>        // constant-time

// pq feature only; without it every call returns PqLayerUnavailable:
ntru_prime::ntru_generate_keypair()          -> Result<(Vec<u8>, Vec<u8>)>
ntru_prime::ntru_encapsulate(pk)             -> Result<(ss, ct)>
ntru_prime::ntru_decapsulate(sk, ct)         -> Result<ss>
dilithium::dilithium_generate_keypair()      -> Result<(pk, sk)>
dilithium::dilithium_sign(msg, sk)           -> Result<sig>
dilithium::dilithium_verify(msg, sig, pk)    -> Result<bool>

// pq feature only — the hybrid two-factor key schedule:
symmetric::expand_hybrid_keys(&master, &ntru_ss)      -> ([u8; 32], [u8; 32])
symmetric::authenticate_hybrid(&master, &ntru_ss, d)  -> [u8; 32]
symmetric::verify_hybrid(&master, &ntru_ss, d, tag)   -> Result<()>
```

Note: `dilithium_verify` returns `Ok(false)` for a structurally valid but
incorrect signature; only malformed keys or an unavailable scheme yield
`Err`. The NTRU-Prime KEM is integrated into the message flow through the
hybrid facade methods and the CLI's `--pq-pubkey`/`--pq-secretkey` flags;
Dilithium3 remains a standalone sign/verify operator.

Hybrid key schedule (message-level): the AES and HMAC subkeys are HKDF
expansions of `master_key ‖ ntru_shared_secret`, so possession of the
image alone is useless without the NTRU secret key, and vice versa.

## Errors (`spectrum::error::SpectrumError`)

Variants at v0.1.0:

- `ImageTooSmall { width, height }`, `ImageTooLarge { width, height }`
- `ImageFormatNotSupported(String)`, `ImageCorrupted(String)`
- `ImageHasNoEntropy` — raised by key derivation for zero-variance images
- `NtruKeyGenerationFailed`, `DilithiumKeyGenerationFailed`,
  `EncapsulationFailed(String)`, `DecapsulationFailed(String)`,
  `SignatureFailed(String)`, `VerificationFailed(String)`,
  `PqLayerUnavailable`, `PqAlgorithmNotFound(String)`,
  `PqInvalidInput { expected }`
- `WtmmAnalysisFailed`, `LacunarityAnalysisFailed`, `EntropyExtractionFailed`
- `ImageMismatch`, `FileNotFound(String)`, `PermissionDenied(String)`
- `InvalidConfiguration(String)`, `Utf8Error`, `SerializationError(String)`
- `DecryptionFailed`, `MalformedMessage(String)`, `Unknown(String)`

`From<image::ImageError>` maps decoder errors to `ImageCorrupted`; decoder
limit errors are intercepted earlier and mapped to `ImageTooLarge`.

## Configuration (`spectrum::config`)

- `EntropyEngineConfig` — per-source enable flags plus knobs (WTMM scale
  range/count, lacunarity scales, multifractal `q` values, gradient bins,
  texture orientations/frequencies, and the Chaos/QuantumDensityMatrix/
  CoupledMapLattice/FractalAware sub-configs).
- `ImagePreprocessorConfig` — `canonical_size` (512×512), `min_size`
  (128×128), `max_size` (4096×4096), `remove_metadata`, `jpeg_quality_threshold`
  (90), `supported_formats` allow-list. `validate` rejects an inverted
  size window (`min_size` ≥ `max_size`).
- `SymmetricConfig` — `nonce_len`; only 12 is valid (the implemented
  96-bit GCM nonce; anything else was never actually used by the
  encryption layer).
- `SpectrumConfig` — bundles the three above plus a `version` field (1).
  `to_json()`/`from_json()`/`save()`/`load()`; parsing is fail-closed:
  unknown fields at any nesting level and unsupported versions are rejected.
  The same `validate` gate runs for programmatic configs
  (`SpectrumCrypto::with_config`).

## Image pipeline (`spectrum::image`)

- `ImagePreprocessor::preprocess(path) -> Result<PreprocessedImage>` —
  sniff → extension cross-check → allow-list → header-only dimension probe →
  min/max size checks → limited decode → JPEG-quality gate → canonical
  resize → metadata strip → grayscale. The resize is aspect-preserving
  into the `canonical_size` target box: a non-square source lands on the
  longest side (e.g. 512×341 for a 3:2 photo at the default 512×512
  target), so `dimensions` may differ from `canonical_size`, which
  reports the configured target. `PreprocessedImage` carries `data`,
  `dimensions`, `canonical_size`, `format`, `original_hash` (SHA-256 of the
  exact file bytes).
- `loader::detect_format`, `loader::sniff_format`,
  `loader::sniff_format_from_file`, `loader::load_image` (decode under
  strict limits derived from the default `max_size`).
- `Image::from_luma(w, h, data)` — in-memory grayscale buffer for the engine.

## Reports and on-disk records (`spectrum::report`, `spectrum::data`)

```rust
AnalysisReport::from_analysis(&analysis, image_hash, format, dimensions, canonical_size)
  .to_json() / .from_json(&s) / .save(path) / .load(path)

BatchManifest::new(entries: Vec<BatchEntry>)
  .to_json() / .from_json(&s) / .save(path) / .load(path)
  .success_count() / .failure_count()
```

`AnalysisReport` (schema version 2) is a versioned, **keyless** JSON
document: adaptive properties, per-source entropy weights, the strategy, and
per-source detail blocks (WTMM τ(q)/f(α), both Hurst estimates, noise
profile, Chaos orbit metrics, QuantumDensityMatrix Hilbert data,
CoupledMapLattice spectral/KL terms, FractalAware classification). Raw
source signatures are not serialized. Written by `analyze --report`.

`KeyRecord` is the `.frk` export: a checksummed, magic-headered record
(`SPX1KEY1`) holding the key + image hash, written 0600 on Unix. The key is
held in a zeroizing buffer, its `Debug` output is redacted, and loading
rejects any key length other than the 134-byte master key. It is a
convenience snapshot only — nothing on disk is required to reproduce a key.

Secret-material handling summary: hex master keys (`derive_key`/
`derive_key_safe`), `.frk` record keys, and in-memory batch-entry keys are
zeroized on drop; `Debug` impls of key-bearing structs redact the key;
sensitive plaintexts should reach the CLI via `--input-file`, not
`--message` (argv is world-readable).

## CLI entry points (`spectrum::cli`)

```rust
cli::cmd_derive(&spectrum, image, detailed)                            -> Result<()>
cli::cmd_analyze(&spectrum, image, detailed, report_path: Option<&str>) -> Result<()>
cli::cmd_batch(&spectrum, input_dir, files: &[String], manifest_out: Option<&str>)
                                                                       -> Result<BatchManifest>
cli::cmd_verify(&spectrum, key_file, image)                            -> Result<bool>
cli::cmd_selftest(with_fs)                                             -> Result<()>
cli::cmd_export(&spectrum, image, output)                              -> Result<()>
cli::cmd_config(output: Option<&str>)                                  -> Result<()>
cli::print_banner()
```

The `encrypt`, `decrypt` and `pq-keygen` commands live in the binary itself
(`src/bin/spectrum.rs`, private `cmd_encrypt`/`cmd_decrypt`/`cmd_pq_keygen`
helpers): encrypt derives via `encrypt_message_safe` (or the hybrid
facade when `--pq-pubkey` is given), serializes and writes the `.spx`
file (and requires exactly one of `--message`/`--input-file`); decrypt
reads, deserializes and calls `decrypt_message_safe` (hybrid messages
require `--pq-secretkey`); `pq-keygen` writes an NTRU-Prime keypair with
the secret file at 0600. The remaining commands are library functions,
testable without spawning the binary. There is no `recover` command:
derivation is deterministic, so `derive` on the exact original file is
the only way to reproduce a key.

## Self-test battery (`spectrum::selftest`)

```rust
selftest::run_selftest(with_fs: bool) -> Result<Vec<SelfTestResult>>
selftest::all_passed(&results)        -> bool
```

Seven in-memory checks (analysis determinism, per-source contribution, key
stability across instances, distinct images → distinct keys, single-pixel
sensitivity, wavelet reconstruction exactness, sniffer rejection of
mislabeled payloads) plus one optional filesystem check (message
encrypt/decrypt roundtrip) when `with_fs` is true. The CLI exits non-zero if
any check fails.

## Shared math (`spectrum::filter`, `spectrum::stats`)

- `filter`: Sobel/Laplacian/Gaussian/Gabor kernels and convolutions;
  morphology (`dilate`, `erode`, `threshold_mask`); `gaussian_blur`;
  `wavelet2d::swt2_decompose` (2D stationary/à-trous transform with
  `reconstruct()`, `detail_modulus()`, `detail_energy()`).
- `stats`: `linear_fit`, `mean`, `variance`, `std_dev`, `skewness`,
  `kurtosis`, `autocorrelation`, `variance_time_fit`/`variance_time_hurst`,
  min/max, binned Shannon entropy, min-max normalization.
