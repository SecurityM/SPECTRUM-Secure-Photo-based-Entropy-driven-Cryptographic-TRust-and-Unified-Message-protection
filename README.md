# SPECTRUM v0.1.0

**S**ecure **P**hoto-based **E**ntropy-driven **C**ryptographic **TR**ust and
**U**nified **M**essage protection.

SPECTRUM is a Rust library and CLI that derives cryptographic keys from image
files and encrypts messages bound to them. A key is a deterministic function
of the exact bytes of one image: the same file always reproduces the same
key, and any other file — a one-pixel edit, a recompression, a re-capture —
derives an unrelated key. Decrypting a message requires the exact image file
it was encrypted under.

> **Status: research software, version 0.1.0. Not audited.** The design is
> unreviewed and the security claims below describe what the implementation
> does, not a guarantee of cryptographic strength. See
> [docs/SECURITY.md](docs/SECURITY.md) for the full limitations before
> relying on it for anything real.

## How it works

```
image file
  │  format sniffing (magic bytes), extension/content cross-check,
  │  size limits enforced at header-parse time, JPEG-quality floor
  ▼
canonicalization ── grayscale, metadata stripped, aspect-preserving
                    resize into the 512×512 target box (a non-square
                    source keeps its aspect ratio, e.g. 512×341; the
                    exact post-resize size is reported in `dimensions`),
  │                 SHA-256 of the exact original file recorded
  ▼
entropy engine ──── 11 independent sources run in parallel (rayon) on a
  │                 ≤160 px working buffer: WTMM singularity analysis,
  │                 lacunarity, multifractal spectrum, dual Hurst
  │                 estimators, gradient, Gabor texture, noise profile,
  │                 Hénon-map "Chaos" source, Hermitian-density-operator
  │                 "QuantumDensityMatrix" source, spatiotemporal
  │                 "CoupledMapLattice" source, and the fractal-aware
  │                 "FractalAware" source (box-counting dimension,
  │                 adaptive complex-Morlet WTMM, f(α) spectrum)
  ▼
strategy + mixer ── deterministic source ranking/weights, weighted byte
  │                 interleave (the "witness")
  ▼
SHAKE256 ────────── 134-byte (1072-bit) master key squeezed from
  │                 witness ‖ SHA-256(exact file)
  ▼
HKDF-SHA256 ─────── 256-bit AES-256-GCM subkey + HMAC-SHA256 subkey
```

Message encryption is AES-256-GCM keyed by the HKDF subkey; an HMAC-SHA256
over (ciphertext ‖ image hash ‖ timestamp) authenticates it. The message
container stores the SHA-256 of the key image and decryption refuses any
other image. No record is produced or required: derivation is a pure
function of the image file.

**Config pairing:** the effective configuration (including `--config`) is
part of the key derivation, so a message encrypted under a custom config
only decrypts under that same config. Encrypt and decrypt must therefore
run with the same `--config` file — a mismatch fails with an image-binding
error that does not name the config as the cause (this workflow is pinned
by `tests/cli_e2e_tests.rs`).

**Optional two-factor mode** (requires the `pq` feature): with
`encrypt --pq-pubkey <file>`, the AES and HMAC subkeys become HKDF
expansions of the image-derived master key ‖ a fresh NTRU-Prime shared
secret, and the NTRU ciphertext is stored in the message. Decryption then
requires **both** the exact image **and** the NTRU-Prime secret key
(`decrypt --pq-secretkey <file>`). A classic build refuses hybrid
messages rather than silently ignoring the PQ factor.

**Honest note on "1072 bits":** the master key is 1072 bits wide, but the
effective security of a derived key is bounded by how unpredictable the
source image actually is. The per-source "entropy" numbers the tools report
are Shannon-style estimates of intermediate feature buffers — they are
heuristics, not measurements of an attacker's work. Low-structure images
(a flat photo, a synthetic gradient) yield keys whose strength is only as
good as their real randomness. Perfectly flat images are rejected outright
(`ImageHasNoEntropy`).

## Quick start

Requires Rust 1.98 (pinned in `rust-toolchain.toml`).

```bash
cargo build --release
cargo test --release

# Derive a key from an image
cargo run --release --bin spectrum -- derive --image photo.png

# Encrypt / decrypt a message bound to an image
cargo run --release --bin spectrum -- encrypt --key-image photo.png --message "hi" --output msg.spx
cargo run --release --bin spectrum -- decrypt --key-image photo.png --input msg.spx

# Optional two-factor mode (requires building with --features pq)
cargo run --release --features pq --bin spectrum -- pq-keygen --public ntru.pub --secret ntru.sk
cargo run --release --features pq --bin spectrum -- encrypt --key-image photo.png --message "hi" --output msg.spx --pq-pubkey ntru.pub
cargo run --release --features pq --bin spectrum -- decrypt --key-image photo.png --input msg.spx --pq-secretkey ntru.sk
```

Passing a secret through `--message` exposes it in the process list
(`ps`, `/proc`, shell history); prefer `--input-file <file>` for anything
sensitive.

## CLI commands

| Command | Purpose |
|---------|---------|
| `derive --image <img> [--detailed]` | Derive the 1072-bit master key (268-char hex) + metadata |
| `encrypt --key-image <img> (--message <s> \| --input-file <f>) --output <out.spx> [--pq-pubkey <file>]` | AES-256-GCM encrypt, bound to the image; with `--pq-pubkey`, two-factor hybrid mode (`pq` feature) |
| `decrypt --key-image <img> --input <msg.spx> [--pq-secretkey <file>]` | Decrypt; verifies image binding and MAC; hybrid messages require the NTRU secret key (`pq` feature) |
| `analyze --image <img> [--detailed] [--report <report.json>]` | Dump the entropy profile; optionally write a JSON report |
| `batch --input-dir <dir> \| --files <imgs...> [--output manifest.json]` | Derive keys for many images; failures are recorded, not fatal |
| `verify --key-file <key.frk> --image <img>` | Re-derive and compare against an exported `.frk` record |
| `selftest [--with-fs]` | Run the built-in correctness battery |
| `config [-o out.json]` | Print/write the default configuration document |
| `export --image <img> --output key.frk` | Save the derived key to a checksummed record |
| `pq-keygen --public <file> --secret <file>` | Generate an NTRU-Prime (sntrup761) keypair for two-factor mode (`pq` feature) |

Global flags: `-C/--config <spectrum.json>` loads a saved configuration,
`-v/--verbose` enables debug logging. Common mistakes fail early: a missing
`--config`, `--key-image`, or `--input` path is reported before any
processing starts.

## Library use

```rust
use spectrum::SpectrumCrypto;

let spectrum = SpectrumCrypto::new();

// Deterministic key from an image file.
let (key_hex, metadata) = spectrum.derive_key_safe("photo.png")?;

// Encrypt / decrypt bound to the same file.
let msg = spectrum.encrypt_message_safe("secret", "photo.png")?;
let plain = spectrum.decrypt_message_safe(&msg, "photo.png")?;
assert_eq!(plain, "secret");
```

`SpectrumCrypto::with_config(&SpectrumConfig) -> Result<...>` builds an
instance from a serializable configuration document (`entropy` knobs for all
eleven sources, `preprocessor` sizes/quality floor/format allow-list,
`symmetric`). The document is validated the same way whether built in code
or loaded from disk. Configs round-trip through
`SpectrumConfig::to_json`/`from_json`; parsing is fail-closed (unknown
fields and unsupported versions are rejected).

The derived key hex is returned in a zeroizing buffer: it is wiped from
memory when dropped, and the `Debug` output of key-bearing structs is
redacted.

## What is deterministic and what is not

- **The key is deterministic.** Same file bytes → same 268-hex-char key,
  through any number of pipeline instances, under any thread count (the
  parallel engine's per-source tasks are order-independent and this is
  pinned by a test running `RAYON_NUM_THREADS=1` against `=4`).
- **Cross-machine determinism is expected, not guaranteed.** The analysis
  math uses f64 transcendentals (`ln`, `log2`, `powf`, `sin`) whose
  last-ULP behavior is delegated to the platform's libm; two builds on
  different CPU architectures or libm implementations could disagree in
  the last bit of one intermediate value, and the avalanche step would
  turn that into a different key. Verify on your target platforms before
  relying on keys derived on separate machines.
- **The metadata timestamp is not.** `KeyMetadata.creation_timestamp` is the
  wall-clock time of the derivation; it differs between runs and is not part
  of the key.
- **Any byte change changes the key.** There is no tolerance and no recovery
  path: a modified image derives an unrelated key, by design.

## Input handling and resource limits

- Magic-byte sniffing rejects non-image payloads; the sniffed content must
  agree with the file's extension claim (renamed/polyglot files are refused
  before decoding).
- Images are rejected below `min_size` (128×128 default) or above `max_size`
  (4096×4096 default). The maximum is enforced twice: from the header before
  any pixel allocation (a small file declaring a huge canvas is rejected with
  `ImageTooLarge`), and again as strict decoder limits (`max_image_width`,
  `max_image_height`, `max_alloc`) applied to every decode path in the crate.
- JPEGs below the configured quality floor (default 90) are rejected, so
  lossy recompression cannot silently replace the key image.
- On-disk records (`.frk` key files, batch manifests) are checksummed and
  written with owner-only permissions (0600 on Unix).

## Tests

316 tests in the default configuration: 247 in-crate unit tests plus 69
integration/property/security tests (`tests/unit_tests.rs`,
`integration_tests.rs`, `property_tests.rs`, `security_tests.rs`,
`fractal_validation.rs`, `cli_e2e_tests.rs`), plus a runnable `spectrum
selftest` battery with the same checks. With `--features pq`, 318 tests run
(247 lib + 2 end-to-end CLI tests for the hybrid flow in
`tests/cli_hybrid_tests.rs`, which compile out without the feature, plus the
other suites).

## Repository layout

| Path | Contents |
|------|----------|
| `src/entropy_engine/` | the 11 sources, adaptive config, strategy, mixer |
| `src/filter/` | Sobel/Laplacian/Gabor kernels, morphology, 2D stationary wavelets |
| `src/image/` | loading, sniffing, canonicalization, decoder limits |
| `src/key_derivation/` | normalization, mixing, SHAKE256 collapse, metadata |
| `src/crypto/` | AES-256-GCM/HMAC; optional NTRU-Prime/Dilithium (`pq` feature) |
| `src/message/` | message container + encrypt/decrypt pipelines |
| `src/cli.rs`, `src/bin/spectrum.rs` | command implementations; thin binary |
| `src/report.rs`, `src/data.rs` | JSON analysis reports; `.frk`/batch records |
| `src/selftest.rs` | the `selftest` battery |
| `examples/` | runnable library examples |
| `tests/`, `benches/` | integration/property/security tests; CLI e2e tests for the hybrid flow (compiled out without `pq`); criterion benches |

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — pipeline, module map, why determinism holds
- [docs/API.md](docs/API.md) — public API reference
- [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) — every command and flag, from the binary's own help
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — assets, adversaries, out-of-scope, residual risks
- [docs/SECURITY.md](docs/SECURITY.md) — implemented properties, limitations, supply chain
- [docs/FRACTAL_AWARE_ANALYSIS.md](docs/FRACTAL_AWARE_ANALYSIS.md) — the FractalAware source
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md) — how to measure; internal design targets
- [CHANGELOG.md](CHANGELOG.md) — release history
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution rules and verification gates

## Features and dependencies

| Feature | Effect |
|---------|--------|
| *(default)* | AES-256-GCM + HMAC layer; no C dependencies |
| `pq` | NTRU-Prime (sntrup761) + Dilithium3 via liboqs (system library required). Adds the `pq-keygen` command, two-factor hybrid message encryption, and standalone Dilithium3 sign/verify operators. Without the feature, hybrid requests fail closed. |

Main dependencies: `image 0.25`, `sha2`, `sha3` (SHAKE256), `hkdf`, `aes-gcm`,
`hmac`, `ascon-hash256`, `zeroize`, `rayon`, `ndarray`, `num-complex`,
`clap`, `serde`/`serde_json`, `rand`, and optionally `oqs`. See
[Cargo.toml](Cargo.toml).

## License

Apache-2.0. See [LICENSE](LICENSE) and [Cargo.toml](Cargo.toml).
