# Changelog

All notable changes to SPECTRUM are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); version
numbers match the crate version in [Cargo.toml](Cargo.toml).

## [0.1.0] — initial release

First published version. Research software: **not audited** — read
[docs/SECURITY.md](docs/SECURITY.md) before relying on any of it.

### Added

**Core**

- Deterministic key derivation from image files: a 1072-bit (134-byte)
  master key that is a pure function of the exact file bytes. Any change —
  a one-pixel edit, a recompression — derives an unrelated key; there is
  no tolerance and no recovery path.
- Entropy engine with eleven independent sources run in parallel
  (WTMM singularity analysis, lacunarity, multifractal spectrum, dual
  Hurst estimators, gradient, Gabor texture, noise profile, Chaos,
  QuantumDensityMatrix, CoupledMapLattice, and the adaptive FractalAware
  source — see [docs/FRACTAL_AWARE_ANALYSIS.md](docs/FRACTAL_AWARE_ANALYSIS.md)).
- Adaptive per-image configuration: complexity bucketing selects source
  parameters table-style; deterministic strategy ranking and weighted
  byte interleave build the derivation witness.
- Zero-variance (perfectly flat) images are refused with
  `ImageHasNoEntropy`.

**Messaging**

- AES-256-GCM message encryption bound to a key image, authenticated by
  HMAC-SHA256 over (ciphertext ‖ image hash ‖ timestamp), MAC verified
  in constant time before decryption.
- Versioned binary container (`.spx`) with bounds-checked parsing and
  trailing-garbage rejection.

**Post-quantum (opt-in `pq` feature, requires system liboqs)**

- NTRU-Prime (sntrup761) hybrid two-factor message mode: decryption
  requires both the exact key image and the recipient's NTRU secret key.
  A classic build refuses hybrid messages rather than ignoring the PQ
  factor.
- Standalone Dilithium3 sign/verify operators (not used by the message
  flow).
- `pq-keygen` command writing the secret key with owner-only permissions.

**Tooling**

- CLI with ten commands (`derive`, `encrypt`, `decrypt`, `analyze`,
  `batch`, `verify`, `selftest`, `config`, `export`, `pq-keygen`) — see
  [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md).
- Versioned, fail-closed JSON configuration (unknown fields and
  unsupported versions are rejected; programmatic configs pass the same
  validation gate).
- `.frk` key records and batch manifests: checksummed, magic-headered,
  written 0600; JSON analysis reports that are keyless by construction.
- `selftest` correctness battery suitable as a deployment gate.
- Criterion benchmark suites (see [docs/BENCHMARKS.md](docs/BENCHMARKS.md)).
- Test suites: unit, integration, property, security, fractal-validation
  and end-to-end CLI tests (316 tests in the default configuration; 318
  with the `pq` feature).

### Security properties (as implemented)

These describe what the implementation does — checkable against the
source — not a guarantee of cryptographic strength:

- AES/HMAC subkeys are HKDF-SHA256 expansions of the master key under
  domain-separated labels; the master key never enters AES-GCM directly.
- Decoder limits (`image::Limits`) plus a header-only dimension probe
  reject decompression bombs before pixel allocation.
- Every untrusted file read goes through a 128 MiB cap enforced on the
  read itself.
- Zero `unsafe` — enforced by `#![forbid(unsafe_code)]` in both crate
  roots.
- Key material in hex form, `.frk` records and batch entries is zeroized
  on drop; `Debug` output of key-bearing structs is redacted.
- Magic-byte sniffing plus extension/content cross-check; JPEG quality
  floor against silent lossy recompression.

### Known limitations

The authoritative list lives in
[docs/SECURITY.md](docs/SECURITY.md). Headlines: whoever can read the
image file can derive the key (the image *is* the secret); message
freshness is warned, not enforced; zeroization is partial and memory is
not locked against swap; the KDF composition is novel and has not been
reviewed by any third party.
