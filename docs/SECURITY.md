# Security notes

> **Status (v0.1.0):** research software. Not audited. Do not rely on this
> crate for production secrets until a formal review is completed.

## Threat model

The adversary knows the algorithm and can observe ciphertexts; they may know
which image was used but hold no key material, and they have a classical (or
near-term quantum) computer.

## The property that defines this design — read this first

**The key is a deterministic function of the image file. Whoever can read
the image file can derive the key.** There is no secret beyond the file
bytes themselves: no password, no KDF work factor, no stored secret. This is
the intended design (the image *is* the secret), and it means:

- If the image is published, sent as an attachment, or recoverable from a
  backup or thumbnail cache, the key is compromised. Image files are
  routinely copied in ways users do not think of as "leaks".
- Guessing/brute-forcing the key means guessing the exact file bytes —
  infeasible for high-entropy photographs, but a key image chosen from a
  small, predictable set (a stock photo, a screenshot someone else also
  has) is guessable.
- **Zero-variance images are refused.** A flat image (every canonical
  pixel identical) is rejected with `ImageHasNoEntropy` before any key is
  derived: such images carry no information, and every one of them would
  otherwise deterministically derive the *same* key. Low-structure
  (but not perfectly flat) images remain accepted — the guard is a
  variance check on the canonical pixels, not a quality judgment. The XOF
  cannot manufacture entropy: the 1072-bit key width does not add
  unpredictability the image lacks, and the per-source "entropy" numbers
  the tools print are Shannon-style estimates of intermediate feature
  buffers — heuristics, not a bound on an attacker's work.

## What the implementation does

| Property | Mechanism |
|----------|-----------|
| Confidentiality | AES-256-GCM under an HKDF-SHA256 subkey expanded from the 1072-bit SHAKE256 master key (the master is never used directly as an AES key) |
| Integrity / authenticity | HMAC-SHA256 over (ciphertext ‖ image hash ‖ timestamp), verified in constant time before decryption |
| Image binding | the key is a strict function of the exact file bytes; the stored image hash must match the presented image (`ImageMismatch` otherwise) |
| Wrong-image rejection | any other image derives an unrelated key and fails the digest check before any ciphertext processing |
| Determinism | pure-function pipeline; no RNG in derivation; same file → same key |
| Sensitivity | the exact-file SHA-256 is bound into the XOF, so a one-pixel/one-bit/recompression change alters the key (locked by tests) |
| Replay | **warning only**: messages older than 30 days produce a log line and still decrypt. Freshness is not enforced in v0.1.0. |

## Known limitations (honest list)

- **No freshness enforcement.** Old messages decrypt indefinitely; the
  30-day replay check is a warning, not a rejection. Applications needing
  freshness must add it.
- **Post-quantum protection is opt-in and partial.** With the `pq` feature,
  hybrid message encryption combines the image-derived master key with a
  fresh NTRU-Prime (sntrup761) shared secret: decryption requires **both**
  the exact image **and** the recipient's NTRU secret key, and the NTRU
  ciphertext rides in the message's `ntru_ciphertext` field. This is a
  two-factor construction — it is *not* an anonymous PQ handshake (the
  recipient's keypair is long-lived, and Dilithium3 signatures are
  standalone operators the message flow does not use). Without the `pq`
  feature, hybrid messages are refused, not silently ignored. "Post-quantum-
  friendly" otherwise means the symmetric core (AES-256-GCM, SHAKE256,
  HKDF, HMAC) has no known quantum break. The hybrid round trip and its
  failure modes are locked by end-to-end CLI tests (`tests/cli_hybrid_tests.rs`:
  keygen → hybrid encrypt → decrypt with both factors; decryption without
  the secret key, with a wrong secret key, or with a different image must
  all fail).
- **Zeroization is partial.** The hex master key returned by the derivation
  API, `.frk` record keys, the `BatchEntry::key_hex` copies inside a running
  process, and the concatenated hybrid IKM (`master ‖ NTRU shared secret`) are
  zeroized on drop (`zeroize` crate). Fixed-size intermediates (HKDF/AES
  subkeys, SHA/XOF state) live in ordinary stack or heap allocations and are
  not wiped. Memory is not locked against swapping. The CLI prints derived keys to stdout, and a plaintext passed
  via `--message` is visible in the process list (`ps`/`/proc`) — use
  `--input-file` for sensitive payloads.
- **The construction is novel.** The "image → feature bytes → XOF" KDF is
  not a standard, analyzed construction. The cryptographic primitives
  underneath (SHAKE256, HKDF, AES-GCM, HMAC, Ascon-Hash256) are standard
  and audited; how this crate composes them is not.
- **No audit.** Nothing here has been reviewed by a third party.
- **Timing.** MAC verification is constant-time; AES-GCM comes from the
  audited `aes-gcm` crate (and liboqs when enabled). Entropy analysis does
  not branch on secret data — the input image is treated as public — so
  analysis timing is not a secret-dependent channel in this threat model.

## Input validation and denial-of-service resistance

- **Magic-byte sniffing** rejects payloads whose leading bytes do not match
  a known signature (PNG, JPEG, BMP, TIFF LE/BE, GIF87a/89a).
- **Extension/content cross-check:** the sniffed type must agree with the
  file extension's claim; renamed or polyglot files are refused before
  decoding.
- **Decompression-bomb resistance:** dimensions are read from the header
  alone (no pixel allocation) and checked against `min_size`/`max_size`;
  the decode then runs under strict `image::Limits` (`max_image_width`,
  `max_image_height`, `max_alloc`) so even a malformed file that misstates
  its header cannot drive an oversized allocation. The standalone
  `load_image` helper applies the same limits. Oversized inputs fail with
  `ImageTooLarge` instead of a warning.
- **JPEG-quality floor** (default 90) rejects low-quality lossy
  recompression rather than silently accepting a weakened key image.
- **Global input-size cap:** every file read from an untrusted path goes
  through `data::read_capped`, which refuses inputs larger than 128 MiB
  before parsing. The cap is enforced on the read itself (`File::take`),
  not on a pre-read size probe, so a file that grows between the size
  check and the read cannot drive an unbounded allocation. All loaders
  use it: key images, `.spx` messages, `.frk` records, batch manifests,
  configs (`--config`), reports and PQ key files.
- **On-disk records** (`.frk` key files, batch manifests) are
  magic-headered, length-checked and SHA-256-checksummed; any
  single-bit modification is rejected (`tampered_key_record_rejected`,
  `tampered_message_rejected` tests). `.frk` loading additionally rejects
  any key length other than the 134-byte master key. They are written with
  owner-only permissions (0600) set before content is written.
- **Message parsing** bounds-checks every slice, rejects any container
  version other than 1, and rejects trailing bytes after the payload.
- **Config parsing** rejects unknown fields at any nesting level and
  unsupported config versions, so a silently dropped knob cannot produce
  divergent derivation between writer and reader. The same validation runs
  for programmatic configs (`SpectrumCrypto::with_config`).

## Supply chain

- `cargo audit` (advisory DB snapshot of 2026-09, after the codec trim):
  **0 vulnerabilities and 0 warnings** in the dependency tree (the former
  `paste` unmaintained warning came in with `image`'s default codecs —
  `exr`/`ravif` — which are no longer compiled in). Re-check with
  `cargo audit` after any dependency change.
- The dependency surface is trimmed to what the code uses: `image` is
  built with `default-features = false` and only the five accepted codecs
  (png, jpeg, bmp, tiff, gif); the default feature set would pull ~15 more
  codecs and 51 extra transitive crates.
- The crate contains **zero `unsafe`** — enforced by
  `#![forbid(unsafe_code)]` in both crate roots, so any future `unsafe`
  fails the build rather than slipping in. All FFI risk is isolated in
  dependencies (`image`, and `oqs`/liboqs when the `pq` feature is
  enabled).

## Operational checks

- `spectrum selftest [--with-fs]` runs the built-in battery (analysis
  determinism, per-source contribution, key stability across instances,
  distinct images → distinct keys, single-pixel sensitivity, wavelet
  reconstruction, sniffer rejection, optional message roundtrip) and exits
  non-zero on any failure — suitable as a deployment gate.
- `spectrum verify` re-derives the key from a key image and compares it to
  an exported `.frk` record, detecting silent image mutation (even a
  one-pixel edit).
- `spectrum batch` records every failure in the JSON manifest instead of
  aborting, so partial bulk failures are visible.
- Analysis reports (`analyze --report`) are keyless by construction; a test
  (`reports_never_contain_key_material`) asserts the serialized document
  never contains the derived key.

## Recommended hardening

1. ~~Wire NTRU-Prime into the message flow~~ **done in this release** as
   opt-in hybrid mode; the remaining PQ gaps are message-level Dilithium
   signatures and an ephemeral-key handshake if anonymous PQ transport is
   required.
2. Enforce message freshness at the application layer if replay matters.
3. ~~Zeroize key material~~ **partially done in this release** (hex master
   key, `.frk` keys, batch `key_hex`, hybrid IKM; remaining: fixed-size subkey
   intermediates and memory locking (mlock) against swap.
4. Run a NIST SP 800-22-style randomness suite over derived keys from a
   large, diverse image corpus.
5. Collision benchmark across 100k+ images.
6. External cryptographic audit — in particular of the KDF composition
   and the hybrid key schedule, which are the novel and least-reviewed
   parts of this design.
