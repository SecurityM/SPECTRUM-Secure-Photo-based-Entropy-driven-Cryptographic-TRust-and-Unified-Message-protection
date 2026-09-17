# Threat model

This document states explicitly what SPECTRUM v0.1.0 defends against, what
it does not, and what remains unreviewed. It complements
[SECURITY.md](SECURITY.md), which lists implementation-level limitations.

**Status: research software, not audited.** No third party has reviewed the
design or this implementation.

## Assets

| Asset | Protected by |
|-------|--------------|
| Message plaintext | AES-256-GCM under an HKDF subkey derived from the image key |
| Message authenticity | HMAC-SHA256 over (ciphertext ‖ image hash ‖ timestamp), constant-time verify before decryption |
| Key image integrity (detection) | the stored image digest fails on any byte change (`ImageMismatch`) |
| Exported key records | checksummed `.frk` files, 0600 permissions |

The primary secret is the **key image file itself**. This is a design
decision, not an oversight: derivation is a pure function of the exact file
bytes, so *whoever can read the image can derive the key*. Nothing else —
no password, no stored key — exists to protect.

## Adversaries and what stops them

| Adversary | Outcome in v0.1.0 |
|-----------|-------------------|
| Network observer with the ciphertext | Blocked by AES-256-GCM + HMAC — *if* they never obtain the key image |
| Recipient's machine compromised after decryption | Plaintext recoverable from disk/memory; not defended (out of scope, same as all file crypto) |
| Attacker who obtains the key image | **Full break.** They derive the key and decrypt everything encrypted under that image, past and future |
| Attacker with a candidate image set | Guessable if the image comes from a small predictable set (stock photos, screenshots). A unique high-entropy photograph is not guessable byte-exactly |
| Malicious `.spx` / `.frk` / config file (DoS) | 128 MiB read cap on the read itself, bounds-checked parsing, trailing-garbage rejection, checksummed records, fail-closed config parsing |
| Malicious image file (decompression bomb, polyglot, mislabeled) | Magic-byte sniffing, extension/content cross-check, header-only dimension probe, strict decoder limits, JPEG quality floor |
| Passive quantum adversary | Symmetric core (AES-256, SHA3, HKDF, HMAC) has no known quantum break; Grover halves effective key strength — still ≥ 2^128 for a 256-bit subkey *whose entropy the image actually supplies*. Opt-in NTRU-Prime hybrid adds a PQ factor to two-factor mode |
| Replay of an old message | **Not stopped.** Age > 30 days logs a warning only; decryption proceeds |

## Trust assumptions

1. The endpoint (OS, compiler, dependencies) is not compromised.
2. The key image travels to the recipient over a channel that guarantees
   byte-exactness and confidentiality — SPECTRUM provides none; the image
   *is* the key.
3. liboqs (when built with `pq`) is the vendored system library's
   implementation, trusted as-is.
4. The user understands that publishing the image anywhere (attachment,
   backup, thumbnail cache) forfeits every message encrypted under it.

## Out of scope

- Compromised endpoints, screen capture, swap/hibernation leaks
  (zeroization is partial and memory is not locked — see SECURITY.md).
- Traffic analysis / metadata (message timestamps are authenticated, not
  concealed).
- Anonymity of sender or recipient. Hybrid mode is two-factor, not an
  anonymous PQ handshake: the recipient's NTRU keypair is long-lived and
  there is no forward secrecy — compromise of the key image + NTRU secret
  key exposes all past hybrid messages encrypted under that pair.
- Denial of service at the network layer.

## Known residual risks (summary)

The full list lives in [SECURITY.md](SECURITY.md). The ones that matter
most, in order:

1. **No external audit.** The KDF composition and hybrid key schedule are
   novel and unreviewed; the underlying primitives are standard.
2. **Key image = single point of failure.** One leak compromises all
   messages under that image, with no revocation mechanism.
3. **Replay not enforced.** Freshness must be added at the application
   layer if it matters.
4. **Memory hygiene is partial.** Fixed-size subkeys are not zeroized;
   swap is not prevented.

## Recommended deployment posture

Until an external audit happens: treat SPECTRUM as an experimental
demonstration of the image-bound-key concept, use unique high-entropy key
images, never reuse a published image, transport key images only over
confidential byte-exact channels, and enforce message freshness in the
application if replay matters. `spectrum selftest --with-fs` is a
reasonable deployment gate for correctness (not security) on a target
machine.
