# Contributing to SPECTRUM

Thanks for considering a contribution. SPECTRUM is cryptography-adjacent
research software, so the bar for changes is higher than usual: correctness
and honesty of claims come first.

## Getting started

```bash
git clone <your-fork>
cd v0.1.0
cargo build --release
cargo test --release          # full default-config suite
cargo test --release --features pq   # requires system liboqs
```

Rust 1.98 is pinned in `rust-toolchain.toml` — use rustup so the pin takes
effect automatically.

## Before you open a PR

Every pull request is expected to pass all of these locally:

```bash
cargo fmt --check                    # formatting (rustfmt defaults)
cargo clippy --all-targets           # zero warnings
cargo clippy --all-targets --features pq
cargo test --release                 # all suites green
cargo test --release --features pq
cargo doc                            # zero warnings
```

There is no CI gate to rely on yet — the checks above are the contract.

## Project rules

1. **Zero dead code.** Nothing lands behind `#[allow(dead_code)]`. If a
   function exists, it is used by production code, tests, or an example —
   otherwise delete it.
2. **Zero `unsafe`.** Both crate roots carry `#![forbid(unsafe_code)]`; do
   not weaken this. FFI belongs in dependencies.
3. **Fail closed.** Untrusted input that cannot be parsed, bounded, or
   validated must produce an error, never a best-effort fallback. Every
   file read from an untrusted path goes through `data::read_capped`.
4. **No panics on hostile input.** Production code must not `unwrap`,
   `expect`, or index in ways a malformed file can reach. The two
   documented exceptions (HMAC key-length invariant, test-image generator)
   are in `src/utils/hashing.rs` and `src/utils/test_images.rs`.
5. **Honest documentation.** Docs describe what the implementation does,
   not what it aspires to. Never claim a guarantee that no test or code
   path supports. Security claims belong in `docs/SECURITY.md` with their
   limitations stated.
6. **Behavior changes need a test.** A regression test that reproduces the
   pre-fix behavior is the norm for bug fixes.
7. **Determinism is a contract.** Derivation must not depend on thread
   count, iteration order of parallel work, or wall-clock time
   (`KeyMetadata.creation_timestamp` is metadata only and never enters the
   key). The `RAYON_NUM_THREADS=1` vs `=4` e2e test in
   `tests/cli_e2e_tests.rs` locks this.

## What especially needs review

Per [docs/SECURITY.md](docs/SECURITY.md), the novel parts are the
least-reviewed: the KDF composition (image → feature bytes → SHAKE256) and
the hybrid PQ key schedule. Security-relevant PRs should say explicitly
what threat they mitigate (see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)).

## Commit style

Short, imperative subject line; body explains *why*. Example from the
existing history:

```
Cap report/config file reads and pin batch/permission guarantees

Config::load (reachable via --config) and AnalysisReport::load still
used unbounded read_to_string — route both through the global 128 MiB
cap with sparse-file regression tests.
```

## Reporting security issues

See the top of [docs/SECURITY.md](docs/SECURITY.md). SPECTRUM v0.1.0 is
unaudited research software — please do not open public issues for
exploitable findings before there is a disclosure channel.
