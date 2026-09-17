# CLI reference

`spectrum` v0.1.0 — every flag below was taken from the binary's own
`--help` output at this version. Common mistakes fail early: a missing
`--config`, `--key-image`, or `--input` path is reported before any
processing starts.

## Global options (available on every command)

| Flag | Effect |
|------|--------|
| `-C, --config <CONFIG>` | Load a `.json` config; overrides built-in defaults for **every** command. Encrypt and decrypt must be given the **same** config for a custom-config message pair — a mismatch fails with an image-binding error that does not name the config as the cause |
| `-v, --verbose` | Enable debug logging |
| `-h, --help` | Print help |
| `-V, --version` | Print version |

## `derive` — deterministic key derivation

```
spectrum derive --image <IMAGE> [--detailed]
```

Derives the 1072-bit master key (268-char hex) of an image and prints it
with metadata (strategy, entropy profile, image hash). `--detailed` adds
per-source detail. Same file → same key, always; nothing is persisted.

## `encrypt` — message encryption

```
spectrum encrypt --key-image <KEY_IMAGE> (--message <MESSAGE> | --input-file <INPUT_FILE>)
                 --output <OUTPUT> [--pq-pubkey <PQ_PUBKEY>]
```

AES-256-GCM encrypts the plaintext bound to the key image and writes the
`.spx` container to `--output`.

- Exactly one of `--message` / `--input-file` is required.
- `--message` is visible in the process list (`ps`, `/proc`, shell
  history); **prefer `--input-file`** for anything sensitive. The file
  must contain UTF-8 text.
- With `--pq-pubkey <file>` (requires a build with `--features pq`):
  hybrid two-factor mode. Decrypting will require both the exact key
  image and the recipient's NTRU-Prime secret key. Without the `pq`
  feature the flag fails with `PqLayerUnavailable`.

## `decrypt` — message decryption

```
spectrum decrypt --key-image <KEY_IMAGE> --input <INPUT> [--pq-secretkey <PQ_SECRETKEY>]
```

Verifies the image binding (the stored SHA-256 must match the presented
image) and the MAC before decrypting; prints the plaintext to stdout.

- Hybrid messages require `--pq-secretkey <file>` (and the `pq`
  feature). A classic build refuses hybrid messages rather than ignoring
  the PQ factor.
- Any byte difference in the key image — an edit, a recompression —
  fails the binding check. There is no recovery path.

## `pq-keygen` — post-quantum keypair (`pq` feature)

```
spectrum pq-keygen --public <PUBLIC> --secret <SECRET>
```

Generates an NTRU-Prime (sntrup761) keypair and writes raw bytes to both
files; the secret file is created with owner-only permissions (0600 on
Unix). Without the `pq` feature the command fails with
`PqLayerUnavailable`.

## `analyze` — entropy profile

```
spectrum analyze --image <IMAGE> [--detailed] [--report <REPORT>]
```

Dumps the entropy profile of an image: per-source estimates, adaptive
properties, selected strategy. `--report` writes a structured, versioned
JSON document that is **keyless by construction** (it contains no key
material and no raw source signatures).

## `batch` — bulk derivation

```
spectrum batch [--input-dir <INPUT_DIR> | --files <FILES>...] [--output <OUTPUT>]
```

Derives keys for every image in a directory (`png jpg jpeg bmp tif tiff
gif`, sorted order) or from an explicit file list (`--files` overrides
`--input-dir`). Failures are recorded in the JSON manifest, not fatal.
The manifest contains every derived key: treat it (and stdout) as secret
material; it is written 0600 on Unix.

## `verify` — key-record check

```
spectrum verify --key-file <KEY_FILE> --image <IMAGE>
```

Re-derives the key from the image and compares it against a `.frk`
record produced by `export`. Detects any silent mutation of the image,
even a one-pixel edit. Prints `VERIFIED` or `MISMATCH` and exits with
code **2** on mismatch (1 on error).

## `selftest` — built-in correctness battery

```
spectrum selftest [--with-fs]
```

Runs the in-memory battery (analysis determinism, per-source
contribution, key stability across instances, distinct images → distinct
keys, single-pixel sensitivity, wavelet reconstruction, sniffer
rejection). `--with-fs` adds a message encrypt/decrypt roundtrip that
touches the filesystem. Prints one line per check and exits non-zero on
any failure — usable as a deployment gate.

## `config` — configuration document

```
spectrum config [-o <OUTPUT>]
```

Prints the default JSON configuration to stdout, or writes it to a file
with `-o`. The intended workflow for a custom config: `spectrum config
-o my.json`, edit, then pass `-C my.json` to every command in a
workload. Config parsing is fail-closed: unknown fields and unsupported
versions are rejected.

## `export` — key record

```
spectrum export --image <IMAGE> --output <OUTPUT>
```

Derives the key and writes it to a checksummed, magic-headered `.frk`
file (0600 on Unix). The record is a convenience snapshot — nothing on
disk is required to reproduce a key; `derive` on the exact original file
is always sufficient. There is no `recover` command by design.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | error (bad arguments, invalid input, processing failure) |
| 2 | `verify` mismatch — the record does not match the image |

## Feature gates

| Feature | Effect on the CLI |
|---------|-------------------|
| *(default)* | All commands except `pq-keygen` and the `--pq-*` flags, which fail closed with `PqLayerUnavailable` |
| `pq` | Enables `pq-keygen`, `--pq-pubkey` / `--pq-secretkey` (hybrid two-factor mode). Requires the system liboqs library |
