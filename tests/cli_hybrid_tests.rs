//! End-to-end tests for the hybrid post-quantum CLI flow.
//!
//! These spawn the real `spectrum` binary (`env!("CARGO_BIN_EXE_spectrum")`)
//! and drive the documented user path: `pq-keygen` → `encrypt --pq-pubkey` →
//! `decrypt --pq-secretkey`, plus the failure cases: decrypting a hybrid
//! message without the NTRU secret key, with a *wrong* secret key, and with
//! a *wrong* key image. The whole file compiles out without the `pq`
//! feature.

#![cfg(feature = "pq")]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

/// Run the real binary and return (success, combined stdout+stderr).
fn run_bin(args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_spectrum"))
        .args(args)
        .output()
        .expect("failed to spawn the spectrum binary");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// A structured (non-flat) 160×160 PNG: a valid key image. `seed` varies
/// the pixels so different calls produce byte-different files (determinism
/// is over exact file bytes — two files with identical pixels are the same
/// key image, whatever their names).
fn sample_image(dir: &TempDir, name: &str, seed: u8) -> PathBuf {
    let path = dir.path().join(name);
    let mut img = image::RgbImage::new(160, 160);
    for (x, y, p) in img.enumerate_pixels_mut() {
        *p = image::Rgb([
            (x * 3 + seed as u32) as u8,
            (y * 5 + seed as u32 * 7) as u8,
            ((x + y) * 7 + seed as u32 * 13) as u8,
        ]);
    }
    image::save_buffer(&path, img.as_raw(), 160, 160, image::ColorType::Rgb8).unwrap();
    path
}

/// Generate an NTRU-Prime keypair through the CLI itself.
fn keypair(dir: &TempDir, tag: &str) -> (PathBuf, PathBuf) {
    let pk = dir.path().join(format!("{tag}.pub"));
    let sk = dir.path().join(format!("{tag}.sk"));
    let (ok, log) = run_bin(&[
        "pq-keygen",
        "--public",
        pk.to_str().unwrap(),
        "--secret",
        sk.to_str().unwrap(),
    ]);
    assert!(ok, "pq-keygen failed: {log}");
    assert!(
        pk.exists() && sk.exists(),
        "keypair files must exist: {log}"
    );
    (pk, sk)
}

#[test]
fn hybrid_cli_roundtrip_and_negative_cases() {
    let dir = TempDir::new().unwrap();
    let img = sample_image(&dir, "key.png", 0);
    let (pk, sk) = keypair(&dir, "recipient");
    let msg = dir.path().join("msg.spx");
    let plaintext = "hybrid e2e hello";

    // 1. Hybrid encrypt with the recipient's public key.
    let (ok, log) = run_bin(&[
        "encrypt",
        "--key-image",
        img.to_str().unwrap(),
        "--message",
        plaintext,
        "--output",
        msg.to_str().unwrap(),
        "--pq-pubkey",
        pk.to_str().unwrap(),
    ]);
    assert!(ok, "hybrid encrypt failed: {log}");
    assert!(msg.exists(), "encrypted message file must exist");
    assert!(
        log.contains("hybrid two-factor"),
        "stdout must announce hybrid mode: {log}"
    );

    // 2. Decrypt with BOTH factors → the exact plaintext comes back.
    let (ok, out) = run_bin(&[
        "decrypt",
        "--key-image",
        img.to_str().unwrap(),
        "--input",
        msg.to_str().unwrap(),
        "--pq-secretkey",
        sk.to_str().unwrap(),
    ]);
    assert!(ok, "hybrid decrypt failed: {out}");
    assert!(
        out.contains(plaintext),
        "stdout must contain the plaintext: {out}"
    );

    // 3. The image alone is not enough: classic decryption of a hybrid
    //    message must fail (the AES/MAC subkeys live in the hybrid schedule).
    let (ok, log) = run_bin(&[
        "decrypt",
        "--key-image",
        img.to_str().unwrap(),
        "--input",
        msg.to_str().unwrap(),
    ]);
    assert!(
        !ok,
        "decrypting a hybrid message without the NTRU secret key must fail: {log}"
    );

    // 4. A *wrong* NTRU secret key is not enough either: decapsulation
    //    yields a different shared secret and the payload must not open.
    let (_pk2, sk2) = keypair(&dir, "other");
    let (ok, log) = run_bin(&[
        "decrypt",
        "--key-image",
        img.to_str().unwrap(),
        "--input",
        msg.to_str().unwrap(),
        "--pq-secretkey",
        sk2.to_str().unwrap(),
    ]);
    assert!(
        !ok,
        "decrypting with the wrong NTRU secret key must fail: {log}"
    );

    // 5. A genuinely different image (different pixels → different bytes →
    //    different key) is rejected even with the right secret key.
    let img2 = sample_image(&dir, "other.png", 91);
    let (ok, log) = run_bin(&[
        "decrypt",
        "--key-image",
        img2.to_str().unwrap(),
        "--input",
        msg.to_str().unwrap(),
        "--pq-secretkey",
        sk.to_str().unwrap(),
    ]);
    assert!(
        !ok,
        "decrypting with a different key image must fail: {log}"
    );
}

#[test]
fn pq_keygen_secret_file_is_owner_only() {
    let dir = TempDir::new().unwrap();
    let (_pk, sk) = keypair(&dir, "perm");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&sk).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret key file must be owner-only (0600)");
    }
}

// The thread-count-invariance e2e test lives in `tests/cli_e2e_tests.rs`:
// it pins non-PQ behavior, so gating it behind this file's `pq` feature
// would leave it uncompiled in the default configuration.
