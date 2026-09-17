//! End-to-end CLI tests that do not depend on the `pq` feature.
//!
//! These spawn the real `spectrum` binary and pin two behavioral contracts
//! that library unit tests cannot cover:
//!
//! 1. **Thread-count invariance** — the derived key must not depend on the
//!    rayon worker count (the parallel engine's per-source tasks are
//!    order-independent by design).
//! 2. **Config-mismatch workflow** — a message encrypted under a custom
//!    config must decrypt only under that same config. The mismatch failure
//!    is the documented footgun: it surfaces as a key-image verification
//!    error, not as anything naming the config.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

/// Run the real binary with an optional config path and extra env, returning
/// (success, combined stdout+stderr).
fn run_bin_with(args: &[&str], config: Option<&str>, env: &[(&str, &str)]) -> (bool, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_spectrum"));
    if let Some(cfg) = config {
        cmd.args(["--config", cfg]);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd
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

fn run_bin(args: &[&str]) -> (bool, String) {
    run_bin_with(args, None, &[])
}

/// A structured (non-flat) 160×160 PNG: a valid key image.
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

/// The hex key line from `spectrum derive` output.
fn derive_key(config: Option<&str>, img: &std::path::Path) -> String {
    let (ok, log) = run_bin_with(&["derive", "--image", img.to_str().unwrap()], config, &[]);
    assert!(ok, "derive failed: {log}");
    log.lines()
        .find_map(|l| l.strip_prefix("Key: "))
        .unwrap_or_else(|| panic!("no key line in derive output: {log}"))
        .to_string()
}

#[test]
fn derived_key_is_independent_of_thread_count() {
    let dir = TempDir::new().unwrap();
    let img = sample_image(&dir, "threads.png", 3);

    let single = derive_key(None, &img);
    // A second derive under a 1-thread rayon pool must produce the exact
    // same key as the default multi-threaded pool.
    let out = Command::new(env!("CARGO_BIN_EXE_spectrum"))
        .args(["derive", "--image", img.to_str().unwrap()])
        .env("RAYON_NUM_THREADS", "1")
        .output()
        .expect("failed to spawn the spectrum binary");
    assert!(
        out.status.success(),
        "derive failed (1 thread): {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let one_thread = stdout
        .lines()
        .find_map(|l| l.strip_prefix("Key: "))
        .unwrap_or_else(|| panic!("no key line in stdout: {stdout}"));
    assert_eq!(
        single, one_thread,
        "key must not depend on the rayon thread count"
    );
}

#[test]
fn custom_config_message_pair_requires_the_same_config() {
    let dir = TempDir::new().unwrap();
    let img = sample_image(&dir, "cfg.png", 7);
    let msg = dir.path().join("msg.spx");
    let custom_cfg = dir.path().join("custom.json");

    // Configs are fail-closed: a partial JSON is rejected (missing fields
    // cannot silently fall back to defaults, or writer/reader configs could
    // diverge). The documented workflow is `spectrum config` → edit → use.
    let (ok, log) = run_bin(&["config"]);
    assert!(ok, "spectrum config must print the default document: {log}");
    let doc: serde_json::Value = {
        let start = log.find('{').expect("config output must contain JSON");
        serde_json::from_str(&log[start..]).expect("config output must be valid JSON")
    };
    let mut custom = doc.clone();
    // A different chaos iteration count changes the Hénon orbit, hence the
    // whole key.
    custom["entropy"]["chaos_config"]["iterations"] = serde_json::json!(256);
    std::fs::write(&custom_cfg, custom.to_string()).unwrap();

    // Sanity: the custom config must actually derive a different key.
    let default_key = derive_key(None, &img);
    let custom_key = derive_key(custom_cfg.to_str(), &img);
    assert_ne!(
        default_key, custom_key,
        "config must change the derived key"
    );

    // Encrypt under the custom config.
    let plaintext = "config-paired payload";
    let (ok, log) = run_bin_with(
        &[
            "encrypt",
            "--key-image",
            img.to_str().unwrap(),
            "--message",
            plaintext,
            "--output",
            msg.to_str().unwrap(),
        ],
        custom_cfg.to_str(),
        &[],
    );
    assert!(ok, "encrypt with custom config failed: {log}");

    // Decrypting with the DEFAULT config must fail (different key → the
    // image-hash binding rejects it before any ciphertext is touched).
    let (ok, log) = run_bin_with(
        &[
            "decrypt",
            "--key-image",
            img.to_str().unwrap(),
            "--input",
            msg.to_str().unwrap(),
        ],
        None,
        &[],
    );
    assert!(
        !ok,
        "decrypt with the wrong (default) config must fail: {log}"
    );

    // Decrypting with the MATCHING config succeeds and recovers the plaintext.
    let (ok, log) = run_bin_with(
        &[
            "decrypt",
            "--key-image",
            img.to_str().unwrap(),
            "--input",
            msg.to_str().unwrap(),
        ],
        custom_cfg.to_str(),
        &[],
    );
    assert!(ok, "decrypt with the matching config must succeed: {log}");
    assert!(
        log.contains(plaintext),
        "plaintext must round-trip exactly, got: {log}"
    );
}
