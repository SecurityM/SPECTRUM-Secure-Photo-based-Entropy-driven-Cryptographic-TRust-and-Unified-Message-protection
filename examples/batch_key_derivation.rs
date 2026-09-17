//! Batch key derivation over a directory of images.
//!
//! Run with:
//!   cargo run --release --example batch_key_derivation -- /path/to/image_dir [manifest.json]
//!
//! Mirrors `spectrum batch`: deterministically derive a key for every image
//! in the directory, write a JSON manifest, and print a short summary table.
//! Derivation is a pure function of each file's exact bytes — nothing is
//! persisted next to the images and re-running reproduces identical keys.
//! Batch output contains the derived keys — treat it as secret.

use spectrum::data::{BatchEntry, BatchManifest};
use spectrum::key_derivation::KeyDerivationPipeline;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .ok_or("usage: batch_key_derivation <image_dir> [manifest.json]")?;
    let manifest_out = args.next();

    // Collect image files deterministically (same rule as the CLI).
    const IMAGE_EXTS: [&str; 7] = ["png", "jpg", "jpeg", "bmp", "tif", "tiff", "gif"];
    let mut paths: Vec<String> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|e| IMAGE_EXTS.contains(&e.to_ascii_lowercase().as_str()))
                .unwrap_or(false)
        })
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    paths.sort();

    if paths.is_empty() {
        return Err(format!("no images found in {dir}").into());
    }

    let pipeline = KeyDerivationPipeline::new();
    let mut entries: Vec<BatchEntry> = Vec::with_capacity(paths.len());
    println!("{:<40} {:<12} key (first 12)", "image", "strategy");
    println!("{}", "-".repeat(70));

    for path in &paths {
        match pipeline.derive_key(path) {
            Ok((key_hex, meta)) => {
                println!(
                    "{:<40} {:<12} {}…",
                    path,
                    meta.strategy_name,
                    &key_hex.as_str()[..12]
                );
                entries.push(BatchEntry::success(
                    path,
                    key_hex.to_string(),
                    meta.image_hash,
                    meta.strategy_name,
                    meta.total_entropy,
                ));
            }
            Err(e) => {
                println!("{:<40} FAILED       {e}", path);
                entries.push(BatchEntry::failure(path, e.to_string()));
            }
        }
    }

    let manifest = BatchManifest::new(entries);
    if let Some(out) = manifest_out {
        manifest.save(&out)?;
        println!("\nManifest written to {out}");
    }
    println!(
        "\n{} ok, {} failed",
        manifest.success_count(),
        manifest.failure_count()
    );
    Ok(())
}
