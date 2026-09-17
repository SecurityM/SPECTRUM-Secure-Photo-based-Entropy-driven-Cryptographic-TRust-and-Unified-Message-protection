//! Minimal end-to-end example: derive a deterministic key, encrypt, round-trip.
//!
//! Run with:
//!   cargo run --release --example basic_encryption -- /path/to/image.png

use spectrum::message::SpectrumMessage;
use spectrum::SpectrumCrypto;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let image = std::env::args()
        .nth(1)
        .ok_or("usage: basic_encryption <image path>")?;
    let spectrum = SpectrumCrypto::new();

    // 1. Derive the deterministic master key from the image. The same file
    //    always yields the same key; no record is produced or needed.
    let (key, meta) = spectrum.derive_key_safe(&image)?;
    println!("key         = {}", key.as_str());
    println!("strategy    = {}", meta.strategy_name);
    println!("entropy     = {:.0} bits", meta.total_entropy);

    // 2. Encrypt under that key — decryption needs only the exact same image.
    let secret = "Hello, SPECTRUM world!";
    let msg = spectrum.encrypt_message_safe(secret, &image)?;

    // 3. Serialize to bytes, then deserialize.
    let bytes = msg.serialize()?;
    let msg = SpectrumMessage::deserialize(&bytes)?;

    // 4. Decrypt with the same image file.
    let plain = spectrum.decrypt_message_safe(&msg, &image)?;
    assert_eq!(plain, secret);
    println!("decrypted    = {plain}");

    // 5. Re-deriving from the same file reproduces the identical key; editing
    //    the file (even by one pixel) would derive an unrelated key.
    let (key2, _) = spectrum.derive_key_safe(&image)?;
    assert_eq!(key, key2);
    println!("re-derived  = OK (strictly deterministic)");
    Ok(())
}
