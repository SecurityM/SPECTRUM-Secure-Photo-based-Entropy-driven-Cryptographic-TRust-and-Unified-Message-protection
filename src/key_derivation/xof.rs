//! Master-key collapse via SHAKE256 (the SPECTRUM XOF layer).
//!
//! The eleven entropy engines analyse an image into a deterministic byte
//! sequence (the *witness*,
//! [`crate::key_derivation::KeyDerivationPipeline::byte_sequence`]), and the
//! 1072-bit master key is squeezed from that witness **plus** the SHA-256 of
//! the exact source-file bytes ([`derive_master_key`]).
//!
//! Binding the source-file digest makes key derivation *strictly
//! deterministic over the file*: the identical file always reproduces the
//! identical key, and any other file — a single pixel changed, recompressed,
//! or a re-capture of the same physical subject — derives an unrelated key.
//! Only the exact original file reproduces a key: the XOF input is never
//! stored anywhere, so no auxiliary record exists that could be replayed.
//!
//! The absorb pipeline is fully sequential and deterministic: domain label,
//! 64-bit little-endian witness length, the witness bytes, then the 32-byte
//! file digest. The squeezed 134 bytes are the master key (`IKM`) that
//! downstream HKDF steps expand into per-purpose 256-bit subkeys.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::types::KEY_LENGTH;

/// Fixed domain-separation label bound into every squeeze. It prevents the
/// XOF output from being confused with any other consumer that absorbs the
/// same bytes, and it version-stamps the master-key format (v3: the input is
/// the deterministic witness ‖ exact-file SHA-256).
pub const XOF_DOMAIN_LABEL: &[u8] = b"SPECTRUM/master-key/shake256/v3\x00";

/// Squeeze the 1072-bit master key from the deterministic image witness and
/// the SHA-256 of the exact source-file bytes.
///
/// The squeezed bytes are the master key (`IKM`) that downstream HKDF steps
/// expand into per-purpose 256-bit subkeys.
pub fn derive_master_key(witness: &[u8], image_sha256: &[u8; 32]) -> [u8; KEY_LENGTH] {
    let mut xof = Shake256::default();
    xof.update(XOF_DOMAIN_LABEL);
    xof.update(&(witness.len() as u64).to_le_bytes());
    xof.update(witness);
    xof.update(image_sha256);
    let mut out = [0u8; KEY_LENGTH];
    xof.finalize_xof().read(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::hashing::compute_sha256;

    #[test]
    fn squeeze_length_is_exactly_key_length() {
        assert_eq!(KEY_LENGTH, 134);
        assert_eq!(crate::types::KEY_BITS, 1072);
        let hash = compute_sha256(b"some image file bytes");
        let key = derive_master_key(b"witness byte sequence", &hash);
        assert_eq!(key.len(), KEY_LENGTH);
    }

    #[test]
    fn squeeze_is_deterministic() {
        let witness = b"witness byte sequence 0123456789";
        let hash = compute_sha256(b"exact image bytes");
        assert_eq!(
            derive_master_key(witness, &hash),
            derive_master_key(witness, &hash)
        );
    }

    #[test]
    fn squeeze_avalanches_on_single_byte_change() {
        let hash = compute_sha256(b"exact image bytes");
        let a = derive_master_key(b"abcdefghijklmnopqrstuvwxyz", &hash);
        let b = derive_master_key(b"abcdefghijklmnopqrstuvwxyZ", &hash);
        let differing = a
            .iter()
            .zip(b.iter())
            .map(|(x, y)| (x ^ y).count_ones())
            .sum::<u32>();
        assert!(
            differing > KEY_LENGTH as u32 * 3,
            "weak avalanche: {differing}"
        );
    }

    #[test]
    fn squeeze_binds_the_exact_file_digest() {
        // Same witness, different source-file digest → unrelated key. This is
        // what guarantees a re-encoded or single-pixel-edited image (whose
        // witness may coincide) still derives a different master key.
        let witness = b"identical witness bytes";
        let hash_a = compute_sha256(b"file A");
        let hash_b = compute_sha256(b"file B");
        assert_ne!(
            derive_master_key(witness, &hash_a),
            derive_master_key(witness, &hash_b)
        );
    }

    #[test]
    fn squeeze_differs_from_sha256_and_is_domain_bound() {
        let witness = b"the-same-witness";
        let hash = compute_sha256(b"the-same-file");
        let key = derive_master_key(witness, &hash);
        // A 32-byte SHA-256 of the same bytes must not equal any prefix of the
        // squeezed output, and reusing the bytes under a different domain
        // label must diverge.
        let sha = compute_sha256(witness);
        assert_ne!(&key[..32], &sha[..]);
        let mut other = Shake256::default();
        other.update(b"SPECTRUM/other-domain\x00");
        other.update(&(witness.len() as u64).to_le_bytes());
        other.update(witness);
        other.update(&hash);
        let mut out = [0u8; KEY_LENGTH];
        other.finalize_xof().read(&mut out);
        assert_ne!(key, out);
    }
}
