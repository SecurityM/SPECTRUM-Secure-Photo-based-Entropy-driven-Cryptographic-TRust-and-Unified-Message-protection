//! Hashing helpers used across SPECTRUM.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Result, SpectrumError};

/// SHA-256 of an arbitrary byte slice.
pub fn compute_sha256<D: AsRef<[u8]>>(data: D) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// HMAC-SHA256 keyed by `key` over `data`.
///
/// The `expect` below is an invariant, not input validation: HMAC (RFC 2104)
/// accepts keys of *any* length (short keys are zero-padded, long keys are
/// first hashed), so `new_from_slice` cannot fail for a slice. There is no
/// caller-facing error to return.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Encode a byte slice as a lowercase hex string.
///
/// Used for master keys of any length (e.g. the 1072-bit / 134-byte key) and
/// for 32-byte image hashes alike.
pub fn key_to_hex(key: &[u8]) -> String {
    hex::encode(key)
}

/// Parse an even-length hex string into raw bytes (any length).
///
/// General-purpose decoder. **Do not use for master keys** — prefer
/// [`hex_to_master`], which rejects wrong lengths and yields zeroizing
/// buffers.
pub fn hex_to_key(hex_str: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str)
        .map_err(|e| SpectrumError::InvalidConfiguration(format!("invalid hex: {e}")))
}

/// Parse a hex-encoded master key into a zeroizing buffer, rejecting empty
/// input fail-closed.
///
/// (HKDF treats the master key as IKM of any length, so "wrong length" is
/// not a cryptographic failure here; the derivation pipeline always emits
/// the 134-byte master key, while tests may pass shorter IKMs.)
///
/// The hex form of the master key appears wherever the key crosses an API
/// boundary (pipeline → message layer, pipeline → CLI); every one of those
/// sites previously decoded into a plain `Vec<u8>` that outlived use in
/// freeable-but-unwiped memory.
pub fn hex_to_master(hex_str: &str) -> Result<Zeroizing<Vec<u8>>> {
    let decoded = hex_to_key(hex_str)?;
    if decoded.is_empty() {
        return Err(SpectrumError::InvalidConfiguration(
            "master key must not be empty".into(),
        ));
    }
    Ok(Zeroizing::new(decoded))
}

/// Parse a hex string into exactly 32 bytes (image hashes, authenticators).
pub fn hex_to_hash(hex_str: &str) -> Result<[u8; 32]> {
    let decoded = hex_to_key(hex_str)?;
    decoded
        .try_into()
        .map_err(|_| SpectrumError::InvalidConfiguration("value must decode to 32 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // SHA-256 of the empty string.
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(key_to_hex(&compute_sha256(b"")), expected);
    }

    #[test]
    fn hex_roundtrip() {
        let key = compute_sha256(b"some image data");
        let hexed = key_to_hex(&key);
        assert_eq!(hexed.len(), 64);
        assert_eq!(hex_to_hash(&hexed).unwrap(), key);
    }

    #[test]
    fn hex_roundtrip_arbitrary_length() {
        // The 1072-bit master key round-trips verbatim through the generic
        // helpers.
        let master: Vec<u8> = (0..crate::types::KEY_LENGTH)
            .map(|i| (i % 251) as u8)
            .collect();
        let hexed = key_to_hex(&master);
        assert_eq!(hexed.len(), crate::types::KEY_LENGTH * 2);
        assert_eq!(hex_to_key(&hexed).unwrap(), master);
    }

    #[test]
    fn hex_rejects_bad_input() {
        assert!(hex_to_key("not-hex!").is_err());
        assert!(hex_to_hash("abcd").is_err()); // too short for a 32-byte hash
    }

    #[test]
    fn master_hex_roundtrip_and_rejects_empty() {
        // The 1072-bit master key round-trips through the master-specific
        // decoder, which yields a zeroizing buffer.
        let master: Vec<u8> = (0..crate::types::KEY_LENGTH)
            .map(|i| (i % 251) as u8)
            .collect();
        let decoded = hex_to_master(&key_to_hex(&master)).unwrap();
        assert_eq!(decoded.as_slice(), master.as_slice());

        // An empty (or whitespace-only) hex string is not a key.
        assert!(hex_to_master("").is_err());
    }
}
