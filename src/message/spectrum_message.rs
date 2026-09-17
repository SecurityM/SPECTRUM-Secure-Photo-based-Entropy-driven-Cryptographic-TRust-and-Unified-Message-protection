//! The on-disk SPECTRUM message container and its fixed binary serialization.

use crate::error::{Result, SpectrumError};
use crate::types::MESSAGE_VERSION;
use crate::utils::serialization::{read_u32_le, read_u64_le, write_u32_le, write_u64_le};

/// A complete encrypted message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpectrumMessage {
    pub version: u32,
    pub timestamp: u64,
    pub image_hash: [u8; 32],
    /// NTRU-Prime ciphertext (reserved for the optional `pq` layer).
    pub ntru_ciphertext: Vec<u8>,
    /// Authenticator / Dilithium signature slot.
    pub signature: Vec<u8>,
    /// AES-256-GCM ciphertext of the payload.
    pub encrypted_message: Vec<u8>,
}

impl SpectrumMessage {
    pub fn new(
        timestamp: u64,
        image_hash: [u8; 32],
        ntru_ciphertext: Vec<u8>,
        signature: Vec<u8>,
        encrypted_message: Vec<u8>,
    ) -> Self {
        SpectrumMessage {
            version: MESSAGE_VERSION,
            timestamp,
            image_hash,
            ntru_ciphertext,
            signature,
            encrypted_message,
        }
    }

    /// Serialize to the compact binary format (length-prefixed fields).
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        write_u32_le(&mut buf, self.version);
        write_u64_le(&mut buf, self.timestamp);
        buf.extend_from_slice(&self.image_hash);

        // Bounded by u32 so writes cannot overflow the prefix.
        for field in [
            &self.ntru_ciphertext,
            &self.signature,
            &self.encrypted_message,
        ] {
            let len = u32::try_from(field.len()).map_err(|_| {
                SpectrumError::SerializationError("message field exceeds u32 length".into())
            })?;
            write_u32_le(&mut buf, len);
            buf.extend_from_slice(field);
        }
        Ok(buf)
    }

    /// Parse a message from the binary format, bounds-checking every slice.
    ///
    /// Messages from a different format version are rejected fail-closed: the
    /// field layout is positional, so silently parsing a future format would
    /// misread every field (previously any `version` was accepted).
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let mut offset = 0usize;
        let version = read_u32_le(data, &mut offset)?;
        if version != MESSAGE_VERSION {
            return Err(SpectrumError::MalformedMessage(format!(
                "unsupported message version {version} (expected {MESSAGE_VERSION})"
            )));
        }
        let timestamp = read_u64_le(data, &mut offset)?;
        let mut image_hash = [0u8; 32];
        image_hash.copy_from_slice(crate::utils::serialization::take(data, &mut offset, 32)?);

        let ntru_len = read_u32_le(data, &mut offset)? as usize;
        let ntru_ciphertext =
            crate::utils::serialization::take(data, &mut offset, ntru_len)?.to_vec();

        let sig_len = read_u32_le(data, &mut offset)? as usize;
        let signature = crate::utils::serialization::take(data, &mut offset, sig_len)?.to_vec();

        let msg_len = read_u32_le(data, &mut offset)? as usize;
        let encrypted_message =
            crate::utils::serialization::take(data, &mut offset, msg_len)?.to_vec();

        // No trailing garbage allowed.
        if offset != data.len() {
            return Err(SpectrumError::MalformedMessage(format!(
                "trailing {} bytes after message",
                data.len() - offset
            )));
        }

        Ok(SpectrumMessage {
            version,
            timestamp,
            image_hash,
            ntru_ciphertext,
            signature,
            encrypted_message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SpectrumMessage {
        SpectrumMessage::new(
            1_700_000_000,
            [0xAB; 32],
            vec![1, 2, 3],
            vec![9, 9, 9, 9],
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        )
    }

    #[test]
    fn serialization_roundtrip() {
        let m = sample();
        let bytes = m.serialize().unwrap();
        let back = SpectrumMessage::deserialize(&bytes).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn truncated_data_fails() {
        let m = sample();
        let bytes = m.serialize().unwrap();
        assert!(SpectrumMessage::deserialize(&bytes[..bytes.len() - 2]).is_err());
    }

    #[test]
    fn trailing_garbage_fails() {
        let m = sample();
        let mut bytes = m.serialize().unwrap();
        bytes.push(0x00);
        assert!(SpectrumMessage::deserialize(&bytes).is_err());
    }

    #[test]
    fn foreign_version_is_rejected() {
        let m = sample();
        let mut bytes = m.serialize().unwrap();
        // Version is the first 4 bytes (little-endian).
        bytes[0] = 0x63;
        bytes[3] = 0x00;
        let err = SpectrumMessage::deserialize(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("version"),
            "error must name the version mismatch: {err}"
        );
    }
}
