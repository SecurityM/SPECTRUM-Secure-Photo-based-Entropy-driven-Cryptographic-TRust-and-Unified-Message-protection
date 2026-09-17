//! Metadata attached to a derived key, enabling reproducibility and matching.

use serde::{Deserialize, Serialize};

use crate::types::STRATEGY_VERSION;

/// Versioned metadata describing how a key was derived.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyMetadata {
    pub version: u32,
    pub strategy_version: u32,
    /// Stable strategy identifier, e.g. `"WTMM_PRIMARY"`.
    pub strategy_name: String,
    /// Entropy source names, most-weight first.
    pub entropy_sources_used: Vec<String>,
    pub image_hash: String,
    pub creation_timestamp: u64,
    /// Estimated total entropy in bits.
    pub total_entropy: f64,
}

impl KeyMetadata {
    pub fn new(
        strategy_name: String,
        entropy_sources_used: Vec<String>,
        image_hash: [u8; 32],
        creation_timestamp: u64,
        total_entropy: f64,
    ) -> Self {
        KeyMetadata {
            version: 1,
            strategy_version: STRATEGY_VERSION,
            strategy_name,
            entropy_sources_used,
            image_hash: hex::encode(image_hash),
            creation_timestamp,
            total_entropy,
        }
    }

    /// Serialize to a human-readable JSON document.
    pub fn to_json(&self) -> Result<String, crate::error::SpectrumError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| crate::error::SpectrumError::SerializationError(e.to_string()))
    }
}

/// Current UNIX timestamp in seconds.
pub fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_json_roundtrip() {
        let md = KeyMetadata::new(
            "BALANCED".into(),
            vec!["WTMM".into(), "Lacunarity".into()],
            [0u8; 32],
            1_700_000_000,
            210.0,
        );
        let json = md.to_json().unwrap();
        let parsed: KeyMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, md);
    }
}
