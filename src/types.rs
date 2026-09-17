//! Shared, versioned types used across the SPECTRUM crate.
//!
//! Kept intentionally small so that structural changes are localized. Anything
//! with a stable binary on-disk representation lives in the [`crate::message`]
//! module instead.

/// The current SPECTRUM message container version.
pub const MESSAGE_VERSION: u32 = 1;

/// Strategy version for the deterministic strategy selector.
pub const STRATEGY_VERSION: u32 = 1;

/// Master key size in bits: the smallest multiple of 8 that can carry the
/// engine's full extracted entropy (up to 1069 real bits) without truncation.
pub const KEY_BITS: usize = 1072;

/// Master key length in bytes (1072 bits).
pub const KEY_LENGTH: usize = KEY_BITS / 8;

/// Default canonical working size for entropy extraction.
pub const DEFAULT_CANONICAL_SIZE: (u32, u32) = (512, 512);

/// Whether SPECTRUM was built with the post-quantum (liboqs) layer enabled.
///
/// Kept as a simple const so callers can branch without cfg-noise:
/// ```ignore
/// if spectrum::types::PQ_ENABLED { ... } else { ... }
/// ```
pub const PQ_ENABLED: bool = cfg!(feature = "pq");

/// NTRU-Prime KEM algorithm handed to liboqs (feature `pq` only).
#[cfg(feature = "pq")]
pub const NTRU_ALGORITHM: oqs::kem::Algorithm = oqs::kem::Algorithm::NtruPrimeSntrup761;

/// Dilithium3 signature algorithm handed to liboqs (feature `pq` only).
#[cfg(feature = "pq")]
pub const DILITHIUM_ALGORITHM: oqs::sig::Algorithm = oqs::sig::Algorithm::Dilithium3;
