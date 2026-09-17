//! Small shared utilities: hashing, binary serialization, logging setup and
//! deterministic test-image generation.

pub mod hashing;
pub mod logging;
pub mod serialization;
pub mod test_images;

pub use hashing::{compute_sha256, hex_to_hash, hex_to_key, hmac_sha256, key_to_hex};
pub use logging::init_logging;
pub use serialization::{read_u32_le, read_u64_le, write_u32_le, write_u64_le};
