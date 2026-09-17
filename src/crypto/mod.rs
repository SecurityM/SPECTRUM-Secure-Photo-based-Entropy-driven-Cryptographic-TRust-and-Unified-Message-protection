//! Post-quantum + symmetric cryptography layer.

pub mod dilithium;
pub mod ntru_prime;
pub mod symmetric;

pub use dilithium::{dilithium_generate_keypair, dilithium_sign, dilithium_verify};
pub use ntru_prime::{ntru_decapsulate, ntru_encapsulate, ntru_generate_keypair};
pub use symmetric::{authenticate, decrypt, encrypt, expand_key, verify};
