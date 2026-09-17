//! Message container and its encryption/decryption pipelines.

pub mod decryption;
pub mod encryption;
pub mod spectrum_message;

pub use decryption::{decrypt_message, decrypt_message_with, decrypt_message_with_pq};
pub use encryption::{encrypt_message, encrypt_message_with, encrypt_message_with_pq};
pub use spectrum_message::SpectrumMessage;
