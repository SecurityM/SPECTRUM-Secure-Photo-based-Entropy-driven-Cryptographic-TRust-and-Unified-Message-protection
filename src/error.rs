//! Error taxonomy for the whole crate. Every fallible operation funnels into
//! [`SpectrumError`] so callers can pattern-match on the failure mode; the
//! fail-closed mapping rules (e.g. decoder limit errors → `ImageTooLarge`)
//! live with the code that raises them.

use std::fmt;

/// The single error type for every fallible operation in this crate.
#[derive(Debug)]
pub enum SpectrumError {
    // --- Image errors -------------------------------------------------------
    ImageTooSmall {
        width: u32,
        height: u32,
    },
    ImageTooLarge {
        width: u32,
        height: u32,
    },
    ImageFormatNotSupported(String),
    ImageCorrupted(String),
    /// Zero-variance image: every canonical pixel is identical. Such images
    /// carry no extractable entropy and would all derive the same key.
    ImageHasNoEntropy,

    // --- Post-quantum errors --------------------------------------------------
    NtruKeyGenerationFailed,
    DilithiumKeyGenerationFailed,
    EncapsulationFailed(String),
    DecapsulationFailed(String),
    SignatureFailed(String),
    VerificationFailed(String),
    PqLayerUnavailable,
    PqAlgorithmNotFound(String),
    /// A PQ key/ciphertext/signature buffer has the wrong length for the
    /// selected algorithm (checked before any liboqs call).
    PqInvalidInput {
        expected: String,
    },

    // --- Entropy analysis errors -------------------------------------------
    WtmmAnalysisFailed,
    LacunarityAnalysisFailed,
    EntropyExtractionFailed,

    // --- Binding errors ------------------------------------------------------
    /// The image used to decrypt does not match the image a message was
    /// encrypted under (different file bytes → different key).
    ImageMismatch,

    // --- File I/O errors ---------------------------------------------------
    FileNotFound(String),
    PermissionDenied(String),

    // --- Configuration errors ----------------------------------------------
    InvalidConfiguration(String),

    // --- General errors ----------------------------------------------------
    Utf8Error,
    SerializationError(String),
    /// AES-GCM failed to open a sealed payload (bad key / tampered data).
    DecryptionFailed,
    /// Malformed or truncated binary message.
    MalformedMessage(String),
    Unknown(String),
}

impl fmt::Display for SpectrumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The enforced limits are the *configured* min_size/max_size (see
            // ImagePreprocessorConfig); hardcoding numbers here used to print
            // a wrong minimum to every user with a custom config.
            SpectrumError::ImageTooSmall { width, height } => {
                write!(
                    f,
                    "Image too small: {width}x{height} (check preprocessor.min_size)"
                )
            }
            SpectrumError::ImageTooLarge { width, height } => {
                write!(
                    f,
                    "Image too large: {width}x{height} (check preprocessor.max_size)"
                )
            }
            SpectrumError::ImageFormatNotSupported(fmt_) => {
                write!(f, "Unsupported image format: {fmt_}")
            }
            SpectrumError::ImageCorrupted(e) => write!(f, "Image corrupted: {e}"),
            SpectrumError::ImageHasNoEntropy => write!(f, "Image has no entropy"),
            SpectrumError::NtruKeyGenerationFailed => write!(f, "NTRU key generation failed"),
            SpectrumError::DilithiumKeyGenerationFailed => {
                write!(f, "Dilithium key generation failed")
            }
            SpectrumError::EncapsulationFailed(e) => write!(f, "NTRU encapsulation failed: {e}"),
            SpectrumError::DecapsulationFailed(e) => write!(f, "NTRU decapsulation failed: {e}"),
            SpectrumError::SignatureFailed(e) => write!(f, "Dilithium signature failed: {e}"),
            SpectrumError::VerificationFailed(e) => write!(f, "Dilithium verification failed: {e}"),
            SpectrumError::PqLayerUnavailable => {
                write!(f, "Post-quantum layer not compiled. Rebuild with the `pq` feature (requires liboqs).")
            }
            SpectrumError::PqAlgorithmNotFound(a) => {
                write!(f, "Post-quantum algorithm not available in liboqs: {a}")
            }
            SpectrumError::PqInvalidInput { expected } => {
                write!(f, "Post-quantum input rejected: {expected}")
            }
            SpectrumError::WtmmAnalysisFailed => write!(f, "WTMM analysis failed"),
            SpectrumError::LacunarityAnalysisFailed => write!(f, "Lacunarity analysis failed"),
            SpectrumError::EntropyExtractionFailed => write!(f, "Entropy extraction failed"),
            SpectrumError::ImageMismatch => {
                write!(f, "key image does not match the message's bound image")
            }
            SpectrumError::FileNotFound(p) => write!(f, "File not found: {p}"),
            SpectrumError::PermissionDenied(p) => write!(f, "Permission denied: {p}"),
            SpectrumError::InvalidConfiguration(c) => write!(f, "Invalid configuration: {c}"),
            SpectrumError::Utf8Error => write!(f, "UTF-8 error"),
            SpectrumError::SerializationError(e) => write!(f, "Serialization error: {e}"),
            SpectrumError::DecryptionFailed => {
                write!(f, "Message decryption/authentication failed")
            }
            SpectrumError::MalformedMessage(e) => write!(f, "Malformed message: {e}"),
            SpectrumError::Unknown(e) => write!(f, "Unknown error: {e}"),
        }
    }
}

impl std::error::Error for SpectrumError {}

impl From<std::io::Error> for SpectrumError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::NotFound => SpectrumError::FileNotFound(err.to_string()),
            std::io::ErrorKind::PermissionDenied => {
                SpectrumError::PermissionDenied(err.to_string())
            }
            _ => SpectrumError::Unknown(err.to_string()),
        }
    }
}

impl From<std::string::FromUtf8Error> for SpectrumError {
    fn from(_: std::string::FromUtf8Error) -> Self {
        SpectrumError::Utf8Error
    }
}

impl From<image::ImageError> for SpectrumError {
    fn from(err: image::ImageError) -> Self {
        SpectrumError::ImageCorrupted(err.to_string())
    }
}

/// Convenience for raising a generic invariant-breaking error from a string.
///
/// The message is carried into the error (surfaced to callers) instead of
/// being logged at debug level and dropped — previously every `bad("...")`
/// call site collapsed into a context-free `EntropyExtractionFailed`, hiding
/// the actual reason (e.g. "WTMM needs at least 4x4 pixels") from users.
pub fn bad<T>(msg: impl Into<String>) -> Result<T> {
    let msg = msg.into();
    log::debug!("{msg}");
    Err(SpectrumError::InvalidConfiguration(msg))
}

pub type Result<T> = std::result::Result<T, SpectrumError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_size_errors_do_not_hardcode_configured_limits() {
        // min_size/max_size are config knobs (default 64x64, not 128x128);
        // the message used to claim a hardcoded 128x128 minimum.
        let e = SpectrumError::ImageTooSmall {
            width: 100,
            height: 100,
        };
        let msg = e.to_string();
        assert!(
            !msg.contains("128"),
            "error message must not hardcode limits: {msg}"
        );
    }

    #[test]
    fn display_covers_every_variant() {
        // One representative per variant: compiles only while every match arm
        // in Display is present, so adding a variant without a message breaks
        // this test.
        let samples: Vec<SpectrumError> = vec![
            SpectrumError::ImageTooSmall {
                width: 1,
                height: 1,
            },
            SpectrumError::ImageTooLarge {
                width: 1,
                height: 1,
            },
            SpectrumError::ImageFormatNotSupported("gif".into()),
            SpectrumError::ImageCorrupted("truncated".into()),
            SpectrumError::ImageHasNoEntropy,
            SpectrumError::NtruKeyGenerationFailed,
            SpectrumError::DilithiumKeyGenerationFailed,
            SpectrumError::EncapsulationFailed("bad pk".into()),
            SpectrumError::DecapsulationFailed("bad ct".into()),
            SpectrumError::SignatureFailed("bad sk".into()),
            SpectrumError::VerificationFailed("scheme".into()),
            SpectrumError::PqLayerUnavailable,
            SpectrumError::PqAlgorithmNotFound("dilithium5".into()),
            SpectrumError::PqInvalidInput {
                expected: "pk".into(),
            },
            SpectrumError::WtmmAnalysisFailed,
            SpectrumError::LacunarityAnalysisFailed,
            SpectrumError::EntropyExtractionFailed,
            SpectrumError::ImageMismatch,
            SpectrumError::FileNotFound("/tmp/x".into()),
            SpectrumError::PermissionDenied("/tmp/y".into()),
            SpectrumError::InvalidConfiguration("bad knob".into()),
            SpectrumError::Utf8Error,
            SpectrumError::SerializationError("json".into()),
            SpectrumError::DecryptionFailed,
            SpectrumError::MalformedMessage("short".into()),
            SpectrumError::Unknown("mystery".into()),
        ];
        for e in samples {
            assert!(
                !e.to_string().is_empty(),
                "variant must have a message: {e:?}"
            );
        }
    }
}
