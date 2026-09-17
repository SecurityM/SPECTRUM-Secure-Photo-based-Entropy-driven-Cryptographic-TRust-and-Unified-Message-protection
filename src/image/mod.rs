//! Image I/O and preprocessing.

pub mod loader;
pub mod preprocessor;

pub use loader::{
    detect_format, load_image, sniff_format, sniff_format_from_file, Image, ImageFormat, ImageInfo,
};
pub use preprocessor::{ImagePreprocessor, PreprocessedImage};
