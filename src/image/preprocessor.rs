//! Canonicalization so the same underlying image always yields the same
//! grayscale buffer regardless of incidental store-level differences.

use image::{DynamicImage, GenericImageView};

use crate::config::ImagePreprocessorConfig;
use crate::error::{Result, SpectrumError};
use crate::utils::hashing::compute_sha256;

use super::loader::{estimate_jpeg_quality, sniff_format, Image, ImageFormat, ImageInfo};

/// A fully-canonicalized grayscale image ready for entropy extraction.
#[derive(Debug, Clone)]
pub struct PreprocessedImage {
    pub data: Vec<u8>,
    pub dimensions: (u32, u32),
    pub canonical_size: (u32, u32),
    pub format: ImageFormat,
    pub original_hash: [u8; 32],
}

/// Load + canonicalize an image file.
#[derive(Debug, Clone, Default)]
pub struct ImagePreprocessor {
    pub config: ImagePreprocessorConfig,
}

impl ImagePreprocessor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: ImagePreprocessorConfig) -> Self {
        ImagePreprocessor { config }
    }

    /// Load, validate, resize, strip metadata and convert to grayscale.
    ///
    /// The file is read **exactly once**: content sniffing, decoding and the
    /// original-file hash all operate on the same immutable buffer. Previously
    /// the file was re-read four times (format probe, magic-byte sniff,
    /// decode, hash), so a key image that changed between reads would bind a
    /// witness derived from one version of the file to a hash of another — a
    /// silently corrupted key with no error.
    ///
    /// The content's magic bytes are sniffed first and must agree with the
    /// format the file's extension claims; a mismatch means the file was
    /// renamed or is a polyglot, and it is rejected before any decoding.
    pub fn preprocess(&self, path: &str) -> Result<PreprocessedImage> {
        // Capped read: a hostile "image" fails closed at the size gate instead
        // of occupying its full size in memory before any sniffing/decoding.
        let file_data = crate::data::read_capped(path)?;

        // Content is the primary signal: magic bytes cannot lie.
        let sniffed = sniff_format(&file_data)?;

        // The container claim comes from the file extension (the same signal
        // the decoder historically trusted); the compatibility check below
        // gives content the final word.
        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| {
                SpectrumError::ImageFormatNotSupported(
                    "file has no extension to name its image format".into(),
                )
            })?;
        let claimed = image::ImageFormat::from_extension(ext).ok_or_else(|| {
            SpectrumError::ImageFormatNotSupported(format!(
                "unrecognized/unsupported file extension: {ext}"
            ))
        })?;
        let format = crate_image_format(claimed, &file_data)?;

        if !format_is_compatible(format, sniffed) {
            return Err(SpectrumError::ImageFormatNotSupported(format!(
                "content is {} but container claims {} — refusing renamed/mislabeled file",
                sniffed.name(),
                format.name()
            )));
        }

        // Enforce the configured allow-list. Previously this knob was stored
        // but never consulted, so restricting `supported_formats` had no
        // effect on what the pipeline accepted. Matching is by format family,
        // so a `JPEG(95)` entry stands for the JPEG family (the numeric
        // quality gate is `jpeg_quality_threshold`'s job).
        if !self
            .config
            .supported_formats
            .iter()
            .any(|allowed| format_is_compatible(*allowed, format))
        {
            let allowed: Vec<String> = self
                .config
                .supported_formats
                .iter()
                .map(|f| f.name())
                .collect();
            return Err(SpectrumError::ImageFormatNotSupported(format!(
                "image format {} is not in the configured allow-list [{}]",
                format.name(),
                allowed.join(", ")
            )));
        }

        // Size validation happens **before** any pixel buffer is allocated.
        // The image's dimensions are read from its header alone; a decompression
        // bomb (small file, enormous declared canvas) is rejected at this point
        // instead of exhausting memory during the decode it used to reach.
        let (w, h) = header_dimensions(&file_data, claimed)?;
        let (min_w, min_h) = self.config.min_size;
        let (max_w, max_h) = self.config.max_size;
        // A min_size above max_size would make every size fail one of the two
        // checks; that is a config error, not a property of the image, so it
        // is raised as such instead of a per-file size rejection.
        if min_w > max_w || min_h > max_h {
            return Err(SpectrumError::InvalidConfiguration(format!(
                "preprocessor.min_size {min_w}x{min_h} exceeds max_size {max_w}x{max_h}"
            )));
        }
        if w < min_w || h < min_h {
            return Err(SpectrumError::ImageTooSmall {
                width: w,
                height: h,
            });
        }
        if w > max_w || h > max_h {
            return Err(SpectrumError::ImageTooLarge {
                width: w,
                height: h,
            });
        }

        // Decode in memory from the exact bytes that were sniffed and that
        // will be hashed below. The decoder's own limits are configured from
        // `max_size` and are enforced while parsing the header, so even a
        // malformed file that misstates its dimensions cannot drive an
        // allocation larger than the configured budget.
        let limits = super::loader::decoder_limits(max_w, max_h);
        let mut reader = image::ImageReader::with_format(std::io::Cursor::new(&file_data), claimed);
        reader.limits(limits);
        let mut img = reader.decode().map_err(|err| match err {
            image::ImageError::Limits(lim) => {
                log::warn!(
                    "decoder refused allocation under limits from max_size {max_w}x{max_h}: {lim}"
                );
                // The `LimitError` carries only a kind, not dimensions, and
                // the header already told the truth above — reuse those.
                SpectrumError::ImageTooLarge {
                    width: w,
                    height: h,
                }
            }
            other => SpectrumError::from(other),
        })?;
        let info = ImageInfo::from_image(&img, format);

        if w > max_w / 2 || h > max_h / 2 {
            log::warn!("Image large: {w}x{h}; consider resizing for performance.");
        }

        // --- JPEG quality gate --------------------------------------------
        if let ImageFormat::JPEG(q) = format {
            if q < self.config.jpeg_quality_threshold {
                return Err(SpectrumError::ImageCorrupted(format!(
                    "JPEG quality {q} is below the {} threshold; lossy recompression \
                     would change the derived key",
                    self.config.jpeg_quality_threshold
                )));
            }
        }

        // --- Resize to canonical size (aspect-preserving) -------------------
        let (cw, ch) = self.config.canonical_size;
        if (w, h) != (cw, ch) {
            img = self.smart_resize(&img, (cw, ch))?;
        }

        // --- Strip metadata by re-encoding as RGBA in memory ----------------
        if self.config.remove_metadata && info.has_metadata {
            img = self.strip_metadata(&img)?;
        }

        let luma = img.to_luma8();
        let (dw, dh) = luma.dimensions();

        // Hash of the exact bytes read at the top — the same buffer that was
        // sniffed and decoded, so the key binds one consistent version of the
        // file even under concurrent modification.
        let original_hash = compute_sha256(&file_data);

        Ok(PreprocessedImage {
            data: luma.to_vec(),
            dimensions: (dw, dh),
            canonical_size: (cw, ch),
            format,
            original_hash,
        })
    }

    /// Build an [`Image`] buffer from a preprocessed result.
    pub fn to_image(pp: &PreprocessedImage) -> Result<Image> {
        let (w, h) = pp.dimensions;
        Image::from_luma(w, h, pp.data.clone())
    }

    /// Aspect-preserving Lanczos3 resize into an exactly `target` box.
    fn smart_resize(&self, img: &DynamicImage, target: (u32, u32)) -> Result<DynamicImage> {
        let (w, h) = img.dimensions();
        let (tw, th) = target;
        // Degenerate source (only reachable with a permissive custom config —
        // the shipped min_size is 128×128): an f64 `as u32` saturates, which
        // would ask resize_exact for a u32::MAX-wide buffer. Refuse instead.
        if w == 0 || h == 0 {
            return Err(SpectrumError::ImageCorrupted(format!(
                "cannot resize a {w}x{h} image"
            )));
        }
        let ratio = (tw as f64 / w as f64).min(th as f64 / h as f64);
        let nw = ((w as f64 * ratio).round() as u32).max(1);
        let nh = ((h as f64 * ratio).round() as u32).max(1);
        Ok(img.resize_exact(nw, nh, image::imageops::FilterType::Lanczos3))
    }

    /// Drop metadata by converting to an in-memory RGBA image.
    fn strip_metadata(&self, img: &DynamicImage) -> Result<DynamicImage> {
        Ok(DynamicImage::ImageRgba8(img.to_rgba8()))
    }
}

/// Read an image's dimensions from its header alone, decoding no pixels.
///
/// The reader runs with **no** limits: this only parses the fixed-size header
/// fields, never the (attacker-controlled) pixel payload. If the header itself
/// cannot be parsed — truncated file, malformed chunks — the format's error is
/// surfaced as [`SpectrumError::ImageCorrupted`], never a panic and never an
/// allocation proportional to the declared canvas.
fn header_dimensions(data: &[u8], format: image::ImageFormat) -> Result<(u32, u32)> {
    let mut reader = image::ImageReader::with_format(std::io::Cursor::new(data), format);
    reader.no_limits();
    reader.into_dimensions().map_err(|err| {
        SpectrumError::ImageCorrupted(format!("image header rejected by decoder: {err}"))
    })
}

/// Map the decoder's built-in format into the crate's [`ImageFormat`],
/// estimating JPEG quality from the file's real quantization tables.
fn crate_image_format(claimed: image::ImageFormat, data: &[u8]) -> Result<ImageFormat> {
    Ok(match claimed {
        image::ImageFormat::Png => ImageFormat::PNG,
        image::ImageFormat::Jpeg => ImageFormat::JPEG(estimate_jpeg_quality(data)),
        image::ImageFormat::Bmp => ImageFormat::BMP,
        image::ImageFormat::Tiff => ImageFormat::TIFF,
        image::ImageFormat::Gif => ImageFormat::GIF,
        other => {
            return Err(SpectrumError::ImageFormatNotSupported(format!(
                "unrecognized/unsupported format: {other:?}"
            )))
        }
    })
}

/// Whether a sniffed content type is compatible with the container format the
/// decoder selected. JPEG quality estimates make the two `JPEG(_)` variants
/// mutually compatible; everything else must match exactly.
fn format_is_compatible(container: ImageFormat, sniffed: ImageFormat) -> bool {
    match (container, sniffed) {
        (ImageFormat::JPEG(_), ImageFormat::JPEG(_)) => true,
        (a, b) => std::mem::discriminant(&a) == std::mem::discriminant(&b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Make a deterministic 512x512 test PNG in a temp dir, returning its path.
    fn make_test_image(tmp: &std::path::Path) -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        // A small gradient + a deterministic high-detail blob.
        let mut img = image::RgbImage::new(512, 512);
        for (x, y, p) in img.enumerate_pixels_mut() {
            let r = (x * 3 + y * 7) as u8;
            let g = ((x as f32 * 0.5) as usize % 256) as u8;
            let b = (y as f32 * 1.3) as usize as u8;
            *p = image::Rgb([r, g, b]);
        }
        let path = tmp.join(format!("test_{n}.png"));
        img.save(&path).unwrap();
        path
    }

    #[test]
    fn canonicalizes_to_target_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = make_test_image(dir.path());
        let pp = ImagePreprocessor::new()
            .preprocess(path.to_str().unwrap())
            .unwrap();
        let (w, h) = pp.dimensions;
        assert_eq!(w, pp.canonical_size.0);
        assert_eq!(h, pp.canonical_size.1);
        assert_eq!(pp.canonical_size, (512, 512));
        assert_eq!(pp.data.len() as u32, w * h);
    }

    #[test]
    fn hash_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = make_test_image(dir.path());
        let a = ImagePreprocessor::new()
            .preprocess(path.to_str().unwrap())
            .unwrap();
        let b = ImagePreprocessor::new()
            .preprocess(path.to_str().unwrap())
            .unwrap();
        assert_eq!(a.original_hash, b.original_hash);
    }

    #[test]
    fn non_square_source_is_resized_aspect_preserving() {
        // The canonical resize is aspect-preserving into the target box: a
        // 600x400 source lands on 512x341 at the default 512x512 target, so
        // `dimensions` honestly differs from `canonical_size` (the target).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wide.png");
        let mut img = ::image::RgbImage::new(600, 400);
        for (x, y, p) in img.enumerate_pixels_mut() {
            *p = ::image::Rgb([
                (x * 5 % 256) as u8,
                (y * 7 % 256) as u8,
                ((x + y) * 3 % 256) as u8,
            ]);
        }
        ::image::save_buffer(&path, img.as_raw(), 600, 400, ::image::ColorType::Rgb8).unwrap();

        let pp = ImagePreprocessor::new()
            .preprocess(path.to_str().unwrap())
            .unwrap();
        let (w, h) = pp.dimensions;
        assert_eq!(pp.canonical_size, (512, 512));
        assert_eq!(w, 512, "longest side lands exactly on the target");
        assert_eq!(h, 341, "short side follows the aspect ratio (rounded)");
        assert_eq!(pp.data.len(), (w * h) as usize);
    }

    /// Craft a PNG whose IHDR declares an enormous canvas while the file
    /// itself stays tiny (zero compressed IDAT): the classic decompression
    /// bomb shape — a few hundred bytes claiming 60000x60000 pixels.
    fn make_bomb_png(dir: &std::path::Path, w: u32, h: u32) -> std::path::PathBuf {
        // IEEE CRC-32 (poly 0xEDB88320), bit-by-bit — no external crate so the
        // fixture needs nothing beyond `image` itself.
        fn crc32(bytes: &[u8]) -> u32 {
            let mut crc: u32 = 0xFFFF_FFFF;
            for &b in bytes {
                crc ^= u32::from(b);
                for _ in 0..8 {
                    let mask = (crc & 1).wrapping_neg();
                    crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
                }
            }
            !crc
        }

        let mut png: Vec<u8> = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&w.to_be_bytes());
        ihdr.extend_from_slice(&h.to_be_bytes());
        ihdr.extend_from_slice(&[8, 0, 0, 0, 0]); // 8-bit, grayscale, no interlace
        let mut chunk: Vec<u8> = 13u32.to_be_bytes().to_vec();
        chunk.extend_from_slice(b"IHDR");
        chunk.extend_from_slice(&ihdr);
        chunk.extend_from_slice(&crc32(&chunk[4..]).to_be_bytes());
        png.extend_from_slice(&chunk);

        // Empty IDAT: a zlib stream over zero bytes — 2-byte zlib header,
        // a single stored deflate block of length 0, and the Adler-32 of
        // the empty input (1). Hand-rolled so no flate2 dependency is needed.
        let idat: Vec<u8> = vec![
            0x78, 0x01, // zlib header (CMF/FLG, valid FCHECK)
            0x01, 0x00, 0x00, 0xFF, 0xFF, // final stored block, LEN=0, NLEN
            0x00, 0x00, 0x00, 0x01, // Adler-32(empty)
        ];
        let mut chunk: Vec<u8> = (idat.len() as u32).to_be_bytes().to_vec();
        chunk.extend_from_slice(b"IDAT");
        chunk.extend_from_slice(&idat);
        chunk.extend_from_slice(&crc32(&chunk[4..]).to_be_bytes());
        png.extend_from_slice(&chunk);
        png.extend_from_slice(&[0, 0, 0, 0, b'I', b'E', b'N', b'D']);

        let p = dir.join(format!("bomb_{w}x{h}.png"));
        std::fs::write(&p, &png).unwrap();
        p
    }

    #[test]
    fn decompression_bomb_is_rejected_before_decoding_pixels() {
        // 60000x60000 grayscale would be ~3.6 GB if allocated; the file is a
        // few hundred bytes. The rejection must come from the header check,
        // before any pixel buffer exists.
        let dir = tempfile::tempdir().unwrap();
        let bomb = make_bomb_png(dir.path(), 60_000, 60_000);
        let size = std::fs::metadata(&bomb).unwrap().len();
        assert!(size < 10_000, "bomb fixture must be tiny, got {size} bytes");

        let res = ImagePreprocessor::new().preprocess(bomb.to_str().unwrap());
        match res {
            Err(SpectrumError::ImageTooLarge { width, height }) => {
                assert_eq!((width, height), (60_000, 60_000));
            }
            other => panic!("expected ImageTooLarge from header check, got {other:?}"),
        }
    }

    #[test]
    fn min_size_above_max_size_is_a_config_error() {
        let cfg = crate::config::ImagePreprocessorConfig {
            min_size: (500, 500),
            max_size: (300, 300),
            ..Default::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("img.png");
        image::RgbImage::new(160, 160).save(&img).unwrap();
        let res = ImagePreprocessor::with_config(cfg).preprocess(img.to_str().unwrap());
        assert!(
            matches!(&res, Err(SpectrumError::InvalidConfiguration(_))),
            "inverted min/max must be rejected as a config error, got {res:?}"
        );
    }

    #[test]
    fn max_size_is_enforced_against_header_dimensions() {
        // Custom config: max 300x300. A 400x400 image is over and must be
        // rejected with its real dimensions; a 300x300 one stays inside.
        let cfg = crate::config::ImagePreprocessorConfig {
            max_size: (300, 300),
            ..Default::default()
        };

        let dir = tempfile::tempdir().unwrap();
        let over = dir.path().join("over.png");
        image::RgbImage::new(400, 400).save(&over).unwrap();
        let res = ImagePreprocessor::with_config(cfg.clone()).preprocess(over.to_str().unwrap());
        assert!(
            matches!(
                res.err(),
                Some(SpectrumError::ImageTooLarge {
                    width: 400,
                    height: 400
                })
            ),
            "400x400 must be rejected by a 300x300 max_size"
        );

        let inside = dir.path().join("inside.png");
        image::RgbImage::new(300, 300).save(&inside).unwrap();
        let res = ImagePreprocessor::with_config(cfg).preprocess(inside.to_str().unwrap());
        assert!(
            res.is_ok(),
            "300x300 must be accepted by a 300x300 max_size"
        );
    }

    #[test]
    fn too_small_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tiny.png");
        image::RgbImage::new(32, 32).save(&p).unwrap();
        let res = ImagePreprocessor::new().preprocess(p.to_str().unwrap());
        assert!(matches!(
            res.err(),
            Some(SpectrumError::ImageTooSmall {
                width: 32,
                height: 32
            })
        ));
    }

    #[test]
    fn renamed_file_is_rejected() {
        // A real PNG saved with a .bmp extension must be refused.
        let dir = tempfile::tempdir().unwrap();
        let png = dir.path().join("secret.png");
        image::RgbImage::new(160, 160).save(&png).unwrap();
        let disguised = dir.path().join("disguised.bmp");
        std::fs::copy(&png, &disguised).unwrap();

        let res = ImagePreprocessor::new().preprocess(disguised.to_str().unwrap());
        assert!(
            matches!(res.err(), Some(SpectrumError::ImageFormatNotSupported(_))),
            "mislabeled payload must be rejected"
        );
    }

    #[test]
    fn honest_file_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("honest.png");
        image::RgbImage::new(160, 160).save(&p).unwrap();
        assert!(ImagePreprocessor::new()
            .preprocess(p.to_str().unwrap())
            .is_ok());
    }

    #[test]
    fn supported_formats_allow_list_is_enforced() {
        // The knob used to be dead: restricting supported_formats had no
        // effect and any format was silently accepted.
        let dir = tempfile::tempdir().unwrap();
        let png = dir.path().join("img.png");
        image::RgbImage::new(160, 160).save(&png).unwrap();

        let cfg = crate::config::ImagePreprocessorConfig {
            supported_formats: vec![ImageFormat::JPEG(95)],
            ..Default::default()
        };
        let restrictive = ImagePreprocessor::with_config(cfg);
        assert!(
            matches!(
                restrictive.preprocess(png.to_str().unwrap()).err(),
                Some(SpectrumError::ImageFormatNotSupported(_))
            ),
            "PNG must be refused when the allow-list only has JPEG"
        );

        let cfg2 = crate::config::ImagePreprocessorConfig {
            supported_formats: vec![ImageFormat::PNG, ImageFormat::JPEG(95)],
            ..Default::default()
        };
        assert!(ImagePreprocessor::with_config(cfg2)
            .preprocess(png.to_str().unwrap())
            .is_ok());
    }

    #[test]
    fn unsupported_extension_is_rejected() {
        // Valid PNG bytes under a .txt extension: the container claim cannot
        // be resolved, so the file is refused (not silently guessed).
        let dir = tempfile::tempdir().unwrap();
        let png = dir.path().join("real.png");
        image::RgbImage::new(160, 160).save(&png).unwrap();
        let p = dir.path().join("image.txt");
        std::fs::copy(&png, &p).unwrap();
        let res = ImagePreprocessor::new().preprocess(p.to_str().unwrap());
        assert!(
            matches!(res.err(), Some(SpectrumError::ImageFormatNotSupported(_))),
            "unresolved container claim must be rejected"
        );
    }

    #[test]
    fn jpeg_quality_gate_uses_the_real_tables() {
        // End-to-end: the gate must reflect the file's actual quantization
        // tables now that quality comes from the DQT, not a hardcoded 95.
        let dir = tempfile::tempdir().unwrap();
        let img = image::DynamicImage::new_rgb8(160, 160);

        let low = dir.path().join("low.jpg");
        let mut out = std::io::BufWriter::new(std::fs::File::create(&low).unwrap());
        let enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 30);
        img.write_with_encoder(enc).unwrap();
        drop(out);
        let res = ImagePreprocessor::new().preprocess(low.to_str().unwrap());
        assert!(
            matches!(res.err(), Some(SpectrumError::ImageCorrupted(_))),
            "quality-30 JPEG must fail the 90 threshold"
        );

        let high = dir.path().join("high.jpg");
        let mut out = std::io::BufWriter::new(std::fs::File::create(&high).unwrap());
        let enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 95);
        img.write_with_encoder(enc).unwrap();
        drop(out);
        assert!(
            ImagePreprocessor::new()
                .preprocess(high.to_str().unwrap())
                .is_ok(),
            "quality-95 JPEG must pass the 90 threshold"
        );
    }
}
