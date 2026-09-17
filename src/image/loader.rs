//! Image loading, format detection and a small ND grayscale buffer used by the
//! entropy engine.

use image::{DynamicImage, GenericImageView};
use serde::{Deserialize, Serialize};

use crate::error::{Result, SpectrumError};

/// A supported raster image format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageFormat {
    PNG,
    /// JPEG with an estimated quality 1..=100.
    JPEG(u8),
    BMP,
    TIFF,
    GIF,
}

impl ImageFormat {
    /// Human-readable name, e.g. `"PNG"` or `"JPEG(90)"`.
    pub fn name(self) -> String {
        match self {
            ImageFormat::PNG => "PNG".to_string(),
            ImageFormat::JPEG(q) => format!("JPEG({q})"),
            ImageFormat::BMP => "BMP".to_string(),
            ImageFormat::TIFF => "TIFF".to_string(),
            ImageFormat::GIF => "GIF".to_string(),
        }
    }

    /// Whether pixels are stored losslessly by this format.
    pub fn is_lossless(self) -> bool {
        matches!(
            self,
            ImageFormat::PNG | ImageFormat::BMP | ImageFormat::TIFF
        )
    }
}

/// First bytes needed to sniff a format and estimate a JPEG's quality.
///
/// 256 bytes would cover a bare SOI+DQT, but real JPEGs routinely carry APP1
/// EXIF blocks of up to 64 KiB **before** the DQT; a window smaller than that
/// silently degrades every EXIF-heavy JPEG to the default-quality fallback
/// (75), which could let a low-quality file pass a 70 threshold. 128 KiB
/// covers SOI + APP0 + APP1 + APP2 + DQT for essentially all real files;
/// a truncated scan still falls back safely (no panic), just conservatively.
const SNIFF_WINDOW: usize = 128 * 1024;

/// Read the first [`SNIFF_WINDOW`] bytes of `path`.
///
/// All sniffing needs is the header; reading the file whole before deciding it
/// is even an image lets an oversized file exhaust memory before any
/// rejection.
fn sniff_window(path: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; SNIFF_WINDOW];
    let mut filled = 0usize;
    loop {
        match f.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => {
                filled += n;
                if filled == buf.len() {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Detect the image format from a file path's extension + sniffed signature.
pub fn detect_format(path: &str) -> Result<ImageFormat> {
    let guesses = image::ImageReader::open(path)
        .map_err(SpectrumError::from)?
        .format();

    match guesses {
        Some(image::ImageFormat::Png) => Ok(ImageFormat::PNG),
        Some(image::ImageFormat::Jpeg) => {
            // Estimate the real quality from the file's quantization tables
            // instead of reporting a hardcoded placeholder — the value feeds
            // the preprocessor's JPEG-quality gate. Only the header is read:
            // the DQT tables live in the first bytes of the stream.
            let data = sniff_window(path)?;
            Ok(ImageFormat::JPEG(estimate_jpeg_quality(&data)))
        }
        Some(image::ImageFormat::Bmp) => Ok(ImageFormat::BMP),
        Some(image::ImageFormat::Tiff) => Ok(ImageFormat::TIFF),
        Some(image::ImageFormat::Gif) => Ok(ImageFormat::GIF),
        other => Err(SpectrumError::ImageFormatNotSupported(format!(
            "unrecognized/unsupported format: {other:?}"
        ))),
    }
}

/// Estimate a JPEG's quantization-table quality on the IJG 1..=100 scale.
///
/// The container carries no explicit quality field, so this reverses libjpeg's
/// standard scaling: the luma DQT table's first entry (the DC term) is mapped
/// back through the IJG formula `t = (16·s + 50)/100`, inverting the rounding
/// via the bucket's lower edge. Quality ≥ 50 maps to scale `s = 200 − 2q`;
/// below 50 to `s = 5000/q`. Calibration check: q=95 → t=2 → 95, q=75 → t=8
/// → 77, q=50 → t=16 → 52, q=25 → t=32 → 25, q=10 → t=80 → 10.
/// A missing or unparseable DQT (no tables yet scanned, e.g. a bare header)
/// falls back to the libjpeg default of 75.
pub(crate) fn estimate_jpeg_quality(data: &[u8]) -> u8 {
    let mut i = 2usize; // skip the SOI marker
    while i + 4 <= data.len() {
        if data[i] != 0xFF {
            i += 1;
            continue;
        }
        let marker = data[i + 1];
        // Standalone markers (RSTn, SOI, EOI, TEM) carry no length field.
        if marker == 0xFF || marker == 0x01 || (0xD0..=0xD9).contains(&marker) {
            i += 2;
            continue;
        }
        let seg_len = (usize::from(data[i + 2]) << 8) | usize::from(data[i + 3]);
        if seg_len < 2 || i + 2 + seg_len > data.len() {
            break;
        }
        if marker == 0xDB && seg_len >= 3 {
            // DQT found: first table's precision bit selects 8/16-bit entries.
            let pq = data[i + 4] >> 4;
            let dc = if pq == 0 {
                Some(f64::from(data[i + 5]))
            } else if seg_len >= 6 {
                Some(f64::from(
                    (u16::from(data[i + 5]) << 8) | u16::from(data[i + 6]),
                ))
            } else {
                None
            };
            if let Some(dc) = dc {
                return quality_from_dc(dc);
            }
        }
        i += 2 + seg_len;
    }
    75
}

/// Map a quantization-table DC entry back to IJG quality (see
/// [`estimate_jpeg_quality`]).
fn quality_from_dc(dc: f64) -> u8 {
    const BASE: f64 = 16.0;
    let scale = (((100.0 * dc) - 50.0) / BASE).max(1.0);
    let q = if scale > 100.0 {
        5000.0 / scale
    } else {
        (200.0 - scale) / 2.0
    };
    q.round().clamp(1.0, 100.0) as u8
}

/// Recognized byte signatures for magic-byte sniffing.
const PNG_MAGIC: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
const JPEG_MAGIC: &[u8] = &[0xFF, 0xD8, 0xFF];
const BMP_MAGIC: &[u8] = b"BM";
/// TIFF: `II*\0` little-endian or `MM\0*` big-endian.
const TIFF_LE_MAGIC: &[u8] = &[0x49, 0x49, 0x2A, 0x00];
const TIFF_BE_MAGIC: &[u8] = &[0x4D, 0x4D, 0x00, 0x2A];
/// GIF: `GIF87a` or `GIF89a`.
const GIF87_MAGIC: &[u8] = b"GIF87a";
const GIF89_MAGIC: &[u8] = b"GIF89a";

/// Sniff the image format from the leading magic bytes of a buffer.
///
/// This does not depend on file extensions (which lie) and is the primary
/// defence against renamed/mislabeled payloads. Returns an error for buffers
/// that are too short to hold any known signature or match none of them.
pub fn sniff_format(bytes: &[u8]) -> Result<ImageFormat> {
    let starts_with = |sig: &[u8]| bytes.len() >= sig.len() && &bytes[..sig.len()] == sig;

    if starts_with(PNG_MAGIC) {
        Ok(ImageFormat::PNG)
    } else if starts_with(JPEG_MAGIC) {
        Ok(ImageFormat::JPEG(estimate_jpeg_quality(bytes)))
    } else if starts_with(BMP_MAGIC) {
        Ok(ImageFormat::BMP)
    } else if starts_with(TIFF_LE_MAGIC) || starts_with(TIFF_BE_MAGIC) {
        Ok(ImageFormat::TIFF)
    } else if starts_with(GIF87_MAGIC) || starts_with(GIF89_MAGIC) {
        Ok(ImageFormat::GIF)
    } else {
        let head: String = bytes
            .iter()
            .take(8)
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        let detail = if head.is_empty() {
            " (empty input)".to_string()
        } else {
            format!(" {head}")
        };
        Err(SpectrumError::ImageFormatNotSupported(format!(
            "unrecognized magic bytes{detail}"
        )))
    }
}

/// Detect the format by sniffing the actual file bytes (magic-byte based).
/// Only the leading bytes are read — the whole file never enters memory here.
pub fn sniff_format_from_file(path: &str) -> Result<ImageFormat> {
    let data = sniff_window(path)?;
    sniff_format(&data)
}

/// Strict decoder limits derived from a maximum canvas size.
///
/// `image::Limits` is `#[non_exhaustive]` in image 0.25, so the struct is
/// built from its default and the fields are assigned individually.
pub(crate) fn decoder_limits(max_w: u32, max_h: u32) -> image::Limits {
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(max_w);
    limits.max_image_height = Some(max_h);
    // Budget for the decoded raster (8 B/px ≈ RGBA8 plus slack for the
    // decoder's intermediate buffers), floored at 64 MiB.
    limits.max_alloc = Some((u64::from(max_w) * u64::from(max_h) * 8).max(64 * 1024 * 1024));
    limits
}

/// Load any supported image file into a [`DynamicImage`].
///
/// Decoding runs under the same strict limits the preprocessing pipeline
/// derives from its default `max_size` (4096×4096), so a hostile file cannot
/// drive an oversized allocation through this path either.
pub fn load_image(path: &str) -> Result<DynamicImage> {
    let (max_w, max_h) = crate::config::ImagePreprocessorConfig::default().max_size;
    let mut reader = image::ImageReader::open(path).map_err(SpectrumError::from)?;
    reader.limits(decoder_limits(max_w, max_h));
    let img = reader.decode().map_err(SpectrumError::from)?;
    Ok(img)
}

/// Metadata about a loaded image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageInfo {
    pub format: ImageFormat,
    pub dimensions: (u32, u32),
    pub has_metadata: bool,
    pub is_lossless: bool,
}

impl ImageInfo {
    /// Build an [`ImageInfo`] from a decoded image + its detected format.
    pub fn from_image(img: &DynamicImage, format: ImageFormat) -> Self {
        let is_lossless = format.is_lossless();
        // PNG and JPEG carry ancillary metadata chunks; treat them heuristically.
        let has_metadata = matches!(format, ImageFormat::PNG | ImageFormat::JPEG(_));
        ImageInfo {
            format,
            dimensions: img.dimensions(),
            has_metadata,
            is_lossless,
        }
    }
}

/// A grayscale (luma) image buffer in row-major order.
///
/// This is the lightweight representation the entropy engine operates on.
#[derive(Debug, Clone)]
pub struct Image {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

impl Image {
    /// Wrap an already-resized grayscale buffer.
    pub fn from_luma(width: u32, height: u32, pixels: Vec<u8>) -> Result<Image> {
        let expected = (width as usize).checked_mul(height as usize);
        match expected {
            Some(n) if n == pixels.len() => Ok(Image {
                width,
                height,
                pixels,
            }),
            Some(n) => Err(SpectrumError::InvalidConfiguration(format!(
                "pixel buffer length {} does not match {width}x{height}={n}",
                pixels.len()
            ))),
            None => Err(SpectrumError::InvalidConfiguration(
                "image dimensions overflow".into(),
            )),
        }
    }

    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    pub fn pixel_count(&self) -> usize {
        self.pixels.len()
    }

    /// Grayscale value at (x, y). Out-of-bounds is clamped to the nearest edge
    /// pixel so that border convolutions stay well-defined. Empty images
    /// (legal via [`Image::from_luma`] with zero dimensions) yield 0 instead
    /// of panicking on the degenerate clamp range or the empty buffer.
    pub fn pixel_clamped(&self, x: i64, y: i64) -> u8 {
        if self.width == 0 || self.height == 0 || self.pixels.is_empty() {
            return 0;
        }
        let xc = x.clamp(0, self.width as i64 - 1) as u32;
        let yc = y.clamp(0, self.height as i64 - 1) as u32;
        let idx = yc as usize * self.width as usize + xc as usize;
        self.pixels[idx]
    }

    /// Aspect-preserving area-average downsample so the longest side is ≤ `max_dim`.
    pub fn downsample_to_max(&self, max_dim: u32) -> Image {
        if self.width <= max_dim && self.height <= max_dim {
            return self.clone();
        }
        let ratio = max_dim as f64 / self.width.max(self.height) as f64;
        let nw = ((self.width as f64 * ratio).round() as u32).max(1);
        let nh = ((self.height as f64 * ratio).round() as u32).max(1);
        let sx = self.width as f64 / nw as f64;
        let sy = self.height as f64 / nh as f64;
        let mut data = Vec::with_capacity((nw * nh) as usize);
        for y in 0..nh {
            let y0 = ((y as f64) * sy).floor() as usize;
            let y1 = (((y as f64 + 1.0) * sy).ceil() as usize).min(self.height as usize);
            for x in 0..nw {
                let x0 = ((x as f64) * sx).floor() as usize;
                let x1 = (((x as f64 + 1.0) * sx).ceil() as usize).min(self.width as usize);
                let mut sum = 0u32;
                let mut cnt = 0u32;
                for yy in y0..y1 {
                    for xx in x0..x1 {
                        sum += self.pixels[yy * self.width as usize + xx] as u32;
                        cnt += 1;
                    }
                }
                data.push((sum / cnt.max(1)) as u8);
            }
        }
        Image {
            width: nw,
            height: nh,
            pixels: data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_luma_checks_length() {
        assert!(Image::from_luma(4, 4, vec![0u8; 16]).is_ok());
        assert!(Image::from_luma(4, 4, vec![0u8; 15]).is_err());
    }

    #[test]
    fn pixel_clamped_bounds() {
        let img = Image::from_luma(3, 3, (0u8..=8).collect()).unwrap();
        // Top-left valid read.
        assert_eq!(img.pixel_clamped(0, 0), 0);
        // Clamped negative x/y -> top-left corner.
        assert_eq!(img.pixel_clamped(-5, -5), 0);
        // Clamped out-of-range -> bottom-right corner (value 8).
        assert_eq!(img.pixel_clamped(100, 100), 8);
    }

    #[test]
    fn pixel_clamped_on_empty_image_never_panics() {
        let empty = Image::from_luma(0, 0, vec![]).unwrap();
        assert_eq!(empty.pixel_clamped(0, 0), 0);
        assert_eq!(empty.pixel_clamped(-3, 7), 0);
    }

    #[test]
    fn sniff_detects_png() {
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        bytes.extend_from_slice(&[0, 0, 0, 13]);
        assert_eq!(sniff_format(&bytes).unwrap(), ImageFormat::PNG);
    }

    /// Build a minimal JPEG byte stream: SOI + one 8-bit DQT segment whose
    /// luma DC entry is `dc`, followed by filler bytes.
    fn jpeg_with_dqt_dc(dc: u8) -> Vec<u8> {
        let mut b = vec![0xFF, 0xD8]; // SOI
        b.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00, dc]); // DQT, Pq=0
        b.extend_from_slice(&[1u8; 63]); // rest of the 64-entry table
        b.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]); // truncated SOS tail
        b
    }

    #[test]
    fn jpeg_quality_is_estimated_from_the_dqt_not_hardcoded() {
        // The old code reported JPEG(95) for every JPEG: a q=10 file sailed
        // through the quality gate. DC=2 must map to ~95, DC=80 to ~10.
        assert_eq!(
            sniff_format(&jpeg_with_dqt_dc(2)).unwrap(),
            ImageFormat::JPEG(95)
        );
        assert_eq!(
            sniff_format(&jpeg_with_dqt_dc(80)).unwrap(),
            ImageFormat::JPEG(10)
        );
    }

    #[test]
    fn detect_format_reads_real_jpeg_quality() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("q30.jpg");
        let img = image::DynamicImage::new_rgb8(48, 48);
        let mut out = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 30);
        img.write_with_encoder(encoder).unwrap();
        drop(out);

        match detect_format(path.to_str().unwrap()).unwrap() {
            ImageFormat::JPEG(q) => assert!(
                (25..=45).contains(&q),
                "quality-30 JPEG must estimate near 30 (+bucket rounding), got {q}"
            ),
            other => panic!("expected JPEG, got {other:?}"),
        }
    }

    #[test]
    fn sniff_detects_jpeg_bmp_tiff_gif() {
        // A bare JPEG header carries no DQT yet → libjpeg default quality.
        let jpeg = sniff_format(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 0]).unwrap();
        assert!(matches!(jpeg, ImageFormat::JPEG(75)), "got {jpeg:?}");
        assert_eq!(sniff_format(b"BM\x36\x00").unwrap(), ImageFormat::BMP);
        assert_eq!(
            sniff_format(&[0x49, 0x49, 0x2A, 0x00, 0x08]).unwrap(),
            ImageFormat::TIFF
        );
        assert_eq!(
            sniff_format(&[0x4D, 0x4D, 0x00, 0x2A, 0x08]).unwrap(),
            ImageFormat::TIFF
        );
        assert_eq!(sniff_format(b"GIF89a").unwrap(), ImageFormat::GIF);
        assert_eq!(sniff_format(b"GIF87a").unwrap(), ImageFormat::GIF);
    }

    #[test]
    fn sniff_rejects_unknown_and_short() {
        assert!(sniff_format(b"not an image at all").is_err());
        assert!(sniff_format(&[]).is_err());
        assert!(sniff_format(&[0x89]).is_err());
    }

    #[test]
    fn sniff_from_file_reads_only_a_window() {
        // A file with a valid image header followed by megabytes of payload is
        // recognized from its leading bytes alone; the reader must not need
        // the whole file in memory to answer.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big.png");
        let mut data = PNG_MAGIC.to_vec();
        data.extend_from_slice(&[0u8; 4]); // IHDR length placeholder
        data.extend_from_slice(b"IHDR");
        data.extend_from_slice(&[0u8; 13]);
        data.extend_from_slice(&vec![0xABu8; 4 * 1024 * 1024]);
        std::fs::write(&p, &data).unwrap();

        assert_eq!(
            sniff_format_from_file(p.to_str().unwrap()).unwrap(),
            ImageFormat::PNG
        );
    }

    #[test]
    fn jpeg_quality_estimated_when_dqt_follows_large_exif() {
        // Regression: a 256-byte sniff window could not see past a real-world
        // APP1 EXIF block (up to 64 KiB), silently degrading every EXIF-heavy
        // JPEG to the default-quality fallback (75). The window must cover
        // SOI + APP1 + DQT.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("exif.jpg");
        let mut data = vec![0xFF, 0xD8]; // SOI
        let exif_len = 60_000usize;
        data.extend_from_slice(&[0xFF, 0xE1]); // APP1
        data.extend_from_slice(&u16::try_from(exif_len + 2).unwrap().to_be_bytes());
        data.extend_from_slice(&vec![0x00; exif_len]); // EXIF payload
        data.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00, 2]); // DQT, DC=2 → q≈95
        data.extend_from_slice(&[1u8; 63]);
        std::fs::write(&p, &data).unwrap();

        match sniff_format_from_file(p.to_str().unwrap()).unwrap() {
            ImageFormat::JPEG(q) => assert!(
                (90..=100).contains(&q),
                "DC=2 must estimate ~95 even behind a large EXIF block, got {q}"
            ),
            other => panic!("expected JPEG, got {other:?}"),
        }
    }

    #[test]
    fn sniff_window_truncates_on_short_file() {
        // A truncated PNG signature (4 of 8 magic bytes) must not panic or
        // over-read; it simply fails to match any format. (Note: "BM" alone
        // WOULD legitimately match BMP — the checker only requires the file
        // to be at least as long as the signature.)
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tiny.bin");
        std::fs::write(&p, [0x89, b'P', b'N', b'G']).unwrap();
        assert!(sniff_format_from_file(p.to_str().unwrap()).is_err());
    }

    #[test]
    fn sniff_matches_extension_detection_on_real_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("real.png");
        image::RgbImage::new(16, 16).save(&p).unwrap();
        let data = std::fs::read(&p).unwrap();
        assert_eq!(sniff_format(&data).unwrap(), ImageFormat::PNG);
        let by_file = sniff_format_from_file(p.to_str().unwrap()).unwrap();
        assert_eq!(by_file, ImageFormat::PNG);
    }

    #[test]
    fn sniff_rejects_text_payload_disguised_as_image() {
        // A hostile "image" that is really a script.
        let hostile = b"#!/bin/sh\nrm -rf /\n";
        assert!(sniff_format(hostile).is_err());
    }
}
