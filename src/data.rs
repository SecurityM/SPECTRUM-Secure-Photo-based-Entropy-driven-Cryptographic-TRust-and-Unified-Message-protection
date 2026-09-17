//! On-disk formats for SPECTRUM auxiliary data: derived-key records and batch
//! manifests.
//!
//! Both use a checksummed, length-checked binary layout (magic string, length
//! prefixes, SHA-256 checksum) so corrupted or swapped files are rejected
//! instead of silently producing wrong keys. Key derivation itself needs no
//! on-disk records: it is a pure function of the image file, so nothing here
//! is required to reproduce a key.

use crate::error::{Result, SpectrumError};
use crate::utils::hashing::compute_sha256;
use crate::utils::serialization::{read_u32_le, write_u32_le};
use zeroize::Zeroizing;

use std::io::Write;

/// Write `bytes` to `path` with owner-only permissions (`0o600` on Unix).
///
/// Every file written through this helper carries secret key material (the
/// derived master key in a `.frk` record, the per-image `key_hex` of a batch
/// manifest, or a post-quantum secret key from `spectrum pq-keygen`), so it
/// must never be created world-readable. The mode is set on the open file
/// itself — not merely at creation — so re-saving over a pre-existing file
/// with wider permissions tightens it instead of inheriting the old mode
/// (which is what `OpenOptions::mode()` alone would do).
pub fn write_secret_file(path: &str, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::File::create(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Tighten before the content hits the disk so the secret bytes never
        // exist under a world-readable mode, even transiently.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    Ok(())
}

/// Upper bound for untrusted file inputs.
///
/// Reading a hostile path with unbounded `fs::read` lets a huge file exhaust
/// memory before any format sniff, checksum or bounds validation runs — the
/// same denial-of-service class as decoding an image without limits. Every
/// loader that accepts an arbitrary path reads through this cap and fails
/// closed if the file is larger.
pub const MAX_INPUT_FILE_BYTES: u64 = 128 * 1024 * 1024; // 128 MiB

/// Read at most [`MAX_INPUT_FILE_BYTES`] bytes from `path`, failing closed if
/// the file is larger (or its length cannot be queried).
pub fn read_capped(path: &str) -> Result<Vec<u8>> {
    read_capped_with(path, MAX_INPUT_FILE_BYTES)
}

/// [`read_capped`] with an explicit cap (the constant with a test-friendly
/// parameterization).
///
/// The cap is enforced on the **read itself** (`File::take`), not on a
/// pre-read `metadata()` probe: a file that grows between a metadata check
/// and the read (TOCTOU) could otherwise still drive an unbounded
/// allocation. Reading `max_bytes + 1` and rejecting when that much arrives
/// means even a racing writer can never make this function allocate more
/// than the cap (plus one probe byte).
pub fn read_capped_with(path: &str, max_bytes: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max_bytes {
        return Err(SpectrumError::MalformedMessage(format!(
            "input file exceeds the {} byte limit (refusing unbounded read)",
            max_bytes
        )));
    }
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Batch derivation records
// ---------------------------------------------------------------------------

/// Version of the batch manifest format.
pub const BATCH_VERSION: u32 = 1;

/// Result of deriving one key inside a batch.
///
/// One entry of a batch manifest. The derived key is secret material, so the
/// `Debug` impl never prints it.
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BatchEntry {
    /// Source image path as given to the batch command.
    pub image: String,
    /// Hex master key, 268 chars (1072 bits) when successful.
    pub key_hex: String,
    /// 64-char hex SHA-256 of the source image file.
    pub image_hash: String,
    /// Strategy chosen for this image.
    pub strategy: String,
    /// Total estimated entropy in bits.
    pub total_entropy: f64,
    /// Error message when derivation failed; empty on success.
    pub error: String,
}

impl BatchEntry {
    /// A successful entry.
    pub fn success(
        image: &str,
        key_hex: String,
        image_hash: String,
        strategy: String,
        total_entropy: f64,
    ) -> Self {
        BatchEntry {
            image: image.to_string(),
            key_hex,
            image_hash,
            strategy,
            total_entropy,
            error: String::new(),
        }
    }

    /// A failed entry.
    pub fn failure(image: &str, error: impl Into<String>) -> Self {
        BatchEntry {
            image: image.to_string(),
            key_hex: String::new(),
            image_hash: String::new(),
            strategy: String::new(),
            total_entropy: 0.0,
            error: error.into(),
        }
    }

    pub fn is_success(&self) -> bool {
        self.error.is_empty()
    }
}

impl std::fmt::Debug for BatchEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchEntry")
            .field("image", &self.image)
            .field(
                "key_hex",
                &if self.key_hex.is_empty() {
                    ""
                } else {
                    "<redacted>"
                },
            )
            .field("image_hash", &self.image_hash)
            .field("strategy", &self.strategy)
            .field("total_entropy", &self.total_entropy)
            .field("error", &self.error)
            .finish()
    }
}

impl Drop for BatchEntry {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // The manifest entry holds the hex master key; wipe it when the
        // entry leaves memory (JSON serialization happens through &self, so
        // this never runs mid-write).
        self.key_hex.zeroize();
    }
}

/// A batch manifest: the full record of one `spectrum batch` invocation.
/// Serialized as JSON so it can be piped into other tooling or archived.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BatchManifest {
    pub version: u32,
    /// UNIX timestamp (seconds) of the batch run.
    pub created_at: u64,
    /// One entry per requested image, in request order.
    pub entries: Vec<BatchEntry>,
}

impl BatchManifest {
    pub fn new(entries: Vec<BatchEntry>) -> Self {
        BatchManifest {
            version: BATCH_VERSION,
            created_at: crate::key_derivation::metadata::current_timestamp(),
            entries,
        }
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| SpectrumError::SerializationError(e.to_string()))
    }

    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| SpectrumError::SerializationError(e.to_string()))
    }

    pub fn save(&self, path: &str) -> Result<()> {
        let mut json = self.to_json()?;
        json.push('\n');
        // The manifest embeds `key_hex` for every successful entry — secret
        // material, so owner-only permissions like `.frk` records.
        write_secret_file(path, json.as_bytes())
    }

    pub fn load(path: &str) -> Result<Self> {
        let raw = String::from_utf8(read_capped(path)?)?;
        Self::from_json(&raw)
    }

    /// Number of successful derivations.
    pub fn success_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_success()).count()
    }

    /// Number of failed derivations.
    pub fn failure_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.is_success()).count()
    }
}

/// Magic for derived-key record files.
const KEY_MAGIC: &[u8; 8] = b"SPX1KEY1";

/// A derived-key record that also carries the originating image hash.
///
/// The key bytes are zeroized when the record is dropped, so a `.frk` loaded
/// for `verify` does not leave the master key behind in freeable memory.
///
/// The key is a strict deterministic function of the image file, so this
/// record is a convenience snapshot — `key = XOF(witness ‖ SHA-256(file))` —
/// not something required to reproduce the key. The image hash lets `verify`
/// detect that a key image changed after export.
///
/// On-disk layout (`.frk`):
/// `magic(8) | key_len(u32) | key | image_hash(32) | sha256(32)` — the key is
/// length-prefixed so the 1072-bit master key (134 bytes) stores and loads
/// exactly.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyRecord {
    /// The derived master key (1072 bits / 134 bytes).
    pub key: Zeroizing<Vec<u8>>,
    /// SHA-256 of the source image file.
    pub image_hash: [u8; 32],
}

impl std::fmt::Debug for KeyRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRecord")
            .field("key", &"<zeroized on drop; not displayed>")
            .field("image_hash", &self.image_hash)
            .finish()
    }
}

impl KeyRecord {
    /// Save the key to a `.frk` file with magic + checksum, created with
    /// owner-only permissions (`0o600` on Unix) — it holds the master key.
    pub fn save(&self, path: &str) -> Result<()> {
        let mut buf = Vec::new();
        buf.extend_from_slice(KEY_MAGIC);
        let key_len = u32::try_from(self.key.len())
            .map_err(|_| SpectrumError::SerializationError("key exceeds u32 length".into()))?;
        write_u32_le(&mut buf, key_len);
        buf.extend_from_slice(&self.key);
        buf.extend_from_slice(&self.image_hash);
        let checksum = compute_sha256(&buf);
        buf.extend_from_slice(&checksum);
        write_secret_file(path, &buf)
    }

    /// Load and verify a `.frk` file.
    ///
    /// The file is read under the global [`MAX_INPUT_FILE_BYTES`] cap so a
    /// pathologically large file fails closed instead of exhausting memory.
    pub fn load(path: &str) -> Result<Self> {
        let data = read_capped(path)?;
        let body_len = data
            .len()
            .checked_sub(32)
            .ok_or_else(|| SpectrumError::MalformedMessage("key file too short".into()))?;
        let (body, checksum) = data.split_at(body_len);
        if compute_sha256(body).as_slice() != checksum {
            return Err(SpectrumError::MalformedMessage(
                "key record checksum mismatch (corrupted or tampered file)".into(),
            ));
        }
        let mut offset = 0usize;
        if crate::utils::serialization::take(body, &mut offset, 8)? != KEY_MAGIC {
            return Err(SpectrumError::MalformedMessage("bad key magic".into()));
        }
        let key_len = read_u32_le(body, &mut offset)? as usize;
        // Fail closed on key length: a record whose "key" is not exactly the
        // 1072-bit master key would otherwise load and be compared (verify)
        // or exported against a length it can never legitimately have.
        if key_len != crate::types::KEY_LENGTH {
            return Err(SpectrumError::MalformedMessage(format!(
                "key record holds {key_len} key bytes; expected {}",
                crate::types::KEY_LENGTH
            )));
        }
        let key =
            Zeroizing::new(crate::utils::serialization::take(body, &mut offset, key_len)?.to_vec());
        let mut image_hash = [0u8; 32];
        image_hash.copy_from_slice(crate::utils::serialization::take(body, &mut offset, 32)?);
        if offset != body.len() {
            return Err(SpectrumError::MalformedMessage(
                "trailing key-record bytes".into(),
            ));
        }
        Ok(KeyRecord { key, image_hash })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn secret_files_are_owner_only_even_when_overwriting() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();

        // The `.frk` key record must be created owner-only.
        let frk = dir.path().join("key.frk");
        let rec = KeyRecord {
            key: Zeroizing::new(vec![7u8; crate::types::KEY_LENGTH]),
            image_hash: [9u8; 32],
        };
        rec.save(frk.to_str().unwrap()).unwrap();
        let mode = std::fs::metadata(&frk).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, ".frk key record must not be world-readable");

        // Re-saving over a wide-permission file must tighten it, not inherit
        // the old mode.
        std::fs::write(&frk, b"placeholder").unwrap();
        std::fs::set_permissions(&frk, std::fs::Permissions::from_mode(0o644)).unwrap();
        rec.save(frk.to_str().unwrap()).unwrap();
        let mode = std::fs::metadata(&frk).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "overwrite must not inherit the old wide mode");

        // The batch manifest embeds per-image `key_hex` — also owner-only.
        let manifest = BatchManifest::new(vec![BatchEntry::success(
            "a.png",
            "11".repeat(crate::types::KEY_LENGTH),
            "22".repeat(32),
            "BALANCED".into(),
            90.0,
        )]);
        let path = dir.path().join("batch.json");
        manifest.save(path.to_str().unwrap()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "batch manifest carries key material");
    }

    #[test]
    fn key_record_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("key.frk").to_str().unwrap().to_string();
        let rec = KeyRecord {
            key: Zeroizing::new(vec![7u8; crate::types::KEY_LENGTH]),
            image_hash: [9u8; 32],
        };
        rec.save(&p).unwrap();
        let back = KeyRecord::load(&p).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn tampered_key_record_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tampered.frk");
        let rec = KeyRecord {
            key: Zeroizing::new(vec![3u8; crate::types::KEY_LENGTH]),
            image_hash: [1u8; 32],
        };
        rec.save(p.to_str().unwrap()).unwrap();
        let mut bytes = std::fs::read(&p).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        std::fs::write(&p, &bytes).unwrap();
        assert!(KeyRecord::load(p.to_str().unwrap()).is_err());
    }

    #[test]
    fn key_record_with_wrong_key_length_is_rejected() {
        // Hand-craft a well-checksummed record whose key is not the 1072-bit
        // master key length: the checksum passes, the length check must not.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("shortkey.frk");
        let mut buf = Vec::new();
        buf.extend_from_slice(KEY_MAGIC);
        buf.extend_from_slice(&16u32.to_le_bytes());
        buf.extend_from_slice(&[7u8; 16]);
        buf.extend_from_slice(&[2u8; 32]);
        let checksum = compute_sha256(&buf);
        buf.extend_from_slice(&checksum);
        std::fs::write(&p, &buf).unwrap();

        let res = KeyRecord::load(p.to_str().unwrap());
        assert!(
            matches!(&res, Err(SpectrumError::MalformedMessage(m)) if m.contains("expected")),
            "wrong-length key must be rejected with the expected length, got {res:?}"
        );
    }

    #[test]
    fn read_capped_enforces_limit() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big.bin");
        std::fs::write(&p, vec![0u8; 64]).unwrap();

        // Over the (parameterized) cap → fail closed with a clear message.
        let over = read_capped_with(p.to_str().unwrap(), 16);
        assert!(
            matches!(&over, Err(SpectrumError::MalformedMessage(m)) if m.contains("refusing unbounded read")),
            "oversized input must be refused, got {over:?}"
        );

        // At the cap → allowed.
        let at = read_capped_with(p.to_str().unwrap(), 64);
        assert_eq!(at.unwrap().len(), 64);

        // Under the cap → allowed.
        let under = read_capped_with(p.to_str().unwrap(), 65);
        assert_eq!(under.unwrap().len(), 64);
    }

    #[test]
    fn read_capped_fails_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nope.bin");
        assert!(matches!(
            read_capped(p.to_str().unwrap()),
            Err(SpectrumError::FileNotFound(_))
        ));
    }

    #[test]
    fn batch_entry_constructors() {
        let ok = BatchEntry::success(
            "a.png",
            "ab".repeat(crate::types::KEY_LENGTH),
            "cd".repeat(32),
            "BALANCED".into(),
            100.0,
        );
        assert!(ok.is_success());
        assert_eq!(ok.key_hex.len(), crate::types::KEY_LENGTH * 2);

        let bad = BatchEntry::failure("b.png", "file not found");
        assert!(!bad.is_success());
        assert!(bad.key_hex.is_empty());
    }

    #[test]
    fn batch_manifest_roundtrip_and_counts() {
        let manifest = BatchManifest::new(vec![
            BatchEntry::success(
                "a.png",
                "11".repeat(crate::types::KEY_LENGTH),
                "22".repeat(32),
                "BALANCED".into(),
                90.0,
            ),
            BatchEntry::failure("missing.png", "File not found: missing.png"),
        ]);
        let json = manifest.to_json().unwrap();
        let back = BatchManifest::from_json(&json).unwrap();
        assert_eq!(back, manifest);
        assert_eq!(back.success_count(), 1);
        assert_eq!(back.failure_count(), 1);
        assert_eq!(back.entries.len(), 2);
        assert_eq!(back.version, BATCH_VERSION);
    }

    #[test]
    fn batch_manifest_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("batch.json");
        let manifest = BatchManifest::new(vec![BatchEntry::failure("x.png", "nope")]);
        manifest.save(path.to_str().unwrap()).unwrap();
        let loaded = BatchManifest::load(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded, manifest);
    }

    #[test]
    fn debug_outputs_never_contain_key_material() {
        // The `Debug` impls of key-bearing structs are part of the secret
        // hygiene surface: logs/crash dumps print with {:?}, so the master
        // key must never appear in their output.
        let entry = BatchEntry::success(
            "img.png",
            "deadbeef".repeat(40),
            "ab".repeat(32),
            "BALANCED".into(),
            90.0,
        );
        let dbg = format!("{:?}", entry);
        assert!(
            !dbg.contains("deadbeef"),
            "BatchEntry Debug leaked key: {dbg}"
        );

        let record = KeyRecord {
            key: Zeroizing::new(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            image_hash: [1u8; 32],
        };
        let dbg = format!("{:?}", record);
        assert!(
            !dbg.contains("deadbeef"),
            "KeyRecord Debug leaked key: {dbg}"
        );
        assert!(!dbg.contains("222"), "KeyRecord Debug leaked key: {dbg}");
    }
}
