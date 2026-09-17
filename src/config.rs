//! Configuration structs with sensible defaults.
//!
//! [`SpectrumConfig`] bundles every knob into one serializable, loadable document so
//! a deployment can persist its exact settings and reproduce keys/messages.

use serde::{Deserialize, Serialize};

use crate::entropy_engine::sources::chaos::ChaosConfig;
use crate::entropy_engine::sources::coupled_map_lattice::CoupledMapLatticeConfig;
use crate::entropy_engine::sources::fractal_analysis::FractalAwareConfig;
use crate::entropy_engine::sources::quantum_density::QuantumDensityConfig;
use crate::entropy_engine::sources::texture::{DEFAULT_FREQUENCIES, DEFAULT_ORIENTATIONS};
use crate::error::{Result, SpectrumError};
use crate::image::loader::ImageFormat;
use crate::types::DEFAULT_CANONICAL_SIZE;

/// Tune the 11-source entropy engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntropyEngineConfig {
    pub wtmm_enabled: bool,
    pub wtmm_min_scale: u32,
    pub wtmm_max_scale: u32,
    pub wtmm_num_scales: u32,

    pub lacunarity_enabled: bool,
    pub lacunarity_scales: Vec<u32>,

    pub multifractal_enabled: bool,
    pub multifractal_q_values: Vec<f64>,

    pub hurst_enabled: bool,

    pub gradient_enabled: bool,
    pub gradient_bins: usize,

    pub texture_enabled: bool,
    pub texture_orientations_deg: Vec<f64>,
    pub texture_frequencies: Vec<f64>,

    pub noise_enabled: bool,

    pub chaos_enabled: bool,
    pub chaos_config: ChaosConfig,

    pub quantum_density_enabled: bool,
    pub quantum_density_config: QuantumDensityConfig,

    pub coupled_map_lattice_enabled: bool,
    pub coupled_map_lattice_config: CoupledMapLatticeConfig,

    pub fractal_aware_enabled: bool,
    pub fractal_aware_config: FractalAwareConfig,
}

impl Default for EntropyEngineConfig {
    fn default() -> Self {
        EntropyEngineConfig {
            wtmm_enabled: true,
            wtmm_min_scale: 1,
            wtmm_max_scale: 256,
            // Cap of 128 = the largest step count the adaptive detector can
            // select, so the shipped default never clips it.
            wtmm_num_scales: 128,
            lacunarity_enabled: true,
            // Full scale universe: the adaptive detector may pick any scale,
            // so the shipped default must not filter any of them out.
            lacunarity_scales: vec![2, 4, 8, 16, 32, 64, 128, 256],
            // (4..256 step-2 universe would be exhaustive; the adaptive bands
            // use only powers of two, all present here.)
            multifractal_enabled: true,
            multifractal_q_values: vec![-2.0, -1.5, -1.0, -0.5, 0.0, 0.5, 1.0, 1.5, 2.0],
            hurst_enabled: true,
            gradient_enabled: true,
            gradient_bins: 256,
            texture_enabled: true,
            texture_orientations_deg: DEFAULT_ORIENTATIONS.to_vec(),
            texture_frequencies: DEFAULT_FREQUENCIES.to_vec(),
            noise_enabled: true,
            chaos_enabled: true,
            chaos_config: ChaosConfig::default(),
            quantum_density_enabled: true,
            quantum_density_config: QuantumDensityConfig::default(),
            coupled_map_lattice_enabled: true,
            coupled_map_lattice_config: CoupledMapLatticeConfig::default(),
            fractal_aware_enabled: true,
            fractal_aware_config: FractalAwareConfig::default(),
        }
    }
}

/// Tune image preprocessing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImagePreprocessorConfig {
    pub canonical_size: (u32, u32),
    pub min_size: (u32, u32),
    pub max_size: (u32, u32),
    pub remove_metadata: bool,
    pub jpeg_quality_threshold: u8,
    pub supported_formats: Vec<ImageFormat>,
}

impl Default for ImagePreprocessorConfig {
    fn default() -> Self {
        ImagePreprocessorConfig {
            canonical_size: DEFAULT_CANONICAL_SIZE,
            min_size: (128, 128),
            max_size: (4096, 4096),
            remove_metadata: true,
            jpeg_quality_threshold: 90,
            supported_formats: vec![
                ImageFormat::PNG,
                ImageFormat::JPEG(95),
                ImageFormat::BMP,
                ImageFormat::TIFF,
                ImageFormat::GIF,
            ],
        }
    }
}

/// Symmetric encryption configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymmetricConfig {
    /// AES-GCM nonce length in bytes.
    pub nonce_len: usize,
}

impl Default for SymmetricConfig {
    fn default() -> Self {
        SymmetricConfig { nonce_len: 12 }
    }
}

/// The bundled top-level configuration document.
///
/// Combination of all configuration sections into a single object
/// that can be saved to / loaded from JSON (`save` / `load`) so deployments
/// reproduce exactly the same derivation and message formats.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpectrumConfig {
    pub entropy: EntropyEngineConfig,
    pub preprocessor: ImagePreprocessorConfig,
    pub symmetric: SymmetricConfig,
    /// Format version marker for forward compatibility.
    pub version: u32,
}

impl Default for SpectrumConfig {
    fn default() -> Self {
        SpectrumConfig {
            entropy: EntropyEngineConfig::default(),
            preprocessor: ImagePreprocessorConfig::default(),
            symmetric: SymmetricConfig::default(),
            version: 1,
        }
    }
}

impl SpectrumConfig {
    /// Serialize to a pretty JSON string.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| SpectrumError::SerializationError(e.to_string()))
    }

    /// Parse a JSON string into a config, rejecting unknown/versioned docs.
    ///
    /// Fail-closed on three fronts: a document whose `version` differs from
    /// the supported one is refused (a future format could rename or
    /// repurpose any knob), unknown fields at *any* nesting level are an
    /// error (serde's default of ignoring them would load a config with
    /// silently dropped settings), and the resulting document must pass the
    /// crate-internal `Self::validate` check.
    pub fn from_json(json: &str) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| SpectrumError::SerializationError(e.to_string()))?;
        reject_unknown_fields(&value, &[])?;
        let cfg: SpectrumConfig = serde_json::from_value(value)
            .map_err(|e| SpectrumError::SerializationError(e.to_string()))?;
        if cfg.version != 1 {
            return Err(SpectrumError::InvalidConfiguration(format!(
                "unsupported config version {} (this build supports version 1)",
                cfg.version
            )));
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Fail-closed validation of knobs that must match what the
    /// implementation actually does, so a written-but-ignored setting can
    /// never produce divergent behaviour between writer and reader.
    pub(crate) fn validate(&self) -> Result<()> {
        // The symmetric layer is specified for the 96-bit GCM nonce; any
        // other value used to be silently ignored by `encrypt`.
        if self.symmetric.nonce_len != 12 {
            return Err(SpectrumError::InvalidConfiguration(format!(
                "symmetric.nonce_len must be 12 (96-bit AES-GCM nonce), got {}",
                self.symmetric.nonce_len
            )));
        }
        Ok(())
    }

    /// Load a config from a JSON file on disk.
    ///
    /// The file is read under the global [`crate::data::MAX_INPUT_FILE_BYTES`]
    /// cap so a pathologically large file fails closed instead of exhausting
    /// memory (this path is reachable straight from the CLI via `--config`).
    pub fn load(path: &str) -> Result<Self> {
        let raw = String::from_utf8(crate::data::read_capped(path)?)?;
        Self::from_json(&raw)
    }

    /// Save the config as pretty JSON to a file.
    pub fn save(&self, path: &str) -> Result<()> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

/// Recursively verify that every object key in `value` is a field the
/// config structs actually declare. Serde's default is to *ignore* unknown
/// keys, which would silently load a config missing the intended setting —
/// the exact failure mode fail-closed config parsing exists to prevent.
fn reject_unknown_fields(value: &serde_json::Value, path: &[&str]) -> Result<()> {
    const TOP: &[&str] = &["entropy", "preprocessor", "symmetric", "version"];
    const ENTROPY: &[&str] = &[
        "wtmm_enabled",
        "wtmm_min_scale",
        "wtmm_max_scale",
        "wtmm_num_scales",
        "lacunarity_enabled",
        "lacunarity_scales",
        "multifractal_enabled",
        "multifractal_q_values",
        "hurst_enabled",
        "gradient_enabled",
        "gradient_bins",
        "texture_enabled",
        "texture_orientations_deg",
        "texture_frequencies",
        "noise_enabled",
        "chaos_enabled",
        "chaos_config",
        "quantum_density_enabled",
        "quantum_density_config",
        "coupled_map_lattice_enabled",
        "coupled_map_lattice_config",
        "fractal_aware_enabled",
        "fractal_aware_config",
    ];
    const PREPROCESSOR: &[&str] = &[
        "canonical_size",
        "min_size",
        "max_size",
        "remove_metadata",
        "jpeg_quality_threshold",
        "supported_formats",
    ];
    const SYMMETRIC: &[&str] = &["nonce_len"];
    const CHAOS: &[&str] = &["iterations", "a", "b"];

    match value {
        serde_json::Value::Object(map) => {
            let known: &[&str] = match path {
                [] => TOP,
                ["entropy"] => ENTROPY,
                ["entropy", "chaos_config"] => CHAOS,
                ["preprocessor"] => PREPROCESSOR,
                ["symmetric"] => SYMMETRIC,
                _ => &[],
            };
            for (key, child) in map {
                if !known.is_empty() && !known.contains(&key.as_str()) {
                    let mut full = path.to_vec();
                    full.push(key);
                    return Err(SpectrumError::InvalidConfiguration(format!(
                        "unknown config field `{}` (typo, or written by a newer version?)",
                        full.join(".")
                    )));
                }
                let mut child_path: Vec<&str> = path.to_vec();
                child_path.push(key.as_str());
                reject_unknown_fields(child, &child_path)?;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for item in items {
                reject_unknown_fields(item, path)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_serializable_and_roundtrip() {
        let cfg = SpectrumConfig::default();
        let json = cfg.to_json().unwrap();
        let back = SpectrumConfig::from_json(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn load_and_save_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spectrum.json");
        let cfg = SpectrumConfig::default();
        cfg.save(path.to_str().unwrap()).unwrap();
        let back = SpectrumConfig::load(path.to_str().unwrap()).unwrap();
        assert_eq!(back.entropy.wtmm_num_scales, 128);
    }

    #[test]
    fn load_refuses_oversized_file() {
        // `--config` hands an arbitrary path to this loader, so it must fail
        // closed under the global input cap like every other untrusted input.
        // A sparse file gives an over-cap logical size without touching that
        // many disk blocks, exercising the real shipped cap (128 MiB).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.json");
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(crate::data::MAX_INPUT_FILE_BYTES + 1).unwrap();
        drop(f);

        let err = SpectrumConfig::load(path.to_str().unwrap())
            .expect_err("oversized config must be refused");
        assert!(
            err.to_string().contains("refusing unbounded read"),
            "expected the capped-read failure, got {err}"
        );
    }

    #[test]
    fn toggling_a_source_survives_roundtrip() {
        let mut cfg = SpectrumConfig::default();
        cfg.entropy.noise_enabled = false;
        let back = SpectrumConfig::from_json(&cfg.to_json().unwrap()).unwrap();
        assert!(!back.entropy.noise_enabled);
    }

    #[test]
    fn foreign_config_version_is_rejected() {
        let mut cfg_json: serde_json::Value =
            serde_json::from_str(&SpectrumConfig::default().to_json().unwrap()).unwrap();
        cfg_json["version"] = serde_json::json!(2);
        let mutated = cfg_json.to_string();
        let err = SpectrumConfig::from_json(&mutated).unwrap_err();
        assert!(err.to_string().contains("version"), "got: {err}");
    }

    #[test]
    fn unknown_config_fields_are_rejected() {
        let json = r#"{
            "entropy": {},
            "preprocessor": {},
            "symmetric": { "nonce_len": 12 },
            "version": 1,
            "future_knob": true
        }"#;
        assert!(SpectrumConfig::from_json(json).is_err());
    }

    #[test]
    fn unknown_field_is_rejected_even_with_valid_document() {
        // Discriminating case: every required field present and valid, plus
        // one unknown knob. The doc contract says this must be refused —
        // silently dropping it would load a config missing the intended
        // setting (the exact failure mode this validation exists for).
        let cfg = SpectrumConfig::default();
        let mut json = serde_json::to_value(&cfg).unwrap();
        json["a_typo_or_future_knob"] = serde_json::json!(true);
        let json = serde_json::to_string(&json).unwrap();
        assert!(
            SpectrumConfig::from_json(&json).is_err(),
            "unknown fields must be rejected, not silently dropped"
        );
    }

    #[test]
    fn unsupported_nonce_len_is_rejected() {
        // nonce_len used to be stored but ignored by the symmetric layer;
        // now the config loader refuses anything but the implemented 12.
        let mut cfg = SpectrumConfig::default();
        cfg.symmetric.nonce_len = 16;
        let err = SpectrumConfig::from_json(&cfg.to_json().unwrap()).unwrap_err();
        assert!(err.to_string().contains("nonce_len"), "got: {err}");
    }
}
