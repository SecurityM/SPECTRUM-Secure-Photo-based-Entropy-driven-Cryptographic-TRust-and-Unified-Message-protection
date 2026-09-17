//! SPECTRUM command-line interface (thin binary).
//!
//! Commands:
//!   derive   — deterministically derive the 1072-bit key of an image
//!   encrypt  — encrypt a message bound to an image, write a `.spx` file
//!   decrypt  — decrypt a `.spx` file using the exact key image
//!   analyze  — dump the entropy profile of an image (--report writes JSON)
//!   batch    — derive keys for every image in a directory / file list
//!   verify   — check a `.frk` key record against its key image
//!   selftest — run the built-in correctness battery
//!   config   — print a default JSON config (or load one for other commands)
//!   export   — derive an image's key and save it to a secret `.frk` file
//!
//! Key derivation is strictly deterministic over the exact file bytes: the
//! same image always yields the same key and any other image yields an
//! unrelated key. Nothing is persisted for `derive`, and `encrypt`/`decrypt`
//! need only the exact same image file — no records.
//!
//! A global `--config <path>` loads settings for **every** command (the same
//! instance backs derive, encrypt, decrypt, analyze, batch, verify and
//! export). This matters for message workflows: encryption and decryption
//! must run under the *same* effective configuration — a message encrypted
//! with a custom config only decrypts with that same config (or an identical
//! one), and a mismatch fails with a key-image verification error that does
//! not name the config as the cause.
//! All command logic lives in the library (`spectrum::cli`) so it is testable.

#![forbid(unsafe_code)]

use std::fs;
use std::process::exit;

use clap::{Parser, Subcommand};

use spectrum::cli;
use spectrum::config::SpectrumConfig;
use spectrum::message::SpectrumMessage;
use spectrum::utils::logging::init_logging;
use spectrum::SpectrumCrypto;

#[derive(Parser)]
#[command(
    name = "spectrum",
    version,
    about = "SPECTRUM: Secure Photo-Based Entropy-Driven Cryptographic Trust and Unified Message Protection"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to a `.json` config file; overrides built-in defaults for every
    /// command. Encrypt and decrypt must be given the SAME config for a
    /// custom-config message pair.
    #[arg(global = true, short = 'C', long)]
    config: Option<String>,

    #[arg(global = true, short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Deterministically derive the 1072-bit key of an image (hex).
    Derive {
        #[arg(short, long)]
        image: String,

        #[arg(short, long)]
        detailed: bool,
    },

    /// Encrypt a message using a key image.
    Encrypt {
        #[arg(short, long)]
        key_image: String,

        /// Plaintext to encrypt. NOTE: command-line arguments are visible to
        /// every process on the system (ps, /proc, shell history); prefer
        /// --input-file for anything sensitive.
        #[arg(short, long)]
        message: Option<String>,

        /// Read the plaintext from this file (safer than --message, which
        /// exposes the plaintext in the process list).
        #[arg(short, long)]
        input_file: Option<String>,

        #[arg(short, long)]
        output: String,

        /// Recipient's NTRU-Prime public key file (hybrid two-factor mode;
        /// requires the `pq` feature and `pq-keygen`-produced keys).
        #[arg(long)]
        pq_pubkey: Option<String>,
    },

    /// Decrypt a message using the exact key image it was encrypted under.
    Decrypt {
        #[arg(short, long)]
        key_image: String,

        #[arg(short, long)]
        input: String,

        /// Recipient's NTRU-Prime secret key file (required for hybrid
        /// messages; requires the `pq` feature).
        #[arg(long)]
        pq_secretkey: Option<String>,
    },

    /// Generate a post-quantum NTRU-Prime keypair (requires the `pq` feature).
    PqKeygen {
        /// Output file for the public key (raw bytes).
        #[arg(short, long)]
        public: String,

        /// Output file for the secret key (raw bytes, 0600 on Unix).
        #[arg(short, long)]
        secret: String,
    },

    /// Analyze the entropy profile of an image.
    Analyze {
        #[arg(short, long)]
        image: String,

        #[arg(short, long)]
        detailed: bool,

        /// Write a structured JSON analysis report to this path.
        #[arg(long)]
        report: Option<String>,
    },

    /// Derive keys for many images at once.
    Batch {
        /// Directory whose images are processed (sorted order).
        #[arg(short, long)]
        input_dir: Option<String>,

        /// Explicit image files (overrides --input-dir).
        #[arg(short, long, num_args = 1..)]
        files: Vec<String>,

        /// Write the JSON batch manifest to this path.
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Verify a `.frk` key record against its key image.
    Verify {
        /// `.frk` record produced by `export`.
        #[arg(short, long)]
        key_file: String,

        /// Key image to re-derive the exported key from.
        #[arg(short, long)]
        image: String,
    },

    /// Run the built-in correctness battery.
    Selftest {
        /// Include checks that touch the filesystem (temp files).
        #[arg(long)]
        with_fs: bool,
    },

    /// Print a default JSON config (with -o, write it to a file).
    Config {
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Export an image's derived key to a secret, checksummed `.frk` file.
    Export {
        #[arg(short, long)]
        image: String,

        #[arg(short, long)]
        output: String,
    },
}

fn main() {
    let cli_args = Cli::parse();
    init_logging(cli_args.verbose);

    // Friendly pre-flight errors for the most common user mistakes: a typo'd
    // path should say so before any processing starts.
    for (flag, path) in [
        ("--config", cli_args.config.as_deref()),
        (
            "--key-image",
            command_key_image(&cli_args.command).as_deref(),
        ),
        ("--input", command_input_file(&cli_args.command).as_deref()),
    ] {
        if let Some(p) = path {
            if !spectrum::cli::file_exists(p) {
                eprintln!("Error: file not found: {p} ({flag})");
                exit(1);
            }
        }
    }

    // Load an explicit config if supplied (-C/--config) for the data commands.
    let spectrum = match &cli_args.config {
        Some(path) => {
            match SpectrumConfig::load(path).and_then(|cfg| SpectrumCrypto::with_config(&cfg)) {
                Ok(spectrum) => spectrum,
                Err(e) => {
                    eprintln!("Error: failed to load config {path}: {e}");
                    exit(1);
                }
            }
        }
        None => SpectrumCrypto::new(),
    };

    let result = match cli_args.command {
        Commands::Derive { image, detailed } => cli::cmd_derive(&spectrum, &image, detailed),
        Commands::Encrypt {
            key_image,
            message,
            input_file,
            output,
            pq_pubkey,
        } => cmd_encrypt(
            &spectrum,
            &key_image,
            message,
            input_file,
            &output,
            pq_pubkey.as_deref(),
        ),
        Commands::Decrypt {
            key_image,
            input,
            pq_secretkey,
        } => cmd_decrypt(&spectrum, &key_image, &input, pq_secretkey.as_deref()),
        Commands::PqKeygen { public, secret } => cmd_pq_keygen(&public, &secret),
        Commands::Analyze {
            image,
            detailed,
            report,
        } => cli::cmd_analyze(&spectrum, &image, detailed, report.as_deref()),
        Commands::Batch {
            input_dir,
            files,
            output,
        } => {
            let dir = input_dir.unwrap_or_else(|| ".".to_string());
            cli::cmd_batch(&spectrum, &dir, &files, output.as_deref()).map(|_| ())
        }
        Commands::Verify { key_file, image } => {
            cli::cmd_verify(&spectrum, &key_file, &image).map(|ok| {
                if !ok {
                    exit(2)
                }
            })
        }
        Commands::Selftest { with_fs } => cli::cmd_selftest(with_fs),
        Commands::Config { output } => cli::cmd_config(output.as_deref()),
        Commands::Export { image, output } => cli::cmd_export(&spectrum, &image, &output),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        exit(1);
    }
}

/// The image path a command will read, for pre-flight existence checks.
fn command_key_image(cmd: &Commands) -> Option<String> {
    match cmd {
        Commands::Derive { image, .. }
        | Commands::Analyze { image, .. }
        | Commands::Export { image, .. }
        | Commands::Verify { image, .. }
        | Commands::Encrypt {
            key_image: image, ..
        }
        | Commands::Decrypt {
            key_image: image, ..
        } => Some(image.clone()),
        _ => None,
    }
}

/// The message file a command will read, for pre-flight existence checks.
fn command_input_file(cmd: &Commands) -> Option<String> {
    match cmd {
        Commands::Decrypt { input, .. } => Some(input.clone()),
        Commands::Encrypt { input_file, .. } => input_file.clone(),
        _ => None,
    }
}

fn cmd_encrypt(
    spectrum: &SpectrumCrypto,
    key_image: &str,
    message: Option<String>,
    input_file: Option<String>,
    output: &str,
    pq_pubkey: Option<&str>,
) -> Result<(), spectrum::error::SpectrumError> {
    let plaintext = match (message, input_file) {
        (Some(m), None) => m,
        // Capped: a pathologically large file fails closed before entering
        // the encryption pipeline, mirroring the image-input limit.
        (None, Some(f)) => String::from_utf8(spectrum::data::read_capped(&f)?).map_err(|_| {
            eprintln!("Error: --input-file must contain UTF-8 text (got binary data)");
            spectrum::error::SpectrumError::Utf8Error
        })?,
        _ => {
            eprintln!("Error: provide either --message or --input-file");
            exit(1);
        }
    };

    let msg = match pq_pubkey {
        Some(pk_path) => {
            let pk = spectrum::data::read_capped(pk_path)?;
            spectrum.encrypt_message_hybrid(&plaintext, key_image, &pk)?
        }
        None => spectrum.encrypt_message_safe(&plaintext, key_image)?,
    };
    let serialized = msg.serialize()?;
    fs::write(output, &serialized)?;

    println!("Message encrypted successfully.");
    if pq_pubkey.is_some() {
        println!("Mode: hybrid two-factor (NTRU-Prime + image key)");
        println!(
            "Decrypting requires BOTH the exact key image ({key_image}) AND the recipient's NTRU-Prime secret key."
        );
    } else {
        println!(
            "Keep the exact key image ({key_image}) to decrypt — the key is deterministic, no record is needed."
        );
    }
    println!("Output: {output}");
    println!("Size: {} bytes", serialized.len());
    Ok(())
}

fn cmd_decrypt(
    spectrum: &SpectrumCrypto,
    key_image: &str,
    input: &str,
    pq_secretkey: Option<&str>,
) -> Result<(), spectrum::error::SpectrumError> {
    // Capped like every other untrusted input path: a hostile "message" file
    // fails closed instead of exhausting memory before deserialization.
    let serialized = spectrum::data::read_capped(input)?;
    let msg = SpectrumMessage::deserialize(&serialized)?;
    let plaintext = match pq_secretkey {
        Some(sk_path) => {
            let sk = spectrum::data::read_capped(sk_path)?;
            spectrum.decrypt_message_hybrid(&msg, key_image, &sk)?
        }
        None => spectrum.decrypt_message_safe(&msg, key_image)?,
    };
    println!("{plaintext}");
    Ok(())
}

/// `spectrum pq-keygen` — generate an NTRU-Prime (sntrup761) keypair and
/// write the raw public/secret bytes to two files. The secret file is
/// written with owner-only permissions via the same helper as `.frk` records
/// when the `pq` feature is enabled.
#[cfg(feature = "pq")]
fn cmd_pq_keygen(
    public_path: &str,
    secret_path: &str,
) -> Result<(), spectrum::error::SpectrumError> {
    let (pk, sk) = spectrum::crypto::ntru_prime::ntru_generate_keypair()?;
    // Owner-only before content, via the same helper as `.frk` records.
    spectrum::data::write_secret_file(secret_path, &sk)?;
    fs::write(public_path, &pk)?;
    println!("NTRU-Prime keypair generated.");
    println!("Public key: {public_path} ({} bytes)", pk.len());
    println!("Secret key: {secret_path} ({} bytes)", sk.len());
    Ok(())
}

/// Without the `pq` feature the command exists but always fails cleanly.
#[cfg(not(feature = "pq"))]
fn cmd_pq_keygen(
    _public_path: &str,
    _secret_path: &str,
) -> Result<(), spectrum::error::SpectrumError> {
    Err(spectrum::error::SpectrumError::PqLayerUnavailable)
}
