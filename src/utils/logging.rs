//! Simple logging setup.

use std::sync::Once;

static INIT: Once = Once::new();

/// Initialize `env_logger` once. The log level comes from the `RUST_LOG`
/// environment variable, defaulting to `Info`.
pub fn init_logging(verbose: bool) {
    INIT.call_once(|| {
        let level = if verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        };
        env_logger::Builder::new().filter_level(level).init();
    });
}
