// SPDX-License-Identifier: MPL-2.0
//! Shared foundation for all NamikazeOS crates.
//!
//! Provides the error type, canonical filesystem paths, the secret registry,
//! logging bootstrap and small filesystem helpers. This crate is the single
//! place where global mutable state is allowed (the secret registry).
//! Built on `namikaze-rt`; the workspace carries zero third-party crates.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use namikaze_rt::fsutil::{zero, ZeroBuf};

/// Canonical result alias used across NamikazeOS.
pub type Result<T> = std::result::Result<T, Error>;

/// The workspace-wide error type (hand-rolled; no derive macros).
#[derive(Debug)]
pub enum Error {
    /// I/O failure.
    Io(std::io::Error),
    /// Configuration rejected (schema, validation, parse).
    Config(String),
    /// Cryptographic failure or malformed protected data.
    Crypto(String),
    /// Everything else, with context.
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Config(m) => write!(f, "configuration error: {m}"),
            Error::Crypto(m) => write!(f, "crypto error: {m}"),
            Error::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<namikaze_rt::Error> for Error {
    fn from(e: namikaze_rt::Error) -> Self {
        match e {
            namikaze_rt::Error::Io(io) => Error::Io(io),
            namikaze_rt::Error::Parse(m) => Error::Config(m),
            namikaze_rt::Error::Invalid(m) => Error::Other(m),
        }
    }
}

/// Canonical configuration directory: /etc/namikaze
pub const ETC_DIR: &str = "/etc/namikaze";
/// Canonical state directory: /var/lib/namikaze
pub const VAR_DIR: &str = "/var/lib/namikaze";
/// Canonical runtime directory: /run/namikaze
pub const RUN_DIR: &str = "/run/namikaze";
/// Workspace version, taken from the crate manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the leveled logger (NK_LOG / RUST_LOG override the default).
pub fn init_tracing(default_level: &str) {
    namikaze_rt::log::init(default_level);
}

static SECRETS: Mutex<Vec<ZeroBuf>> = Mutex::new(Vec::new());

/// Register a copy of secret bytes so `namikaze-wipe` can zero them later.
pub fn register_secret(bytes: &[u8]) {
    if let Ok(mut guard) = SECRETS.lock() {
        guard.push(ZeroBuf::new(bytes.to_vec()));
    }
}

/// Zero every registered secret buffer. Used by namikaze-wipe on teardown.
pub fn zeroize_registered() -> usize {
    match SECRETS.lock() {
        Ok(mut guard) => {
            let n = guard.len();
            for buf in guard.iter_mut() {
                zero(&mut buf.0);
            }
            guard.clear();
            n
        }
        Err(_) => 0,
    }
}

/// Resolve a path under /etc/namikaze.
pub fn etc_path(rel: &str) -> PathBuf {
    Path::new(ETC_DIR).join(rel)
}

/// Resolve a path under /var/lib/namikaze.
pub fn var_path(rel: &str) -> PathBuf {
    Path::new(VAR_DIR).join(rel)
}

/// Write a file with parent directory creation and 0600 permissions.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Append a line to a log file, creating parent directories as needed.
pub fn append_log(path: &Path, line: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::OpenOptions::new().create(true).append(true).open(path)?;
    {
        use std::io::Write;
        writeln!(f, "{line}")?;
    }
    Ok(())
}

/// Read the first line of a file (trailing newline stripped).
pub fn read_first_line(path: &Path) -> Result<String> {
    let raw = fs::read_to_string(path)?;
    Ok(raw.lines().next().unwrap_or_default().trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_registry_roundtrip() {
        register_secret(b"alpha");
        register_secret(b"beta");
        assert_eq!(zeroize_registered(), 2);
        assert_eq!(zeroize_registered(), 0);
    }

    #[test]
    fn error_display() {
        assert_eq!(Error::Crypto("bad".into()).to_string(), "crypto error: bad");
        assert_eq!(Error::Config("x".into()).to_string(), "configuration error: x");
    }
}
