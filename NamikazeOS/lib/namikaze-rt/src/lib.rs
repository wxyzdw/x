// SPDX-License-Identifier: MPL-2.0
//! namikaze-rt: the dependency-free runtime toolkit of NamikazeOS.
//!
//! The workspace has a hard rule: zero third-party crates. Everything a
//! component needs that the standard library does not provide lives here,
//! written from first principles and pinned by public test vectors:
//!
//! - [`sha256`]: FIPS 180-4 hashing (streaming + file digests)
//! - [`mac`]: HMAC-SHA256 and PBKDF2-HMAC-SHA256
//! - [`aead`]: XChaCha20-Poly1305 AEAD (RFC 8439 + draft-irtf XChaCha)
//! - [`json`]: JSON value tree, parser and deterministic writers
//! - [`toml`]: strict TOML subset parser (the configuration surface)
//! - [`hex`], [`b64`]: wire encodings
//! - [`args`]: the tiny command line parser every binary shares
//! - [`log`]: leveled logging with env override
//! - [`walk`], [`tempfile`], [`secure`]: filesystem helpers and secret hygiene
//! - [`prompt`]: terminal prompts (non-secret input)
//! - [`http`]: minimal HTTP/1.1 server for loopback services
//! - [`lz`]: LZ4-block-format compressor/decompressor (our own framing)
//! - [`random`]: kernel entropy via /dev/urandom
//!
//! The crate is `#![forbid(unsafe_code)]`; syscalls that std cannot express
//! belong to `namikaze-ffi`, never here.

#![forbid(unsafe_code)]

pub mod aead;
pub mod args;
pub mod b64;
pub mod fsutil;
pub mod hex;
pub mod hmac;
pub mod http;
pub mod json;
pub mod log;
pub mod lz;
pub mod prompt;
pub mod random;
pub mod sha256;
pub mod toml;

/// Unified error for the runtime toolkit.
#[derive(Debug)]
pub enum Error {
    /// I/O failure from the standard library.
    Io(std::io::Error),
    /// A parser rejected its input.
    Parse(String),
    /// A value is structurally invalid (length, range, encoding).
    Invalid(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Parse(m) => write!(f, "parse error: {m}"),
            Error::Invalid(m) => write!(f, "invalid input: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Canonical result alias for the toolkit.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_is_prefixed() {
        let e = Error::Invalid("x too short".into());
        assert_eq!(e.to_string(), "invalid input: x too short");
    }
}
