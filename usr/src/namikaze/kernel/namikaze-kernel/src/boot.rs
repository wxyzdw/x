// SPDX-License-Identifier: MPL-2.0
//! boot: the `namikaze.*` command-line options the kernel stage reads.

use crate::draw::ArrayString;

/// The options this stage understands. Seals are owned by value, so no
/// reference can outlive its text.
pub struct BootOptions {
    bootid: ArrayString,
    namfs: ArrayString,
    safe_mode: bool,
}

impl BootOptions {
    /// Parse the bootloader command line for the options the splash
    /// shows. Only the seal's characters are kept, truncated to 32.
    pub fn parse(raw: &[u8]) -> Self {
        let mut options =
            Self { bootid: ArrayString::from(""), namfs: ArrayString::from(""), safe_mode: false };
        for token in raw.split(|b| *b == b' ') {
            if let Some(rest) = strip(token, b"namikaze.bootid=") {
                for byte in rest.iter().take(32) {
                    options.bootid.push_ascii(*byte);
                }
            }
            if let Some(rest) = strip(token, b"namikaze.namfs=") {
                for byte in rest.iter().take(32) {
                    options.namfs.push_ascii(*byte);
                }
            }
            if strip(token, b"namikaze.safe=yes").is_some() {
                options.safe_mode = true;
            }
        }
        options
    }

    /// The bootid seal as text, or `None` when the command line had none.
    pub fn ref_str(&self) -> Option<&str> {
        if self.bootid.is_empty() {
            None
        } else {
            Some(self.bootid.as_str())
        }
    }

    /// The NamFS persistent-layer label, or `None` when volatile.
    pub fn namfs_label(&self) -> Option<&str> {
        if self.namfs.is_empty() {
            None
        } else {
            Some(self.namfs.as_str())
        }
    }

    pub fn safe_mode(&self) -> bool {
        self.safe_mode
    }
}

fn strip<'a>(token: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    token.starts_with(prefix).then(|| &token[prefix.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bootid_and_safe_mode() {
        let raw = b"namikaze.live=volatile namikaze.bootid=0123456789abcdef namikaze.safe=yes";
        let boot = BootOptions::parse(raw);
        assert_eq!(boot.ref_str(), Some("0123456789abcdef"));
        assert!(boot.safe_mode());
    }

    #[test]
    fn tolerates_missing_options() {
        let boot = BootOptions::parse(b"quiet loglevel=3");
        assert_eq!(boot.ref_str(), None);
        assert!(!boot.safe_mode());
    }

    #[test]
    fn truncates_overlong_seals() {
        let boot = BootOptions::parse(b"namikaze.bootid=00112233445566778899aabbccddeeff0011");
        assert_eq!(boot.ref_str(), Some("00112233445566778899aabbccddeeff"));
    }
}
