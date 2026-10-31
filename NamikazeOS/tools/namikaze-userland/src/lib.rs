// SPDX-License-Identifier: MPL-2.0
#![forbid(unsafe_code)]
//! namikaze-userland: the NamikazeOS core userland.
//!
//! One multi-call binary provides the standard tool names (`ls`, `cat`,
//! `cp`, ...). The set is modeled on the scope of Chimera Linux's
//! chimerautils (a C codebase used here as a scope reference only); every
//! line of this implementation is original, MPL-2.0, memory-safe Rust.
//!
//! Hardening rules for every tool:
//!   - `#![forbid(unsafe_code)]` crate-wide
//!   - no panics on the runtime path; arguments are validated first
//!   - deterministic output: byte ordering, C locale only, always UTC
//!   - binary-safe I/O via `read_until`/`io::copy`, never line-lossy text
//!   - panics that still escape a tool are contained by the dispatcher,
//!     which exits 70 instead of aborting the caller
//!
//! The tool name list lives in the `TOOLS` file next to this crate and is
//! cross-checked against `registry::TOOLS`, the overlay ebuild and
//! `scripts/mkrootfs.sh` by `scripts/verify_all.py`.

pub mod registry;
pub mod tools;

/// Exit status: success.
pub const EXIT_OK: i32 = 0;
/// Exit status: any runtime failure.
pub const EXIT_FAILURE: i32 = 1;
/// Exit status: bad command line (sysexits EX_USAGE).
pub const EXIT_USAGE: i32 = 64;
/// Exit status: a panic escaped a tool and was contained by the dispatcher.
pub const EXIT_PANIC: i32 = 70;

/// Print a tool-scoped diagnostic to stderr and return EXIT_FAILURE.
pub fn fail(tool: &str, msg: &str) -> i32 {
    eprintln!("namikaze-userland: {tool}: {msg}");
    EXIT_FAILURE
}

/// Print a usage diagnostic to stderr and return EX_USAGE.
pub fn usage(tool: &str, msg: &str) -> i32 {
    eprintln!("namikaze-userland: {tool}: {msg}");
    EXIT_USAGE
}

/// Final path component of a raw path string (no filesystem access).
/// Trailing slashes are ignored; "/" and "" both yield "/".
pub fn basename_of(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/";
    }
    match trimmed.rfind('/') {
        Some(pos) => &trimmed[pos + 1..],
        None => trimmed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_of_basic() {
        assert_eq!(basename_of("a/b/c"), "c");
        assert_eq!(basename_of("/usr/bin/ls"), "ls");
        assert_eq!(basename_of("trailing/"), "trailing");
        assert_eq!(basename_of("/"), "/");
        assert_eq!(basename_of(""), "/");
        assert_eq!(basename_of("plain"), "plain");
    }

    #[test]
    fn fail_and_usage_return_statuses() {
        assert_eq!(fail("cat", "boom"), EXIT_FAILURE);
        assert_eq!(usage("ls", "bad flag"), EXIT_USAGE);
    }
}
