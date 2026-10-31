// SPDX-License-Identifier: MPL-2.0
//! Leveled logging without dependencies.
//!
//! Level comes from `NK_LOG` (or the conventional `RUST_LOG`) as one of
//! `error|warn|info|debug|trace`; anything else falls back to the default
//! the binary passes to [`init`]. Output goes to stderr in a stable
//! `LEVEL message` format so OpenRC and the ISO boot log stay parseable.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

impl Level {
    fn parse(s: &str) -> Option<Level> {
        match s.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Level::Error),
            "warn" | "warning" => Some(Level::Warn),
            "info" => Some(Level::Info),
            "debug" => Some(Level::Debug),
            "trace" => Some(Level::Trace),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }
}

static MAX: AtomicU8 = AtomicU8::new(2);
static DEFAULT_LABEL: OnceLock<String> = OnceLock::new();

/// Initialize the global level. `default_level` applies when neither `NK_LOG`
/// nor `RUST_LOG` is set or parseable.
pub fn init(default_level: &str) {
    let _ = DEFAULT_LABEL.set(default_level.to_string());
    let from_env = std::env::var("NK_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .ok()
        .and_then(|s| Level::parse(&s))
        .or_else(|| Level::parse(default_level))
        .unwrap_or(Level::Info);
    MAX.store(from_env as u8, Ordering::Relaxed);
}

fn enabled(level: Level) -> bool {
    (level as u8) <= MAX.load(Ordering::Relaxed)
}

pub fn emit(level: Level, msg: std::fmt::Arguments<'_>) {
    if enabled(level) {
        eprintln!("{} {msg}", level.as_str());
    }
}

/// Log at error level.
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => { $crate::log::emit($crate::log::Level::Error, format_args!($($arg)*)) };
}

/// Log at warn level.
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => { $crate::log::emit($crate::log::Level::Warn, format_args!($($arg)*)) };
}

/// Log at info level.
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => { $crate::log::emit($crate::log::Level::Info, format_args!($($arg)*)) };
}

/// Log at debug level.
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => { $crate::log::emit($crate::log::Level::Debug, format_args!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_parse_and_order() {
        assert_eq!(Level::parse("WARN"), Some(Level::Warn));
        assert_eq!(Level::parse("nope"), None);
        assert!(Level::Error < Level::Trace);
    }

    #[test]
    fn emit_respects_level() {
        MAX.store(1, Ordering::Relaxed);
        // must not panic regardless; output is filtered
        emit(Level::Info, format_args!("hidden"));
        emit(Level::Warn, format_args!("shown"));
    }
}
