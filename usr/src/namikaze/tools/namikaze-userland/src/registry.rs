// SPDX-License-Identifier: MPL-2.0
#![forbid(unsafe_code)]
//! Tool registry: the single mapping from tool name to implementation.
//!
//! The names and their order must match the `TOOLS` file next to this
//! crate; the tools-guard fails the build on any drift.

use crate::tools;

/// Signature every tool entry point exposes.
pub type ToolFn = fn(&[String]) -> i32;

/// The full tool table, alphabetically sorted.
pub const TOOLS: &[(&str, ToolFn)] = &[
    ("basename", tools::fs::basename),
    ("cat", tools::fs::cat),
    ("chmod", tools::fs::chmod),
    ("clear", tools::misc::clear),
    ("cmp", tools::misc::cmp),
    ("comm", tools::misc::comm),
    ("cp", tools::fs::cp),
    ("cut", tools::text::cut),
    ("date", tools::sys::date),
    ("dirname", tools::fs::dirname),
    ("dmesg", tools::procs::dmesg),
    ("echo", tools::fs::echo),
    ("env", tools::sys::env),
    ("expand", tools::text::expand),
    ("false", tools::sys::r#false),
    ("fold", tools::text::fold),
    ("free", tools::procs::free),
    ("head", tools::text::head),
    ("hostname", tools::sys::hostname),
    ("id", tools::sys::id),
    ("kill", tools::procs::kill),
    ("ln", tools::fs::ln),
    ("ls", tools::fs::ls),
    ("mkdir", tools::fs::mkdir),
    ("mktemp", tools::misc::mktemp),
    ("mv", tools::fs::mv),
    ("nproc", tools::sys::nproc),
    ("paste", tools::text::paste),
    ("printenv", tools::sys::printenv),
    ("ps", tools::procs::ps),
    ("pwd", tools::fs::pwd),
    ("readlink", tools::fs::readlink),
    ("rm", tools::fs::rm),
    ("rmdir", tools::fs::rmdir),
    ("seq", tools::text::seq),
    ("sha256sum", tools::misc::sha256sum),
    ("sleep", tools::sys::sleep),
    ("sort", tools::text::sort),
    ("stat", tools::fs::stat),
    ("tail", tools::text::tail),
    ("tee", tools::text::tee),
    ("touch", tools::fs::touch),
    ("tr", tools::text::tr),
    ("true", tools::sys::r#true),
    ("tty", tools::sys::tty),
    ("uname", tools::sys::uname),
    ("uniq", tools::text::uniq),
    ("wc", tools::text::wc),
    ("which", tools::sys::which),
    ("whoami", tools::sys::whoami),
];

/// Resolve a tool name to its entry point.
pub fn lookup(name: &str) -> Option<ToolFn> {
    for (n, f) in TOOLS {
        if *n == name {
            return Some(*f);
        }
    }
    None
}

/// All tool names, in registry order.
pub fn names() -> Vec<&'static str> {
    TOOLS.iter().map(|(n, _)| *n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_roundtrip() {
        assert!(lookup("ls").is_some());
        assert!(lookup("cat").is_some());
        assert!(lookup("no-such-tool").is_none());
    }

    #[test]
    fn registry_is_sorted_and_unique() {
        let mut names = names();
        let sorted = names.clone();
        names.sort_unstable();
        assert_eq!(names, sorted, "registry must stay alphabetically sorted");
        assert_eq!(names.len(), 50, "registry size must match the TOOLS file");
    }
}
