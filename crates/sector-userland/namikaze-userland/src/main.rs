// SPDX-License-Identifier: MPL-2.0
#![forbid(unsafe_code)]
//! Multi-call entry point.
//!
//! The binary dispatches on `argv[0]` (the symlinked tool name, busybox
//! style) or, when invoked as `namikaze-userland`, on the first argument.
//! Any panic escaping a tool is contained here and becomes exit status 70
//! instead of an abort, so a failing tool never takes down its caller.

use std::panic::AssertUnwindSafe;
use std::process::ExitCode;

use namikaze_userland::{registry, EXIT_PANIC, EXIT_USAGE};

fn dispatch(name: &str, args: &[String]) -> i32 {
    match registry::lookup(name) {
        Some(tool) => tool(args),
        None => namikaze_userland::fail(name, "no such tool"),
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();

    let argv0 = namikaze_userland::basename_of(
        argv.first().map(String::as_str).unwrap_or("namikaze-userland"),
    );
    let (name, rest): (&str, &[String]) = if registry::lookup(argv0).is_some() {
        (argv0, &argv[1..])
    } else if argv.len() > 1 && registry::lookup(&argv[1]).is_some() {
        (&argv[1], &argv[2..])
    } else {
        eprintln!("usage: namikaze-userland TOOL [ARG...]");
        eprintln!("       (or invoke via a symlinked tool name: ls, cat, cp, ...)");
        eprintln!("tools: {}", registry::names().join(" "));
        return ExitCode::from(EXIT_USAGE as u8);
    };

    let code = std::panic::catch_unwind(AssertUnwindSafe(|| dispatch(name, rest))).unwrap_or_else(
        |_| {
            eprintln!("namikaze-userland: {name}: internal panic contained, exiting");
            EXIT_PANIC
        },
    );
    ExitCode::from(code as u8)
}
