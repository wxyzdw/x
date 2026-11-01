// SPDX-License-Identifier: MPL-2.0
//! namikaze-rc: Plan 9's rc shell, adapted to Rust for NamikazeOS.
//!
//! One quoting mechanism ('...'), lists instead of strings, if/while/for
//! with conditions in parentheses, `~` pattern matching, `` ` ``{...}
//! command substitution, pipelines, redirections (<, >, >>, <>),
//! backgrounding with &, && and ||, globs (* ? [class]) and the
//! builtins cd, pwd, shift, true, false, exit, . and eval.
//!
//! Adapted from the semantics of Plan 9's rc(1) (the shell itself is
//! /sys/src/cmd/rc); everything here is a from-scratch Rust
//! implementation with positioned syntax errors and Plan 9 errno
//! wording for runtime failures.
//!
//! Usage:
//!   namikaze-rc               interactive session
//!   namikaze-rc script.rc     run a script
//!   namikaze-rc -c 'line'     run one command line

#![forbid(unsafe_code)]

mod glob;
mod interp;
mod lex;
mod parse;
mod unparse;

use std::io::{BufRead, Write};

const USAGE: &str = "namikaze-rc: Plan 9's rc shell, adapted to Rust

usage:
  namikaze-rc               interactive session
  namikaze-rc script.rc [args...]
                            run a script; args become $*
  namikaze-rc -c 'line'     run one command line";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        None => interactive(),
        Some("-c") => match args.get(1) {
            Some(line) => run_line(line, &args[2..]),
            None => {
                eprintln!("{USAGE}");
                2
            }
        },
        Some("-h" | "--help") => {
            println!("{USAGE}");
            0
        }
        Some(file) => run_file(file, &args[1..]),
    };
    std::process::exit(code);
}

fn run_line(line: &str, extra: &[String]) -> i32 {
    let node = match parse::parse(line) {
        Ok(node) => node,
        Err(e) => {
            eprintln!("namikaze-rc: {e}");
            return 2;
        }
    };
    let mut it = interp::Interp::new();
    it.script_args = extra.to_vec();
    it.vars.insert("*".into(), extra.to_vec());
    match it.run(&node) {
        Ok(code) => code,
        Err(interp::RunError::Exit(code)) => code,
        Err(e) => {
            eprintln!("namikaze-rc: {e}");
            1
        }
    }
}

fn run_file(path: &str, script_args: &[String]) -> i32 {
    let src = match std::fs::read_to_string(path) {
        Ok(src) => src,
        Err(e) => {
            let what = match e.kind() {
                std::io::ErrorKind::NotFound => format!("{path}: file does not exist"),
                std::io::ErrorKind::PermissionDenied => format!("{path}: permission denied"),
                _ => format!("{path}: {e}"),
            };
            eprintln!("namikaze-rc: {what}");
            return 1;
        }
    };
    let node = match parse::parse(&src) {
        Ok(node) => node,
        Err(e) => {
            eprintln!("namikaze-rc: {path}: {e}");
            return 2;
        }
    };
    let mut it = interp::Interp::new();
    it.script_args = script_args.to_vec();
    it.vars.insert("*".into(), script_args.to_vec());
    match it.run(&node) {
        Ok(code) => code,
        Err(interp::RunError::Exit(code)) => code,
        Err(e) => {
            eprintln!("namikaze-rc: {e}");
            1
        }
    }
}

fn interactive() -> i32 {
    println!("namikaze-rc {} - Plan 9's rc shell adapted to Rust", env!("CARGO_PKG_VERSION"));
    let stdin = std::io::stdin();
    let mut last = 0;
    let mut lines = stdin.lock().lines();
    loop {
        print!("; ");
        let _ = std::io::stdout().flush();
        let mut line = match lines.next() {
            Some(Ok(line)) => line,
            Some(Err(e)) => {
                eprintln!("namikaze-rc: read error: {e}");
                return last;
            }
            None => {
                println!();
                return last;
            }
        };
        // continuation while the input cannot parse as a prefix: keep
        // reading when the error is an unterminated quote or block
        loop {
            match parse::parse(&line) {
                Ok(node) => {
                    let mut it = interp::Interp::new();
                    match it.run(&node) {
                        Ok(code) => last = code,
                        Err(interp::RunError::Exit(code)) => return code,
                        Err(e) => eprintln!("namikaze-rc: {e}"),
                    }
                    break;
                }
                Err(e) if e.msg.contains("unterminated") => {
                    print!("... ");
                    let _ = std::io::stdout().flush();
                    match lines.next() {
                        Some(Ok(more)) => {
                            line.push('\n');
                            line.push_str(&more);
                        }
                        _ => {
                            eprintln!("namikaze-rc: {e}");
                            return last;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("namikaze-rc: {e}");
                    break;
                }
            }
        }
    }
}
