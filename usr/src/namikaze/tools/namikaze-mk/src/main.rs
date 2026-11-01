// SPDX-License-Identifier: MPL-2.0
//! namikaze-mk: Plan 9's mk, adapted to Rust for NamikazeOS.
//!
//! The dependency semantics of mk(1): rules with attributes
//! (D, E, N, Q, U, V), meta-rules with % and & stems, variables with
//! lists, `<file` includes, recipe variables ($target, $prereq,
//! $newprereq, $stem, $pid), command-line variable overrides in any
//! argument position, and the mk defaults: the first rule's target is
//! the goal, unknown variables expand to nothing, recipes run through
//! $MKSHELL (default /bin/sh).
//!
//! Usage:
//!   namikaze-mk [-f mkfile] [-n] [-a] [target ...] [VAR=value ...]

#![forbid(unsafe_code)]

mod graph;
mod parse;

use std::process::exit;

use graph::Engine;

const USAGE: &str = "namikaze-mk: Plan 9's mk, adapted to Rust

usage:
  namikaze-mk [-f mkfile] [-n] [-a] [target ...] [VAR=value ...]

  -f mkfile   read this mkfile instead of ./mkfile (repeatable)
  -n          print the recipes without running them
  -a          force every target to be remade
  --          treat every later argument as a goal or variable
  target      goals to build (default: the first rule's target)
  VAR=value   override a variable, in any argument position";

fn fail(msg: &str) -> ! {
    eprintln!("namikaze-mk: {msg}");
    exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut files: Vec<String> = Vec::new();
    let mut goals: Vec<String> = Vec::new();
    let mut overrides: Vec<(String, Vec<String>)> = Vec::new();
    let mut dry_run = false;
    let mut force = false;
    let mut after_dashdash = false;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].clone();
        i += 1;
        if after_dashdash {
            push_goal_or_override(&arg, &mut goals, &mut overrides);
            continue;
        }
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                exit(0);
            }
            "-n" => dry_run = true,
            "-a" => force = true,
            "--" => after_dashdash = true,
            "-f" => match args.get(i) {
                Some(file) => {
                    files.push(file.clone());
                    i += 1;
                }
                None => fail("-f needs a file name"),
            },
            _ => push_goal_or_override(&arg, &mut goals, &mut overrides),
        }
    }

    if files.is_empty() {
        files.push("mkfile".to_string());
    }

    let mut engine = Engine::new();
    engine.dry_run = dry_run;
    engine.force = force;

    for file in &files {
        let items = match parse::parse_file(file, 0) {
            Ok(items) => items,
            Err(e) => fail(&e.to_string()),
        };
        // splice includes in file order
        let mut flat: Vec<parse::Item> = Vec::new();
        for item in items {
            match item {
                parse::Item::Include { file } => match parse::parse_file(&file, 1) {
                    Ok(inner) => flat.extend(inner),
                    Err(e) => fail(&e.to_string()),
                },
                other => flat.push(other),
            }
        }
        if let Err(e) = engine.load(&flat) {
            fail(&e.to_string());
        }
    }

    // command-line overrides beat mkfile assignments, in any position
    for (name, values) in overrides {
        engine.vars.insert(name, values);
    }

    if goals.is_empty() {
        match engine.default_target() {
            Some(t) => goals.push(t),
            None => fail("no targets and the mkfile has no rules"),
        }
    }

    let mut status = 0;
    for goal in &goals {
        let mut chain = Vec::new();
        if let Err(e) = engine.build(goal, None, &mut chain) {
            eprintln!("namikaze-mk: {e}");
            status = 1;
            break;
        }
    }
    exit(status);
}

fn push_goal_or_override(arg: &str, goals: &mut Vec<String>, overrides: &mut Vec<(String, Vec<String>)>) {
    if let Some((name, rest)) = arg.split_once('=') {
        if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            let values = rest.split(' ').filter(|s| !s.is_empty()).map(String::from).collect();
            overrides.push((name.to_string(), values));
            return;
        }
    }
    goals.push(arg.to_string());
}
