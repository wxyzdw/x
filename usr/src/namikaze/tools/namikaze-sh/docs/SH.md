# namikaze-sh

The NamikazeOS login shell: a POSIX-flavored subset written from scratch
in safe Rust. No libc, no third-party crates, `#![forbid(unsafe_code)]`.

## Why

A privacy-focused distribution should not depend on a historical shell
codebase as the default login environment. `namikaze-sh` implements the
part of POSIX shell semantics that interactive and scripting use on this
system actually need, with memory safety guaranteed by construction.

## Language

- pipelines of simple commands with `|`
- redirection: `<`, `>`, `>>`, `2>`
- sequencing: `;`, `&&`, `||`
- quoting: single and double quotes
- parameter expansion: `$VAR` (environment and shell-local)
- builtins: `cd`, `pwd`, `exit`, `export`, `unset`, `echo`, `true`,
  `false`, `help`
- external commands resolve over `PATH` and run through `std::process`

## Modes

Invoked with no arguments it is interactive: it prints a banner and a
`PWD$` prompt when stdin is a terminal. Invoked with a script path (or
as `#!` interpreter) it executes the file line by line. The login-shell
`-` prefix on `argv[0]` is accepted and ignored.

## Exit codes

A pipeline returns the exit status of its last command. `&&` and `||`
propagate status in the standard way, so `set -e`-style logic is written
explicitly. `exit N` terminates with `N`.
