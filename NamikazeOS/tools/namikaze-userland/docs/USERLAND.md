# NamikazeOS Userland Strategy

NamikazeOS ships a self-hosted userland written from scratch in memory-safe
Rust. The legacy C core toolchain (and every third-party userland source
tree) is absent by policy; the whole stack builds with `cargo build
--workspace` alone. Enforcement is mechanical: `cargo xtask tools-guard`,
`cargo xtask gnu-guard` and `cargo xtask dep-guard` fail the build on any
drift.

## Layer 1 - the hardened core: `namikaze-userland`

One memory-safe multi-call binary (`#![forbid(unsafe_code)]`) provides
**50 tools** (basename, cat, chmod, clear, cmp, comm, cp, cut, date, dirname,
dmesg, echo, env, expand, false, fold, free, head, hostname, id, kill, ln,
ls, mkdir, mktemp, mv, nproc, paste, printenv, ps, pwd, readlink, rm, rmdir,
seq, sha256sum, sleep, sort, stat, tail, tee, touch, tr, true, tty, uname,
uniq, wc, which, whoami) dispatched busybox-style on argv0.

Hardening properties:

- arguments validated before use; panics on the runtime path are contained
  by the dispatcher and become exit status 70, never an abort
- deterministic output: byte ordering, C locale only, always UTC - no
  timezone leaks into logs, filenames or reports
- binary-safe I/O (`read_until` / `io::copy`), never line-lossy text
- `sha256sum` runs on the workspace's own FIPS 180-4 implementation
  (`namikaze-rt::sha256`), pinned by public test vectors

The tool set lives in one file: `TOOLS` next to the crate sources.
`cargo xtask tools-guard` cross-checks it against the Rust registry table
and the overlay ebuild symlink farm, so a name can never drift between
them.

## Layer 2 - the shell: `namikaze-sh`

The login shell is `namikaze-sh`, a POSIX-flavoured subset written in the
same discipline: pipelines with `|`, redirections `< > >> 2>`, sequencing
with `;` and `&&`/`||`, single/double quoting, `$VAR` expansion and the
builtin set (cd, pwd, exit, export, unset, echo, true, false, help). The
lexer, parser and executor are pure std; external commands resolve over
PATH and run through std::process with no exec-family syscalls of our own.

## Layer 3 - everything else is a NamikazeOS crate

Scope beyond the 50 tools and the shell is deliberately served by purpose-
built Rust components instead of a generic toolbox: logging is
`namikaze-logd` (tamper-evident, hash-chained), time is `namikaze-chrono` +
`namikaze-ntp`, observation is `namikaze-metrics`, packaging is
`namikaze-pkg` with `namikaze-mirror`, and rescue operations are
`namikaze-rescue`. Where a classic utility is genuinely missing, the fix is
a new applet in `namikaze-userland` or a new sector crate - never a
third-party source import.

## History note

Earlier releases pinned the BSD userland of Chimera Linux (chimerautils) as
layer 2. The zero-third-party policy of the v3 Rust edition retired that
pin: the scope reference was used to size the Rust tool set, and every line
in the tree is now original, MPL-2.0, memory-safe Rust.
