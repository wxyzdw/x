# Contributing

NamikazeOS is a std-only, zero-third-party-dependency Rust workspace. The
guard system enforces the house rules mechanically, so most of this file
is "what the guards will check anyway".

## The one command that matters

There is no shell, no make and no xtask: a plain build does everything.
From the workspace directory, `src/` (beside the `os/` tree it packs):

    cargo build

This compiles every crate AND runs the complete dist pipeline through
the `namikaze` tool's build script: the ten tree guards, the SBOM, the
bare-metal kernel (build + ELF validation + staging), the deterministic
NamFS demo volume, the OneISO image, the independent deep audit and the
dist checksums. CI runs the same steps plus `cargo test --workspace`,
`cargo fmt -- --check` and `cargo clippy --workspace --all-targets --
-D warnings`.

Single steps are available as subcommands of the same library functions:

    cargo run -p namikaze -- guard        # the ten guards
    cargo run -p namikaze -- iso          # only the image step
    cargo run -p namikaze -- pipeline     # the full pipeline, verbose

## House rules (all enforced by guards)

1. Zero third-party crates. Every `[dependencies]` entry must be a
   `namikaze-*` path dependency. If you need a library capability, write
   the minimal version in `namikaze-rt` (crypto, toml, json, http, lz ...)
   with tests.
2. MPL-2.0 SPDX header on line 1-5 of every `.rs` file:
   `// SPDX-License-Identifier: MPL-2.0`
3. ASCII-only engineering sources. Localized prose lives only in
   `namikaze-i18n` locales and its docs directory.
4. No theme codenames anywhere in the tree.
5. No banned legacy toolchain tokens (`gnu-guard` keeps the list).
6. `#![forbid(unsafe_code)]` everywhere. The documented exceptions are
   namikaze-ffi, the PAM glue in namikaze-sentinel and the audited
   hardware-boundary modules of namikaze-kernel (`limine`, `fb`, `port`);
   anything else needs a written P0 justification first.
7. Version discipline: the root `[workspace.package]` version is the only
   place a version is set. Crate manifests inherit it; overlay ebuilds
   must match (version-guard checks both).
8. The Niri session files under `etc/`, `usr/bin/` and the overlay
   (`var/db/repos/namikaze/`) must stay in sync byte-for-byte (desk-guard).
9. Userland tools must exist in three places at once: the `TOOLS` file,
   `src/registry.rs` and the userland ebuild symlink loop (tools-guard).
10. No credential-shaped strings anywhere in tracked files, and no
    `.env` / `*.pem` / `*.key` blobs tracked at all (secrets-guard).
11. Git index hygiene: docs and configs are plain 100644; executable
    bits only for scripts and init.d entries, and no symlinks or
    submodule/gitlink entries anywhere (modes-guard).
12. The bare-metal kernel (`kernel/namikaze-kernel`) targets
    `x86_64-unknown-none` and stays excluded from the workspace; the
    `namikaze` pipeline builds it with a nested cargo invocation. Never
    depend on it from userland or add it to workspace members (the
    freestanding entry point must not link on a hosted target).
13. The dist pipeline is the single source of truth for artifacts: never
    generate ISOs, volumes or checksums with anything but the pipeline
    (namikaze-dist), and never ship an image the `namikaze-audit` has
    not passed.

## Rust style

- `cargo fmt` (rustfmt defaults, see rustfmt.toml) - CI denies diffs.
- `cargo clippy --workspace --all-targets -- -D warnings` - CI denies
  warnings; fix the cause, do not silence it.
- Tests live next to the code (`#[cfg(test)] mod tests`) and must not
  require root, network or a display.

## Commits and versions

- Conventional, imperative, one logical change per commit:
  `ci: ...`, `guards: ...`, `storage: ...`, `network: ...`.
- Semver only. Pre-releases are `X.Y.Z-alpha.N`. Bump the root manifest
  version, rename the overlay ebuilds (`*_<old>.ebuild` ->
  `*_<new>.ebuild`), then run `cargo run -p namikaze -- ebuilds` for
  missing ones (version-guard verifies consistency).

## Adding a guard or a pipeline step

1. Guards: create `lib/namikaze-guards/src/<name>.rs` exposing
   `pub(crate) fn run(root: &Path) -> Result<()>`, register it in
   `GUARDS`, add tests for the failure path, not only the happy path.
2. Pipeline steps: add a module to `lib/namikaze-dist` exposing
   `pub fn run(root: &Path) -> Result<()>`, call it from
   `pipeline::full_build` in the right order, mirror it as a `namikaze`
   CLI subcommand, and document it in the pipeline module docs.
