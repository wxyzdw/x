# Contributing

NamikazeOS is a std-only, zero-third-party-dependency Rust workspace. The
guard system enforces the house rules mechanically, so most of this file
is "what the guards will check anyway".

## The one command that matters

Before every push, from the `NamikazeOS/` workspace directory (the
repository root only carries project meta):

    cargo run -p xtask -- ci

This runs the exact CI gate locally: tree guards, workspace build, tests,
rustfmt, clippy with warnings denied, and the SBOM. If it passes locally
it passes in CI (same steps, same order).

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
6. `#![forbid(unsafe_code)]` everywhere. The two documented exceptions are
   namikaze-ffi and the PAM glue in namikaze-sentinel; anything else needs
   a written P0 justification first.
7. Version discipline: the root `[workspace.package]` version is the only
   place a version is set. Crate manifests inherit it; overlay ebuilds
   must match (version-guard checks both).
8. The Niri session files under `sysroot/` and `overlay/` must stay in
   sync byte-for-byte (desk-guard).
9. Userland tools must exist in three places at once: the `TOOLS` file,
   `src/registry.rs` and the userland ebuild symlink loop (tools-guard).
10. No credential-shaped strings anywhere in tracked files, and no
    `.env` / `*.pem` / `*.key` blobs tracked at all (secrets-guard).
11. Git index hygiene: docs and configs are plain 100644; executable
    bits only for scripts and init.d entries, and no symlinks or
    submodule/gitlink entries anywhere (modes-guard).
12. The bare-metal kernel (`kernel/namikaze-kernel`) is built only by
    `cargo xtask kernel` for `x86_64-unknown-none` and stays excluded
    from the workspace; never depend on it from userland or add it to
    workspace members (the freestanding entry point must not link on a
    hosted target).

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
  version, then regenerate overlay ebuilds with `cargo run -p xtask -- ebuilds`
  (version-guard verifies consistency).

## Adding a guard or task

1. Create `xtask/src/guards/<name>.rs` (or `tasks/<name>.rs`) exposing
   `pub(crate) fn run(root: &Path) -> Result<()>`.
2. Register it in `guards::GUARDS` (or the `main` dispatch and USAGE).
3. Add tests for the failure path, not only the happy path.
