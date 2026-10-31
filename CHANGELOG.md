# Changelog

All notable changes to NamikazeOS are documented here. The format follows
the Keep a Changelog structure; the project uses pure semantic versioning.

## [3.0.0-alpha.3]

### Changed - field hardening (post-release)

- **ISO writer audited against the spec**: directory extents are now
  published block-aligned (ECMA-119 6.8), the volume set size, volume
  sequence number and logical block size fields carry correct 4-byte
  both-endian values instead of a spilled u32 pair, the four volume
  dates sit at their spec offsets and the file structure version byte
  (offset 881) is written as 1. The independent validator grew M path
  table, Rock Ridge, extent-overlap and limine.lock supply-chain
  checks and passes 24/24 against the rebuilt image.
- **two new guards (10 total)**: `secrets-guard` fails on
  credential-shaped strings in any tracked file and on tracked
  `.env`/`*.pem`/`*.key` names; `modes-guard` enforces git index
  hygiene - executable bits only for scripts and init.d entries, and
  symlinks or submodule/gitlink entries never.
- **CI supply chain hardened**: every workflow action is pinned to the
  exact audited commit (ref name kept as a comment) and checkouts run
  with `persist-credentials: false`.
- **regression tests**: the El Torito boot record, the catalog
  validation entry, the ECMA-119 PVD field layout and directory extent
  alignment are pinned by unit tests in the xtask ISO module.

### Changed - repository restructure (post-release)

- **role-based layout**: the repository root now carries only project
  meta (README, LICENSE, policy docs, CI workflows); the entire product
  tree moved under `NamikazeOS/` with the 51 crates grouped by role:
  `lib/` (7 foundational libraries), `services/` (21 init.d services
  and the boot chain) and `tools/` (23 userland CLIs), next to
  `xtask/`, `iso/`, `kernel/`, `overlay/` and `sysroot/`.
- **guards follow the tree**: xtask walks the new layout; the CI
  workflow runs the gate from `NamikazeOS/` and the release artifacts
  come from `NamikazeOS/dist/`.
- **repository hygiene**: stale development clones (gitlink
  directories), the vendored skills mirror, the legacy Forgejo
  workflows and the obsolete transplant script are no longer tracked;
  file modes normalized (docs and configs are no longer marked
  executable).

### Added - CI hardening (post-release)

- **CI gate unified**: the workflow now runs `cargo run -p xtask -- ci`,
  the same command maintainers run locally: guards, workspace build,
  tests, rustfmt check, clippy with warnings denied and the SBOM.
- **version-guard (8th guard)**: fails on any manifest pinning its own
  version, any component missing a current overlay ebuild, and any
  stale ebuild version - workspace and overlay can no longer drift.
- **xtask modularized**: `guards/`, `tasks/` and `util.rs` modules
  replace the single-file xtask; new guards and tasks are registered in
  one list.
- **static musl matrix fixed**: aarch64-unknown-linux-musl builds now
  link with the toolchain-bundled rust-lld via `.cargo/config.toml`
  (the host system ld rejects target-specific flags); both musl targets
  verified to build the full workspace.
- **repository meta**: SECURITY.md policy, CONTRIBUTING.md (the house
  rules the guards enforce), pull request and issue templates, and a
  dependabot config for the workflow actions.
- **crate docs**: SH, ANON, CLOAK, DNS, VAULT, SANDBOX, WATCH, LIVE,
  PKG, DOCTOR, INIT and RT manuals added inside their crates.
- **lint debt cleared**: rustfmt applied across the workspace and every
  clippy warning fixed (including the `iter_skip_zero` denial in
  namikaze-scrub); `cargo fmt --check` and `clippy -D warnings` are now
  hard gates.

### Added - OneISO image pipeline

- **Pure-Rust ISO writer**: `cargo xtask iso` now builds the OneISO image
  end to end with no external tools - a hand-written ECMA-119 ISO9660
  serializer (`tasks/iso/image.rs`) with El Torito BIOS + UEFI boot
  support, little- and big-endian path tables and the Rock Ridge SUSP
  subset (SP, RR, NM, PX).
- **Pinned Limine payload**: official bootloader binaries vendored under
  `iso/payload/limine/v12.9.6/` and verified against
  `iso/manifest/limine.lock` (tarball + per-file SHA-256) before
  staging; Limine is boot firmware (BSD-2-Clause), not a Cargo
  dependency, so the zero-third-party rule is untouched.
- **Round-trip verification**: every build re-parses the image
  (`tasks/iso/verify.rs`) - volume descriptors, full directory walk with
  real-name resolution, SHA-256 of every file extent, El Torito
  validation checksum and both boot entries, path table links.
- **Deterministic output**: sorted entries, fixed 1980-01-01 epoch,
  zeroed padding; two builds of one staging tree are byte-identical and
  the release `.sha256` sidecar seals exactly that hash.
- **Release wiring**: the tag pipeline builds the ISO and attaches it
  (plus its SHA-256) to the GitHub release next to SBOM, bootid and
  SHA256SUMS; `cargo xtask` alias added so the documented interface
  works from the repository root.

### Added - new components

- **namikaze-trace (sector-observe)**: tamper-evident execution activity
  ledger. Polls the process table, detects PID reuse (same pid, different
  binary or start tick) and records every execution into the same
  SHA-256 hash-chain JSONL format as namikaze-logd. Ships an OpenRC
  service and unit tests for stat parsing, PID reuse and chain tampering.
- **namikaze-attest (sector-supply)**: supply-chain attestation. Builds
  a deterministic SHA-256 manifest over a release artifact directory and
  seals it with HMAC-SHA256 (constant-time comparison); `verify`
  re-fingerprints a deployment and reports MISSING/CHANGED files. The
  key travels with the release channel (`--key` or NK_ATTEST_KEY),
  never with the image.
- **namikaze-dupe (sector-storage)**: leftover copy finder for sensitive
  data. Two-stage duplicate detection (size plus 4 KiB head hash, then
  full hash for candidate groups) across /tmp, /var/tmp and ~/.cache;
  `zero` overwrites extra copies with zeros preserving size (keeper
  first) and is a dry run unless `--apply`. Deletes nothing (P9).

### Changed

- Workspace version 3.0.0-alpha.2 -> 3.0.0-alpha.3; all overlay ebuilds
  renamed accordingly; ebuild HOMEPAGE now points at the GitHub
  repository.
- CI mirrored to GitHub Actions (`.github/workflows/ci.yml`): workspace
  build, unit tests, all tree guards and the SBOM run on every push and
  pull request, next to the static musl matrix.

## [3.0.0-alpha.2]

### Changed - licensing

- **License switched from GPL-3.0-only to MPL-2.0** across the whole tree:
  LICENSE, every SPDX header (93 files), workspace manifest, cargo-deny
  policy and all overlay ebuilds. Rationale: file-level copyleft keeps the
  project strict about its own sources while permitting relaxed terms for
  larger integrated works when that becomes necessary; and the previous
  license tied the tree to the legacy project family the system no longer
  ships.

### Changed - GNU-free system stack

The target system no longer contains or references the legacy C toolchain
family. Engineering tokens naming it are banned tree-wide by the new
`gnu-guard` (xtask + verify mirror, documented allowlist only).

- **Bootloader: Limine 12.9.6 (BSD-2-Clause)** replaces the legacy loader.
  New `iso/limine/limine.conf` (six boot modes incl. new safe mode),
  `scripts/fetch-limine.sh` pins the prebuilt release with SHA-256
  `b38aabb042b0c0f9f562b7741be3c1204838d7bbacfa78bb411c674bd5b984ee`,
  `scripts/mkiso.sh` assembles with genisoimage + Limine El Torito images
  and seals the hybrid MBR with `limine bios-install`, and the OneISO
  manifest now declares per-arch `loader` fields. Boot trees are renamed to
  the Limine `${ARCH}` macro values (x86-64, aarch64, armhf, riscv64,
  loongarch64, ppc64le) so one entry set serves every machine.
  `namikaze-install` renders `limine.conf` (`render_limine`).
- **Core userland: chimerautils 15.1.2 (BSD-2-Clause)** integrated as the
  complete portable base (FreeBSD-derived tools, Meson build), pinned by
  `overlay/sys-apps/chimerautils/chimerautils-15.1.2.ebuild` with the
  verified upstream tarball digest
  (`b03e279e0e291968852094ec2946329ac450c863eda909bed0b8a2e1baf884fe`),
  added to `overlay/package.sets/core`, documented in `docs/USERLAND.md`
  and `third_party/chimerautils/` (license + integration notes).
- **C library: musl; compiler: LLVM/Clang** documented as the only target
  toolchain; the profile make.defaults explains the musl/llvm selection
  and `kernel/build.sh` now builds with `LLVM=1` end to end.

### Changed - sector consolidation (11 to 7)

Similar sectors merged; crate names and ebuild names unchanged.

- `sector-boot` + `sector-hardware` -> **`sector-platform`**
- `sector-live` + `sector-data` -> **`sector-storage`**
- `sector-pkg` + `sector-install` + `sector-userland` -> **`sector-supply`**

### Added - new components

- **`namikaze-dns`** (sector-network): encrypted DNS policy manager; DoT/
  DoH-only upstream model with SNI pins and blocked zones, renders the
  loopback stub and resolver drop-in; ships `/etc/namikaze/dns.toml` and
  the `namikaze-dns` OpenRC oneshot.
- **`namikaze-doctor`** (sector-core): system diagnostics; hardening
  sysctl verdicts and version fingerprint, human and machine output.
- **`namikaze-ledger`** (sector-security): tamper-evident audit trail;
  SHA-256 hash-chained JSONL records, append/verify/show, refuses to
  append onto a broken chain.
- **`namikaze-sandbox`** (sector-security): application confinement
  profile compiler; deny-by-default TOML profiles rendered into
  deterministic launch recipes and ruleset summaries; ships an example
  profile under `/etc/namikaze/sandbox/`.
- **`namikaze-rescue`** (sector-supply): offline rescue planner; emits the
  Limine rescue entry and the hash-verify-before-mount repair recipe.
- **`namikaze-userland`**: 5 new tools (clear, cmp, expand, fold, whoami),
  45 -> 50 tools, with unit tests.

### Added - guards and verification

- `cargo xtask gnu-guard` + `gnu-guard-mirror` in `scripts/verify_all.py`
- `cargo xtask userland-guard` + `userland-guard-*` mirrors (chimerautils
  pin, Limine pin, boot template, OneISO loader, mkiso wiring)
- CI (`.forgejo/workflows/ci.yaml`) runs all six guards
- `verify_all.py` now understands raw Rust strings (`r#"..."#`), checks
  the Limine cmdline tokens, the OneISO loader declarations and the new
  version/parity state

### Housekeeping

- Workspace version bumped to 3.0.0-alpha.2 (pure semver)
- README/ARCHITECTURE/HARDWARE/PERSISTENCE/QUICKSTART and the Turkish
  overview rewritten for the new stack, layout and license
- mkrootfs builds and stages the five new binaries; namikaze-dns joins
  the default runlevel; tmpfiles entries for the new runtime directories

## [3.0.0-alpha.1]

Initial Rust Edition source drop: 35 crates across 11 sectors, Niri
Wayland session stack, dm-verity + LUKS2 live persistence, mainline LTS
kernel fragments for seven architectures, OneISO multi-arch manifest,
offline verification battery (30 checks) and release packaging pipeline.
