# Changelog

All notable changes to NamikazeOS are documented here. The format follows
the Keep a Changelog structure; the project uses pure semantic versioning.

## [3.0.0-alpha.5]

### Changed - the repository becomes the filesystem

- **The `airootfs/` and `NamikazeOS/` directories are gone: the
  repository root IS the filesystem root.** The tree now reads like the
  booted system: system configuration at `etc/` (policy, init.d,
  cron, greetd, pam.d, profile.d), the session entry at `usr/bin/`,
  AppArmor and sysctl fragments at `lib/`, the bootloader payload at
  `boot/`, the state and log skeletons at `var/lib/namikaze/` and
  `var/log/namikaze/`, the root home at `root/`.
- **The Rust workspace moved to its FHS home**: `usr/src/namikaze/`
  (Cargo.toml, 58 crates, kernel configs). The `namikaze` tool
  resolves the filesystem root by walking up to
  `usr/src/namikaze/Cargo.toml`; the dist pipeline treats the repo
  root as `root` and the workspace as `namikaze_common::WORKSPACE`.
- **The overlay moved to portage's real home**: `var/db/repos/namikaze/`.
- All path constants updated across the guards, the dist pipeline and
  the ISO staging (desk-guard pairs, modes-guard allowlist,
  tools-guard three-way check, version-guard manifest and ebuild
  paths, dep-guard group roots, SBOM group roots). `release` now zips
  the whole filesystem source tree as
  `NamikazeOS-<version>-source.zip`.
- CI runs everything from `usr/src/namikaze`; artifacts upload from
  `usr/src/namikaze/dist`. Version bumped tree-wide, 58 overlay
  ebuilds renamed.

### Added - the Plan 9 heritage

- **The full Plan 9 4th edition source tree was surveyed directory by
  directory** (http://9p.io/sources/plan9/): 894 directories, 16,015
  files, ~277 MB, every listing recorded in
  `usr/src/namikaze/docs/plan9/plan9-tree.json` by the reproducible
  `usr/src/namikaze/docs/plan9/plan9_crawl.py`. The analysis and the per-directory
  adaptation verdicts are in
  `usr/src/namikaze/docs/plan9/plan9-adaptation.md`. Upstream is MIT
  (Plan 9 Foundation); the survey read `fcall.h`, `error.h`, `rc(1)`
  and `mk(1)` as the ground truth for the ports.
- **`lib/namikaze-9p`**: the 9P2000 protocol stack -
  wire codec transcribed from `fcall.h`, a server framework in the
  shape of `lib9p` (Fsys trait, fid table, walk/open/read semantics,
  partial-walk replies), a synthetic file tree in the shape of
  `lib9p/file.c` (static and dynamic files, content snapshotted at
  open), a synchronous client with strict reply validation, and an
  error taxonomy bound to the exact strings of
  `/sys/src/9/port/error.h`. Malformed frames are answered with a
  salvaged tag and the session survives; hostile or buggy peers
  cannot wedge a connection.
- **`tools/namikaze-rc`**: Plan 9's rc shell in Rust - single-quote
  quoting with `''` doubling, list variables with `(a b c)` literals,
  `^` concatenation with the pairwise/singleton/cross rules, `$x(1 2)`
  subscripts, `$#x`, `~` pattern matching, backquote command
  substitution, if/while/for, `if not`, assignments scoped to a
  command per the manual's rule, globs on the result of substitution,
  pipelines, `< > >> <>` redirections, `&` backgrounding, positioned
  syntax errors and Plan 9 errno wording for runtime failures.
- **`tools/namikaze-mk`**: Plan 9's mk in Rust - rules with the D, E,
  N, Q, U, V attributes, meta-rules with `%` and `&` stems,
  `$target $prereq $newprereq $stem $pid`, `<file` includes,
  command-line variable overrides in any argument position, `-n` and
  `-a`, cycle detection that prints the loop, and failures that name
  the mkfile line.
- **`tools/namikaze-9srv`**: serve a real directory read-only over
  9P2000, or probe any 9P server with a full traced session
  (`probe --trace` prints both frames of every exchange).
- 93 new tests across the four crates (37 + 35 + 18 + 3), all std-only,
  zero third-party dependencies, `#![forbid(unsafe_code)]`. The
  workspace is now 62 crates; the overlay is 62 ebuilds
  (`EBUILD_SECTORS` extended, curated ebuilds added for the four).

## [3.0.0-alpha.4]

### Added - the airootfs generation

- **The repo is the filesystem**: `sysroot/` becomes `airootfs/`, the
  live root filesystem tree in the Arch-releng style, but persistent and
  encrypted. New policy files ship in it: `etc/namikaze/namfs.conf`
  (persistence mode, volume path, passphrase source, KDF iterations),
  `etc/namikaze/namfs.tab` (volume table) and a user-facing `motd`;
  `var/lib/namikaze/` and `root/` slots added.
- **NamFS** (`lib/namikaze-fs`): the native encrypted persistent volume
  format, written from scratch with zero dependencies - AES-256 core
  (FIPS-197, pinned by the C.3 known-answer vector), XTS tweakable mode
  (IEEE 1619, tweak encrypted with the second key), PBKDF2-HMAC-SHA256
  gate (RFC vectors), HMAC-anchored 512-byte header, passphrase verifier
  checked before any data access, per-file SHA-256 integrity, sealed
  free space, rewrite-on-put entry table. 10 unit tests including
  wrong-passphrase rejection and ciphertext tamper detection.
- **`namikaze-fstool`**: create / put / get / list / info / verify CLI
  over NamFS, with deterministic volume creation (explicit salt, uuid
  and timestamp) for reproducible builds.
- **Deterministic demo volume in every ISO**: the pipeline seals
  `airootfs`'s config set into `dist/namfs/namikaze-demo.namfs`
  (passphrase `namikaze-demo`, byte-stable across builds, covered by
  SHA256SUMS) and stages it at `boot/namfs/` in the image.
- **The kernel parses the persistent layer**: `namikaze.namfs=<label>`
  on the command line is reported on COM1 and drawn on the splash
  footer next to the bootid seal.
- **Independent deep audit in pure Rust** (`namikaze-iso/src/audit.rs`
  + `namikaze-audit` tool): full ECMA-119 + El Torito re-derivation
  (descriptor set walk, PVD both-endian halves, catalog checksum, L/M
  path table mirroring, Rock Ridge SP/NM/PX, record sanity, extent
  overlap detection, staged-file presence, limine.lock supply chain) -
  the successor of the retired Python validator; the pipeline refuses
  to finish unless it passes.

### Changed - one command builds everything

- **xtask is gone.** The orchestration crate is dissolved: the ten tree
  guards live in `lib/namikaze-guards`, the ISO writer + staging +
  verifier in `lib/namikaze-iso` (with the bootid seal), and the dist
  steps (SBOM, kernel build + validation, checksums, ebuilds, source
  zip, pipeline) in `lib/namikaze-dist`. The new `namikaze` tool
  (`tools/namikaze`) exposes them as CLI subcommands - and its
  `build.rs` runs the entire pipeline on every plain `cargo build`:
  guards, SBOM, kernel, NamFS volume, ISO, audit, checksums. No shell,
  no make, no xtask anywhere in the chain.
- **Shared foundations moved to `namikaze-common`**: the guard/task
  helper toolkit (`util`), the SBOM generator, the kernel-image ELF
  validator (with the Limine protocol markers) and the overlay ebuild
  sector table; `iso/` renamed to `boot/` (it is the boot payload
  tree) and all path constants updated.
- **CI mirrors the architecture**: the gate job is now
  `cargo build --workspace` (the pipeline) + tests + fmt + clippy, and
  uploads the ISO and the NamFS demo volume as artifacts; the release
  job produces the full dist set with one build. Cross builds skip the
  pipeline (TARGET != HOST detection in build.rs).
- **51 -> 58 crates** (guards, fs, iso, dist + the namikaze/fstool/
  audit tools), ebuild sectors extended, version bumped everywhere and
  guard paths updated to the new tree (desk-guard pairs, modes-guard
  allowlist, naming-guard codenames location, version-guard ebuild
  source). The `cargo xtask` alias is gone from `.cargo/config.toml`.

## [3.0.0-alpha.3]

### Added - bare-metal kernel stage (post-release)

- **namikaze-kernel**: a freestanding `no_std`, zero-dependency Rust
  kernel stage under `kernel/namikaze-kernel/`, booted by Limine through
  the boot protocol (base revision 2) and painting the OneISO boot
  splash on the firmware framebuffer: a nine-tailed chakra fox over a
  dark warm field (the project's namesake mood), the NAMIKAZE title in
  block glyphs, the version, the bootid seal parsed from the kernel
  command line and an animated progress bar, mirrored onto COM1. The
  crate stays outside the workspace by design and carries its own lib
  target for unit tests (font coverage, protocol constants, ELF
  validation, boot option parsing).
- **`cargo xtask kernel`**: builds the kernel for x86_64-unknown-none,
  runs its lib tests, fmt and clippy, validates the ELF (class,
  machine, entry point) and proves the Limine request markers survived
  linking, then stages the artifact. The step is part of the `ci` gate
  and of the CI workflow (the target is installed there).
- **ISO boots the splash**: `iso` stages a built kernel at
  `boot/namikaze-kernel`, activating the new first entry of
  `iso/limine/limine.conf` (`protocol: limine`); Limine hides the entry
  when no kernel was staged. The dep-guard now also scans the kernel
  crate's manifest for third-party dependencies.
- **workspace tidy**: file modes across the tree renormalized again
  after an environment recycle re-flagged executables (modes-guard
  rules), and the independent ISO validator is persisted under
  `scripts/` with its full deep-check suite.

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
