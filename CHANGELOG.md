# Changelog

All notable changes to NamikazeOS are documented here. The format follows
the Keep a Changelog structure; the project uses pure semantic versioning.

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
