# NamikazeOS 3.0.0-alpha.4 (Rust Edition)

A privacy-first, anonymity-oriented operating system built on a Gentoo stage3
base with a fully memory-safe, **dependency-free Rust userland** running on
the unmodified mainline Linux LTS kernel, wrapped in an **airootfs-style live
filesystem with a native encrypted persistent layer (NamFS)**. One ISO, every
machine. One key, one owner.

Status: developed in the open at https://github.com/wxyzdw/x.
The v2.2.0 release line (shell/BASIC userland) remains published; this
workspace is the from-scratch Rust rewrite ("Rust Edition") that becomes
3.0.0.

## Principles

| # | Principle | Enforcement |
|---|-----------|-------------|
| P0 | Memory safety first | `#![forbid(unsafe_code)]` in every crate; `unsafe` only in audited spots: the `namikaze-ffi` syscall boundary, the opt-in `namikaze-sentinel` PAM module ABI hook and the hardware-boundary modules of `namikaze-kernel` (SAFETY-commented, CI-enforced) |
| P1 | One command builds everything | A plain `cargo build` runs the guards, the SBOM, the bare-metal kernel, the NamFS volume, the ISO, the deep audit and the checksums - no shell, no make, no xtask (`tools/namikaze/build.rs`) |
| P2 | Zero theme in engineering | No codenames, no emoji, ASCII-only sources (ascii-guard) |
| P3 | One system, all machines | Single multi-arch ISO; CPU features and boards detected at boot |
| P4 | Confidential by default | Live persistent by default, everything encrypted, deny-by-default egress |
| P5 | Zero third-party dependencies | The entire workspace compiles with `std` alone; crypto (SHA-256, HMAC, PBKDF2, XChaCha20-Poly1305, AES-256-XTS), parsers, compression, HTTP, CLI and logging are hand-written and pinned by public test vectors (dep-guard) |
| P6 | The repo is the filesystem | `airootfs/` mirrors the live root filesystem; what you see in the tree is what boots |
| P7 | Compliance as code | CIS/STIG/NIST controls ship as executable profiles |
| P8 | Encrypt everything, expose nothing | Tiered encryption; destructive tools are opt-in |
| P9 | Conceal, don't erase | Wrong passphrases never destroy data; they conceal it |

## The airootfs and NamFS (new in 3.0.0-alpha.4)

`airootfs/` is the live root filesystem tree - the Arch-releng
`airootfs` idea, but persistent and encrypted. The ISO boots it live
(squashfs slot in the boot tree); the writable layer is NamFS:

- **NamFS** (`lib/namikaze-fs`) is the native encrypted persistent
  volume format, implemented from scratch in the workspace: AES-256-XTS
  sector encryption (FIPS-197 core, IEEE 1619 tweakable mode), key
  derivation with PBKDF2-HMAC-SHA256, HMAC-anchored header, per-file
  SHA-256 integrity. Wrong passphrases are rejected before any data is
  touched; free space is indistinguishable from sealed space.
- **`namikaze-fstool`** creates, fills, inspects and verifies volumes:
  `create | put | get | list | info | verify`.
- **The pipeline ships a deterministic demo volume** in every ISO
  (`boot/namfs/namikaze-demo.namfs`, 1 MiB, passphrase
  `namikaze-demo`, byte-stable across builds) so the persistent layer
  can be exercised anywhere.
- **Policy lives in the airootfs**: `airootfs/etc/namikaze/namfs.conf`
  (mode = volatile | persistent | ask, volume path, passphrase source,
  KDF iterations) and `airootfs/etc/namikaze/namfs.tab` (volume table).
  The bare-metal kernel parses `namikaze.namfs=<label>` on its command
  line and reports the persistent layer on the splash and COM1.
- The LUKS2 path (`namikaze-persist`, argon2id) stays for full-disk
  installs; NamFS is the lightweight, self-contained layer for the live
  system and application containers.

## Kernel

Two layers:

- The **mainline Linux LTS** series, fetched and verified from
  kernel.org in CI. NamikazeOS contributes configuration fragments only:
  KSPP hardening plus per-architecture universal coverage
  (`kernel/configs/fragments/`), merged by `namikaze kernel-fragments`
  and validated by `namikaze kernel-check`. No fork, no out-of-tree
  patches. See `kernel/README.md`.
- The **bare-metal Rust kernel** (`kernel/namikaze-kernel`): a
  freestanding `no_std`, zero-dependency stage booted by Limine through
  the boot protocol (base revision 2) straight into the framebuffer.
  It paints the boot splash (the nine-tailed chakra fox over a dark
  warm field, the title, the version, the bootid seal, the NamFS
  persistent-layer label and an animated progress bar), mirrors every
  step onto COM1 and parks quiescently. `unsafe` exists only in three
  audited boundary modules (`limine`, `fb`, `port`).

## Live persistent system

The ISO boots live; boot modes are selected in the Limine menu or with
`namikaze.live=` on the command line:

| Mode | Command line | Behavior |
|---|---|---|
| Persistent (default) | `namikaze.live=persist` | Upper layer on the encrypted volume (NamFS or LUKS2); reboots keep everything |
| Volatile | `namikaze.live=volatile` | tmpfs upper layer; leaves no trace |
| Copy to RAM | `namikaze.live=ram` | System image copied to RAM, media released |
| Session | `namikaze.live=session` | RAM during the session, flushed to the volume on clean shutdown |

Persistence is allowlist-only (`airootfs/etc/namikaze/persistence.conf`);
`/usr`, `/boot` and `/lib` stay sealed by dm-verity. Whole-image updates flow
through `namikaze-secupdate` (SHA-256-verified bundles, atomic slot
rotation, offline rollback). See
`tools/namikaze-persist/docs/PERSISTENCE.md`.

## Repository layout: the repo IS the filesystem

The repository root is the airootfs - the live root filesystem itself.
Every directory is a real FHS location, and the sources live inside the
filesystem they build, at the place FHS reserves for them:

```
/ (repository root = filesystem root)
|-- etc/                    system configuration (what boots)
|   |-- namikaze/           namfs.conf, namfs.tab, motd, system.toml,
|   |                       dns.toml, ntp.toml, persistence.conf, sandbox
|   |-- init.d/  cron.*/  local.d/  profile.d/
|   `-- greetd/  pam.d/
|-- boot/                   bootloader payload tree: pinned Limine
|   |                       binaries (limine.lock-sha256-verified),
|   `--                     limine.conf, oneiso.toml manifest
|-- usr/
|   |-- bin/                session entry (namikaze-session)
|   `-- src/namikaze/       THE Rust workspace (58 crates, zero
|       |                   third-party deps) - Cargo.toml, .cargo,
|       |-- kernel/         bare-metal no_std Rust kernel (Limine
|       |                   splash stage) + Linux LTS config fragments
|       |-- lib/            namikaze-rt, -common, -fs (NamFS), -iso,
|       |                   -dist (release pipeline), -guards, -ffi,
|       |                   -i18n, -config, -live-core, -persist-core
|       |-- services/       namikaze-init (PID 1), -detect, -hal,
|       |                   -oomd, -sentinel, -guard, -watch,
|       |                   -secupdate, -secpatch, -mirror, -cloak,
|       |                   -dns, -usbguard, -live, -firstboot, -desk,
|       |                   -tune, -ntp, -logd, -metrics, -trace
|       `-- tools/          namikaze (build orchestration: its
|                           build.rs IS the pipeline), namikaze-fstool,
|                           namikaze-audit, namikaze-userland (50-tool
|                           multi-call binary), namikaze-sh, -doctor,
|                           -vault, -seal, -ledger, -sandbox, -anon,
|                           -macspin, -persist, -backup, -scrub,
|                           -wipe, -share, -decoy, -report, -dupe,
|                           -guest, -pkg, -install, -rescue, -attest,
|                           -chrono
|-- var/
|   |-- db/repos/namikaze/  the ::namikaze Gentoo overlay (its real
|   |                       portage home): ebuilds, package sets,
|   |                       profiles
|   |-- lib/namikaze/       state skeleton
|   `-- log/namikaze/       log skeleton
`-- root/                   root home skeleton
```

Documentation lives **inside the crates it describes**: each crate
carries its own `docs/` directory next to the sources. Project meta
(this README, LICENSE, SECURITY, CONTRIBUTING, CHANGELOG and the CI
workflows) sits at the filesystem root like a well-kept /-level.

## One command: cargo build

There is no make, no autoconf, no shell, no xtask - the build is Rust
from the first byte to the shipped image. From `NamikazeOS/`:

```sh
cd NamikazeOS
cargo build                          # EVERYTHING: guards + sbom + kernel
                                     # + NamFS volume + ISO + audit + checksums
cargo test  --workspace              # the unit test suite (crypto vectors included)
cargo fmt -- --check                 # formatting gate
cargo clippy --workspace --all-targets -- -D warnings
```

The build drops the full dist set into `dist/`:
`NamikazeOS-<version>-oneiso.iso` (+ `.sha256`),
`namfs/namikaze-demo.namfs`, `sbom.json`, `bootid`, `SHA256SUMS`,
`kernel/namikaze-kernel`.

Single steps (same library functions the pipeline uses):

```sh
cargo run -p namikaze -- guard       # the 10 tree guards
cargo run -p namikaze -- iso         # only the image step
cargo run -p namikaze -- kernel      # only the bare-metal kernel
cargo run -p namikaze -- audit dist/NamikazeOS-*-oneiso.iso dist/iso-staging
cargo run -p namikaze -- release ../download   # source zip + checksums
NAMFS_PASSPHRASE=namikaze-demo cargo run -p namikaze-fstool -- \
    info dist/namfs/namikaze-demo.namfs            # open the demo volume
```

The bare-metal kernel needs the `x86_64-unknown-none` target
(`rustup target add x86_64-unknown-none`); CI installs it.

Distro-side steps (stage3 unpack, binhost, Linux kernel builds) stay in
CI; the guards and the pipeline are the gate every commit passes.

## License

MPL-2.0 for the entire workspace. See `LICENSE`.
