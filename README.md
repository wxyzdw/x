# NamikazeOS 3.0.0-alpha.2 (Rust Edition)

A privacy-first, anonymity-oriented operating system built on a Gentoo stage3
base with a fully memory-safe, **dependency-free Rust userland** running on
the unmodified mainline Linux LTS kernel. One ISO, every machine. One key,
one owner.

Status: source drop prepared during the git.disroot.org storage freeze.
The v2.2.0 release line (shell/BASIC userland) remains published; this
workspace is the from-scratch Rust rewrite ("Rust Edition") that becomes
3.0.0.

## Principles

| # | Principle | Enforcement |
|---|-----------|-------------|
| P0 | Memory safety first | `#![forbid(unsafe_code)]` in every crate; `unsafe` only in two audited spots: the `namikaze-ffi` syscall boundary and the opt-in `namikaze-sentinel` PAM module ABI hook (SAFETY-commented, CI-enforced) |
| P1 | Zero theme in engineering | No codenames, no emoji, ASCII-only sources (`cargo xtask ascii-guard`) |
| P2 | One system, all machines | Single multi-arch ISO; CPU features and boards detected at boot |
| P3 | Confidential by default | Live persistent by default, everything encrypted, deny-by-default egress |
| P4 | Zero third-party dependencies | The entire workspace compiles with `std` alone; crypto, parsers, compression, HTTP, CLI and logging are hand-written in `namikaze-rt` and pinned by public test vectors (`cargo xtask dep-guard`) |
| P5 | Smallest footprint | RAM budgets measured in CI |
| P6 | Compliance as code | CIS/STIG/NIST controls ship as executable profiles |
| P7 | English-only sources | User-facing strings live in `namikaze-i18n/locales` only; localized prose lives in `namikaze-i18n/docs` |
| P8 | Encrypt everything, expose nothing | Tiered encryption; destructive tools are opt-in |
| P9 | Conceal, don't erase | Wrong passphrases never destroy data; they conceal it |

## Kernel

The kernel is the **unmodified mainline Linux LTS** series, fetched and
verified from kernel.org in CI. NamikazeOS contributes configuration
fragments only: KSPP hardening plus per-architecture universal coverage
(`kernel/configs/fragments/`), merged by `cargo xtask kernel-fragments` and
validated by `cargo xtask kernel-check`. No fork, no out-of-tree patches.
See `kernel/README.md`.

## Live persistent system

The ISO boots live; all changes persist on a LUKS2 volume (argon2id) that
only the passphrase creator can open. Boot modes selected in the Limine menu
or with `namikaze.live=` on the command line:

| Mode | Command line | Behavior |
|---|---|---|
| Persistent (default) | `namikaze.live=persist` | Upper layer on the encrypted volume; reboots keep everything |
| Volatile | `namikaze.live=volatile` | tmpfs upper layer; leaves no trace |
| Copy to RAM | `namikaze.live=ram` | System image copied to RAM, media released |
| Session | `namikaze.live=session` | RAM during the session, flushed to the volume on clean shutdown |

Persistence is allowlist-only (`/etc/namikaze/persistence.conf`); `/usr`,
`/boot` and `/lib` stay sealed by dm-verity. Whole-image updates flow
through `namikaze-secupdate` (SHA-256-verified bundles, atomic slot
rotation, offline rollback). See
`crates/sector-storage/namikaze-persist/docs/PERSISTENCE.md`.

## Workspace layout (11 sectors, 48 crates + xtask)

Documentation lives **inside the crates it describes**; each crate carries
its own `docs/` directory next to the sources.

```
crates/sector-foundation/  namikaze-rt (std-only toolkit: SHA-256, HMAC,
                           PBKDF2, XChaCha20-Poly1305, JSON, TOML, LZ4-block,
                           HTTP, CLI, logging, entropy)
crates/sector-core/        namikaze-common, -ffi, -config, -doctor, -oomd,
                           namikaze-i18n
crates/sector-platform/    namikaze-init (PID 1), -detect, -hal (boot +
                           hardware bring-up)
crates/sector-userland/    namikaze-userland (50-tool multi-call binary),
                           namikaze-sh (POSIX-flavoured login shell)
crates/sector-security/    namikaze-vault, -sentinel, -guard, -seal, -watch,
                           -sandbox, -ledger, -secupdate
crates/sector-network/     namikaze-anon, -cloak, -dns, -usbguard, -macspin
crates/sector-storage/     namikaze-live-core, -live, -persist-core, -persist,
                           -backup, -scrub, -wipe, -share, -decoy, -report
crates/sector-desk/        namikaze-desk (Niri session factory), -tune,
                           -firstboot, -guest
crates/sector-supply/      namikaze-pkg, -install, -rescue, -secpatch,
                           -mirror
crates/sector-time/        namikaze-chrono (civil time + TZif), -ntp (SNTPv4)
crates/sector-observe/     namikaze-logd (hash-chained logs), -metrics
xtask/                     build orchestration + 7 CI guards (std-only)
```

## Building everything with cargo

There is no make, no autoconf, no shell build scripts: every step of the
pipeline is a cargo or xtask invocation.

```sh
cargo build --workspace          # the entire OS userland
cargo test  --workspace          # 193 unit tests (crypto vectors included)
cargo run -p xtask -- verify-all # the 7 CI guards
cargo run -p xtask -- sbom       # dist/sbom.json (declares 0 third-party deps)
cargo run -p xtask -- kernel-fragments   # per-arch kernel configs
cargo run -p xtask -- kernel-check dist/kernel-configs/x86_64.config
cargo run -p xtask -- bootid     # dist/bootid boot seal
cargo run -p xtask -- iso        # OneISO staging plan
cargo run -p xtask -- release ../download  # source zip + SHA256SUMS
```

Distro-side steps (stage3 unpack, binhost, kernel builds) stay in CI; the
guards above are the gate every commit passes.

## License

MPL-2.0 for the entire workspace. See `LICENSE`.
