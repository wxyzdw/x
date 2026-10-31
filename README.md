# NamikazeOS 3.0.0-alpha.3 (Rust Edition)

A privacy-first, anonymity-oriented operating system built on a Gentoo stage3
base with a fully memory-safe, **dependency-free Rust userland** running on
the unmodified mainline Linux LTS kernel. One ISO, every machine. One key,
one owner.

Status: developed in the open at https://github.com/wxyzdw/x.
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
(`NamikazeOS/kernel/configs/fragments/`), merged by `cargo xtask
kernel-fragments` and validated by `cargo xtask kernel-check`. No fork,
no out-of-tree patches. See `NamikazeOS/kernel/README.md`.

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
`NamikazeOS/tools/namikaze-persist/docs/PERSISTENCE.md`.

## Repository layout

The repository root carries only project meta (this README, LICENSE,
policy docs and the CI workflows); the entire product tree lives under
`NamikazeOS/`, grouped by role. Documentation lives **inside the crates
it describes**: each crate carries its own `docs/` directory next to the
sources.

```
NamikazeOS/
├── Cargo.toml    workspace manifest: 51 crates, zero third-party deps
├── lib/          foundational libraries other crates link against
│                 namikaze-rt (std-only toolkit: SHA-256, HMAC, PBKDF2,
│                 XChaCha20-Poly1305, JSON, TOML, LZ4-block, HTTP, CLI,
│                 logging, entropy), namikaze-common, -ffi (audited unsafe
│                 boundary), -i18n (locale catalogs), -config (system
│                 configuration schema), -live-core, -persist-core
├── services/     system services: the init.d-managed daemons and the
│                 boot chain - namikaze-init (PID 1), -detect (initramfs
│                 probing), -hal (hardware adaptation), -oomd (pressure
│                 guardian), -sentinel, -guard (nftables policy),
│                 -watch (integrity), -secupdate, -secpatch, -mirror,
│                 -cloak (Tor), -dns (encrypted resolver), -usbguard,
│                 -live, -firstboot, -desk (Niri session), -tune, -ntp,
│                 -logd, -metrics, -trace
├── tools/        userland command-line tools: namikaze-userland (50-tool
│                 multi-call binary), namikaze-sh (login shell), -doctor
│                 (diagnostics), -vault, -seal, -ledger, -sandbox, -anon,
│                 -macspin, -persist, -backup, -scrub, -wipe, -share,
│                 -decoy, -report, -dupe (leftover copy finder), -guest,
│                 -pkg, -install, -rescue, -attest, -chrono
├── xtask/        build orchestration + 8 CI guards (std-only)
├── iso/          OneISO payload: Limine binaries, manifests, limine.conf
├── kernel/       mainline LTS configuration fragments (KSPP + per-arch)
├── overlay/      the ::namikaze Gentoo overlay (ebuilds, package sets)
├── sysroot/      rootfs skeleton: etc/init.d services, greetd, namikaze
│                 system configuration
└── .cargo/       the cargo xtask alias + musl rust-lld linker config
```

## Building everything with cargo

There is no make, no autoconf, no shell build scripts: every step of the
pipeline is a cargo or xtask invocation, run from `NamikazeOS/`.

```sh
cd NamikazeOS
cargo build --workspace          # the entire OS userland
cargo test  --workspace          # 203 unit tests (crypto vectors included)
cargo run -p xtask -- verify-all # the 8 CI guards
cargo run -p xtask -- sbom       # dist/sbom.json (declares 0 third-party deps)
cargo run -p xtask -- kernel-fragments   # per-arch kernel configs
cargo run -p xtask -- kernel-check dist/kernel-configs/x86_64.config
cargo run -p xtask -- bootid     # dist/bootid boot seal
cargo run -p xtask -- iso        # OneISO image end to end
cargo run -p xtask -- release ../download  # source zip + SHA256SUMS
```

Distro-side steps (stage3 unpack, binhost, kernel builds) stay in CI; the
guards above are the gate every commit passes.

## License

MPL-2.0 for the entire workspace. See `LICENSE`.
