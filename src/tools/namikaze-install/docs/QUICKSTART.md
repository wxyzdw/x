# NamikazeOS Quickstart

End-to-end guide: from a clean checkout to a bootable OneISO and a running
persistent live session. All commands run from the repository root.

## 1. Prerequisites

- Rust 1.75+ (stable); no other build-time tooling for the workspace itself
- `mksquashfs` (squashfs-tools), `genisoimage`, `zip` for the packaging tasks
- optional: `qemu-system-x86_64` for the persistence smoke test
- optional: cross toolchains per target architecture

## 2. Source guards

Run the hygiene gates before anything else. All seven must pass.

```
cargo run -p namikaze -- guard ascii-guard  # no non-ASCII bytes in sources
cargo run -p namikaze -- guard naming-guard # no theme codenames anywhere
cargo run -p namikaze -- guard license-guard # MPL-2.0 SPDX on every .rs
cargo run -p namikaze -- guard gnu-guard    # no legacy-toolchain tokens
cargo run -p namikaze -- guard dep-guard    # zero third-party dependencies
cargo run -p namikaze -- guard tools-guard  # TOOLS == registry == ebuild
cargo run -p namikaze -- guard desk-guard   # Niri session files agree across the tree
```

`cargo run -p namikaze -- guard` runs the whole gate in one command.

## 3. Kernel (mainline, unmodified)

The kernel is the unmodified mainline LTS tree; NamikazeOS contributes config
fragments only (KSPP hardening + per-arch universal coverage). Merge and
validate them without leaving cargo:

```
cargo run -p namikaze -- kernel-fragments
cargo run -p namikaze -- kernel-check dist/kernel-configs/x86_64.config
```

The kernel tree itself is fetched and verified in CI; `kernel/README.md`
documents the fragment philosophy.

## 4. Build

```
cargo build --release --workspace    # every userland binary
cargo test  --workspace              # 193 unit tests incl. crypto vectors
```

Release binaries land in `target/release/`; CI stages them into the rootfs
squashfs and the initramfs (`namikaze-init` is the static PID 1).

## 5. SBOM, boot seal and ISO

```
cargo run -p namikaze -- sbom   # dist/sbom.json (third_party_dependencies = 0)
cargo run -p namikaze -- bootid # dist/bootid, stamped into the Limine config
cargo run -p xtask -- iso       # per-arch staging plan + genisoimage command
```

## 6. Install

`namikaze-install` is arch-agnostic: the user never states the architecture.

```
namikaze-install usb /dev/sdX --persist --yes   # boot ESP + boot tree + persist
namikaze-install iso <payload> <out.iso>        # assemble a OneISO
namikaze-install verify /dev/sdX                # labels + seals on the medium
```

## 7. First boot

`namikaze-firstboot` walks through language, anonymity level and sentinel
consent (KVKK/GDPR-informed); `namikaze-tune` recommends the Argon2id
profile for the machine's RAM. The Niri Wayland session comes up through
greetd/agreety with the hardened PAM chain.

## 8. Day two

- `namikaze-doctor run` - full health check
- `namikaze-report html` - self-audit report
- `namikaze-secupdate status/stage/apply/rollback` - atomic image updates
- `namikaze-backup --repo DIR put ...` - encrypted, deduplicated backups
- `namikaze-logd query --verify` - tamper check on the system log chain
- `namikaze-mirror serve` - offline package mirror for air-gapped updates
