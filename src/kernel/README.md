# NamikazeOS kernel integration

NamikazeOS runs the **unmodified mainline Linux LTS kernel**. There is no
fork and no out-of-tree patch: hardening and hardware coverage are delivered
exclusively through configuration fragments, so the trust anchor stays at
kernel.org. The Rust userland talks to this kernel through stable UAPI only.

## Why mainline-only

- Auditable: the kernel source is exactly what kernel.org publishes.
- Reproducible: fragments + pinned version are the entire delta.
- Universal: defconfig per architecture plus fragments gives one kernel per
  architecture that boots every supported machine (OneISO requirement).
- Rust in the kernel is intentionally NOT used yet: no out-of-tree Rust
  modules, no experimental bindings. All memory-safety guarantees live in
  the userland until mainline Rust support stabilizes.

## The bare-metal Rust kernel stage

Next to the Linux integration lives `namikaze-kernel/`: a freestanding,
`no_std`, zero-dependency Rust binary that is booted by Limine directly
(boot protocol, base revision 2) and paints the OneISO boot splash on the
firmware framebuffer - the nine-tailed chakra fox over a dark warm field,
the project title, the running version, the bootid seal and an animated
progress bar, mirrored onto COM1. It is the demo stage for the bare-metal
boot path, not a replacement for the Linux kernel.

- Build + verify + stage: `cargo build` runs it, or `cargo run -p namikaze -- kernel` (requires the
  `x86_64-unknown-none` target). The task validates the ELF (class,
  machine, entry point) and proves the Limine request markers survived
  linking, then drops the artifact under `dist/kernel/`.
- The crate is deliberately excluded from the cargo workspace so host
  builds never drag the freestanding entry point onto a hosted linker;
  unit tests run through its lib target (`cargo test --lib`).
- `iso` stages a built kernel at `boot/namikaze-kernel`, which activates
  the "bare-metal kernel" entry in `boot/limine/limine.conf`. The protocol
  constants (base revision 2 tag, request ids, delimited-scan markers)
  are transcribed from the pinned limine-protocol spec that the official
  C template depends on.

## Files

- Source arrives as a kernel.org LTS tarball, verified against the signed
  sha256sums list (VERSION defaults to the current longterm series from
  releases.json); the fetch runs on the build host, not in this tree.
- The build merges the default config with `configs/fragments/hardened.config`
  and the matching `universal-ARCH.config` via the official merge_config tool,
  then produces bzImage/Image/modules/dtbs.
- `configs/fragments/hardened.config` - KSPP-aligned hardening (already
  applied to every architecture).
- `configs/fragments/universal-*.config` - per-architecture device coverage.

## Architectures

| Fragment | Target | Boot image |
|---|---|---|
| universal-x86_64.config | x86_64 | bzImage |
| universal-arm64.config | aarch64 (single multi_v8) | Image |
| universal-armv7.config | armv7 | zImage |
| universal-riscv64.config | riscv64 | Image.gz |
| universal-loongarch64.config | loongarch64 | vmlinuz.efi |
| universal-ppc64le.config | ppc64le | vmlinux (Petitboot) |
| universal-s390x.config | s390x | bzImage (KVM/LPAR, no live USB) |

## Required versions

- `squashfs`, `overlayfs`, `dm-verity`, `dm-crypt` and `dm-integrity` must be
  built-in (`=y`) on every architecture: the live stage and the persistence
  stage depend on them before any module can load.
- Static initramfs binaries (musl) require `CONFIG_RD_*` decompressors and
  devtmpfs; no udev is required for the boot path (by-label links are
  published by the initramfs helper).
