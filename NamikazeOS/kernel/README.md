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

## Files

- `fetch.sh [VERSION]` - download and verify the LTS tarball from kernel.org
  (uses the signed sha256sums list; VERSION defaults to the current longterm
  series from releases.json).
- `build.sh ARCH` - defconfig + `hardened.config` + `universal-ARCH.config`
  merged with the official merge_config tool, then bzImage/Image/modules/dtbs.
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
