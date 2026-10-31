# xtask iso: the OneISO pipeline

One command builds the distributable image of NamikazeOS:

```sh
cargo xtask iso
```

The pipeline is pure Rust end to end - no ISO tool, no shell script, no
third-party crate. It runs anywhere the workspace builds, including CI,
and produces:

```
dist/NamikazeOS-<version>-oneiso.iso        the image (~4.7 MiB skeleton)
dist/NamikazeOS-<version>-oneiso.iso.sha256 release seal
dist/iso-staging/                           the staged tree it was built from
```

## Pipeline stages

| stage | module | what it does |
| --- | --- | --- |
| stage | `tasks/iso/stage.rs` | assembles `dist/iso-staging` from repo inputs |
| write | `tasks/iso/image.rs` | serializes ISO9660 + El Torito from the tree |
| verify | `tasks/iso/verify.rs` | re-parses the image, checks every file's SHA-256 |
| seal | `tasks/iso/mod.rs` | writes the SHA-256 sidecar |

## What goes onto the image

```
/limine.conf             boot menu, stamped with the bootid seal
/limine-bios-cd.bin      El Torito BIOS boot image (Limine, no-emulation)
/limine-uefi-cd.bin      El Torito UEFI boot image (Limine, no-emulation)
/EFI/BOOT/BOOT*.EFI      USB boot binaries for x86-64, aarch64, riscv64,
                         loongarch64
/boot/<tree>/            one directory per manifest architecture; each
                         carries BOOT-INPUTS.txt naming the exact kernel,
                         initramfs and rootfs artifacts the kernel build
                         pipeline supplies
/.bootid                 the bootid seal (Rock Ridge name preserved)
/LICENSE                 repository license (MPL-2.0)
/README.txt              image guide for the person holding the USB stick
/manifest/               oneiso.toml + limine.lock (reproducibility record)
/payload/limine/         Limine attribution (BSD-2-Clause LICENSE)
/sbom.json               workspace crate inventory
/SHA256SUMS              checksums of every file on the image
```

## Determinism

The writer is deterministic by construction:

- entries are sorted; ISO identifiers are deduplicated per directory
- every timestamp is the fixed epoch 1980-01-01T00:00:00Z
- padding and the 32 KiB system area are zeroed
- the bootid comes from `dist/bootid` when present, so repeated builds of
  one release seal identically

Two consecutive builds of the same staging tree produce byte-identical
images (same SHA-256). This is what makes the `.sha256` sidecar a real
release seal.

## Image format coverage

- ISO9660 level interchange, 2048-byte logical blocks
- primary volume descriptor, El Torito boot record, set terminator
- little- and big-endian path tables (root-first, parents before children)
- Rock Ridge SUSP subset: SP (root), RR marker, NM (real names), PX
  (portable attributes, directories 0555 / files 0444)
- El Torito catalog: validation entry (checksum covers all 16 words),
  no-emulation BIOS entry (`limine-bios-cd.bin`), UEFI section (platform
  0xEF, `limine-uefi-cd.bin`)

## The Limine payload

Limine is the OneISO bootloader (BSD-2-Clause; it is boot firmware, not a
Cargo dependency, so the zero-third-party-dependency rule is untouched).
Its binaries are vendored under `iso/payload/limine/v<version>/` and
verified against `iso/manifest/limine.lock` (version, tarball SHA-256,
per-file SHA-256) before staging; any mismatch fails the build.

## Boot payload policy

Kernel, initramfs and rootfs artifacts are produced by the kernel build
pipeline outside this repository and dropped into `boot/<tree>/` by CI
(or a local kernel build). The manifest (`iso/manifest/oneiso.toml`)
declares the expected path of every artifact per tree. Entries in
`limine.conf` whose files do not resolve are hidden by Limine, so the
image is coherent at every stage of the fill-in process; today it boots
to the bootloader menu with the payload slots documented in-tree.

## Independent verification

Beyond the built-in round-trip reader, the image was cross-checked with
external tooling: `file` reports `ISO 9660 CD-ROM filesystem data
'NAMIKAZE_ISO'`, and a third-party ECMA-119 walk (PVD fields, directory
records, Rock Ridge NM resolution, El Torito checksum and both boot
entries) agrees with the writer on every structure.
