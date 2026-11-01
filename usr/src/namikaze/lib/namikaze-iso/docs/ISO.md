# The OneISO image pipeline

`namikaze-iso` builds the single bootable image of NamikazeOS end to end,
in pure Rust, with no external tools. It runs as steps 5-6 of the dist
pipeline (so a plain `cargo build` produces it) and standalone via
`cargo run -p namikaze -- iso`.

## Stages

1. **stage** - assemble `dist/iso-staging` from repo inputs: the pinned
   Limine binaries (each sha256-checked against `boot/manifest/limine.lock`),
   the boot menu stamped with the bootid seal, per-architecture boot tree
   manifests, the airootfs documentation set, the NamFS demo volume, the
   bare-metal kernel when built, licenses and checksums (see `stage.rs`).
2. **write** - serialize a deterministic ISO9660 + El Torito image with
   the hand-written ECMA-119 writer (see `image.rs`).
3. **verify** - re-parse the image and check every structure and every
   file's SHA-256 against the staging tree (see `verify.rs`).
4. **seal** - emit the SHA-256 sidecar next to the image.
5. **audit** - the independent deep auditor (`audit.rs`, exposed as
   `namikaze-audit`) re-derives the image from the spec with no code
   shared with the writer: descriptor set, both-endian halves, El Torito
   catalog checksum, L/M path table mirroring, Rock Ridge records,
   extent overlaps, staged-file presence and the limine.lock supply
   chain. The pipeline refuses to finish while any check fails.

Output: `dist/NamikazeOS-<version>-oneiso.iso` (+ `.sha256`).

## Boot payload policy

Linux kernel/initramfs/rootfs artifacts come from the kernel build
pipeline (dist/ inputs, CI-supplied). The manifest declares them, the
staging tree documents each slot in `boot/<tree>/`, and Limine hides
menu entries whose files are absent - the image is valid at every stage
of that fill-in process. The bare-metal Rust kernel
(`boot/namikaze-kernel`) and the NamFS demo volume
(`boot/namfs/namikaze-demo.namfs`) are produced by the pipeline itself
and are therefore always present.
