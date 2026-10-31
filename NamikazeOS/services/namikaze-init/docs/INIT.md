# namikaze-init

PID 1 of the NamikazeOS initramfs: the single-ISO, multi-arch boot
sequence, in safe Rust.

## Boot sequence

1. Mount pseudo filesystems so the environment is usable.
2. Parse the kernel command line (`namikaze.*` and standard keys).
3. Locate the ISO medium by label (`NAMIKAZE_ISO`) and mount it
   read-only.
4. Mount the per-architecture squashfs, verifying the dm-verity root
   hash BEFORE any pivot (tamper-evident live root).
5. Build a writable tmpfs overlay on top of the read-only root.
6. Move pseudo filesystems into the new root, `pivot_root`, exec
   OpenRC.

On unrecoverable failure the init drops to an emergency shell if one is
embedded in the initramfs, otherwise it halts with a clear message.

## Live modes

The `namikaze.live-mode` selection maps to `namikaze_live_core::LiveMode`:
`persist` (LUKS-backed upper layer via `namikaze-persist`), `volatile`
(fresh tmpfs every boot) and `session` (upper layer kept for the login
session, flushed by `namikaze-live session-flush`).

## Why an OS-specific init

The generic initramfs tools verify nothing and understand nothing about
the dm-verity + overlay + multi-arch layout this distribution ships.
Owning the 300 lines of boot logic in safe Rust means the verification
order (hash before pivot, before any writable path exists) is enforced
by the same code review and CI gate as everything else, and the boot
path compiles for every target architecture in the workspace.
