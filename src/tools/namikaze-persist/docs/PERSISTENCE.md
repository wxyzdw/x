# NamikazeOS live persistent system

The single ISO boots live; a LUKS2 volume holds everything that changes. The
system image itself stays read-only and dm-verity sealed. Only the user who
created the passphrase can open the volume. Wrong passphrases never destroy
data - they conceal it (P9).

## Media layout (namikaze-install usb --persist)

```
p1  NAMIKAZE-ESP      FAT32    512 MiB   EFI/BOOT, Limine
p2  NAMIKAZE-BOOT     ext4     6 GiB     boot/<arch> trees, rootfs.img,
                                          firmware.img, /.bootid seal
p3  namikaze-persist  LUKS2    rest      see below
```

Persist volume (ext4 inside LUKS2, argon2id):

```
upper/           overlayfs upper layer for the root
work/            overlayfs work directory
home/ etc/ var/ root/   bind/overlay targets from the allowlist
packages/        signed image layers from namikaze-pkg
snapshots/       namikaze-live snapshot archives
persistence.conf allowlist
```

## Boot flow

```
Firmware -> Limine (${ARCH} macro selects the per-arch tree) -> kernel + initramfs
  namikaze-detect: DT/DMI/CPU -> /run/namikaze/hardware.env
  live stage (namikaze-init):
    1. locate boot media via the bootid seal (namikaze.bootid)
    2. mount rootfs.img read-only (dm-verity verified when a hash is given)
    3. resolve namikaze.live mode; on persist: prompt for the passphrase,
       cryptsetup open (argon2id), mount ext4, validate persistence.conf
    4. assemble the overlay (upper on the volume) and apply the allowlist
    5. write /run/namikaze/live.env, pivot, exec /sbin/init
  userland: namikaze-hal apply, namikaze-guard, namikaze-cloak, Niri (Wayland)
```

Fallback policy: `namikaze.persist.fallback=volatile` (default) continues the
boot volatile when the volume is missing or the passphrase fails; `panic`
stops instead. Five passphrase attempts with exponential backoff; every
failure is recorded into the Sentinel early-event log.

## Modes

| Mode | Upper layer | Survives reboot | Trace left |
|---|---|---|---|
| persist | LUKS2 volume | yes | on your own encrypted volume |
| volatile | tmpfs | no | none |
| ram | tmpfs + image in RAM | no | none; media can be pocketed |
| session | tmpfs, flushed at clean shutdown | only clean shutdowns | on your own encrypted volume |

## Allowlist rules

- `bind` entries live directly on the volume; `overlay` entries merge over
  the read-only image with their own upper/work pair.
- `/usr`, `/boot`, `/lib`, `/lib64`, `/bin`, `/sbin` are denied: system
  integrity stays verifiable.
- Package changes are image layers: `namikaze-pkg install` records a signed
  squashfs layer, `namikaze-live refresh` pivots into the new stack (or the
  next boot assembles it).

## Security properties

- LUKS2 + argon2id scaled by `namikaze-persist-core` (memory-hard; GPU/ASIC
  guessing is uneconomical). Passphrases never appear in argv or logs.
- No extra key slots are created automatically; slot 7 is reserved for
  explicit recovery keys.
- No header backup by default: without the header the volume is invisible on
  the disk (plausible deniability). `namikaze-persist header-backup` writes
  one to a second device and refuses to store it on the same device.
- TRIM is off by default (`namikaze.persist.trim=on` to trade usage-pattern
  leakage for flash wear).
- Session mode on a shared machine leaves nothing when the power is cut.

## Verification

The QEMU persistence smoke test (CI workflow) boots the ISO twice: create the
volume, write a proof file, reboot, unlock, assert the file survived.
