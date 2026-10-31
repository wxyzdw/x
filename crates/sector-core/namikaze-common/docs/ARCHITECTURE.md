# NamikazeOS Architecture

## Layers

```
L0  Kernel (mainline Linux LTS, unmodified; KSPP-hardened config fragments)
L1  Initramfs: namikaze-init (static Rust) with the live-persist stage
L2  System base: Gentoo stage3 + portage + OpenRC
L3  Userland: namikaze-userland (50-tool Rust multi-call core, takeover by
    symlink farm) + namikaze-sh (login shell) + NamikazeOS services:
    guard/anon/seal/watch/cloak/sentinel/usbguard/oomd/ntp/logd/metrics
L4  Desktop: Niri (Wayland) + greetd + foot/waybar/fuzzel/mako, privacy-defaulted
```

## Sector organization

Eleven sectors, fifty crates, one xtask; documentation lives inside each
crate (`<crate>/docs/`), not at the repository root.

```
sector-foundation  rt (std-only toolkit: SHA-256, HMAC, PBKDF2,
                   XChaCha20-Poly1305, JSON, TOML, LZ4-block, HTTP, CLI,
                   logging, entropy)
sector-core        common, ffi, config, oomd, i18n, doctor
sector-platform    init, detect, hal (boot + hardware bring-up)
sector-userland    userland (50-tool multi-call binary), sh (login shell)
sector-storage     live-core, live, persist-core, persist, backup, share,
                   scrub, wipe, decoy, report (data lifecycle)
sector-security    sentinel, watch, seal, guard, vault, secupdate,
                   ledger, sandbox
sector-network     anon, cloak, usbguard, dns, macspin
sector-supply      pkg, secpatch, install, rescue, mirror
sector-desk        firstboot, guest, tune, desk (Niri session factory)
sector-time        chrono (civil time + TZif), ntp (SNTPv4)
sector-observe     logd (hash-chained logs), metrics (/proc sampler)
```

Dependency direction: foundation <- core <- every other sector; no crate
depends on a third-party source (enforced by `cargo xtask dep-guard`).

## Boot chain

```
UEFI SecureBoot (own keyset) or BIOS El Torito
  -> Limine (BSD-2-Clause loader; ${ARCH} macro picks the per-arch tree;
     signed config; locked cmdline)
     menu default: namikaze.live=persist (live persistent system)
  -> kernel (module_sig_force, lockdown=confidentiality)
  -> namikaze-init: mount pseudo-fs, find media via bootid seal, verify
     dm-verity root hash BEFORE pivot, resolve namikaze.live mode:
       persist  -> passphrase prompt, LUKS2 open (argon2id), overlay upper
                   on the volume, allowlist binds/overlays, live.env
       volatile -> tmpfs upper, nothing written back
       session  -> tmpfs upper, flushed on clean shutdown
       ram      -> image copied to RAM, media released
     pivot_root, exec /sbin/init (OpenRC)
  -> OpenRC: namikaze-hal apply, namikaze-guard, namikaze-cloak, oomd,
     ntp, logd, metrics, sentinel; namikaze-pkg lowerdir stack assembled
     before greetd
  -> greetd/agreety (PAM: faillock + namikaze-sentinel) -> niri Wayland session
```

## Userland strategy

Self-hosted Rust userland, no legacy C core toolchain, no third-party
userland source:

1. `namikaze-userland` - the hardened Rust multi-call core (50 tools,
   MPL-2.0, original implementation, zero dependencies). In the packaged
   image every tool name in its TOOLS file is symlinked to it; on portage
   systems the symlink farm lives under /usr/lib/namikaze/userland/bin and
   takes precedence via profile.d.
2. `namikaze-sh` - the login shell: pipelines, redirections, sequencing,
   conditionals, quoting, variable expansion and the builtin set, all pure
   std.
3. Everything beyond that scope is a purpose-built NamikazeOS crate
   (logd for logging, chrono/ntp for time, metrics for observation, mirror
   for packaging); missing utilities become new applets, never imports.

The tool set is single-sourced in the userland `TOOLS` file;
`cargo xtask tools-guard` keeps the registry and ebuild in lockstep and
`cargo xtask gnu-guard` keeps the replaced stack out of the tree. The full
strategy is documented in `crates/sector-userland/namikaze-userland/docs/USERLAND.md`.

## Data tiers

| Tier | Content | Protection |
|------|---------|------------|
| 0 | System binaries | read-only image + dm-verity + signatures (tamper-evident) |
| 1 | Live persistent upper layer, /etc, /var | LUKS2 argon2id (namikaze-persist) |
| 2 | /home | LUKS2 + per-user fscrypt |
| 3 | Secrets | namikaze-vault XChaCha20-Poly1305 containers (PBKDF2-HMAC-SHA256 KDF from namikaze-rt) |
| 4 | Hidden (opt-in) | Detached-header LUKS2 volumes (no header on disk = invisible) |

## Key hierarchy

```
passphrase --argon2id--> LUKS2 keyslot --> volume key --> tier-1/2 devices
slot 0: user passphrase      slot 1: TPM2 PCR policy + PIN      slot 2: recovery code
```

## OneISO

One ISO9660 hybrid carries per-arch kernels/initramfs/squashfs trees
(`/boot/amd64`, `/boot/arm64`, `/boot/armv7`, `/boot/riscv64`, `/boot/ppc64le`)
plus the firmware layer (`firmware.img` mounted at /lib/firmware). Limine
picks the tree via its ${ARCH} macro; the ESP exposes
`BOOTX64.EFI`/`BOOTAA64.EFI`/`BOOTRISCV64.EFI`; ppc64le boots via Petitboot's
ISO9660 kboot parser. `namikaze-detect` then applies a microarch profile
(x86-64-v2/v3/v4, armv8.0/8.1+) and `namikaze-hal` resolves the board plan
(DTB, modules, GPU/WiFi drivers) from the curated database.

## Package flow

`::gentoo` (base) < `::namikaze` overlay (our ebuilds, MPL-2.0) <
`namikaze-pkg` (signed squashfs image layers over the read-only root;
collision-free by construction; verified layers; live refresh or next-boot
assembly; rollback via snapshots) with `namikaze-mirror` serving verified
indexes for a fully offline update loop.

## Image update flow

Whole-image updates bypass the package layer entirely and are handled by
`namikaze-secupdate`:

```
bundle (rootfs.img + sha256 manifest)
  -> stage    : verify manifest, fsynced copy, re-verify staged bytes
  -> apply    : slot rotation current<-staged, previous<-current (renames)
  -> promote  : publish current into the mounted boot partition
  -> rollback : restore previous, offline, no network required
```

All rotations are same-filesystem renames behind fsync barriers, so a power
cut at any point leaves either the old or the new image in `current`, never
a half-written one.
