# NamikazeOS hardware compatibility

One ISO, every machine: each architecture ships exactly one kernel; device
differences are resolved at boot by `namikaze-detect` (initramfs) and
`namikaze-hal` (userland) against the curated board database in
`services/namikaze-hal/src/board_db.rs`.

## Architectures

| Arch | Machines | Boot chain | Status |
|---|---|---|---|
| x86_64 | Any Intel 2008+, AMD; desktops, servers, VMs (virtio/cirrus) | UEFI Secure Boot / Legacy BIOS | stable target |
| aarch64 | See board table | U-Boot + Limine; Raspberry Pi: firmware -> U-Boot -> Limine | stable target |
| armv7 | RPi 2, Odroid XU4, PocketBeagle, Wandboard | U-Boot direct boot | supported |
| armv6 | RPi Zero/1 | U-Boot direct boot | experimental |
| riscv64 | VisionFive 2, Lichee Pi 4A, HiFive Unmatched, Milk-V Pioneer | U-Boot / zero-stage | supported |
| loongarch64 | Loongson 3A5000 / 3A6000 | Loongson UEFI | experimental |
| ppc64le | Raptor Talos II, Blackbird | Petitboot (DTB from firmware) | supported |
| s390x | IBM Z (LPAR/KVM) | zipl / KVM | installed target only |

## aarch64 board profiles

| Profile id | Device | SoC | GPU | WiFi |
|---|---|---|---|---|
| rpi5 | Raspberry Pi 5 | BCM2712 | vc4 (RP1 display) | none onboard |
| rpi4 | Raspberry Pi 4 / 400 / CM4 | BCM2711 | vc4+v3d | brcmfmac43455 |
| rpi3 | Raspberry Pi 3 | BCM2837 | vc4 | brcmfmac43430 |
| rpi-zero-2-w | Raspberry Pi Zero 2 W | BCM2837 | vc4 | brcmfmac43436 |
| rock-5b | Radxa Rock 5B | RK3588 | panthor | optional M.2 E-key (rtw89) |
| orangepi-5 | Orange Pi 5 | RK3588s | panthor | optional |
| rock-5-itx | Radxa Rock 5 ITX | RK3588 | panthor | optional M.2 E-key (rtw89) |
| lubancat-4 | LubanCat 4 | RK3588s | panthor | optional M.2 |
| rock-3a | Radxa Rock 3A | RK3568 | panfrost | optional SDIO |
| radxa-zero-3 | Radxa Zero 3 / 3E | RK3566 | panfrost | optional USB dongle |
| orangepi-pc | Orange Pi PC | H3 | framebuffer | optional xradio |
| pine64 | Pine64 | A64 | lima | optional RTL8723BS |
| pine-h64 | Pine H64 | H6 | panfrost | optional |
| odroid-n2 | Odroid N2/N2+ | S922X | panfrost | optional |
| bananapi-m5 | Banana Pi BPI-M5 | S905X3 (SM1) | panfrost | none onboard |
| le-potato | Libre Computer Le Potato | S905X | framebuffer | none onboard |
| beagleplay | BeaglePlay | AM625 | framebuffer | wl1837 |
| visionfive-2 | StarFive VisionFive 2 | JH7110 | powervr | none onboard |
| lichee-pi-4a | Lichee Pi 4A | TH1520 | powervr | none onboard |
| hifive-unmatched | HiFive Unmatched | FU740 | framebuffer | none onboard |
| milkv-pioneer | Milk-V Pioneer | SG2042 | framebuffer | none onboard |
| apple-m1 | Apple M1 (j274) | T8103 | agx (Asahi userland) | brcmfmac |
| apple-m2 | Apple M2 (j473s) | T6020 | agx (Asahi userland) | brcmfmac |
| jetson-orin-nano | Jetson Orin Nano | Tegra234 | tegra | optional M.2 |
| generic-aarch64 | Any aarch64 DT machine (fallback profile) | varies | framebuffer | varies |

Fixtures: `Quirk::Experimental` boards are excluded from the certified build;
`Quirk::RequiresAsahi` boards need the vendor userland stack installed.

## Driver class coverage

- GPU: i915/xe, amdgpu, nouveau, panfrost/panthor/lima, vc4/v3d, msm/freedreno,
  powervr, Apple agx (experimental), virtio/cirrus/bochs, simpledrm fallback.
- WiFi: iwlwifi, ath9k/ath10k/ath11k/ath12k, rtw88/rtw89, mt76, brcmfmac,
  mwifiex, wl18xx, rtl8xxxu.
- Bluetooth: btusb, hciuart with BCM/RTL H4 attachments.
- Ethernet: r8169, igb/igc/e1000e, stmmac family (dwmac-rk/sun8i/meson8b/
  starfive/thead/sifive), bcmgenet, am65-cpsw-nuss, mvneta.
- Storage: NVMe, AHCI, UAS, SD/eMMC, UFS, virtio-blk.
- Cameras: uvcvideo plus libcamera sensors imx219/imx708/ov5647.
- Firmware: full linux-firmware union packed by the ISO pipeline
  (`namikaze-img`) as a read-only firmware layer; `namikaze-hal firmware-plan BOARD` prints the per-board
  thin set for constrained media.

## Adding a board

1. Append a `board!` row to `board_db.rs` (compatible strings, DTB path,
   firmware dirs, module order, quirks).
2. Add the SoC to `universal-<arch>.config` if the family is not covered yet.
3. Extend `gpu.rs`/`wifi.rs` selection when the SoC needs a new mapping.
4. Add the profile to the tables above and to the CI bring-up matrix.
