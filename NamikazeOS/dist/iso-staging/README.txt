NamikazeOS 3.0.0-alpha.3 OneISO
==========================

One image, every architecture: x86-64, aarch64, armhf, riscv64,
ppc64le and loongarch64 boot trees on a single ISO9660 volume.

volume label : NAMIKAZE_ISO
bootid seal  : aed7716e1759a5a7531f4015b418af1b (/.bootid)
bootloader   : Limine (BIOS El Torito + UEFI El Torito + USB EFI trees)
menu config  : /limine.conf

Boot modes are selected from the Limine menu; entries whose kernel
or rootfs files are not staged are hidden by the bootloader.

Layout
         ------
/limine.conf            boot menu (stamped with bootid + verity)
/limine-bios-cd.bin     El Torito BIOS boot image
/limine-uefi-cd.bin     El Torito UEFI boot image
/EFI/BOOT/BOOT*.EFI     USB UEFI boot binaries
/boot/<tree>/           per-architecture kernel payloads
/.bootid                install-time boot seal
/manifest/              ISO + payload manifests (reproducibility)
/sbom.json              workspace crate inventory
/SHA256SUMS             checksums of every file on this image

Writing to USB: use namikaze-install, which stamps the bootid seal
on the target volume and verifies the image checksums first.
