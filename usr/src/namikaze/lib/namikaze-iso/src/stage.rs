// SPDX-License-Identifier: MPL-2.0
//! stage: assemble the OneISO staging tree under dist/iso-staging.
//!
//! The staging tree is the single input of the ISO writer. Everything the
//! repository actually ships goes in verbatim (Limine bootloader binaries,
//! boot menu config, licenses, manifests); per-architecture boot payload
//! slots (vmlinuz/initrd/rootfs) are declared by `boot/manifest/oneiso.toml`
//! and documented in-tree, because those artifacts are produced by the
//! kernel build pipeline outside this repository.

use std::path::Path;

use namikaze_common::{Error, Result};
use namikaze_rt::sha256::sha256_file_hex;

use super::toml::{self, Section};

/// Assemble the staging tree; returns the parsed manifest sections and the
/// bootid seal string for reporting.
pub(crate) fn populate(root: &Path, staging: &Path) -> Result<(Vec<Section>, String)> {
    let manifest_path = root.join("boot/manifest/oneiso.toml");
    let manifest = toml::parse_file(&manifest_path)?;
    let iso = toml::section(&manifest, "iso", false)
        .ok_or_else(|| Error::Config("oneiso.toml: missing [iso] section".into()))?;
    let label = iso.get("label").unwrap_or("NAMIKAZE_ISO").to_string();

    let bootid = read_or_seal_bootid(root)?;

    // The staging tree starts from scratch on every build (determinism).
    if staging.exists() {
        std::fs::remove_dir_all(staging)?;
    }
    std::fs::create_dir_all(staging)?;

    stage_limine(root, staging)?;
    stage_boot_config(root, staging, &label, &bootid)?;
    stage_boot_trees(staging, &manifest)?;
    stage_kernel(root, staging)?;
    stage_namfs(root, staging)?;
    stage_docs(root, staging, &label, &bootid)?;
    stage_manifests(root, staging)?;
    stage_sbom(root, staging)?;
    stage_checksums(staging)?;

    Ok((manifest, bootid))
}

/// Stage the deterministic NamFS demo volume (dist/namfs) into the boot
/// tree so every ISO ships an openable encrypted-volume example. Absence
/// is not an error: older dist trees simply ship without it.
fn stage_namfs(root: &Path, staging: &Path) -> Result<()> {
    let volume = namikaze_common::util::workspace_dir(root).join("dist/namfs/namikaze-demo.namfs");
    if !volume.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(staging.join("boot/namfs"))?;
    std::fs::copy(&volume, staging.join("boot/namfs/namikaze-demo.namfs"))?;
    println!("stage: NamFS demo volume staged at boot/namfs/namikaze-demo.namfs");
    Ok(())
}

/// Stage the bare-metal Rust kernel when it has been built
/// (the dist pipeline -> dist/kernel/namikaze-kernel). Absence is not
/// an error: the ISO then simply carries no kernel entry payload, and
/// Limine hides the unresolvable menu entry.
fn stage_kernel(root: &Path, staging: &Path) -> Result<()> {
    let built = namikaze_common::util::workspace_dir(root).join("dist/kernel/namikaze-kernel");
    if !built.exists() {
        return Ok(());
    }
    namikaze_common::kernel_image::validate_elf(&std::fs::read(&built)?)
        .map_err(|e| Error::Other(format!("staged kernel rejected: {e}")))?;
    std::fs::copy(&built, staging.join("boot/namikaze-kernel"))?;
    println!("stage: bare-metal kernel staged at boot/namikaze-kernel");
    Ok(())
}

/// Reuse the dist/bootid seal when present so repeated builds of the same
/// release stay byte-identical; generate one otherwise (bootid task).
fn read_or_seal_bootid(root: &Path) -> Result<String> {
    let path = namikaze_common::util::workspace_dir(root).join("dist/bootid");
    if path.exists() {
        let id = std::fs::read_to_string(&path)?.trim().to_string();
        if !id.is_empty() {
            return Ok(id);
        }
    }
    crate::seal::run(root)?;
    Ok(std::fs::read_to_string(&path)?.trim().to_string())
}

/// Verify and copy the pinned Limine binaries (lock-checked).
fn stage_limine(root: &Path, staging: &Path) -> Result<()> {
    let lock_path = root.join("boot/manifest/limine.lock");
    let lock = toml::parse_file(&lock_path)?;
    let meta = toml::section(&lock, "limine", false)
        .ok_or_else(|| Error::Config("limine.lock: missing [limine] section".into()))?;
    let version =
        meta.get("version").ok_or_else(|| Error::Config("limine.lock: missing version".into()))?;
    let payload = root.join("boot/payload/limine").join(format!("v{version}"));

    for entry in toml::sections(&lock, "file") {
        let name = entry
            .get("name")
            .ok_or_else(|| Error::Config("limine.lock: [[file]] missing name".into()))?;
        let expected = entry
            .get("sha256")
            .ok_or_else(|| Error::Config(format!("limine.lock: {name} missing sha256")))?;
        let src = payload.join(name);
        let actual = sha256_file_hex(&src).map_err(|_| {
            Error::Other(format!(
                "limine payload {name} missing; run the payload fetch for v{version}"
            ))
        })?;
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(Error::Other(format!(
                "limine payload {name}: sha256 mismatch (expected {expected}, got {actual})"
            )));
        }
        let role = entry.get("role").unwrap_or("");
        let dest = if role.starts_with("uefi-usb-") {
            staging.join("EFI/BOOT")
        } else {
            staging.to_path_buf()
        };
        std::fs::create_dir_all(&dest)?;
        std::fs::copy(&src, dest.join(name))?;
    }

    // Attribution travels with the payload.
    let license = payload.join("LICENSE");
    if license.exists() {
        std::fs::create_dir_all(staging.join("payload/limine"))?;
        std::fs::copy(&license, staging.join("payload/limine/LICENSE"))?;
        std::fs::write(
            staging.join("payload/limine/README.txt"),
            format!(
                "Limine bootloader binaries, version {version}, BSD-2-Clause.\n\
                 Verified against iso/manifest/limine.lock at ISO build time.\n"
            ),
        )?;
    }
    Ok(())
}

/// Substitute the boot menu template: the bootid seal goes into every
/// cmdline; the dm-verity token is dropped when no root hash exists (the
/// documented dev flow - namikaze-init then skips verification).
fn stage_boot_config(root: &Path, staging: &Path, label: &str, bootid: &str) -> Result<()> {
    let template = root.join("boot/limine/limine.conf");
    let mut conf = std::fs::read_to_string(&template)?;
    conf = conf.replace("@BOOTID@", bootid);
    if conf.contains("@VERITY@") {
        // No squashfs root hash is staged yet: drop the token entirely so
        // namikaze-init runs in its documented unverified mode.
        while let Some(start) = conf.find(" namikaze.verity=@VERITY@") {
            conf.replace_range(start..start + " namikaze.verity=@VERITY@".len(), "");
        }
    }
    // Tokens may remain inside the template's documentation comments; any
    // live (non-comment) token is a substitution bug and fails the build.
    for (lineno, line) in conf.lines().enumerate() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('#') && (line.contains("@VERITY@") || line.contains("@BOOTID@")) {
            return Err(Error::Config(format!(
                "limine.conf line {}: unsubstituted token in live text",
                lineno + 1
            )));
        }
    }
    std::fs::write(staging.join("limine.conf"), conf)?;
    std::fs::write(staging.join(".bootid"), format!("{bootid}\n"))?;
    let _ = label;
    Ok(())
}

/// One BOOT-INPUTS.txt per manifest tree: names the exact artifacts the
/// kernel pipeline drops into boot/<tree>/ (vmlinuz, initrd, rootfs, dtbs,
/// microcode). The entries in limine.conf hide themselves until those files
/// exist, so the ISO boots its available modes on any given machine.
fn stage_boot_trees(staging: &Path, manifest: &[Section]) -> Result<()> {
    for arch in toml::sections(manifest, "arch") {
        let tree = arch
            .get("tree")
            .ok_or_else(|| Error::Config("oneiso.toml: [[arch]] missing tree".into()))?;
        let dir = staging.join("boot").join(tree);
        std::fs::create_dir_all(&dir)?;
        let mut note = String::new();
        note.push_str("NamikazeOS OneISO boot tree\n");
        note.push_str("===========================\n\n");
        note.push_str(&format!("tree: {tree}\nloader: {}\n\n", arch.get("loader").unwrap_or("-")));
        note.push_str("Artifacts supplied by the kernel build pipeline (dist/ inputs):\n");
        for key in ["kernel", "initramfs", "squashfs", "dtbs", "microcode"] {
            if let Some(rel) = arch.get(key) {
                note.push_str(&format!("  boot/{tree}/{rel}\n"));
            }
        }
        note.push_str("\nBoot entries whose files are absent are hidden by the bootloader,\n");
        note.push_str("so this tree degrades gracefully on any given machine.\n");
        std::fs::write(dir.join("BOOT-INPUTS.txt"), note)?;
    }
    Ok(())
}

/// Human-facing text files: README, repository license, boot seal doc.
fn stage_docs(root: &Path, staging: &Path, label: &str, bootid: &str) -> Result<()> {
    // LICENSE is repository meta and lives at the repo root, one level
    // above the workspace directory the tasks run from.
    let license = root.join("LICENSE");
    let license =
        if license.exists() { license } else { root.parent().unwrap_or(root).join("LICENSE") };
    std::fs::copy(license, staging.join("LICENSE"))?;
    let readme = format!(
        "NamikazeOS {version} OneISO\n\
         ==========================\n\n\
         One image, every architecture: x86-64, aarch64, armhf, riscv64,\n\
         ppc64le and loongarch64 boot trees on a single ISO9660 volume.\n\n\
         volume label : {label}\n\
         bootid seal  : {bootid} (/.bootid)\n\
         bootloader   : Limine (BIOS El Torito + UEFI El Torito + USB EFI trees)\n\
         menu config  : /limine.conf\n\n\
         Boot modes are selected from the Limine menu; entries whose kernel\n\
         or rootfs files are not staged are hidden by the bootloader.\n\n\
         Layout\n         ------\n\
         /limine.conf            boot menu (stamped with bootid + verity)\n\
         /limine-bios-cd.bin     El Torito BIOS boot image\n\
         /limine-uefi-cd.bin     El Torito UEFI boot image\n\
         /EFI/BOOT/BOOT*.EFI     USB UEFI boot binaries\n\
         /boot/<tree>/           per-architecture kernel payloads\n\
         /.bootid                install-time boot seal\n\
         /manifest/              ISO + payload manifests (reproducibility)\n\
         /sbom.json              workspace crate inventory\n\
         /SHA256SUMS             checksums of every file on this image\n\n\
         Writing to USB: use namikaze-install, which stamps the bootid seal\n\
         on the target volume and verifies the image checksums first.\n",
        version = namikaze_common::VERSION,
    );
    std::fs::write(staging.join("README.txt"), readme)?;
    Ok(())
}

/// Manifest copies: the ISO documents exactly what built it.
fn stage_manifests(root: &Path, staging: &Path) -> Result<()> {
    std::fs::create_dir_all(staging.join("manifest"))?;
    std::fs::copy(root.join("boot/manifest/oneiso.toml"), staging.join("manifest/oneiso.toml"))?;
    std::fs::copy(root.join("boot/manifest/limine.lock"), staging.join("manifest/limine.lock"))?;
    Ok(())
}

/// Workspace crate inventory; generated on demand if the CI gate has not
/// produced one yet.
fn stage_sbom(root: &Path, staging: &Path) -> Result<()> {
    let src = namikaze_common::util::workspace_dir(root).join("dist/sbom.json");
    if !src.exists() {
        namikaze_common::sbom::run(root)?;
    }
    std::fs::copy(&src, staging.join("sbom.json"))?;
    Ok(())
}

/// SHA256SUMS over every staged file (itself excluded), sorted for a
/// deterministic layout. This is the manifest namikaze-install verifies.
fn stage_checksums(staging: &Path) -> Result<()> {
    let mut files = namikaze_rt::fsutil::walk_files(staging);
    files.sort();
    let mut lines = Vec::new();
    for f in &files {
        let name = f.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if name == "SHA256SUMS" {
            continue;
        }
        let rel = f.strip_prefix(staging).unwrap_or(f).display().to_string();
        lines.push(format!("{}  {rel}", sha256_file_hex(f)?));
    }
    std::fs::write(staging.join("SHA256SUMS"), lines.join("\n") + "\n")?;
    Ok(())
}
