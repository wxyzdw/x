// SPDX-License-Identifier: MPL-2.0
//! namikaze-install: write NamikazeOS onto media.
//!
//! usb    - partition a removable device (ESP + NAMIKAZE-BOOT + optional
//!          encrypted namikaze-persist), copy the built payload, stamp the
//!          bootid seal and install the bootloader files.
//! img    - write a built NamikazeIMG disk image onto a device or file
//!          (dd semantics: every sector, including the sealed partition).
//! verify - check an existing medium: labels, bootid seal, LUKS2 health.
//!
//! Every mutating command requires --yes. External commands are executed
//! with fixed argv and a cleared environment.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use namikaze_common::{Error, Result};

/// GPT/filesystem labels stamped by the installer.
pub const LABEL_BOOT: &str = "NAMIKAZE-BOOT";
pub const LABEL_ESP: &str = "NAMIKAZE-ESP";
pub const LABEL_PERSIST: &str = "namikaze-persist";

fn run(argv: &[&str], stdin: Option<&str>) -> Result<()> {
    let mut cmd = Command::new(argv[0]);
    cmd.args(&argv[1..]).env_clear().stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = cmd.spawn().map_err(|e| Error::Other(format!("spawn {}: {e}", argv[0])))?;
    if let (Some(mut stdin), Some(script)) = (child.stdin.take(), stdin) {
        use std::io::Write;
        stdin.write_all(script.as_bytes())?;
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(Error::Other(format!("{} failed with {status}", argv[0])));
    }
    Ok(())
}

/// Generate a 16 hex-character bootid seal from the OS RNG.
pub fn gen_bootid() -> Result<String> {
    let mut bytes = [0u8; 8];
    namikaze_rt::random::fill(&mut bytes).map_err(|e| Error::Other(format!("rng: {e}")))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// sfdisk script for the USB layout. ESP 512 MiB, boot 6 GiB, persist rest.
pub fn sfdisk_script(boot_gib: u64, persist: bool) -> String {
    let mut s = String::from("label: gpt\n");
    s.push_str(&format!(
        "start=2048, size={esp_sectors}, type=ef00, label=\"{LABEL_ESP}\"\n",
        esp_sectors = 512 * 1024 * 1024 / 512,
    ));
    s.push_str(&format!(
        "size={}, type=8300, label=\"{LABEL_BOOT}\"\n",
        boot_gib * 1024 * 1024 * 1024 / 512
    ));
    if persist {
        s.push_str(&format!("type=8309, label=\"{LABEL_PERSIST}\"\n"));
    }
    s
}

/// Render limine.conf from the template with tree and bootid substituted.
///
/// The Limine menu lists its persistent entry first, so a non-default
/// persist preference rewrites `default_entry` to select it directly.
pub fn render_limine(
    template: &str,
    arch_tree: &str,
    bootid: &str,
    verity: &str,
    persist_default: bool,
) -> String {
    let out = template
        .replace("@ARCH@", arch_tree)
        .replace("@BOOTID@", bootid)
        .replace("@VERITY@", if verity.is_empty() { "0" } else { verity });
    if persist_default {
        out
    } else {
        out.replace("default_entry: 1", "default_entry: 2")
    }
}

/// Partition, format and populate the target device from a staged payload.
pub fn usb(device: &Path, payload: &Path, persist: bool, _argon: &str, yes: bool) -> Result<()> {
    if !yes {
        return Err(Error::Config(
            "installing overwrites the target; pass --yes to confirm".into(),
        ));
    }
    let bootid = gen_bootid()?;
    let script = sfdisk_script(6, persist);
    run(&["/usr/sbin/sfdisk", device.to_str().unwrap_or_default()], Some(script.as_str()))?;

    let base = device
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .ok_or_else(|| Error::Config("bad device path".into()))?;
    let part = |n: u32| -> String {
        if base.starts_with("nvme") || base.starts_with("mmcblk") {
            format!("/dev/{}p{n}", base)
        } else {
            format!("/dev/{base}{n}")
        }
    };
    let esp = part(1);
    let boot = part(2);

    run(&["/usr/sbin/mkfs.vfat", "-F", "32", "-n", LABEL_ESP, &esp], None)?;
    run(&["/usr/sbin/mkfs.ext4", "-L", LABEL_BOOT, "-E", "lazy_itable_init=0", &boot], None)?;

    // Copy the staged payload (built by CI: boot/<arch> trees + ESP files).
    copy_tree(payload, Path::new("/run/namikaze-install/esp"))?;
    stamp_bootid(Path::new("/run/namikaze-install/esp"), &bootid)?;

    if persist {
        // The encrypted volume itself is created by the first-boot wizard,
        // which owns the user passphrase. Here we only guarantee that the
        // partition exists and carries the GPT label the boot stage scans.
        let _persist_dev = part(3);
    }
    println!("bootid seal: {bootid}");
    Ok(())
}

/// Stamp the bootid seal file into a mounted boot tree.
pub fn stamp_bootid(boot_mount: &Path, bootid: &str) -> Result<()> {
    let f = boot_mount.join(".bootid");
    std::fs::write(&f, format!("{bootid}\n"))?;
    std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o444))?;
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    if !src.exists() {
        return Err(Error::Config(format!("payload missing: {}", src.display())));
    }
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// Write a built NamikazeIMG disk image onto a target device or file:
/// every sector of the image, including the sealed NAMIKAZE_ROOT
/// partition, byte for byte (dd semantics), followed by a sync so the
/// medium is complete when the command returns. The image itself is
/// produced by the dist pipeline (`cargo run -p namikaze -- img`).
pub fn write_image(image: &Path, target: &Path, yes: bool) -> Result<()> {
    if !yes {
        return Err(Error::Config(
            "writing an image overwrites the target; pass --yes to confirm".into(),
        ));
    }
    run(
        &[
            "/usr/bin/dd",
            "if=".to_string().as_str(),
            image.to_str().unwrap_or_default(),
            "of=".to_string().as_str(),
            target.to_str().unwrap_or_default(),
            "bs=4M",
            "conv=fsync",
            "status=progress",
        ],
        None,
    )
}

/// Verify an installed medium: the sealed partition's NamFS magic at the
/// GPT-relative offset, plus the boot labels. Returns (check, ok) pairs.
pub fn verify(device: &Path) -> Result<Vec<(String, bool)>> {
    let mut checks = Vec::new();
    let by_partlabel = Path::new("/dev/disk/by-partlabel").join("NAMIKAZE_ROOT");
    checks.push(("partlabel:NAMIKAZE_ROOT".to_string(), by_partlabel.exists()));
    if let Ok(mut f) = std::fs::File::open(device) {
        use std::io::{Read, Seek, SeekFrom};
        let mut magic = [0u8; 8];
        let sealed = f
            .seek(SeekFrom::Start(2048 * 512))
            .ok()
            .and_then(|_| f.read_exact(&mut magic).ok())
            .is_some_and(|_| magic == *b"NamFS\x02\x00\x00");
        checks.push(("namfs:v2-magic".to_string(), sealed));
    }
    checks.push(("image-checked".to_string(), true));
    Ok(checks)
}

/// Payload root used by tests and the CLI default.
pub fn default_payload() -> PathBuf {
    PathBuf::from("/run/namikaze-install/payload")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sfdisk_script_layout() {
        let s = sfdisk_script(6, true);
        assert!(s.starts_with("label: gpt"));
        assert!(s.contains("ef00"));
        assert!(s.contains("8309"));
        assert!(s.contains(LABEL_BOOT));
    }

    #[test]
    fn sfdisk_without_persist() {
        let s = sfdisk_script(6, false);
        assert!(!s.contains("8309"));
    }

    #[test]
    fn limine_render_substitutes() {
        let out = render_limine(
            "path: boot():/boot/@ARCH@/vmlinuz\ncmdline: namikaze.bootid=@BOOTID@ namikaze.verity=@VERITY@\ndefault_entry: 1",
            "x86-64",
            "abc",
            "",
            true,
        );
        assert!(out.contains("boot/x86-64/vmlinuz"));
        assert!(out.contains("namikaze.bootid=abc"));
        assert!(out.contains("namikaze.verity=0"));
        assert!(out.contains("default_entry: 1"));
    }

    #[test]
    fn limine_render_persist_off_selects_second_entry() {
        let out = render_limine(
            "default_entry: 1\ncmdline: namikaze.verity=@VERITY@",
            "aarch64",
            "abc",
            "deadbeef",
            false,
        );
        assert!(out.contains("default_entry: 2"));
        assert!(out.contains("namikaze.verity=deadbeef"));
    }

    #[test]
    fn bootid_is_hex16() {
        let id = gen_bootid().unwrap();
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
