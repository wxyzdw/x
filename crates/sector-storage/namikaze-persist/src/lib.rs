// SPDX-License-Identifier: MPL-2.0
//! namikaze-persist: lifecycle of the LUKS2 encrypted persist volume.
//!
//! The external `cryptsetup` binary is used on purpose: LUKS2 and argon2id
//! must not be re-implemented. Every invocation uses a fixed argv, a cleared
//! environment and stdin for the passphrase, so secrets never appear in
//! process listings or logs. All mutating operations require `--yes`.

#![forbid(unsafe_code)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};

use namikaze_common::{Error, Result};
use namikaze_ffi as ffi;
use namikaze_persist_core::{
    format_argv, parse_luks_dump, validate_passphrase, ArgonProfile, IntegrityMode,
};
use namikaze_rt::fsutil::ZeroBuf;

/// Mapper device name created by `cryptsetup open`.
pub const MAPPER_NAME: &str = "namikaze-persist";
/// Directory the unlocked volume is mounted at during boot.
pub const PERSIST_MOUNT: &str = "/run/persist";

/// Directory layout created inside a freshly formatted persist volume.
pub const PERSIST_DIRS: &[&str] = &[
    "upper", "work", "home", "etc", "var", "root", "packages", "snapshots",
];

fn run_cryptsetup(argv: &[String], passphrase: Option<&ZeroBuf>) -> Result<()> {
    let mut cmd = Command::new("/usr/sbin/cryptsetup");
    cmd.args(&argv[1..])
        .env_clear()
        .stdin(if passphrase.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null());
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::Other(format!("spawn cryptsetup: {e}")))?;
    if let (Some(mut stdin), Some(pass)) = (child.stdin.take(), passphrase) {
        stdin
            .write_all(pass.as_slice())
            .map_err(Error::Io)?;
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(Error::Other(format!(
            "cryptsetup {:?} failed: {}",
            argv.get(1).unwrap_or(&String::new()),
            status
        )));
    }
    Ok(())
}

/// Read a machine resource snapshot for PBKDF scaling (cpus, RAM KiB).
pub fn machine_resources() -> (u32, u64) {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(2);
    let mut ram_kb: u64 = 2 * 1024 * 1024;
    if let Ok(text) = fs::read_to_string("/proc/meminfo") {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                if let Ok(kb) = rest.trim().trim_end_matches(" kB").replace(',', "").parse() {
                    ram_kb = kb;
                }
            }
        }
    }
    (cpus, ram_kb)
}

/// Format `device` as LUKS2 and lay out the persist directory structure.
/// The passphrase is validated, registered for wipe-on-exit, and never
/// written anywhere. No additional key slots are created.
pub fn create_volume(
    device: &Path,
    argon: ArgonProfile,
    integrity: IntegrityMode,
    passphrase: &ZeroBuf,
) -> Result<()> {
    validate_passphrase(passphrase).map_err(|e| Error::Config(e.to_string()))?;
    namikaze_common::register_secret(passphrase.as_slice());

    let (cpus, ram_kb) = machine_resources();
    let argv = format_argv(
        device.to_str().unwrap_or_default(),
        argon,
        integrity,
        cpus,
        ram_kb,
    );
    run_cryptsetup(&argv, Some(passphrase))?;

    run_cryptsetup(
        &[
            "cryptsetup".into(),
            "open".into(),
            "--type".into(),
            "luks2".into(),
            device.to_str().unwrap_or_default().into(),
            "--key-file=-".into(),
            MAPPER_NAME.into(),
        ],
        Some(passphrase),
    )?;

    let mapper = format!("/dev/mapper/{MAPPER_NAME}");
    let mkfs = Command::new("/usr/sbin/mkfs.ext4")
        .args(["-L", "namikaze-persist", "-E", "lazy_itable_init=0", &mapper])
        .env_clear()
        .status()?;
    if !mkfs.success() {
        let _ = run_cryptsetup(
            &["cryptsetup".into(), "close".into(), MAPPER_NAME.into()],
            None,
        );
        return Err(Error::Other("mkfs.ext4 failed".into()));
    }

    let root = Path::new(PERSIST_MOUNT);
    for dir in PERSIST_DIRS {
        fs::create_dir_all(root.join(dir))?;
    }
    fs::write(root.join("persistence.conf"), namikaze_live_core::DEFAULT_CONF)?;

    run_cryptsetup(
        &["cryptsetup".into(), "close".into(), MAPPER_NAME.into()],
        None,
    )?;
    Ok(())
}

/// Open the volume with the given passphrase (slot 0). Returns the mapper
/// path. The caller mounts and later closes via `close_volume`.
pub fn unlock_volume(device: &Path, passphrase: &ZeroBuf) -> Result<String> {
    namikaze_common::register_secret(passphrase.as_slice());
    run_cryptsetup(
        &[
            "cryptsetup".into(),
            "open".into(),
            "--type".into(),
            "luks2".into(),
            device.to_str().unwrap_or_default().into(),
            "--key-file=-".into(),
            MAPPER_NAME.into(),
        ],
        Some(passphrase),
    )?;
    Ok(format!("/dev/mapper/{MAPPER_NAME}"))
}

/// Close the volume and flush buffers.
pub fn close_volume() -> Result<()> {
    ffi::do_sync();
    run_cryptsetup(
        &["cryptsetup".into(), "close".into(), MAPPER_NAME.into()],
        None,
    )
}

/// Read `luksDump` output for a device.
pub fn dump(device: &Path) -> Result<String> {
    let out = Command::new("/usr/sbin/cryptsetup")
        .arg("luksDump")
        .arg(device)
        .env_clear()
        .output()?;
    if !out.status.success() {
        return Err(Error::Other("cryptsetup luksDump failed".into()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Export a LUKS2 header backup. Refuses to write the backup onto the same
/// device that holds the volume: a header copy next to the volume defeats
/// the deniability property of an absent header.
pub fn header_backup(device: &Path, out: &Path) -> Result<()> {
    let dev_meta = device.metadata()?;
    if let Ok(out_meta) = out.metadata() {
        let (a, b) = (dev_meta.dev(), out_meta.dev());
        if a == b {
            return Err(Error::Config(
                "refusing header backup onto the same device as the volume".into(),
            ));
        }
    }
    let status = Command::new("/usr/sbin/cryptsetup")
        .args(["luksHeaderBackup", device.to_str().unwrap_or_default()])
        .arg(out)
        .env_clear()
        .status()?;
    if !status.success() {
        return Err(Error::Other("luksHeaderBackup failed".into()));
    }
    fs::set_permissions(out, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(())
}

/// Restore a LUKS2 header backup onto `device`. Requires `--yes`.
pub fn header_restore(device: &Path, from: &Path, yes: bool) -> Result<()> {
    if !yes {
        return Err(Error::Config(
            "header restore is destructive; pass --yes to confirm".into(),
        ));
    }
    let status = Command::new("/usr/sbin/cryptsetup")
        .args(["luksHeaderRestore", device.to_str().unwrap_or_default()])
        .arg(from)
        .env_clear()
        .status()?;
    if !status.success() {
        return Err(Error::Other("luksHeaderRestore failed".into()));
    }
    Ok(())
}

/// Doctor report: parsed summary plus named checks (name, ok, detail).
pub fn doctor(device: &Path) -> Result<Vec<(String, bool, String)>> {
    let text = dump(device)?;
    let summary = parse_luks_dump(&text);
    Ok(namikaze_persist_core::doctor_checks(&summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_resources_sane() {
        let (cpus, ram) = machine_resources();
        assert!(cpus >= 1);
        assert!(ram > 0);
    }
}
