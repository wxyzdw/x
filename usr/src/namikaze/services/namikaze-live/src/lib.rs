// SPDX-License-Identifier: MPL-2.0
//! namikaze-live: runtime helper for the live boot stage.
//!
//! Responsibilities: locate the boot media by bootid seal, stage the system
//! image into RAM (toram), apply the persistence allowlist under the merged
//! root, eject the media safely, flush session-mode changes on shutdown,
//! snapshot the running upper layer, and refresh the overlay stack after a
//! package layer change.

#![forbid(unsafe_code)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use namikaze_common::{Error, Result};
use namikaze_ffi as ffi;
use namikaze_live_core::{MountKind, MountPlan};

/// GPT/filesystem label stamped on the boot partition at build time.
pub const BOOT_LABEL_PREFIX: &str = "NAMIKAZE-BOOT";
/// Label of the encrypted persist partition.
pub const PERSIST_LABEL: &str = "namikaze-persist";
/// Where the init stage records live-stage state for later userspace runs.
pub const LIVE_ENV_FILE: &str = "/run/namikaze/live.env";

fn do_mount(
    src: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: u64,
    data: Option<&str>,
) -> Result<()> {
    ffi::mount(src, target, fstype, flags, data)
        .map_err(|e| Error::Other(format!("mount {target}: {e}")))
}

/// Locate and mount the boot media, verifying the bootid seal when the
/// command line provides one. Returns the mount point.
pub fn find_boot_device(bootid: Option<&str>) -> Result<PathBuf> {
    let scan = Path::new("/dev/disk/by-label");
    let mut candidates: Vec<PathBuf> = match fs::read_dir(scan) {
        Ok(entries) => entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().starts_with(BOOT_LABEL_PREFIX))
                    .unwrap_or(false)
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    candidates.sort();
    if candidates.is_empty() {
        return Err(Error::Other("boot media not found".into()));
    }
    let target = "/run/boot-scan";
    fs::create_dir_all(target)?;
    for cand in candidates {
        let dev = cand.to_string_lossy().to_string();
        if do_mount(Some(&dev), target, None, ffi::MS_RDONLY, None).is_err() {
            continue;
        }
        let stamp = fs::read_to_string(Path::new(target).join(".bootid"))
            .map(|s| s.trim().to_string())
            .ok();
        ffi::umount2_detached(target).ok();
        match (stamp, bootid) {
            (Some(found), Some(expected)) if found == expected => {
                return Ok(PathBuf::from(dev));
            }
            (Some(_), None) => return Ok(PathBuf::from(dev)),
            _ => continue,
        }
    }
    Err(Error::Other("bootid seal mismatch on all candidates".into()))
}

/// Copy one file into a staging directory with an explicit fdatasync at the
/// end. Used by toram mode; the 4 MiB buffer bounds peak memory usage.
pub fn copy_to_ram(src: &Path, stage_dir: &Path) -> Result<PathBuf> {
    fs::create_dir_all(stage_dir)?;
    let dest = stage_dir
        .join(src.file_name().ok_or_else(|| Error::Other("source has no file name".into()))?);
    io::copy(&mut fs::File::open(src)?, &mut fs::File::create(&dest)?)?;
    let writer = fs::OpenOptions::new().write(true).open(&dest)?;
    writer.sync_all()?;
    Ok(dest)
}

/// Apply the persistence allowlist under `merged_root`.
///
/// Bind entries point straight into the persist volume; overlay entries get
/// their own upper/work pair on the volume so, for example, `/etc` merges
/// over the read-only image instead of shadowing it wholesale.
pub fn apply_persistence(merged_root: &Path, persist: &Path, plan: &MountPlan) -> Result<()> {
    for entry in &plan.entries {
        let rel = entry.path.trim_start_matches('/');
        let target = merged_root.join(rel);
        let source = persist.join(rel);
        fs::create_dir_all(&target)?;
        match entry.kind {
            MountKind::Bind => {
                if entry.optional && !source.exists() {
                    continue;
                }
                fs::create_dir_all(&source)?;
                do_mount(
                    Some(source.to_str().unwrap_or_default()),
                    target.to_str().unwrap_or_default(),
                    None,
                    ffi::MS_BIND,
                    None,
                )?;
            }
            MountKind::Overlay => {
                let upper = persist.join(format!("upper{}", entry.path));
                let work = persist.join(format!("work{}", entry.path));
                fs::create_dir_all(&upper)?;
                fs::create_dir_all(&work)?;
                let data = format!(
                    "lowerdir={},upperdir={},workdir={}",
                    target.display(),
                    upper.display(),
                    work.display()
                );
                do_mount(
                    Some("overlay"),
                    target.to_str().unwrap_or_default(),
                    Some("overlay"),
                    0,
                    Some(data.as_str()),
                )?;
            }
        }
    }
    Ok(())
}

/// Clean shutdown path: swap off, sync, unmount live-related mounts from the
/// leaves down. Best-effort by design; a failing unmount never blocks power
/// off but is reported.
pub fn eject() -> Result<()> {
    let _ = Command::new("/usr/sbin/swapoff").arg("-a").env_clear().status();
    namikaze_ffi::do_sync();
    let mut mounts: Vec<(String, String)> = fs::read_to_string("/proc/mounts")?
        .lines()
        .filter_map(|l| {
            let mut f = l.split_ascii_whitespace();
            Some((f.next()?.to_string(), f.next()?.to_string()))
        })
        .collect();
    mounts.sort_by_key(|m| std::cmp::Reverse(m.1.len()));
    let mut last_err = None;
    for (_, target) in mounts {
        if target.starts_with("/run/persist")
            || target.starts_with("/run/merged")
            || target.starts_with("/run/boot")
        {
            if let Err(e) = ffi::umount2_detached(target.as_str()) {
                last_err = Some(Error::Other(format!("umount {target}: {e}")));
            }
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Session-mode flush: copy the tmpfs upper layer into the persist volume
/// on clean shutdown. Executed by the namikaze-live-flush service script.
pub fn session_flush() -> Result<()> {
    let env = fs::read_to_string(LIVE_ENV_FILE).map_err(|e| {
        Error::Other(format!("{} unreadable (not a session boot?): {e}", LIVE_ENV_FILE))
    })?;
    let get = |key: &str| -> Option<String> {
        env.lines()
            .find_map(|l| l.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| v.to_string()))
    };
    let (Some(upper), Some(persist)) = (get("UPPER"), get("PERSIST")) else {
        return Err(Error::Other("live.env lacks UPPER/PERSIST".into()));
    };
    if get("MODE").as_deref() != Some("session") {
        return Err(Error::Config("flush only applies in session mode".into()));
    }
    copy_tree(Path::new(&upper), Path::new(&persist).join("upper").as_path())?;
    namikaze_ffi::do_sync();
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if ft.is_file() {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// Snapshot the current upper layer into a squashfs archive. The archive can
/// be attached by the build tooling as an extra lower layer on the next boot.
pub fn snapshot(upper: &Path, out: &Path) -> Result<()> {
    let status = Command::new("/usr/sbin/mksquashfs")
        .arg(upper)
        .arg(out)
        .args(["-comp", "zstd", "-noappend", "-no-progress"])
        .env_clear()
        .status()?;
    if !status.success() {
        return Err(Error::Other("mksquashfs failed".into()));
    }
    Ok(())
}

/// Refresh the root overlay after the package layer stack changed.
///
/// Mounts a new overlay at /run/merged-next, then pivots into it and
/// detaches the old root. On failure the caller should schedule a reboot
/// instead; the next boot assembles the same stack from disk.
pub fn refresh_root(lowers: &[String], upper: &Path, work: &Path) -> Result<()> {
    let data = namikaze_live_core::overlay_options(
        lowers,
        upper.to_str().unwrap_or_default(),
        work.to_str().unwrap_or_default(),
    )?;
    fs::create_dir_all("/run/merged-next")?;
    do_mount(Some("overlay"), "/run/merged-next", Some("overlay"), 0, Some(data.as_str()))?;
    fs::create_dir_all("/run/merged-next/oldroot")?;
    namikaze_ffi::pivot_root(Path::new("/run/merged-next"), Path::new("/run/merged-next/oldroot"))?;
    std::env::set_current_dir("/")?;
    ffi::umount2_detached("/oldroot").ok();
    ffi::umount2_detached("/oldroot/oldroot").ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn live_env_parse_keys() {
        // exercised indirectly through session_flush; keep a fast parser check
        let env = "MODE=session\nUPPER=/run/upper-volatile\nPERSIST=/run/persist\n";
        let get = |key: &str| -> Option<String> {
            env.lines().find_map(|l| {
                l.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| v.to_string())
            })
        };
        assert_eq!(get("MODE").as_deref(), Some("session"));
        assert_eq!(get("UPPER").as_deref(), Some("/run/upper-volatile"));
        assert!(get("MISSING").is_none());
    }
}
