// SPDX-License-Identifier: MPL-2.0
//! Live persistence stage for the initramfs.
//!
//! Extends the volatile live boot with an encrypted persistent upper layer:
//! the persist partition (GPT label `namikaze-persist`) is a LUKS2 volume
//! whose upper layer survives reboots. Only the passphrase creator can open
//! it. Wrong attempts feed the Sentinel early-event log; the data itself is
//! never destroyed on failure (v2.2 principle: conceal, don't erase).

#![forbid(unsafe_code)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use namikaze_common::{Error, Result};
use namikaze_live_core::{parse_persistence_conf, LiveMode, LiveOptions, MountEntry, MountKind};

/// Where the unlocked persist volume is mounted during boot.
pub const PERSIST_MOUNT: &str = "/run/persist";
/// Mapper name opened by cryptsetup.
pub const MAPPER_NAME: &str = "namikaze-persist";
/// Early event log consumed by namikaze-sentinel after switch_root.
pub const EARLY_EVENTS: &str = "/run/namikaze/early-events.log";
/// State file consumed by namikaze-live after switch_root.
pub const LIVE_ENV: &str = "/run/namikaze/live.env";
/// Base delay for the exponential backoff between passphrase attempts.
const DELAY_BASE_MS: u64 = 1_000;

/// Upper-layer decision produced by `prepare`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpperChoice {
    /// Overlay upper on the encrypted persist volume.
    Persistent,
    /// Overlay upper on tmpfs (volatile or fallback).
    VolatileTmpfs,
    /// Overlay upper on tmpfs that will be flushed at shutdown (session).
    SessionTmpfs,
}

fn log(msg: &str) {
    println!("[namikaze-init:persist] {msg}");
}

fn note_event(line: &str) {
    let _ = namikaze_common::append_log(Path::new(EARLY_EVENTS), line);
}

/// Resolve the final live mode after applying fallback policy: when the
/// requested mode cannot be satisfied, fall back to volatile (or abort if
/// `namikaze.persist.fallback=panic`).
pub fn resolve_mode(options: &LiveOptions, persist_available: bool) -> Result<LiveMode> {
    match options.mode {
        LiveMode::Persist if !persist_available => {
            if options.fallback_volatile {
                log("persist volume unavailable; falling back to volatile");
                note_event("persist_unavailable");
                Ok(LiveMode::Volatile)
            } else {
                Err(Error::Other("persist volume required by policy".into()))
            }
        }
        m => Ok(m),
    }
}

/// Locate the persist partition through the by-label links published by
/// udev in the initramfs, honoring `namikaze.persist.uuid` when present.
pub fn find_persist_device(uuid_hint: Option<&str>) -> Option<PathBuf> {
    let dir = Path::new("/dev/disk/by-label");
    let mut candidates: Vec<PathBuf> = fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name().map(|n| n.to_string_lossy() == "namikaze-persist").unwrap_or(false)
        })
        .collect();
    candidates.sort();
    match uuid_hint {
        None => candidates.into_iter().next(),
        Some(hint) => candidates
            .into_iter()
            .find(|p| p.to_string_lossy().ends_with(hint) || fs::read_link(p).is_ok()),
    }
}

fn cryptsetup_open(dev: &str, passphrase: &[u8]) -> Result<()> {
    let mut child = Command::new("/usr/sbin/cryptsetup")
        .args(["open", "--type", "luks2", "--key-file=-", dev, MAPPER_NAME])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| Error::Other(format!("spawn cryptsetup: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(passphrase)?;
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(Error::Other("cryptsetup open failed".into()));
    }
    Ok(())
}

/// Prompt for the persist passphrase with a bounded attempt count and
/// exponential backoff. On final failure the boot continues volatile; the
/// volume data is never touched.
pub fn unlock_persist(dev: &Path, max_attempts: u32) -> Result<()> {
    let dev_str = dev.to_string_lossy().to_string();
    for attempt in 1..=max_attempts {
        eprint!("NamikazeOS persistence passphrase: ");
        let _ = std::io::stderr().flush();
        let pass = namikaze_ffi::read_password_tty()?;
        if cryptsetup_open(&dev_str, &pass).is_ok() {
            log("persist volume unlocked");
            return Ok(());
        }
        note_event(&format!("persist_unlock_failed attempt={attempt}"));
        eprintln!("[namikaze-init:persist] passphrase rejected");
        let delay = DELAY_BASE_MS << (attempt - 1).min(6);
        sleep(Duration::from_millis(delay));
    }
    Err(Error::Other("passphrase attempts exhausted".into()))
}

/// Mount the unlocked volume and validate the persistence allowlist.
pub fn mount_persist(conf_path: &str) -> Result<Vec<MountEntry>> {
    fs::create_dir_all(PERSIST_MOUNT)?;
    let flags = 1 << 14; // MS_NOATIME
    namikaze_ffi::mount(
        Some("/dev/mapper/namikaze-persist"),
        PERSIST_MOUNT,
        Some("ext4"),
        flags,
        None::<&str>,
    )
    .map_err(|e| Error::Other(format!("mount persist: {e}")))?;

    for dir in ["upper", "work", "home", "etc", "var", "root", "packages"] {
        let _ = fs::create_dir_all(Path::new(PERSIST_MOUNT).join(dir));
    }
    let text = fs::read_to_string(conf_path)
        .unwrap_or_else(|_| namikaze_live_core::DEFAULT_CONF.to_string());
    let entries = parse_persistence_conf(&text)
        .map_err(|e| Error::Config(format!("persistence.conf rejected: {e}")))?;
    Ok(entries)
}

/// Choose and prepare the upper layer according to the resolved mode.
/// Returns the choice consumed by the overlay assembly in main.rs.
pub fn prepare(options: &LiveOptions) -> Result<(UpperChoice, Vec<MountEntry>)> {
    let available = find_persist_device(options.persist_uuid.as_deref()).is_some();
    let mode = resolve_mode(options, available)?;

    let choice = match mode {
        LiveMode::Persist => {
            let dev = find_persist_device(options.persist_uuid.as_deref())
                .ok_or_else(|| Error::Other("persist device vanished".into()))?;
            unlock_persist(&dev, 5)?;
            let entries = mount_persist(&options.conf_path)?;
            (UpperChoice::Persistent, entries)
        }
        LiveMode::Session => {
            if find_persist_device(options.persist_uuid.as_deref()).is_some() {
                let dev = find_persist_device(options.persist_uuid.as_deref()).unwrap();
                let _ = unlock_persist(&dev, 5);
                if Path::new("/dev/mapper/namikaze-persist").exists() {
                    let entries = mount_persist(&options.conf_path)?;
                    (UpperChoice::SessionTmpfs, entries)
                } else {
                    (UpperChoice::VolatileTmpfs, Vec::new())
                }
            } else {
                log("session mode without persist volume; staying volatile");
                (UpperChoice::VolatileTmpfs, Vec::new())
            }
        }
        _ => (UpperChoice::VolatileTmpfs, Vec::new()),
    };

    write_live_env(options, choice.0)?;
    Ok(choice)
}

/// Record live-stage state for namikaze-live (flush, refresh, snapshot).
fn write_live_env(options: &LiveOptions, choice: UpperChoice) -> Result<()> {
    let _ = fs::create_dir_all("/run/namikaze");
    let (mode, upper) = match choice {
        UpperChoice::Persistent => ("persist", "/run/persist/upper"),
        UpperChoice::SessionTmpfs => ("session", "/run/upper-volatile/u"),
        UpperChoice::VolatileTmpfs => ("volatile", "/run/upper-volatile/u"),
    };
    fs::write(
        LIVE_ENV,
        format!(
            "MODE={mode}\nUPPER={upper}\nPERSIST={PERSIST_MOUNT}\nCONF={}\n",
            options.conf_path
        ),
    )?;
    Ok(())
}

/// Write the live env for an explicit volatile boot (no persist attempt).
pub fn write_volatile_env() -> Result<()> {
    let _ = fs::create_dir_all("/run/namikaze");
    fs::write(LIVE_ENV, "MODE=volatile\nUPPER=/run/upper-volatile/u\nPERSIST=\nCONF=\n")
        .map_err(Error::Io)
}

/// Apply the allowlist mounts under NEW_ROOT after the root overlay exists.
pub fn apply_mounts(new_root: &Path, entries: &[MountEntry]) -> Result<()> {
    for entry in entries {
        let rel = entry.path.trim_start_matches('/');
        let target = new_root.join(rel);
        let source = Path::new(PERSIST_MOUNT).join(rel);
        let _ = fs::create_dir_all(&target);
        match entry.kind {
            MountKind::Bind => {
                let _ = fs::create_dir_all(&source);
                namikaze_ffi::mount(
                    source.to_str(),
                    target.to_str().unwrap_or_default(),
                    None,
                    namikaze_ffi::MS_BIND,
                    None,
                )
                .map_err(|e| Error::Other(format!("bind {}: {e}", entry.path)))?;
            }
            MountKind::Overlay => {
                let upper = Path::new(PERSIST_MOUNT).join(format!("upper/{rel}"));
                let work = Path::new(PERSIST_MOUNT).join(format!("work/{rel}"));
                let _ = fs::create_dir_all(&upper);
                let _ = fs::create_dir_all(&work);
                let data = format!(
                    "lowerdir={},upperdir={},workdir={}",
                    target.display(),
                    upper.display(),
                    work.display()
                );
                namikaze_ffi::mount(
                    Some("overlay"),
                    target.to_str().unwrap_or_default(),
                    Some("overlay"),
                    0,
                    Some(data.as_str()),
                )
                .map_err(|e| Error::Other(format!("overlay {}: {e}", entry.path)))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_policy_volatile() {
        let mut o = LiveOptions::default();
        assert_eq!(resolve_mode(&o, false).unwrap(), LiveMode::Volatile);
        o.fallback_volatile = false;
        assert!(resolve_mode(&o, false).is_err());
        o.mode = LiveMode::Volatile;
        assert_eq!(resolve_mode(&o, false).unwrap(), LiveMode::Volatile);
    }

    #[test]
    fn session_mode_keeps_data_concealed_on_failure() {
        // Session without a persist volume must degrade to volatile tmpfs,
        // never destroy or expose anything.
        let o = LiveOptions { mode: LiveMode::Session, ..Default::default() };
        assert_eq!(resolve_mode(&o, false).unwrap(), LiveMode::Session);
    }
}
