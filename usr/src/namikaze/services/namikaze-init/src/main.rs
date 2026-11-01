// SPDX-License-Identifier: MPL-2.0
//! namikaze-init: PID 1 of the NamikazeOS initramfs.
//!
//! Boot sequence (NamikazeIMG: one disk, one partition, everything
//! encrypted):
//!   1. Mount pseudo filesystems so the environment is usable.
//!   2. Parse the kernel command line (namikaze.* and standard keys).
//!   3. Find the sealed NAMIKAZE_ROOT partition, stage it into /run and
//!      open it as a NamFS volume - the passphrase gate runs here,
//!      before any file is touched.
//!   4. Read the rootfs.nampack entry and unpack every verified file
//!      into a tmpfs root (modes included).
//!   5. Build a writable overlay on top of the unpacked root.
//!   6. Move pseudo filesystems into the new root, pivot_root, exec OpenRC.
//!
//! On unrecoverable failure the init drops to an emergency shell if one is
//! embedded in the initramfs, otherwise it halts with a clear message.

#![forbid(unsafe_code)]

mod boot;
mod persist;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use namikaze_common::{Error, Result};
use namikaze_ffi as ffi;
use namikaze_live_core::LiveMode;

const NEW_ROOT: &str = "/newroot";

fn log(msg: &str) {
    println!("[namikaze-init] {msg}");
}

/// Parse the kernel command line into key/value pairs.
fn parse_cmdline() -> Result<Vec<(String, String)>> {
    let raw = namikaze_common::read_first_line(Path::new("/proc/cmdline"))?;
    Ok(raw
        .split_whitespace()
        .map(|tok| match tok.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (tok.to_string(), String::new()),
        })
        .collect())
}

fn cmdline_get<'a>(items: &'a [(String, String)], key: &str) -> Option<&'a str> {
    items.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// Safe mount wrapper mapping nix errors into our error type.
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

/// Best-effort mount used during early boot.
fn try_mount(
    src: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: u64,
    data: Option<&str>,
) {
    let _ = do_mount(src, target, fstype, flags, data);
}

fn mount_pseudo_fs() {
    let flags = ffi::MS_NOSUID | ffi::MS_NODEV | ffi::MS_NOEXEC;
    try_mount(Some("proc"), "/proc", Some("proc"), flags, None);
    try_mount(Some("sysfs"), "/sys", Some("sysfs"), flags, None);
    try_mount(Some("devtmpfs"), "/dev", Some("devtmpfs"), ffi::MS_NOSUID, None);
    try_mount(Some("tmpfs"), "/run", Some("tmpfs"), flags, None);
}

/// Find the sealed partition, waiting for udev to publish the
/// by-partlabel link. Returns the staged NamFS volume path.
fn open_sealed_volume(live_opts: &namikaze_live_core::LiveOptions) -> Result<PathBuf> {
    for attempt in 0..15 {
        for dev in boot::find_root_device() {
            if !boot::looks_like_namfs(&dev) {
                continue;
            }
            log(&format!("sealed partition found at {}", dev.display()));
            let pass: Vec<u8> = match &live_opts.img_pass {
                Some(given) => given.clone().into_bytes(),
                None => {
                    // the honest default: ask, never guess
                    boot::ask_passphrase(3)?
                }
            };
            return boot::stage_partition(&dev, &pass);
        }
        if attempt % 5 == 0 {
            log("waiting for the sealed NAMIKAZE_ROOT partition...");
        }
        sleep(Duration::from_secs(1));
    }
    Err(Error::Other("no sealed NAMIKAZE_ROOT partition found".into()))
}

/// Unpack the verified rootfs pack into the tmpfs lower root and mount
/// the overlay over NEW_ROOT.
fn mount_rootfs(volume: &Path, live_opts: &namikaze_live_core::LiveOptions) -> Result<()> {
    let pass: Vec<u8> = match &live_opts.img_pass {
        Some(given) => given.clone().into_bytes(),
        None => Vec::new(), // the volume is already authenticated
    };
    let pack = boot::read_pack(volume, &pass).or_else(|first| {
        // the staged volume gate already consumed the tty passphrase;
        // retry with it before giving up (img_pass users never land here)
        if live_opts.img_pass.is_some() {
            return Err(first);
        }
        let prompted = boot::ask_passphrase(3)?;
        boot::read_pack(volume, &prompted)
    })?;

    let lower = "/run/rootfs-lower";
    std::fs::create_dir_all(lower)?;
    let flags = ffi::MS_NOSUID | ffi::MS_NODEV;
    try_mount(Some("tmpfs"), lower, Some("tmpfs"), flags, None);
    std::fs::create_dir_all(NEW_ROOT)?;
    boot::unpack_rootfs(&pack, Path::new(lower))?;
    log("rootfs unpacked and verified (NamFS seal + per-file SHA-256)");
    Ok(())
}

fn overlay_upper(choice: persist::UpperChoice) -> Result<()> {
    // upperdir and workdir must live on the SAME filesystem.
    let (upper, work) = match choice {
        persist::UpperChoice::Persistent => {
            (PathBuf::from("/run/persist/upper"), PathBuf::from("/run/persist/work"))
        }
        persist::UpperChoice::VolatileTmpfs | persist::UpperChoice::SessionTmpfs => {
            let base = PathBuf::from("/run/upper-volatile");
            std::fs::create_dir_all(&base)?;
            let flags = ffi::MS_NOSUID | ffi::MS_NODEV;
            try_mount(Some("tmpfs"), base.to_str().unwrap_or_default(), Some("tmpfs"), flags, None);
            (base.join("u"), base.join("work"))
        }
    };
    std::fs::create_dir_all(&upper)?;
    std::fs::create_dir_all(&work)?;
    let options = format!(
        "lowerdir=/run/rootfs-lower,upperdir={},workdir={}",
        upper.display(),
        work.display()
    );
    do_mount(
        Some("overlay"),
        NEW_ROOT,
        Some("overlay"),
        ffi::MS_NOSUID | ffi::MS_NODEV,
        Some(options.as_str()),
    )?;
    Ok(())
}

fn move_and_pivot() -> Result<()> {
    for dir in ["/dev", "/proc", "/sys", "/run"] {
        let target = Path::new(NEW_ROOT).join(dir.trim_start_matches('/'));
        let _ = std::fs::create_dir_all(&target);
        try_mount(None, dir, None, ffi::MS_MOVE, None);
    }
    // pivot_root cannot be issued from the initramfs rootfs itself (the
    // kernel refuses a pivot whose old root is rootfs), so the handover
    // is the standard switch_root sequence: MS_MOVE the new root onto
    // /, then let the caller exec /sbin/init from the moved root.
    std::env::set_current_dir("/")?;
    ffi::mount(Some(NEW_ROOT), "/", None, ffi::MS_MOVE, None)
        .map_err(|e| Error::Other(format!("move {NEW_ROOT} to /: {e}")))?;
    std::env::set_current_dir("/")?;
    Ok(())
}

fn emergency(reason: &str) -> ! {
    eprintln!("[namikaze-init] EMERGENCY: {reason}");
    loop {
        if Command::new("/bin/sh").status().is_ok() {
            log("emergency shell exited; rebooting");
        }
        sleep(Duration::from_secs(2));
    }
}

fn main() {
    if let Err(e) = run() {
        emergency(&e.to_string());
    }
    // run() never returns on success: it execs /sbin/init.
    unreachable!("run() must exec or abort");
}

fn run() -> Result<()> {
    log(concat!("NamikazeOS initramfs init ", env!("CARGO_PKG_VERSION")));
    mount_pseudo_fs();
    let raw_cmdline = namikaze_common::read_first_line(Path::new("/proc/cmdline"))?;
    let items = parse_cmdline()?;
    let live_opts = namikaze_live_core::parse_cmdline(&raw_cmdline);
    let _ = cmdline_get(&items, "namikaze.verity"); // pack hashes supersede verity
    let volume = open_sealed_volume(&live_opts)?;
    mount_rootfs(&volume, &live_opts)?;

    // Live persistence: unlock the encrypted upper layer when requested and
    // available; degrade to volatile otherwise (never destroy data).
    let (choice, entries) = if live_opts.mode == LiveMode::Volatile {
        persist::write_volatile_env()?;
        (persist::UpperChoice::VolatileTmpfs, Vec::new())
    } else {
        persist::prepare(&live_opts)?
    };
    overlay_upper(choice)?;
    persist::apply_mounts(Path::new(NEW_ROOT), &entries)?;
    move_and_pivot()?;
    log("pivoted; handing over to /sbin/init");
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new("/sbin/init").exec();
    Err(Error::Other(format!("exec /sbin/init: {err}")))
}
