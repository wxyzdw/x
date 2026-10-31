// SPDX-License-Identifier: MPL-2.0
//! namikaze-init: PID 1 of the NamikazeOS initramfs.
//!
//! Boot sequence (single-ISO, multi-arch):
//!   1. Mount pseudo filesystems so the environment is usable.
//!   2. Parse the kernel command line (namikaze.* and standard keys).
//!   3. Locate the ISO medium by label and mount it read-only.
//!   4. Mount the per-architecture squashfs, verifying the dm-verity root
//!      hash BEFORE any pivot (tamper-evident live root).
//!   5. Build a writable tmpfs overlay on top of the read-only root.
//!   6. Move pseudo filesystems into the new root, pivot_root, exec OpenRC.
//!
//! On unrecoverable failure the init drops to an emergency shell if one is
//! embedded in the initramfs, otherwise it halts with a clear message.

#![forbid(unsafe_code)]

mod persist;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use namikaze_common::{Error, Result};
use namikaze_ffi as ffi;
use namikaze_live_core::LiveMode;

const ISO_LABEL: &str = "NAMIKAZE_ISO";
const NEW_ROOT: &str = "/newroot";
const OLD_ROOT: &str = "/oldroot";

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

fn machine_tree() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "armv7",
        "riscv64" => "riscv64",
        "powerpc64" => "ppc64le",
        _ => "unknown",
    }
}

/// Wait for the ISO medium and mount it. Retries while udev settles.
fn mount_iso() -> Result<PathBuf> {
    let candidates = [
        PathBuf::from("/dev/disk/by-label").join(ISO_LABEL),
        PathBuf::from("/dev/sr0"),
    ];
    std::fs::create_dir_all("/run/iso")?;
    for attempt in 0..15 {
        for cand in &candidates {
            if !cand.exists() {
                continue;
            }
            let dev = cand.to_str().unwrap_or_default().to_string();
            if do_mount(Some(&dev), "/run/iso", Some("iso9660"), ffi::MS_RDONLY, None).is_ok()
                || do_mount(Some(&dev), "/run/iso", Some("udf"), ffi::MS_RDONLY, None).is_ok()
            {
                log("ISO medium mounted");
                return Ok(PathBuf::from("/run/iso"));
            }
        }
        if attempt % 5 == 0 {
            log("waiting for ISO medium...");
        }
        sleep(Duration::from_secs(1));
    }
    Err(Error::Other("no medium with label ".to_string() + ISO_LABEL))
}

fn verity_open(sqfs: &Path, root_hash: &str) -> Result<PathBuf> {
    let mapper = PathBuf::from("/dev/mapper/namikaze-root");
    let status = Command::new("/usr/sbin/veritysetup")
        .args([
            "open",
            sqfs.to_str().unwrap_or_default(),
            "namikaze-root",
            "--root-hash",
            root_hash,
        ])
        .status();
    match status {
        Ok(s) if s.success() => Ok(mapper),
        _ => Err(Error::Other(
            "veritysetup failed; refusing to mount unverified root".into(),
        )),
    }
}

fn mount_rootfs(iso: &Path, items: &[(String, String)]) -> Result<()> {
    let sqfs = iso.join("boot").join(machine_tree()).join("rootfs.img");
    if !sqfs.exists() {
        return Err(Error::Other(format!("squashfs not found: {}", sqfs.display())));
    }
    let source = match cmdline_get(items, "namikaze.verity") {
        Some(hash) => {
            log("verifying rootfs with dm-verity");
            verity_open(&sqfs, hash)?
        }
        None => {
            log("no root hash in cmdline; mounting squashfs directly");
            sqfs.clone()
        }
    };
    std::fs::create_dir_all(NEW_ROOT)?;
    do_mount(
        Some(source.to_str().unwrap_or_default()),
        NEW_ROOT,
        Some("squashfs"),
        ffi::MS_RDONLY,
        None,
    )?;
    Ok(())
}

fn overlay_upper(choice: persist::UpperChoice) -> Result<()> {
    // upperdir and workdir must live on the SAME filesystem.
    let (upper, work) = match choice {
        persist::UpperChoice::Persistent => (
            PathBuf::from("/run/persist/upper"),
            PathBuf::from("/run/persist/work"),
        ),
        persist::UpperChoice::VolatileTmpfs | persist::UpperChoice::SessionTmpfs => {
            let base = PathBuf::from("/run/upper-volatile");
            std::fs::create_dir_all(&base)?;
            let flags = ffi::MS_NOSUID | ffi::MS_NODEV;
            try_mount(
                Some("tmpfs"),
                base.to_str().unwrap_or_default(),
                Some("tmpfs"),
                flags,
                None,
            );
            (base.join("u"), base.join("work"))
        }
    };
    std::fs::create_dir_all(&upper)?;
    std::fs::create_dir_all(&work)?;
    let options = format!(
        "lowerdir={NEW_ROOT},upperdir={},workdir={}",
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
    std::fs::create_dir_all(Path::new(NEW_ROOT).join(OLD_ROOT))?;
    std::env::set_current_dir(NEW_ROOT)?;
    ffi::pivot_root(Path::new("."), Path::new(OLD_ROOT))?;
    std::env::set_current_dir("/")?;
    ffi::umount2_detached(OLD_ROOT).ok();
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
    let iso = mount_iso()?;
    mount_rootfs(&iso, &items)?;

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
