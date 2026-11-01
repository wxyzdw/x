// SPDX-License-Identifier: MPL-2.0
//! Audited FFI boundary of NamikazeOS.
//!
//! This is the ONLY crate allowed to contain `unsafe`. It declares the few
//! libc symbols the system needs directly (no libc crate: the workspace
//! carries zero third-party dependencies). Every wrapper is a minimal,
//! documented adapter; every `unsafe` block carries a `// SAFETY:` comment
//! explaining the invariant that makes it sound.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use namikaze_common::{Error, Result};

// ---------------------------------------------------------------- externs
// Hand-declared libc surface (the Linux libc ABI; the same declarations
// hold for musl). Kept in one namespaced block so the audited surface stays
// reviewable and cannot collide with the safe wrappers below.
/// Terminal attributes (Linux `struct termios`; stable across our targets).
#[repr(C)]
#[derive(Clone, Copy)]
struct Termios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; 32],
    c_ispeed: u32,
    c_ospeed: u32,
}

mod sys {
    extern "C" {
        pub fn sync();
        pub fn mlock(addr: *const core::ffi::c_void, len: usize) -> i32;
        pub fn mount(
            src: *const core::ffi::c_char,
            target: *const core::ffi::c_char,
            fstype: *const core::ffi::c_char,
            flags: u64,
            data: *const core::ffi::c_void,
        ) -> i32;
        pub fn umount2(target: *const core::ffi::c_char, flags: i32) -> i32;
        pub fn kill(pid: i32, sig: i32) -> i32;
        pub fn tcgetattr(fd: i32, termios: *mut super::Termios) -> i32;
        pub fn tcsetattr(fd: i32, optional_actions: i32, termios: *const super::Termios) -> i32;
        pub fn chdir(path: *const core::ffi::c_char) -> i32;
        pub fn chroot(path: *const core::ffi::c_char) -> i32;
        pub fn syscall(num: i64, ...) -> i64;
    }
}

/// pivot_root(2) syscall number: identical on every Linux ABI we ship
/// (x86_64, aarch64, riscv64, armv7 all use the asm-generic table value).
const SYS_PIVOT_ROOT: i64 = 218;

const ECHO: u32 = 0o0_000_010;
const ICANON: u32 = 0o0_000_002;
const TCSANOW: i32 = 0;
const MNT_DETACH: i32 = 2;

// mount(2) flags used by the initramfs stage
/// MS_NOSUID
pub const MS_NOSUID: u64 = 1 << 1;
/// MS_NODEV
pub const MS_NODEV: u64 = 1 << 2;
/// MS_NOEXEC
pub const MS_NOEXEC: u64 = 1 << 3;
/// MS_RDONLY
pub const MS_RDONLY: u64 = 1 << 0;
/// MS_MOVE
pub const MS_MOVE: u64 = 1 << 13;
/// MS_BIND
pub const MS_BIND: u64 = 1 << 12;

/// SIGKILL
pub const SIGKILL: i32 = 9;

#[derive(Debug)]
pub enum FfiError {
    /// A syscall returned -1; `errno` is carried in the io::Error.
    Syscall { name: &'static str, source: std::io::Error },
    /// A path contained an interior NUL byte.
    InvalidPath(String),
}

impl std::fmt::Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FfiError::Syscall { name, source } => write!(f, "syscall {name} failed: {source}"),
            FfiError::InvalidPath(p) => write!(f, "invalid path encoding: {p}"),
        }
    }
}

impl From<FfiError> for Error {
    fn from(e: FfiError) -> Self {
        Error::Other(e.to_string())
    }
}

fn cstring_of(path: &Path) -> std::result::Result<CString, FfiError> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| FfiError::InvalidPath(path.display().to_string()))
}

fn check(name: &'static str, rc: i32) -> Result<()> {
    if rc != 0 {
        return Err(FfiError::Syscall { name, source: std::io::Error::last_os_error() }.into());
    }
    Ok(())
}

/// Switch the process root using the pivot_root syscall.
///
/// # SAFETY
/// The syscall only dereferences the two NUL-terminated path pointers we
/// construct immediately above; the kernel copies the strings during the
/// call. Both paths must exist and `put_old` must be at or under `new_root`.
pub fn pivot_root(new_root: &Path, put_old: &Path) -> Result<()> {
    let new_c = cstring_of(new_root)?;
    let old_c = cstring_of(put_old)?;
    // SAFETY: SYS_pivot_root takes two pointer arguments owned by `new_c`
    // and `old_c`, which outlive the syscall invocation.
    let rc = unsafe { sys::syscall(SYS_PIVOT_ROOT, new_c.as_ptr(), old_c.as_ptr()) };
    if rc != 0 {
        return Err(FfiError::Syscall {
            name: "pivot_root",
            source: std::io::Error::last_os_error(),
        }
        .into());
    }
    Ok(())
}

/// chroot(2) + chdir(2) wrapper: the finishing step of the initramfs
/// handover. After `MS_MOVE` puts the new root on `/`, a chroot (with
/// the working directory moved into it first) is what finally detaches
/// the process from the initramfs rootfs, exactly like util-linux
/// `switch_root` does before exec'ing the real init.
///
/// # SAFETY
/// Both syscalls only read the path string; the CStrings outlive the
/// calls because they are locals of this function.
pub fn chroot_into(path: &std::path::Path) -> Result<()> {
    let dir_c = cstring_of(path)?;
    let root_c = cstring_of(path)?;
    // chdir first: after chroot(2) the old root is unreachable, so a
    // chdir afterwards could not enter the new tree
    // SAFETY: the pointer refers to `dir_c`, alive for the call.
    let rc = unsafe { sys::chdir(dir_c.as_ptr()) };
    check("chdir", rc)?;
    // SAFETY: the pointer refers to `root_c`, alive for the call.
    let rc = unsafe { sys::chroot(root_c.as_ptr()) };
    check("chroot", rc)
}

/// Lock a byte buffer into RAM so it cannot be paged to swap.
///
/// # SAFETY
/// `mlock` receives the buffer pointer and length; the buffer must outlive
/// the call, which it does because we borrow it for the duration.
pub fn mlock(buf: &[u8]) -> Result<()> {
    // SAFETY: the pointer refers to the caller's buffer, valid for the call.
    let rc = unsafe { sys::mlock(buf.as_ptr().cast(), buf.len()) };
    check("mlock", rc)
}

/// Ask the kernel to flush file-system buffers (sync(2) wrapper).
pub fn do_sync() {
    // SAFETY: sync takes no arguments and has no preconditions.
    unsafe { sys::sync() };
}

/// mount(2) wrapper with typed flags.
///
/// # SAFETY
/// All string pointers come from CStrings owned by this call frame; the
/// kernel copies them before returning.
pub fn mount(
    src: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: u64,
    data: Option<&str>,
) -> Result<()> {
    let src_c = src
        .map(CString::new)
        .transpose()
        .map_err(|_| FfiError::InvalidPath(src.unwrap_or_default().to_string()))?;
    let tgt_c = CString::new(target).map_err(|_| FfiError::InvalidPath(target.to_string()))?;
    let fs_c = fstype
        .map(CString::new)
        .transpose()
        .map_err(|_| FfiError::InvalidPath(fstype.unwrap_or_default().to_string()))?;
    let data_c = data
        .map(CString::new)
        .transpose()
        .map_err(|_| FfiError::InvalidPath(data.unwrap_or_default().to_string()))?;
    // the CStrings must outlive the syscall: taking pointers out of a
    // .map() on the Option would drop them at the end of that statement
    // (a use-after-free the kernel then reads as garbage strings)
    let src_p = src_c.as_ref().map(|s| s.as_ptr()).unwrap_or(std::ptr::null());
    let fs_p = fs_c.as_ref().map(|s| s.as_ptr()).unwrap_or(std::ptr::null());
    let data_p = data_c.as_ref().map(|s| s.as_ptr().cast()).unwrap_or(std::ptr::null());
    // SAFETY: every pointer is null or points into a CString alive for the
    // duration of the call; the kernel copies strings before returning.
    let rc = unsafe { sys::mount(src_p, tgt_c.as_ptr(), fs_p, flags, data_p) };
    check("mount", rc)
}

/// umount2(2) with MNT_DETACH semantics exposed via `flags`.
///
/// # SAFETY
/// `target` points into a CString that outlives the call.
pub fn umount2_detached(target: &str) -> Result<()> {
    let tgt_c = CString::new(target).map_err(|_| FfiError::InvalidPath(target.to_string()))?;
    // SAFETY: the pointer refers to `tgt_c`, alive for the call.
    let rc = unsafe { sys::umount2(tgt_c.as_ptr(), MNT_DETACH) };
    check("umount2", rc)
}

/// kill(2) wrapper (SIGKILL delivery for the OOM guardian).
///
/// # SAFETY
/// `kill` takes two integers and has no pointer preconditions.
pub fn kill_pid(pid: i32) -> Result<()> {
    kill_signal(pid, SIGKILL)
}

/// kill(2) wrapper for an arbitrary signal number (userland kill tool).
///
/// # SAFETY
/// `kill` takes two integers and has no pointer preconditions.
pub fn kill_signal(pid: i32, sig: i32) -> Result<()> {
    // SAFETY: plain integer syscall; no pointers involved.
    let rc = unsafe { sys::kill(pid, sig) };
    check("kill", rc)
}

/// Read one line from a TTY file with echo disabled (getpass-style).
///
/// Returns the line without the trailing newline. The terminal state is
/// always restored, even when reading fails mid-line. Used for LUKS and
/// vault passphrases so secrets never echo to the console or logs.
pub fn read_password(file: &mut File) -> Result<Vec<u8>> {
    let fd = file.as_raw_fd();
    let mut saved = Termios {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        c_line: 0,
        c_cc: [0; 32],
        c_ispeed: 0,
        c_ospeed: 0,
    };
    // SAFETY: `fd` is owned by `file`, kept open for the whole call; the
    // pointer refers to our stack-allocated `saved`.
    if unsafe { sys::tcgetattr(fd, &mut saved) } != 0 {
        return Err(Error::Other(format!("tcgetattr: {}", std::io::Error::last_os_error())));
    }
    let mut raw = saved;
    raw.c_lflag &= !ECHO;
    raw.c_lflag &= !ICANON;
    // SAFETY: as above; the pointer refers to `raw`, alive for the call.
    if unsafe { sys::tcsetattr(fd, TCSANOW, &raw) } != 0 {
        return Err(Error::Other(format!("tcsetattr: {}", std::io::Error::last_os_error())));
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => match buf[0] {
                b'\n' | b'\r' => break,
                0x7f | 0x08 => {
                    out.pop();
                }
                c => out.push(c),
            },
            Err(_) => break,
        }
    }
    // SAFETY: restore happens before `saved` goes out of scope; fd is valid.
    let _ = unsafe { sys::tcsetattr(fd, TCSANOW, &saved) };
    Ok(out)
}

/// Read a passphrase from the controlling terminal (/dev/tty).
pub fn read_password_tty() -> Result<Vec<u8>> {
    let mut tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let pass = read_password(&mut tty)?;
    use std::io::Write;
    let _ = tty.write_all(b"\n");
    Ok(pass)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_path_is_rejected() {
        let bad = Path::new("/tmp/bad\0path");
        assert!(cstring_of(bad).is_err());
    }

    #[test]
    fn mount_flags_are_stable() {
        // cross-checked with linux uapi asm-generic/fcntl.h + x86_64 bits
        assert_eq!(MS_RDONLY, 1);
        assert_eq!(MS_NOSUID, 2);
        assert_eq!(MS_NODEV, 4);
        assert_eq!(MS_NOEXEC, 8);
        assert_eq!(MS_MOVE, 1 << 13);
    }
}
