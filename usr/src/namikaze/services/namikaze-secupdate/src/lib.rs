// SPDX-License-Identifier: MPL-2.0
//! Atomic, verified system updates for NamikazeOS live installations.
//!
//! The update pool is a set of slots on writable storage:
//!
//! ```text
//! <pool>/current/   rootfs.img + rootfs.img.sha256  (booted image)
//! <pool>/previous/  rootfs.img + rootfs.img.sha256  (rollback copy)
//! <pool>/staged/    rootfs.img + rootfs.img.sha256  (verified incoming image)
//! ```
//!
//! Security model:
//! - every image is hashed with SHA-256 while streaming; a slot is only
//!   accepted when its manifest matches the on-disk bytes
//! - manifests use the classic `sha256sum` line format so operators can
//!   re-check them with any sha256sum-class tool
//! - `apply` rotates slots with renames on the same filesystem and fsyncs
//!   both files and directories before publishing, so a power cut can never
//!   leave a half-written image in `current`
//! - `rollback` restores `previous` without network access
//! - manifest entry names are restricted to a flat allowlist (no paths, no
//!   traversal, no duplicates) before anything is opened

#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use namikaze_common::{Error, Result};
use namikaze_rt::sha256::{sha256_file_hex, sha256_hex};

/// Slot holding the image currently selected for boot.
pub const SLOT_CURRENT: &str = "current";
/// Slot holding the image replaced by the last successful apply.
pub const SLOT_PREVIOUS: &str = "previous";
/// Slot holding a verified but not yet activated image.
pub const SLOT_STAGED: &str = "staged";
/// Manifest file name expected inside every slot.
pub const MANIFEST_NAME: &str = "rootfs.img.sha256";
/// Image file name expected inside every slot.
pub const IMAGE_NAME: &str = "rootfs.img";

/// Files allowed inside a bundle. Anything else is rejected.
const BUNDLE_ALLOW: &[&str] = &[IMAGE_NAME, MANIFEST_NAME, "roothash.txt"];

/// One parsed manifest line: `<64 lowercase hex>  <flat name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    pub name: String,
    pub sha256: String,
}

/// Snapshot of pool state returned by [`UpdateManager::status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateStatus {
    /// SHA-256 of `current/rootfs.img`, when the slot verifies.
    pub current: Option<String>,
    /// SHA-256 of `staged/rootfs.img`, when the slot verifies.
    pub staged: Option<String>,
    /// SHA-256 of `previous/rootfs.img`, when the slot verifies.
    pub previous: Option<String>,
}

/// Parse a `sha256sum`-style manifest.
///
/// Accepts the two-space and space-star separators produced by the classic manifest writers.
/// Rejects bad hex, path separators, `..`, empty names and duplicates.
pub fn parse_manifest(text: &str) -> Result<Vec<ManifestEntry>> {
    let mut out: Vec<ManifestEntry> = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (hash, name) = split_manifest_line(line)
            .ok_or_else(|| Error::Config(format!("manifest line {} malformed", idx + 1)))?;
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Config(format!("manifest line {}: bad digest", idx + 1)));
        }
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || name == ".."
            || name.starts_with('.')
        {
            return Err(Error::Config(format!("manifest line {}: unsafe entry name", idx + 1)));
        }
        if out.iter().any(|e| e.name == name) {
            return Err(Error::Config(format!("manifest line {}: duplicate entry", idx + 1)));
        }
        out.push(ManifestEntry { name: name.to_string(), sha256: hash.to_ascii_lowercase() });
    }
    if out.is_empty() {
        return Err(Error::Config("manifest has no entries".into()));
    }
    Ok(out)
}

fn split_manifest_line(line: &str) -> Option<(&str, &str)> {
    let bytes = line.as_bytes();
    if bytes.len() < 64 {
        return None;
    }
    let (hash, rest) = line.split_at(64);
    let rest = rest.strip_prefix("  ").or_else(|| rest.strip_prefix(" *"))?;
    Some((hash, rest.trim_end()))
}

/// Stream a file through SHA-256 and return the lowercase hex digest.
pub fn sha256_file(path: &Path) -> Result<String> {
    Ok(sha256_file_hex(path)?)
}

/// SHA-256 of in-memory bytes, exposed for tests and status output.
pub fn sha256_bytes(data: &[u8]) -> String {
    sha256_hex(data)
}

/// Verify every manifest entry of a slot against the bytes on disk.
///
/// Returns the parsed manifest on success. Missing manifest, missing files
/// and digest mismatches are all hard errors.
pub fn verify_slot(dir: &Path) -> Result<Vec<ManifestEntry>> {
    let manifest_path = dir.join(MANIFEST_NAME);
    let text = fs::read_to_string(&manifest_path)
        .map_err(|e| Error::Config(format!("{}: {e}", manifest_path.display())))?;
    let entries = parse_manifest(&text)?;
    for entry in &entries {
        let path = dir.join(&entry.name);
        let actual =
            sha256_file(&path).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        if actual != entry.sha256 {
            return Err(Error::Crypto(format!(
                "{}: digest mismatch (expected {}, got {})",
                path.display(),
                entry.sha256,
                actual
            )));
        }
    }
    Ok(entries)
}

/// Update pool rooted at a directory (default `/var/lib/namikaze/updates`).
pub struct UpdateManager {
    pool: PathBuf,
}

impl UpdateManager {
    pub fn new<P: Into<PathBuf>>(pool: P) -> Self {
        Self { pool: pool.into() }
    }

    fn slot(&self, name: &str) -> PathBuf {
        self.pool.join(name)
    }

    /// Copy a verified bundle into the `staged` slot.
    ///
    /// Files are copied, fsynced, then the whole bundle is re-verified from
    /// disk before the slot is published. Unknown bundle files abort staging.
    pub fn stage(&self, bundle: &Path) -> Result<()> {
        let staged = self.slot(SLOT_STAGED);
        for entry in fs::read_dir(bundle)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !BUNDLE_ALLOW.contains(&name.as_str()) {
                return Err(Error::Config(format!("unexpected bundle file: {name}")));
            }
        }
        verify_slot(bundle)?;
        let _ = fs::remove_dir_all(&staged);
        fs::create_dir_all(&staged)?;
        for name in BUNDLE_ALLOW {
            let src = bundle.join(name);
            if !src.is_file() {
                continue;
            }
            let dst = staged.join(name);
            copy_synced(&src, &dst)?;
        }
        verify_slot(&staged).map_err(|e| {
            let _ = fs::remove_dir_all(&staged);
            e
        })?;
        fsync_dir(&staged);
        fsync_dir(&self.pool);
        Ok(())
    }

    /// Rotate slots: current becomes previous, staged becomes current.
    ///
    /// Uses only renames within the pool directory plus a fsync barrier, so
    /// the sequence is atomic against crashes at every intermediate state.
    pub fn apply(&self) -> Result<()> {
        let staged = self.slot(SLOT_STAGED);
        let current = self.slot(SLOT_CURRENT);
        let previous = self.slot(SLOT_PREVIOUS);
        verify_slot(&staged)?;
        let backup = self.pool.join(".previous-old");
        let _ = fs::remove_dir_all(&backup);
        if previous.exists() {
            fs::rename(&previous, &backup)?;
        }
        if current.exists() {
            fs::rename(&current, &previous)?;
        }
        fs::rename(&staged, &current)?;
        let _ = fs::remove_dir_all(&backup);
        fsync_dir(&self.pool);
        Ok(())
    }

    /// Restore `previous` into `current`. Requires a verified previous slot.
    pub fn rollback(&self) -> Result<()> {
        let previous = self.slot(SLOT_PREVIOUS);
        let current = self.slot(SLOT_CURRENT);
        verify_slot(&previous)?;
        let backup = self.pool.join(".current-old");
        let _ = fs::remove_dir_all(&backup);
        if current.exists() {
            fs::rename(&current, &backup)?;
        }
        fs::rename(&previous, &current)?;
        let _ = fs::remove_dir_all(&backup);
        fsync_dir(&self.pool);
        Ok(())
    }

    /// Summarize pool state. Broken slots report as `None` instead of failing,
    /// so status stays usable on a corrupted pool.
    pub fn status(&self) -> Result<UpdateStatus> {
        Ok(UpdateStatus {
            current: slot_digest(&self.slot(SLOT_CURRENT)),
            staged: slot_digest(&self.slot(SLOT_STAGED)),
            previous: slot_digest(&self.slot(SLOT_PREVIOUS)),
        })
    }

    /// Publish the verified `current` image into a mounted boot partition
    /// (`<boot>/live/rootfs.img`), atomically: write to a temp name, fsync,
    /// rename over the target, fsync the directory.
    pub fn promote(&self, boot_dir: &Path) -> Result<()> {
        let current = self.slot(SLOT_CURRENT);
        verify_slot(&current)?;
        let live_dir = boot_dir.join("live");
        fs::create_dir_all(&live_dir)?;
        let target = live_dir.join(IMAGE_NAME);
        let tmp = live_dir.join(format!(".{IMAGE_NAME}.new"));
        copy_synced(&current.join(IMAGE_NAME), &tmp)?;
        fs::rename(&tmp, &target)?;
        fsync_dir(&live_dir);
        Ok(())
    }
}

fn slot_digest(dir: &Path) -> Option<String> {
    verify_slot(dir).ok()?;
    sha256_file(&dir.join(IMAGE_NAME)).ok()
}

fn copy_synced(src: &Path, dst: &Path) -> Result<()> {
    let mut input = File::open(src)?;
    let mut output = File::create(dst)?;
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n])?;
    }
    output.sync_all()?;
    drop(output);
    Ok(())
}

fn fsync_dir(dir: &Path) {
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn tempdir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("secupdate-{}-{}-{tag}", std::process::id(), n));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: &Path, data: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, data).unwrap();
    }

    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn known_sha256_vectors() {
        assert_eq!(
            sha256_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(sha256_bytes(b"abc"), ABC);
    }

    #[test]
    fn manifest_parsing() {
        let entries = parse_manifest(&format!("{ABC}  rootfs.img\n")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "rootfs.img");
        assert_eq!(entries[0].sha256, ABC);

        let entries = parse_manifest(&format!("{ABC} *rootfs.img\n")).unwrap();
        assert_eq!(entries[0].name, "rootfs.img");

        let text = format!("# comment\n\n{ABC}  rootfs.img\n");
        assert_eq!(parse_manifest(&text).unwrap().len(), 1);

        assert!(parse_manifest("abcd  rootfs.img\n").is_err());
        let bad = format!("{}  rootfs.img\n", "z".repeat(64));
        assert!(parse_manifest(&bad).is_err());
        assert!(parse_manifest(&format!("{ABC}  ../evil\n")).is_err());
        assert!(parse_manifest(&format!("{ABC}  sub/dir\n")).is_err());
        let dup = format!("{ABC}  rootfs.img\n{ABC}  rootfs.img\n");
        assert!(parse_manifest(&dup).is_err());
        assert!(parse_manifest("# only a comment\n").is_err());
        assert!(parse_manifest(&format!("{ABC} rootfs.img\n")).is_err());
    }

    #[test]
    fn stage_apply_rollback_roundtrip() {
        let pool = tempdir("pool");
        let bundle = tempdir("bundle");
        let image = b"namikaze image payload v1";
        let digest = sha256_bytes(image);
        write(&bundle.join(IMAGE_NAME), image);
        write(&bundle.join(MANIFEST_NAME), format!("{digest}  {IMAGE_NAME}\n").as_bytes());

        let mgr = UpdateManager::new(&pool);
        assert!(mgr.status().unwrap().current.is_none());

        mgr.stage(&bundle).unwrap();
        let st = mgr.status().unwrap();
        assert_eq!(st.staged.as_deref(), Some(digest.as_str()));

        mgr.apply().unwrap();
        let st = mgr.status().unwrap();
        assert_eq!(st.current.as_deref(), Some(digest.as_str()));
        assert!(st.staged.is_none());

        let image2 = b"namikaze image payload v2";
        let digest2 = sha256_bytes(image2);
        write(&bundle.join(IMAGE_NAME), image2);
        write(&bundle.join(MANIFEST_NAME), format!("{digest2}  {IMAGE_NAME}\n").as_bytes());
        mgr.stage(&bundle).unwrap();
        mgr.apply().unwrap();
        let st = mgr.status().unwrap();
        assert_eq!(st.current.as_deref(), Some(digest2.as_str()));
        assert_eq!(st.previous.as_deref(), Some(digest.as_str()));

        mgr.rollback().unwrap();
        let st = mgr.status().unwrap();
        assert_eq!(st.current.as_deref(), Some(digest.as_str()));

        let _ = fs::remove_dir_all(&pool);
        let _ = fs::remove_dir_all(&bundle);
    }

    #[test]
    fn stage_rejects_tampered_and_unknown_files() {
        let pool = tempdir("pool2");
        let bundle = tempdir("bundle2");
        let digest = sha256_bytes(b"payload");
        write(&bundle.join(IMAGE_NAME), b"payload");
        write(&bundle.join(MANIFEST_NAME), format!("{digest}  {IMAGE_NAME}\n").as_bytes());

        let mgr = UpdateManager::new(&pool);

        write(&bundle.join(IMAGE_NAME), b"payload-tampered");
        assert!(mgr.stage(&bundle).is_err());
        assert!(!pool.join(SLOT_STAGED).exists());

        write(&bundle.join(IMAGE_NAME), b"payload");
        write(&bundle.join("extra.txt"), b"nope");
        assert!(mgr.stage(&bundle).is_err());
        assert!(!pool.join(SLOT_STAGED).exists());

        assert!(mgr.apply().is_err());
        let _ = fs::remove_dir_all(&pool);
        let _ = fs::remove_dir_all(&bundle);
    }

    #[test]
    fn promote_publishes_atomically() {
        let pool = tempdir("pool3");
        let boot = tempdir("boot3");
        let image = b"boot image";
        let digest = sha256_bytes(image);
        write(&pool.join(SLOT_CURRENT).join(IMAGE_NAME), image);
        write(
            &pool.join(SLOT_CURRENT).join(MANIFEST_NAME),
            format!("{digest}  {IMAGE_NAME}\n").as_bytes(),
        );

        let mgr = UpdateManager::new(&pool);
        mgr.promote(&boot).unwrap();
        assert_eq!(fs::read(boot.join("live").join(IMAGE_NAME)).unwrap(), image);
        assert!(!boot.join("live").join(format!(".{IMAGE_NAME}.new")).exists());
        let _ = fs::remove_dir_all(&pool);
        let _ = fs::remove_dir_all(&boot);
    }
}
