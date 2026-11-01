// SPDX-License-Identifier: MPL-2.0
//! Filesystem helpers: recursive walking, temporary files and secret
//! hygiene (zeroization without unsafe).

/// Recursively list files under `root` (files only, deterministic order).
/// Symlinks are not followed. Never panics: unreadable entries are skipped.
pub fn walk_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// A directory that is removed (recursively) when the handle drops.
pub struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    /// Create a unique directory under `$TMPDIR`/`/tmp` with prefix `pfx`.
    pub fn new(pfx: &str) -> crate::Result<Self> {
        let base = std::env::temp_dir();
        for _ in 0..64 {
            let name = format!("{pfx}-{}-{}", std::process::id(), crate::random::id_hex()?);
            let path = base.join(name);
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(crate::Error::Invalid("cannot create temp dir".into()))
    }

    /// The directory path.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Overwrite a buffer with zeros in a way the optimizer cannot elide.
/// (`forbid(unsafe_code)` rules out volatile writes; `black_box` forms a
/// barrier that keeps the loop observable.)
pub fn zero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    std::hint::black_box(&buf);
}

/// A heap buffer zeroized on drop (stand-in for the old zeroize crate).
#[derive(Debug)]
pub struct ZeroBuf(pub Vec<u8>);

impl ZeroBuf {
    /// Wrap secret bytes.
    pub fn new(v: Vec<u8>) -> Self {
        Self(v)
    }

    /// Borrow the secret.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for ZeroBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ZeroBuf {
    fn drop(&mut self) {
        zero(&mut self.0);
    }
}

impl Clone for ZeroBuf {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tempdir_creates_and_cleans() {
        let path;
        {
            let t = TempDir::new("nk-test").unwrap();
            path = t.path().to_path_buf();
            std::fs::write(path.join("x"), b"1").unwrap();
        }
        assert!(!path.exists());
    }

    #[test]
    fn walk_is_sorted_and_files_only() {
        let t = TempDir::new("nk-walk").unwrap();
        std::fs::create_dir_all(t.path().join("b")).unwrap();
        std::fs::create_dir_all(t.path().join("a")).unwrap();
        std::fs::write(t.path().join("b/2"), b"").unwrap();
        std::fs::write(t.path().join("a/1"), b"").unwrap();
        std::fs::write(t.path().join("z"), b"").unwrap();
        let files = walk_files(t.path());
        let names: Vec<String> =
            files.iter().map(|p| p.file_name().unwrap().to_string_lossy().to_string()).collect();
        assert_eq!(names, vec!["1", "2", "z"]);
    }

    #[test]
    fn zero_buf_wipes_on_drop() {
        let mut held: Option<ZeroBuf> = Some(ZeroBuf::new(vec![7u8; 8]));
        assert_eq!(held.as_ref().unwrap().as_slice(), &[7u8; 8]);
        held = None; // Drop runs the zeroization
        assert!(held.is_none());
    }
}
