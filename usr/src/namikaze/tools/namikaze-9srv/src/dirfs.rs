// SPDX-License-Identifier: MPL-2.0
//! DirFs: a read-only Fsys over a real directory tree. This is the
//! "everything is a file" of Plan 9 applied to an ordinary directory:
//! walks resolve names, reads return file bytes, directory reads
//! return stat streams. Node ids are per-connection counters mapped to
//! paths; qid paths derive from the same counter for stability.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use namikaze_9p::error::{Errno, Error, Result};
use namikaze_9p::proto::{
    Dir, Qid, DMDIR, DMEXEC, DMREAD, DMWRITE, ORDWR, OTRUNC, OWRITE, QTDIR, QTFILE,
};
use namikaze_9p::server::Fsys;

pub struct DirFs {
    paths: HashMap<u64, PathBuf>,
    parents: HashMap<u64, u64>,
    next: u64,
}

impl DirFs {
    /// Serve the tree under `root` (it must exist and be a directory).
    pub fn new(root: &Path) -> Result<DirFs, Error> {
        if !root.is_dir() {
            return Err(Error::Server(Errno::BadSpec)
                .with_ctx(format!("{} is not a directory", root.display())));
        }
        let mut fs = DirFs { paths: HashMap::new(), parents: HashMap::new(), next: 0 };
        fs.paths.insert(0, root.to_path_buf());
        fs.parents.insert(0, 0);
        fs.next = 1;
        Ok(fs)
    }

    fn path_of(&self, node: u64) -> Result<&Path, Error> {
        self.paths.get(&node).map(|p| p.as_path()).ok_or(Error::Server(Errno::BadFid))
    }

    fn alloc(&mut self, path: PathBuf, parent: u64) -> u64 {
        let id = self.next;
        self.next += 1;
        self.paths.insert(id, path);
        self.parents.insert(id, parent);
        id
    }

    fn stat_dir(&self, path: &Path, qid: Qid, name: String) -> Dir {
        let meta = fs::metadata(path).ok();
        let mut mode = 0u32;
        let mut length = 0u64;
        let mut mtime = 0u32;
        let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        if let Some(meta) = &meta {
            use std::os::unix::fs::PermissionsExt;
            let bits = meta.permissions().mode();
            if bits & 0o4 != 0 {
                mode |= DMREAD;
            }
            if bits & 0o2 != 0 {
                mode |= DMWRITE;
            }
            if bits & 0o1 != 0 {
                mode |= DMEXEC;
            }
            if is_dir {
                mode |= DMDIR;
            }
            length = meta.len();
            mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
        }
        Dir {
            typ: 0,
            dev: 0,
            qid,
            mode,
            atime: mtime,
            mtime,
            length,
            name,
            uid: "namikaze".into(),
            gid: "namikaze".into(),
            muid: String::new(),
        }
    }

    fn qid_for(&self, node: u64) -> Qid {
        let is_dir = self.path_of(node).map(|p| p.is_dir()).unwrap_or(false);
        Qid { typ: if is_dir { QTDIR } else { QTFILE }, vers: 0, path: node }
    }
}

impl Fsys for DirFs {
    fn attach(&mut self, _uname: &str, aname: &str) -> Result<(u64, Qid)> {
        if !(aname.is_empty() || aname == "/") {
            // one export point per server, as the flag sets it
            return Err(Error::Server(Errno::BadSpec));
        }
        Ok((0, self.qid_for(0)))
    }

    fn walk(&mut self, node: u64, name: &str) -> Result<(u64, Qid)> {
        let path = self.path_of(node)?.to_path_buf();
        // "." and ".." work from files too, as in plan9
        if name == ".." {
            let parent = self.parents.get(&node).copied().unwrap_or(0);
            let qid = self.qid_for(parent);
            return Ok((parent, qid));
        }
        if name == "." {
            let qid = self.qid_for(node);
            return Ok((node, qid));
        }
        if !path.is_dir() {
            return Err(Error::Server(Errno::NotADirectory));
        }
        let child = path.join(name);
        if !child.exists() {
            return Err(
                Error::Server(Errno::NotFound).with_ctx(format!("walk {}", child.display()))
            );
        }
        let id = self.alloc(child, node);
        let qid = self.qid_for(id);
        Ok((id, qid))
    }

    fn open(&mut self, node: u64, mode: u8) -> Result<(Qid, u32)> {
        let qid = self.qid_for(node);
        let write_open = mode == OWRITE || mode == ORDWR || mode & OTRUNC != 0;
        if write_open {
            return Err(
                Error::Server(Errno::ReadOnly).with_ctx("this server exports a read-only view")
            );
        }
        let _ = self.path_of(node)?;
        Ok((qid, 8192))
    }

    fn read(&mut self, node: u64, offset: u64, count: u32) -> Result<Vec<u8>> {
        let path = self.path_of(node)?.to_path_buf();
        if path.is_dir() {
            return Err(Error::Server(Errno::IsDirectory));
        }
        let data = fs::read(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::Server(Errno::NotFound),
            std::io::ErrorKind::PermissionDenied => Error::Server(Errno::Permission),
            _ => Error::Server(Errno::Io).with_ctx(format!("read {}", path.display())),
        })?;
        if offset >= data.len() as u64 {
            return Ok(Vec::new());
        }
        let off = offset as usize;
        let end = off.saturating_add(count as usize).min(data.len());
        Ok(data[off..end].to_vec())
    }

    fn read_dir(&mut self, node: u64, offset: u64, count: u32) -> Result<Vec<u8>> {
        let path = self.path_of(node)?.to_path_buf();
        if !path.is_dir() {
            return Err(Error::Server(Errno::NotADirectory));
        }
        let mut names: Vec<String> = fs::read_dir(&path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::PermissionDenied => Error::Server(Errno::Permission),
                _ => Error::Server(Errno::Io).with_ctx(format!("read {}", path.display())),
            })?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        let mut blob = Vec::new();
        let mut produced = 0u64;
        for name in names {
            let child = path.join(&name);
            // a stable id for the child within this connection
            let id = match self.paths.iter().find(|(_, p)| **p == child) {
                Some((id, _)) => *id,
                None => self.alloc(child.clone(), node),
            };
            let raw = self.stat_dir(&child, self.qid_for(id), name).encode()?;
            if produced < offset {
                produced += raw.len() as u64;
                continue;
            }
            if blob.len() + raw.len() > count as usize {
                break;
            }
            blob.extend_from_slice(&raw);
            produced += raw.len() as u64;
        }
        Ok(blob)
    }

    fn stat(&mut self, node: u64) -> Result<Dir> {
        let path = self.path_of(node)?.to_path_buf();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "/".to_string());
        Ok(self.stat_dir(&path, self.qid_for(node), name))
    }

    fn write(&mut self, _node: u64, _offset: u64, _data: &[u8]) -> Result<u32> {
        Err(Error::Server(Errno::ReadOnly))
    }

    fn create(&mut self, _dir: u64, _name: &str, _perm: u32, _mode: u8) -> Result<(u64, Qid, u32)> {
        Err(Error::Server(Errno::ReadOnly))
    }

    fn remove(&mut self, _node: u64) -> Result<()> {
        Err(Error::Server(Errno::ReadOnly))
    }

    fn wstat(&mut self, _node: u64, _stat: &Dir) -> Result<()> {
        Err(Error::Server(Errno::ReadOnly))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use namikaze_9p::proto::OREAD;

    fn temp_tree(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dirfs-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("sub")).expect("mkdir");
        fs::write(dir.join("hello.txt"), b"hi dirfs\n").expect("write");
        fs::write(dir.join("sub/nested.txt"), b"nested\n").expect("write");
        dir
    }

    #[test]
    fn walks_reads_and_stats_a_real_tree() {
        let root = temp_tree("walk");
        let mut fs = DirFs::new(&root).expect("new");
        let (root_node, root_qid) = fs.attach("glenda", "").expect("attach");
        assert!(root_qid.is_dir());

        let (hello, qid) = fs.walk(root_node, "hello.txt").expect("walk");
        assert!(!qid.is_dir());
        let (sub, _) = fs.walk(root_node, "sub").expect("walk sub");
        let (nested, _) = fs.walk(sub, "nested.txt").expect("walk nested");
        let (back, _) = fs.walk(nested, "..").expect("dot dot");
        assert_eq!(back, sub);

        fs.open(hello, OREAD).expect("open");
        assert_eq!(fs.read(hello, 0, 8192).expect("read"), b"hi dirfs\n");
        assert_eq!(fs.read(hello, 100, 4).expect("read past end"), Vec::<u8>::new());

        let stat = fs.stat(hello).expect("stat");
        assert_eq!(stat.name, "hello.txt");
        assert_eq!(stat.length, 9);
        assert_eq!(stat.qid.path, qid.path);

        // directory read: two entries, whole stat blobs
        let blob = fs.read_dir(root_node, 0, 8192).expect("read_dir");
        let mut names = Vec::new();
        let mut pos = 0;
        while pos < blob.len() {
            let len = u16::from_le_bytes([blob[pos], blob[pos + 1]]) as usize;
            let d = Dir::decode(&blob[pos..pos + len]).expect("entry");
            names.push(d.name.clone());
            pos += len;
        }
        assert_eq!(names, vec!["hello.txt", "sub"]);

        let err = fs.write(hello, 0, b"x").expect_err("read-only server");
        assert_eq!(Errno::leaf(&err), Errno::ReadOnly);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn bad_aname_and_missing_files_are_classified() {
        let root = temp_tree("aname");
        let mut fs = DirFs::new(&root).expect("new");
        let err = fs.attach("glenda", "/elsewhere").expect_err("bad aname");
        assert_eq!(Errno::leaf(&err), Errno::BadSpec);
        let (root_node, _) = fs.attach("glenda", "").expect("attach");
        let err = fs.walk(root_node, "void").expect_err("missing");
        assert_eq!(Errno::leaf(&err), Errno::NotFound);
        let _ = fs::remove_dir_all(&root);
    }
}
