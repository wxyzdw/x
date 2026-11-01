// SPDX-License-Identifier: MPL-2.0
//! The synthetic file tree: an in-memory [`Fsys`] implementation adapted
//! from Plan 9's `/sys/src/lib9p/file.c`. A tree is built once with
//! directories, static files and dynamic files (content generated at
//! open time, snapshotted per connection, exactly like lib9p's
//! `readstr`/`readbuf` pattern); the 9P server serves it to any client.

use std::collections::HashMap;

use crate::error::{Errno, Error, Result};
use crate::proto::{Dir, Qid, QTDIR, QTFILE, DMDIR, DMREAD, DMWRITE};
use crate::server::Fsys;

/// A content generator for dynamic files, called once per open and the
/// result cached for the connection's lifetime of that fid.
pub type Gen = fn() -> Vec<u8>;

struct Node {
    name: String,
    parent: u64,
    children: Vec<u64>,
    dir: bool,
    static_data: Vec<u8>,
    gen: Option<Gen>,
    mode: u32,
    mtime: u32,
}

impl Node {
    fn qid(&self, path: u64) -> Qid {
        Qid { typ: if self.dir { QTDIR } else { QTFILE }, vers: self.mtime, path }
    }
}

/// An in-memory read-only file tree served over 9P.
pub struct Synth {
    nodes: Vec<Node>,
    /// Per-connection snapshots of dynamic file content, keyed by node.
    opened: HashMap<u64, Vec<u8>>,
    uname: String,
}

impl Synth {
    /// A tree with only the root directory. The root's qid path is 0.
    pub fn new() -> Synth {
        Synth {
            nodes: vec![Node {
                name: "/".to_string(),
                parent: 0,
                children: Vec::new(),
                dir: true,
                static_data: Vec::new(),
                gen: None,
                mode: DMDIR | 0o555,
                mtime: 0,
            }],
            opened: HashMap::new(),
            uname: String::new(),
        }
    }

    /// Add a directory under `parent`; returns its node id.
    /// Fails with [`Errno::Exists`] on a duplicate name.
    pub fn dir(&mut self, parent: u64, name: &str) -> Result<u64> {
        self.add(parent, name, true, Vec::new(), None)
    }

    /// Add a static file under `parent`; returns its node id.
    pub fn file(&mut self, parent: u64, name: &str, data: &[u8]) -> Result<u64> {
        self.add(parent, name, false, data.to_vec(), None)
    }

    /// Add a dynamic file whose content is produced by `gen` at open
    /// time (e.g. /dev/time). Returns its node id.
    pub fn dynamic(&mut self, parent: u64, name: &str, gen: Gen) -> Result<u64> {
        self.add(parent, name, false, Vec::new(), Some(gen))
    }

    fn add(
        &mut self,
        parent: u64,
        name: &str,
        dir: bool,
        data: Vec<u8>,
        gen: Option<Gen>,
    ) -> Result<u64> {
        if name.is_empty() || name.contains('/') {
            return Err(Error::BadField {
                op: "Synth::add",
                why: format!("name \"{name}\" must be a plain leaf name"),
            });
        }
        let (parent_is_dir, duplicate) = {
            let p = self.node_of(parent)?;
            (p.dir, p.children.iter().any(|c| self.nodes[*c as usize].name == name))
        };
        if !parent_is_dir {
            return Err(Error::Server(Errno::NotADirectory));
        }
        if duplicate {
            return Err(Error::Server(Errno::Exists));
        }
        let id = self.nodes.len() as u64;
        self.nodes.push(Node {
            name: name.to_string(),
            parent,
            children: Vec::new(),
            dir,
            static_data: data,
            gen,
            mode: if dir { DMDIR | 0o555 } else { 0o444 },
            mtime: 0,
        });
        self.nodes[parent as usize].children.push(id);
        Ok(id)
    }

    fn node_of(&self, id: u64) -> Result<&Node, Error> {
        self.nodes.get(id as usize).ok_or(Error::Server(Errno::BadFid))
    }

    /// Resolve one absolute path (no "..", no ".") from the root, for
    /// tests and for tools that pre-resolve export points.
    pub fn node(&self, path: &[&str]) -> Result<u64> {
        let mut cur = 0u64;
        for part in path {
            let node = self.node_of(cur)?;
            if !node.dir {
                return Err(Error::Server(Errno::NotADirectory));
            }
            cur = node
                .children
                .iter()
                .copied()
                .find(|c| self.nodes[*c as usize].name == *part)
                .ok_or(Error::Server(Errno::NotFound))?;
        }
        Ok(cur)
    }

    fn dir_entry(&self, id: u64) -> Dir {
        let n = &self.nodes[id as usize];
        Dir {
            typ: 0,
            dev: 0,
            qid: n.qid(id),
            mode: n.mode,
            atime: 0,
            mtime: n.mtime,
            length: if n.dir { 0 } else { n.static_data.len() as u64 },
            name: n.name.clone(),
            uid: "namikaze".to_string(),
            gid: "namikaze".to_string(),
            muid: String::new(),
        }
    }

    fn content_of(&mut self, id: u64) -> Result<Vec<u8>, Error> {
        if let Some(snap) = self.opened.get(&id) {
            return Ok(snap.clone());
        }
        let n = self.node_of(id)?;
        if n.dir {
            return Err(Error::Server(Errno::IsDirectory));
        }
        match n.gen {
            Some(gen) => Ok(gen()),
            None => Ok(n.static_data.clone()),
        }
    }
}

impl Default for Synth {
    fn default() -> Synth {
        Synth::new()
    }
}

impl Fsys for Synth {
    fn attach(&mut self, uname: &str, aname: &str) -> Result<(u64, Qid)> {
        if !(aname.is_empty() || aname == "/") {
            // one export point per Synth tree, like lib9p's single root
            return Err(Error::Server(Errno::BadSpec));
        }
        self.uname = uname.to_string();
        Ok((0, self.nodes[0].qid(0)))
    }

    fn walk(&mut self, node: u64, name: &str) -> Result<(u64, Qid)> {
        let n = self.node_of(node)?;
        if !n.dir {
            return Err(Error::Server(Errno::NotADirectory));
        }
        if name == ".." {
            let parent = n.parent;
            return Ok((parent, self.nodes[parent as usize].qid(parent)));
        }
        if name == "." {
            return Ok((node, n.qid(node)));
        }
        let child = n
            .children
            .iter()
            .copied()
            .find(|c| self.nodes[*c as usize].name == name)
            .ok_or(Error::Server(Errno::NotFound))?;
        let qid = self.nodes[child as usize].qid(child);
        Ok((child, qid))
    }

    fn open(&mut self, node: u64, mode: u8) -> Result<(Qid, u32)> {
        let n = self.node_of(node)?;
        let qid = n.qid(node);
        let writing = mode == crate::proto::OWRITE
            || mode == crate::proto::ORDWR
            || mode & crate::proto::OTRUNC != 0;
        if qid.is_dir() && mode != crate::proto::OREAD {
            return Err(Error::Server(Errno::IsDirectory));
        }
        if writing && !qid.is_dir() {
            let writable = self.node_of(node)?.mode & DMWRITE != 0;
            if !writable {
                return Err(Error::Server(Errno::Permission));
            }
        }
        // snapshot dynamic content now, so one connection sees one
        // consistent view for the lifetime of the fid
        if let Some(gen) = self.node_of(node)?.gen {
            let snap = gen();
            self.opened.insert(node, snap);
        }
        let _ = self.node_of(node)?.mode & DMREAD; // existence check is the read path
        Ok((qid, 8192))
    }

    fn read(&mut self, node: u64, offset: u64, count: u32) -> Result<Vec<u8>> {
        let n = self.node_of(node)?;
        if n.dir {
            return Err(Error::Server(Errno::IsDirectory));
        }
        // plan9 semantics: a read at or past the end of file returns
        // zero bytes; it is not an error
        let content = self.content_of(node)?;
        if offset >= content.len() as u64 {
            return Ok(Vec::new());
        }
        let off = offset as usize;
        let end = off.saturating_add(count as usize).min(content.len());
        Ok(content[off..end].to_vec())
    }

    fn write(&mut self, _node: u64, _offset: u64, _data: &[u8]) -> Result<u32> {
        Err(Error::Server(Errno::ReadOnly))
    }

    fn stat(&mut self, node: u64) -> Result<Dir> {
        let _ = self.node_of(node)?;
        Ok(self.dir_entry(node))
    }

    fn read_dir(&mut self, node: u64, offset: u64, count: u32) -> Result<Vec<u8>> {
        if !self.node_of(node)?.dir {
            return Err(Error::Server(Errno::NotADirectory));
        }
        let kids = self.node_of(node)?.children.clone();
        let mut blob: Vec<u8> = Vec::new();
        let mut produced = 0u64;
        for child in kids {
            if produced < offset {
                // entries before the cursor are already consumed
                produced += self.dir_entry(child).encode()?.len() as u64;
                continue;
            }
            let raw = self.dir_entry(child).encode()?;
            if blob.len() + raw.len() > count as usize {
                break; // never emit a partial stat entry
            }
            blob.extend_from_slice(&raw);
            produced += raw.len() as u64;
        }
        Ok(blob)
    }

    fn create(&mut self, _dir: u64, _name: &str, _perm: u32, _mode: u8) -> Result<(u64, Qid, u32)> {
        Err(Error::Server(Errno::ReadOnly))
    }

    fn remove(&mut self, _node: u64) -> Result<()> {
        Err(Error::Server(Errno::ReadOnly))
    }

    fn clunk(&mut self, node: u64) -> Result<()> {
        self.opened.remove(&node);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{OREAD, OWRITE};

    fn demo_tree() -> Synth {
        let mut s = Synth::new();
        let top = s.dir(0, "top").expect("dir");
        s.file(top, "hello", b"hi from plan9\n").expect("file");
        s.dynamic(top, "clock", || b"12:00:00\n".to_vec()).expect("dynamic");
        s.dir(top, "empty").expect("empty dir");
        s
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let mut s = Synth::new();
        s.file(0, "a", b"x").expect("first a");
        let err = s.file(0, "a", b"y").expect_err("duplicate a");
        assert_eq!(Errno::leaf(&err), Errno::Exists);
    }

    #[test]
    fn slash_names_are_rejected() {
        let mut s = Synth::new();
        let err = s.file(0, "a/b", b"x").expect_err("embedded slash");
        assert!(matches!(err, Error::BadField { .. }), "got {err:?}");
    }

    #[test]
    fn walk_and_lookup_agree() {
        let mut s = demo_tree();
        let top = s.node(&["top"]).expect("top");
        let (walked, qid) = s.walk(0, "top").expect("walk top");
        assert_eq!(walked, top);
        assert!(qid.is_dir());
        let hello = s.node(&["top", "hello"]).expect("hello");
        assert_eq!(s.walk(top, "hello").expect("walk hello").0, hello);
        let missing = s.walk(top, "nope").expect_err("missing element");
        assert_eq!(Errno::leaf(&missing), Errno::NotFound);
    }

    #[test]
    fn dot_dot_stays_rooted() {
        let mut s = demo_tree();
        let (root, _) = s.walk(0, "..").expect("root's parent is root");
        assert_eq!(root, 0);
        let top = s.node(&["top"]).expect("top");
        let (back, _) = s.walk(top, "..").expect("top's parent");
        assert_eq!(back, 0);
    }

    #[test]
    fn open_modes_are_checked() {
        let mut s = demo_tree();
        let top = s.node(&["top"]).expect("top");
        let err = s.open(top, OWRITE).expect_err("dir opened for write");
        assert_eq!(Errno::leaf(&err), Errno::IsDirectory);
        let hello = s.node(&["top", "hello"]).expect("hello");
        let err = s.open(hello, OWRITE).expect_err("read-only file");
        assert_eq!(Errno::leaf(&err), Errno::Permission);
        s.open(hello, OREAD).expect("read open ok");
    }

    #[test]
    fn dynamic_content_is_snapshotted_at_open() {
        let mut s = demo_tree();
        let clock = s.node(&["top", "clock"]).expect("clock");
        let (_, _) = s.open(clock, OREAD).expect("open clock");
        let first = s.read(clock, 0, 8192).expect("read clock");
        assert_eq!(first, b"12:00:00\n");
        // a second read through the same fid hits the snapshot
        let again = s.read(clock, 0, 8192).expect("read clock again");
        assert_eq!(again, first);
    }

    #[test]
    fn read_past_end_is_empty_not_an_error() {
        let mut s = demo_tree();
        let hello = s.node(&["top", "hello"]).expect("hello");
        s.open(hello, OREAD).expect("open");
        assert_eq!(s.read(hello, 3, 4).expect("slice"), b"from");
        // plan9 semantics: at or past EOF a read returns zero bytes
        let past_end = s.read(hello, 1000, 4).expect("read past end");
        assert!(past_end.is_empty());
        let at_end = s.read(hello, 14, 4).expect("read exactly at EOF");
        assert!(at_end.is_empty());
    }

    #[test]
    fn directory_reads_emit_whole_stat_entries() {
        let mut s = demo_tree();
        let top = s.node(&["top"]).expect("top");
        let blob = s.read_dir(top, 0, 8192).expect("dir read");
        // three children, each a full stat blob
        let mut n = 0;
        let mut pos = 0;
        while pos < blob.len() {
            let len = u16::from_le_bytes([blob[pos], blob[pos + 1]]) as usize;
            Dir::decode(&blob[pos..pos + len]).expect("whole entry");
            pos += len;
            n += 1;
        }
        assert_eq!(n, 3, "hello, clock, empty");
        assert_eq!(blob.len() as u64, pos as u64);
    }

    #[test]
    fn read_only_server_refuses_mutations() {
        let mut s = demo_tree();
        let top = s.node(&["top"]).expect("top");
        let err = s.create(top, "new", 0o644, OWRITE).expect_err("create");
        assert_eq!(Errno::leaf(&err), Errno::ReadOnly);
        let err = s.write(top, 0, b"x").expect_err("write");
        assert_eq!(Errno::leaf(&err), Errno::ReadOnly);
        let err = s.remove(top).expect_err("remove");
        assert_eq!(Errno::leaf(&err), Errno::ReadOnly);
    }
}
