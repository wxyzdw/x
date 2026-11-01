// SPDX-License-Identifier: MPL-2.0
//! The 9P server side: the [`Fsys`] backend trait and the connection
//! state machine. Adapted from Plan 9's `/sys/src/lib9p` (srv.c) with
//! the fid table, open-mode checks and walk semantics of the 9P2000
//! spec enforced locally, and every backend failure mapped through the
//! errno catalogue onto a canonical `Rerror`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use crate::error::{Errno, Error, Result};
use crate::proto::{self, Dir, Msg, Qid, IOHDRSZ, MAX_MSIZE, MIN_MSIZE};
use crate::synth::Synth;

/// Initial message size before `Tversion` settles it.
pub const DEFAULT_MSIZE: u32 = 8192;
/// Consecutive protocol failures tolerated before the connection is
/// dropped (a wedged peer must not spin the server forever).
const MAX_CONSECUTIVE_ERRORS: u32 = 64;

/// The file system behind a 9P connection. One instance serves one
/// connection; spawn one per accepted socket (a factory does exactly
/// that). All mutating methods default to [`Errno::ReadOnly`], so a
/// backend only overrides what it supports.
pub trait Fsys: Send {
    /// Establish the root of the export for this connection.
    fn attach(&mut self, uname: &str, aname: &str) -> Result<(u64, Qid)>;

    /// Step from `node` through `name`. Returns the child node and qid.
    fn walk(&mut self, node: u64, name: &str) -> Result<(u64, Qid)>;

    /// Open `node` with the given mode; returns the qid and iounit.
    fn open(&mut self, node: u64, mode: u8) -> Result<(Qid, u32)>;

    /// Create a file in an open directory fid. Read-only by default.
    fn create(&mut self, _dir: u64, _name: &str, _perm: u32, _mode: u8) -> Result<(u64, Qid, u32)> {
        Err(Error::Server(Errno::ReadOnly))
    }

    /// Read `count` bytes of file content at `offset`.
    fn read(&mut self, node: u64, offset: u64, count: u32) -> Result<Vec<u8>>;

    /// Read a directory stream of whole stat entries at the byte
    /// cursor `offset` (Plan 9 directory semantics).
    fn read_dir(&mut self, node: u64, offset: u64, count: u32) -> Result<Vec<u8>>;

    /// Write to a file. Read-only by default.
    fn write(&mut self, _node: u64, _offset: u64, _data: &[u8]) -> Result<u32> {
        Err(Error::Server(Errno::ReadOnly))
    }

    /// Stat a node.
    fn stat(&mut self, node: u64) -> Result<Dir>;

    /// Rewrite part of a stat. Read-only by default.
    fn wstat(&mut self, _node: u64, _stat: &Dir) -> Result<()> {
        Err(Error::Server(Errno::ReadOnly))
    }

    /// Remove a file. Read-only by default.
    fn remove(&mut self, _node: u64) -> Result<()> {
        Err(Error::Server(Errno::ReadOnly))
    }

    /// A fid pointing at `node` was released.
    fn clunk(&mut self, _node: u64) -> Result<()> {
        Ok(())
    }
}

struct Fid {
    node: u64,
    qid: Qid,
    /// Open mode, `None` while the fid is only walked to.
    open: Option<u8>,
}

/// One served connection: framing, fid table and dispatch.
pub struct ServerConn<S: Read + Write> {
    io: S,
    msize: u32,
    fids: HashMap<u32, Fid>,
}

impl<S: Read + Write> ServerConn<S> {
    /// A connection serving over `io` at the default msize.
    pub fn new(io: S) -> ServerConn<S> {
        ServerConn { io, msize: DEFAULT_MSIZE, fids: HashMap::new() }
    }

    /// Serve requests until EOF. Transport errors are returned;
    /// protocol errors are answered with `Rerror` and tolerated up to
    /// [`MAX_CONSECUTIVE_ERRORS`] in a row.
    pub fn serve(&mut self, fsys: &mut dyn Fsys) -> Result<()> {
        let mut consecutive = 0u32;
        loop {
            let body = match self.read_frame() {
                Ok(body) => body,
                // EOF (or transport death) ends the session cleanly
                Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            match Msg::parse(&body) {
                Ok(msg) => {
                    match self.dispatch(fsys, msg) {
                        Ok(()) => consecutive = 0,
                        Err(e) => {
                            // dispatch only fails on transport errors
                            return Err(e.with_ctx("serve: dispatch"));
                        }
                    }
                }
                Err(parse_err) => {
                    consecutive += 1;
                    let tag = salvage_tag(&body);
                    let ename = Errno::leaf(&parse_err).wire();
                    let reply = Msg::Rerror { tag, ename };
                    if let Err(write_err) = self.send(&reply) {
                        return Err(write_err.with_ctx("serve: rerror after parse failure"));
                    }
                    if consecutive >= MAX_CONSECUTIVE_ERRORS {
                        return Err(parse_err
                            .with_ctx(format!("{MAX_CONSECUTIVE_ERRORS} consecutive failures")));
                    }
                }
            }
        }
    }

    /// Read one length-prefixed body (without the 4-byte size).
    fn read_frame(&mut self) -> Result<Vec<u8>, Error> {
        let mut size_buf = [0u8; 4];
        self.io.read_exact(&mut size_buf)?;
        let size = u32::from_le_bytes(size_buf);
        if size < 7 {
            return Err(Error::BadField {
                op: "read_frame",
                why: format!("frame of {size} bytes is below the 7-byte minimum"),
            });
        }
        if size > self.msize {
            return Err(Error::Oversize { op: "read_frame", limit: self.msize, got: size });
        }
        let mut body = vec![0u8; (size - 4) as usize];
        self.io.read_exact(&mut body)?;
        Ok(body)
    }

    fn send(&mut self, msg: &Msg) -> Result<(), Error> {
        let frame = msg.serialize(self.msize)?;
        self.io.write_all(&frame)?;
        self.io.flush()?;
        Ok(())
    }

    /// Reply with `Rerror`, mapping any backend error through the errno
    /// catalogue. Returns false when the error was transport-fatal.
    fn rerror(&mut self, tag: u16, err: &Error) -> Result<(), Error> {
        let ename = match err {
            Error::Server(e) => e.wire(),
            other => format!("internal error: {other}"),
        };
        self.send(&Msg::Rerror { tag, ename })
    }

    fn dispatch(&mut self, fsys: &mut dyn Fsys, msg: Msg) -> Result<(), Error> {
        let tag = msg.tag();
        match msg {
            Msg::Tversion { tag, msize, version } => {
                let granted = negotiate(&version, msize);
                self.msize = granted.msize;
                self.fids.clear(); // a Tversion restarts the session
                self.send(&Msg::Rversion { tag, msize: granted.msize, version: granted.version })?;
            }
            Msg::Tauth { tag, .. } => {
                self.rerror(tag, &Error::Server(Errno::AuthRequired))?;
            }
            Msg::Tattach { tag, fid, afid: _, uname, aname } => {
                if self.fids.contains_key(&fid) {
                    self.rerror(
                        tag,
                        &Error::Server(Errno::InUse)
                            .with_ctx(format!("Tattach: fid {fid} already in use")),
                    )?;
                    return Ok(());
                }
                match fsys.attach(&uname, &aname) {
                    Ok((node, qid)) => {
                        self.fids.insert(fid, Fid { node, qid, open: None });
                        self.send(&Msg::Rattach { tag, aqid: qid })?;
                    }
                    Err(e) => self.rerror(tag, &e)?,
                }
            }
            Msg::Tflush { tag, oldtag: _ } => {
                // sequential server: nothing is ever in flight
                self.send(&Msg::Rflush { tag })?;
            }
            Msg::Twalk { tag, fid, newfid, wnames } => {
                self.dispatch_walk(fsys, tag, fid, newfid, &wnames)?;
            }
            Msg::Topen { tag, fid, mode } => {
                let bad = self.preopen_check(&fid, &mode);
                if let Some(err) = bad {
                    self.rerror(tag, &err)?;
                    return Ok(());
                }
                let node = match self.fids.get(&fid) {
                    Some(f) => f.node,
                    None => {
                        self.rerror(tag, &Error::Server(Errno::BadFid))?;
                        return Ok(());
                    }
                };
                match fsys.open(node, mode) {
                    Ok((qid, iounit)) => {
                        if let Some(f) = self.fids.get_mut(&fid) {
                            f.open = Some(mode & 0x07);
                            f.qid = qid;
                        }
                        self.send(&Msg::Ropen { tag, qid, iounit })?;
                    }
                    Err(e) => self.rerror(tag, &e)?,
                }
            }
            Msg::Tcreate { tag, fid, name, perm, mode } => {
                let err = match self.fid_for_write(&fid) {
                    Ok(node) => match fsys.create(node, &name, perm, mode) {
                        Ok((node, qid, iounit)) => {
                            if let Some(f) = self.fids.get_mut(&fid) {
                                f.node = node;
                                f.qid = qid;
                                f.open = Some(mode & 0x07);
                            }
                            self.send(&Msg::Rcreate { tag, qid, iounit })?;
                            None
                        }
                        Err(e) => Some(e),
                    },
                    Err(e) => Some(e),
                };
                if let Some(e) = err {
                    self.rerror(tag, &e)?;
                }
            }
            Msg::Tread { tag, fid, offset, count } => {
                let is_dir = match self.read_check(&fid, count) {
                    Ok(is_dir) => is_dir,
                    Err(e) => {
                        self.rerror(tag, &e)?;
                        return Ok(());
                    }
                };
                let node = match self.fids.get(&fid) {
                    Some(f) => f.node,
                    None => {
                        self.rerror(tag, &Error::Server(Errno::BadFid))?;
                        return Ok(());
                    }
                };
                let data = if is_dir {
                    fsys.read_dir(node, offset, count)
                } else {
                    fsys.read(node, offset, count)
                };
                match data {
                    Ok(data) => {
                        if data.len() as u32 > count {
                            self.rerror(
                                tag,
                                &Error::BadField {
                                    op: "Tread",
                                    why: format!(
                                        "backend returned {} bytes for a read of {count}",
                                        data.len()
                                    ),
                                },
                            )?;
                        } else {
                            self.send(&Msg::Rread { tag, data })?;
                        }
                    }
                    Err(e) => self.rerror(tag, &e)?,
                }
            }
            Msg::Twrite { tag, fid, offset, data } => {
                let err = match self.fid_for_write(&fid) {
                    Ok(node) => match fsys.write(node, offset, &data) {
                        Ok(count) => {
                            self.send(&Msg::Rwrite { tag, count })?;
                            None
                        }
                        Err(e) => Some(e),
                    },
                    Err(e) => Some(e),
                };
                if let Some(e) = err {
                    self.rerror(tag, &e)?;
                }
            }
            Msg::Tclunk { tag, fid } => {
                let err = match self.fids.remove(&fid) {
                    Some(f) => fsys.clunk(f.node).err(),
                    None => Some(Error::Server(Errno::BadFid)),
                };
                match err {
                    Some(e) => self.rerror(tag, &e)?,
                    None => self.send(&Msg::Rclunk { tag })?,
                }
            }
            Msg::Tremove { tag, fid } => {
                let err = match self.fids.remove(&fid) {
                    Some(f) => fsys.remove(f.node).err(),
                    None => Some(Error::Server(Errno::BadFid)),
                };
                match err {
                    Some(e) => self.rerror(tag, &e)?,
                    None => self.send(&Msg::Rremove { tag })?,
                }
            }
            Msg::Tstat { tag, fid } => {
                let err = match self.fids.get(&fid) {
                    Some(f) => match fsys.stat(f.node) {
                        Ok(stat) => {
                            self.send(&Msg::Rstat { tag, stat })?;
                            None
                        }
                        Err(e) => Some(e),
                    },
                    None => Some(Error::Server(Errno::BadFid)),
                };
                if let Some(e) = err {
                    self.rerror(tag, &e)?;
                }
            }
            Msg::Twstat { tag, fid, stat } => {
                let err = match self.fids.get(&fid) {
                    Some(f) => fsys.wstat(f.node, &stat).err(),
                    None => Some(Error::Server(Errno::BadFid)),
                };
                match err {
                    Some(e) => self.rerror(tag, &e)?,
                    None => self.send(&Msg::Rwstat { tag })?,
                }
            }
            // messages this stack never sends
            Msg::Rversion { .. }
            | Msg::Rauth { .. }
            | Msg::Rattach { .. }
            | Msg::Rerror { .. }
            | Msg::Rflush { .. }
            | Msg::Rwalk { .. }
            | Msg::Ropen { .. }
            | Msg::Rcreate { .. }
            | Msg::Rread { .. }
            | Msg::Rwrite { .. }
            | Msg::Rclunk { .. }
            | Msg::Rremove { .. }
            | Msg::Rstat { .. }
            | Msg::Rwstat { .. } => {
                self.rerror(
                    tag,
                    &Error::State {
                        op: "dispatch",
                        why: format!("unexpected {} from a client", proto::type_name(msg.typ())),
                    },
                )?;
            }
        }
        Ok(())
    }

    fn dispatch_walk(
        &mut self,
        fsys: &mut dyn Fsys,
        tag: u16,
        fid: u32,
        newfid: u32,
        wnames: &[String],
    ) -> Result<(), Error> {
        let (start, open) = match self.fids.get(&fid) {
            Some(f) => (f.node, f.open.is_some()),
            None => {
                return self.rerror(tag, &Error::Server(Errno::BadFid));
            }
        };
        if open {
            return self.rerror(
                tag,
                &Error::Server(Errno::BadUseFd)
                    .with_ctx(format!("Twalk: fid {fid} is open; walking an open fid is illegal")),
            );
        }
        if self.fids.contains_key(&newfid) && newfid != fid {
            return self.rerror(
                tag,
                &Error::Server(Errno::InUse)
                    .with_ctx(format!("Twalk: newfid {newfid} already in use")),
            );
        }
        let mut qids: Vec<Qid> = Vec::with_capacity(wnames.len());
        let mut cur = start;
        for name in wnames {
            match fsys.walk(cur, name) {
                Ok((next, qid)) => {
                    cur = next;
                    qids.push(qid);
                }
                Err(_) => {
                    // 9P2000: a partial prefix is a legal answer; the
                    // new fid is established only on full success
                    return self.send(&Msg::Rwalk { tag, wqids: qids });
                }
            }
        }
        if !qids.is_empty() || wnames.is_empty() {
            let qid = match qids.last() {
                Some(q) => *q,
                None => match self.fids.get(&fid) {
                    Some(f) => f.qid,
                    None => return self.rerror(tag, &Error::Server(Errno::BadFid)),
                },
            };
            self.fids.insert(newfid, Fid { node: cur, qid, open: None });
        }
        self.send(&Msg::Rwalk { tag, wqids: qids })
    }

    /// Common checks for opens; `None` means "proceed to the backend".
    fn preopen_check(&self, fid: &u32, mode: &u8) -> Option<Error> {
        let f = match self.fids.get(fid) {
            Some(f) => f,
            None => return Some(Error::Server(Errno::BadFid)),
        };
        if f.open.is_some() {
            return Some(
                Error::Server(Errno::BadUseFd)
                    .with_ctx(format!("Topen: fid {fid} is already open")),
            );
        }
        let access = mode & 0x07;
        if access > proto::OEXEC {
            return Some(
                Error::Server(Errno::BadArg)
                    .with_ctx(format!("Topen: open mode {mode:#04x} has an invalid access field")),
            );
        }
        let known = proto::OTRUNC | proto::OCEXEC | proto::ORCLOSE | proto::OEXCL;
        if mode & !0x07 & !known != 0 {
            return Some(
                Error::Server(Errno::BadArg)
                    .with_ctx(format!("Topen: open mode {mode:#04x} sets unknown flags")),
            );
        }
        None
    }

    /// A readable, open fid: returns whether it points at a directory.
    fn read_check(&self, fid: &u32, count: u32) -> Result<bool, Error> {
        let f = self.fids.get(fid).ok_or(Error::Server(Errno::BadFid))?;
        let mode = f.open.ok_or_else(|| {
            Error::Server(Errno::BadUseFd).with_ctx(format!("Tread: fid {fid} is not open"))
        })?;
        if mode != proto::OREAD && mode != proto::ORDWR && mode != proto::OEXEC {
            return Err(Error::Server(Errno::BadUseFd)
                .with_ctx(format!("Tread: fid {fid} is open for writing, not reading")));
        }
        if count > self.read_capacity() {
            return Err(Error::Server(Errno::TooBig).with_ctx(format!(
                "Tread: count of {count} exceeds the negotiated read capacity of {}",
                self.read_capacity()
            )));
        }
        Ok(f.qid.is_dir())
    }

    /// Bytes a read may return: msize minus the read header room.
    fn read_capacity(&self) -> u32 {
        self.msize.saturating_sub(IOHDRSZ)
    }

    /// An open, writable fid, for Twrite/Tcreate.
    fn fid_for_write(&mut self, fid: &u32) -> Result<u64, Error> {
        let f = self.fids.get(fid).ok_or(Error::Server(Errno::BadFid))?;
        let mode = f.open.ok_or_else(|| {
            Error::Server(Errno::BadUseFd).with_ctx(format!("Twrite: fid {fid} is not open"))
        })?;
        if mode != proto::OWRITE && mode != proto::ORDWR {
            return Err(Error::Server(Errno::BadUseFd)
                .with_ctx(format!("Twrite: fid {fid} is not open for writing")));
        }
        Ok(f.node)
    }
}

fn salvage_tag(body: &[u8]) -> u16 {
    // body = type(1) + tag(2) + ...; recover the tag for an Rerror even
    // when the rest failed to parse
    if body.len() >= 3 {
        u16::from_le_bytes([body[1], body[2]])
    } else {
        proto::NOTAG
    }
}

struct Granted {
    msize: u32,
    version: String,
}

fn negotiate(offered: &str, requested: u32) -> Granted {
    let msize = requested.clamp(MIN_MSIZE, MAX_MSIZE);
    // we speak plain 9P2000; a "9P2000.x" dialect offer falls back to
    // the base dialect per the spec's negotiation rule
    if offered == proto::VERSION_9P2000 || offered.starts_with("9P2000.") {
        Granted { msize, version: proto::VERSION_9P2000.to_string() }
    } else {
        Granted { msize, version: "unknown".to_string() }
    }
}

/// Accept connections forever, serving each on its own thread with a
/// fresh backend from `factory`. Blocks the caller.
pub fn serve(listener: TcpListener, factory: impl Fn() -> Box<dyn Fsys> + Send + Sync + 'static) {
    for stream in listener.incoming() {
        match stream {
            Ok(sock) => {
                let fsys = factory();
                thread::spawn(move || {
                    let mut conn = ServerConn::new(sock);
                    let mut fsys = fsys;
                    if let Err(e) = conn.serve(fsys.as_mut()) {
                        eprintln!("namikaze-9p: connection ended: {e}");
                    }
                });
            }
            Err(e) => eprintln!("namikaze-9p: accept failed: {e}"),
        }
    }
}

/// Serve exactly one connection over an already-established stream.
pub fn serve_conn<S: Read + Write>(io: S, fsys: Box<dyn Fsys>) -> Result<()> {
    let mut fsys = fsys;
    ServerConn::new(io).serve(&mut *fsys)
}

/// Convenience: a Synth tree wrapped in a boxed backend.
pub fn serve_synth(synth: Synth) -> Box<dyn Fsys> {
    Box::new(synth)
}

/// Convenience: dial a TCP listener socket for tests and small servers.
pub fn listen(addr: &str) -> Result<TcpListener> {
    Ok(TcpListener::bind(addr)?)
}
