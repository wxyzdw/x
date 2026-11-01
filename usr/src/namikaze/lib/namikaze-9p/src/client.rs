// SPDX-License-Identifier: MPL-2.0
//! The 9P client side: dial, version negotiation, attach, walk, open,
//! read, write, stat and clunk over any duplex stream. Adapted from
//! Plan 9's `/sys/src/lib9pclient` usage patterns with one synchronous
//! outstanding request per connection and strict reply validation:
//! every reply's type and tag are checked, and a partial walk names the
//! exact element that failed.

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::error::{Errno, Error, Result};
use crate::proto::{self, Dir, Msg, Qid};

/// Largest frame the client offers at version negotiation.
pub const CLIENT_MSIZE: u32 = 8192;

/// A synchronous 9P2000 connection. The caller owns fid allocation, as
/// in lib9pclient: `attach` a fid, `walk` it to a file, `open`, use it,
/// then `clunk`.
pub struct Conn<S: Read + Write> {
    io: S,
    msize: u32,
    next_tag: u16,
    /// Set when the session ended on a transport error; further RPCs
    /// are refused with a State error instead of corrupting the wire.
    dead: Option<String>,
}

impl<S: Read + Write> Conn<S> {
    /// Take an established duplex stream and negotiate 9P2000 over it.
    pub fn new(mut io: S) -> Result<Conn<S>, Error> {
        let hello = Msg::Tversion {
            tag: proto::NOTAG,
            msize: CLIENT_MSIZE,
            version: proto::VERSION_9P2000.to_string(),
        };
        let frame = hello.serialize(CLIENT_MSIZE)?;
        io.write_all(&frame)?;
        io.flush()?;

        let body = read_frame(&mut io, CLIENT_MSIZE)?;
        let msg = Msg::parse(&body)?;
        let (msize, version) = match msg {
            Msg::Rversion { tag, msize, version } if tag == proto::NOTAG => (msize, version),
            other => {
                return Err(Error::State {
                    op: "version",
                    why: format!(
                        "expected Rversion with NOTAG, got {}",
                        proto::type_name(other.typ())
                    ),
                });
            }
        };
        if version != proto::VERSION_9P2000 {
            return Err(Error::Version { got: version });
        }
        let msize = msize.min(CLIENT_MSIZE);
        if msize < 16 {
            return Err(Error::BadField {
                op: "version",
                why: format!("peer granted an msize of {msize}, below the minimum of 16"),
            });
        }
        Ok(Conn { io, msize, next_tag: 1, dead: None })
    }

    /// The negotiated message size.
    pub fn msize(&self) -> u32 {
        self.msize
    }

    /// Send one pre-serialized frame (protocol diagnostics and tests).
    pub fn send_raw(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.io.write_all(frame)?;
        self.io.flush()?;
        Ok(())
    }

    /// Receive one raw frame (protocol diagnostics and tests).
    pub fn recv_raw(&mut self) -> Result<Vec<u8>, Error> {
        read_frame(&mut self.io, self.msize)
    }

    fn tag(&mut self, op: &'static str) -> Result<u16, Error> {
        if let Some(why) = &self.dead {
            return Err(Error::State { op, why: format!("connection is dead: {why}") });
        }
        let tag = self.next_tag;
        self.next_tag = self
            .next_tag
            .checked_add(1)
            .filter(|t| *t != proto::NOTAG)
            .ok_or(Error::State { op, why: "tag space exhausted".into() })?;
        Ok(tag)
    }

    /// One request/reply exchange with full type and tag validation.
    pub fn rpc(&mut self, msg: Msg) -> Result<Msg, Error> {
        let op = proto::type_name(msg.typ());
        let tag = msg.tag();
        let frame = msg.serialize(self.msize)?;
        if let Err(e) = self.io.write_all(&frame).and_then(|_| self.io.flush()) {
            let why = format!("{op} write failed: {e}");
            self.dead = Some(why.clone());
            return Err(Error::Io(e).with_ctx(why));
        }
        let body = match read_frame(&mut self.io, self.msize) {
            Ok(body) => body,
            Err(Error::Io(e)) => {
                let why = format!("{op} read failed: {e}");
                self.dead = Some(why.clone());
                return Err(Error::Io(e).with_ctx(why));
            }
            Err(other) => return Err(other.with_ctx(op)),
        };
        let reply = Msg::parse(&body)?;
        if reply.tag() != tag {
            return Err(Error::State {
                op,
                why: format!("reply tag {} does not match request tag {tag}", reply.tag()),
            });
        }
        match reply {
            Msg::Rerror { ename, .. } => {
                Err(Error::Server(Errno::classify(&ename)).with_ctx(op))
            }
            other if other.typ() == msg.typ() + 1 => Ok(other),
            other => Err(Error::State {
                op,
                why: format!(
                    "expected {} for {op}, got {}",
                    proto::type_name(msg.typ() + 1),
                    proto::type_name(other.typ())
                ),
            }),
        }
    }

    /// Attach a fid to the export named `aname`; returns the root qid.
    pub fn attach(&mut self, fid: u32, afid: u32, uname: &str, aname: &str) -> Result<Qid, Error> {
        let tag = self.tag("Tattach")?;
        match self.rpc(Msg::Tattach { tag, fid, afid, uname: uname.into(), aname: aname.into() })? {
            Msg::Rattach { aqid, .. } => Ok(aqid),
            other => Err(unexpected("Tattach", other)),
        }
    }

    /// Walk `wnames` from `fid` into `newfid`; returns one qid per name.
    pub fn walk(&mut self, fid: u32, newfid: u32, wnames: &[String]) -> Result<Vec<Qid>, Error> {
        if wnames.len() > proto::MAX_WELEM {
            return Err(Error::BadField {
                op: "walk",
                why: format!(
                    "{} names exceed the {} element limit",
                    wnames.len(),
                    proto::MAX_WELEM
                ),
            });
        }
        let tag = self.tag("Twalk")?;
        match self.rpc(Msg::Twalk { tag, fid, newfid, wnames: wnames.to_vec() })? {
            Msg::Rwalk { wqids, .. } => {
                if wqids.len() != wnames.len() {
                    let stop = wqids.len();
                    let name = wnames.get(stop).map(String::as_str).unwrap_or("?");
                    return Err(Error::Server(Errno::NotFound).with_ctx(format!(
                        "walk stopped at element {stop} \"{name}\" ({} of {} elements resolved)",
                        stop,
                        wnames.len()
                    )));
                }
                Ok(wqids)
            }
            other => Err(unexpected("Twalk", other)),
        }
    }

    /// Walk a slash-separated path from `root` into `newfid`, in
    /// chunks of at most 16 elements (the protocol walk limit), reusing
    /// `newfid` as the stepping stone for later chunks. Diagnostics
    /// name the failing element and the path context.
    pub fn walk_path(&mut self, root: u32, newfid: u32, path: &str) -> Result<Vec<Qid>, Error> {
        let parts: Vec<String> = path
            .split('/')
            .filter(|p| !p.is_empty() && *p != ".")
            .map(String::from)
            .collect();
        if parts.is_empty() {
            return Err(Error::BadField {
                op: "walk_path",
                why: format!("path \"{path}\" has no elements"),
            });
        }
        let mut all: Vec<Qid> = Vec::with_capacity(parts.len());
        for chunk in parts.chunks(proto::MAX_WELEM) {
            let from = if all.is_empty() { root } else { newfid };
            let ids = self
                .walk(from, newfid, chunk)
                .map_err(|e| e.with_ctx(format!("walk_path \"{path}\"")))?;
            all.extend(ids);
        }
        Ok(all)
    }

    /// Open a walked fid; returns the final qid and iounit.
    pub fn open(&mut self, fid: u32, mode: u8) -> Result<(Qid, u32), Error> {
        let tag = self.tag("Topen")?;
        match self.rpc(Msg::Topen { tag, fid, mode })? {
            Msg::Ropen { qid, iounit, .. } => Ok((qid, iounit)),
            other => Err(unexpected("Topen", other)),
        }
    }

    /// Read up to `count` bytes at `offset` (clamped to the negotiated
    /// iounit so a single read never overflows one frame).
    pub fn read(&mut self, fid: u32, offset: u64, count: u32) -> Result<Vec<u8>, Error> {
        let count = count.min(self.read_capacity());
        let tag = self.tag("Tread")?;
        match self.rpc(Msg::Tread { tag, fid, offset, count })? {
            Msg::Rread { data, .. } => Ok(data),
            other => Err(unexpected("Tread", other)),
        }
    }

    /// Read whole file content by looping until a short read.
    pub fn read_all(&mut self, fid: u32) -> Result<Vec<u8>, Error> {
        let cap = self.read_capacity();
        let mut out = Vec::new();
        let mut offset = 0u64;
        loop {
            let chunk = self.read(fid, offset, cap)?;
            let n = chunk.len() as u64;
            if n == 0 {
                return Ok(out);
            }
            out.extend_from_slice(&chunk);
            offset += n;
        }
    }

    /// Write `data` at `offset`; returns bytes written.
    pub fn write(&mut self, fid: u32, offset: u64, data: &[u8]) -> Result<u32, Error> {
        let tag = self.tag("Twrite")?;
        let capped = data.len().min((self.msize.saturating_sub(proto::IOHDRSZ + 12)) as usize);
        match self.rpc(Msg::Twrite {
            tag,
            fid,
            offset,
            data: data[..capped].to_vec(),
        })? {
            Msg::Rwrite { count, .. } => Ok(count),
            other => Err(unexpected("Twrite", other)),
        }
    }

    /// Stat a fid.
    pub fn stat(&mut self, fid: u32) -> Result<Dir, Error> {
        let tag = self.tag("Tstat")?;
        match self.rpc(Msg::Tstat { tag, fid })? {
            Msg::Rstat { stat, .. } => Ok(stat),
            other => Err(unexpected("Tstat", other)),
        }
    }

    /// Release a fid.
    pub fn clunk(&mut self, fid: u32) -> Result<(), Error> {
        let tag = self.tag("Tclunk")?;
        match self.rpc(Msg::Tclunk { tag, fid })? {
            Msg::Rclunk { .. } => Ok(()),
            other => Err(unexpected("Tclunk", other)),
        }
    }

    /// Read capacity derived from the negotiated msize.
    fn read_capacity(&self) -> u32 {
        self.msize.saturating_sub(proto::IOHDRSZ)
    }
}

impl Conn<TcpStream> {
    /// Dial `host:port` and negotiate 9P2000.
    pub fn dial(addr: &str) -> Result<Conn<TcpStream>, Error> {
        let sock = TcpStream::connect(addr)?;
        Conn::new(sock)
    }
}

/// Read one length-prefixed frame body from a buffered stream.
fn read_frame<R: Read>(io: &mut R, msize: u32) -> Result<Vec<u8>, Error> {
    let mut size_buf = [0u8; 4];
    io.read_exact(&mut size_buf)?;
    let size = u32::from_le_bytes(size_buf);
    if size < 7 {
        return Err(Error::BadField {
            op: "read_frame",
            why: format!("frame of {size} bytes is below the 7-byte minimum"),
        });
    }
    if size > msize {
        return Err(Error::Oversize { op: "read_frame", limit: msize, got: size });
    }
    let mut body = vec![0u8; (size - 4) as usize];
    io.read_exact(&mut body)?;
    Ok(body)
}

/// The reply type was syntactically valid but not the answer to our
/// request (the rpc() type check passed, so this is a logic slip).
fn unexpected(op: &'static str, msg: Msg) -> Error {
    Error::State {
        op,
        why: format!("unexpected reply type {}", proto::type_name(msg.typ())),
    }
}
