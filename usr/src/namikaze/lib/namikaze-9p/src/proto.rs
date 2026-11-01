// SPDX-License-Identifier: MPL-2.0
//! The 9P2000 message set, transcribed from Plan 9's
//! `/sys/include/fcall.h` (4th edition) and adapted to a typed Rust
//! enum. Every message carries its `tag`; parsing and serialization are
//! total functions over `Result` and never panic on malformed input.

use crate::codec::{Reader, Writer};
use crate::error::Error;

// Message types (fcall.h)
pub const TVERSION: u8 = 100;
pub const RVERSION: u8 = 101;
pub const TAUTH: u8 = 102;
pub const RAUTH: u8 = 103;
pub const TATTACH: u8 = 104;
pub const RATTACH: u8 = 105;
pub const TERROR: u8 = 106; // illegal
pub const RERROR: u8 = 107;
pub const TFLUSH: u8 = 108;
pub const RFLUSH: u8 = 109;
pub const TWALK: u8 = 110;
pub const RWALK: u8 = 111;
pub const TOPEN: u8 = 112;
pub const ROPEN: u8 = 113;
pub const TCREATE: u8 = 114;
pub const RCREATE: u8 = 115;
pub const TREAD: u8 = 116;
pub const RREAD: u8 = 117;
pub const TWRITE: u8 = 118;
pub const RWRITE: u8 = 119;
pub const TCLUNK: u8 = 120;
pub const RCLUNK: u8 = 121;
pub const TREMOVE: u8 = 122;
pub const RREMOVE: u8 = 123;
pub const TSTAT: u8 = 124;
pub const RSTAT: u8 = 125;
pub const TWSTAT: u8 = 126;
pub const RWSTAT: u8 = 127;

/// The only protocol dialect this stack speaks.
pub const VERSION_9P2000: &str = "9P2000";
/// Sent in place of a fid when no fid applies.
pub const NOFID: u32 = u32::MAX;
/// Tag that identifies no message.
pub const NOTAG: u16 = u16::MAX;
/// Plan 9 caps a walk at 16 elements per request.
pub const MAX_WELEM: usize = 16;
/// Ceiling we accept for `msize` regardless of what the peer offers.
pub const MAX_MSIZE: u32 = 1 << 20;
/// Smallest legal frame: size(4) + type(1) + tag(2) + one field byte.
pub const MIN_MSIZE: u32 = 16;

/// Plan 9's IOHDRSZ: header room a read/write must leave in one frame.
pub const IOHDRSZ: u32 = 24;

// Qid types (fcall.h)
pub const QTDIR: u8 = 0x80;
pub const QTAPPEND: u8 = 0x40;
pub const QTEXCL: u8 = 0x20;
pub const QTMOUNT: u8 = 0x10;
pub const QTAUTH: u8 = 0x08;
pub const QTTMP: u8 = 0x04;
pub const QTSYMLINK: u8 = 0x02;
pub const QTFILE: u8 = 0x00;

// Open modes (fcall.h)
pub const OREAD: u8 = 0;
pub const OWRITE: u8 = 1;
pub const ORDWR: u8 = 2;
pub const OEXEC: u8 = 3;
pub const OTRUNC: u8 = 16;
pub const OCEXEC: u8 = 32;
pub const ORCLOSE: u8 = 64;
pub const OEXCL: u8 = 128;

// Directory mode bits (fcall.h)
pub const DMDIR: u32 = 0x8000_0000;
pub const DMAPPEND: u32 = 0x4000_0000;
pub const DMEXCL: u32 = 0x2000_0000;
pub const DMMOUNT: u32 = 0x1000_0000;
pub const DMAUTH: u32 = 0x0800_0000;
pub const DMTMP: u32 = 0x0400_0000;
pub const DMSYMLINK: u32 = 0x0200_0000;
pub const DMREAD: u32 = 4;
pub const DMWRITE: u32 = 2;
pub const DMEXEC: u32 = 1;

/// Human-readable name of a message type, for diagnostics and traces.
pub fn type_name(t: u8) -> &'static str {
    match t {
        TVERSION => "Tversion",
        RVERSION => "Rversion",
        TAUTH => "Tauth",
        RAUTH => "Rauth",
        TATTACH => "Tattach",
        RATTACH => "Rattach",
        TERROR => "Terror",
        RERROR => "Rerror",
        TFLUSH => "Tflush",
        RFLUSH => "Rflush",
        TWALK => "Twalk",
        RWALK => "Rwalk",
        TOPEN => "Topen",
        ROPEN => "Ropen",
        TCREATE => "Tcreate",
        RCREATE => "Rcreate",
        TREAD => "Tread",
        RREAD => "Rread",
        TWRITE => "Twrite",
        RWRITE => "Rwrite",
        TCLUNK => "Tclunk",
        RCLUNK => "Rclunk",
        TREMOVE => "Tremove",
        RREMOVE => "Rremove",
        TSTAT => "Tstat",
        RSTAT => "Rstat",
        TWSTAT => "Twstat",
        RWSTAT => "Rwstat",
        _ => "unknown",
    }
}

/// The unique file identifier: type flags, version (for cache
/// invalidation) and a server-unique path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Qid {
    /// QT* flags.
    pub typ: u8,
    /// Version of the file, bumped on modification.
    pub vers: u32,
    /// Server-unique path.
    pub path: u64,
}

impl Qid {
    /// True when the qid carries `QTDIR`.
    pub fn is_dir(&self) -> bool {
        self.typ & QTDIR != 0
    }
}

/// One decoded 9P2000 message. `tag` is present in every variant; the
/// four-byte size prefix is transport framing and lives outside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    Tversion {
        tag: u16,
        msize: u32,
        version: String,
    },
    Rversion {
        tag: u16,
        msize: u32,
        version: String,
    },
    Tauth {
        tag: u16,
        afid: u32,
        uname: String,
        aname: String,
    },
    Rauth {
        tag: u16,
        aqid: Qid,
    },
    Tattach {
        tag: u16,
        fid: u32,
        afid: u32,
        uname: String,
        aname: String,
    },
    Rattach {
        tag: u16,
        aqid: Qid,
    },
    /// Received only; never sent by this stack.
    Rerror {
        tag: u16,
        ename: String,
    },
    Tflush {
        tag: u16,
        oldtag: u16,
    },
    Rflush {
        tag: u16,
    },
    Twalk {
        tag: u16,
        fid: u32,
        newfid: u32,
        wnames: Vec<String>,
    },
    Rwalk {
        tag: u16,
        wqids: Vec<Qid>,
    },
    Topen {
        tag: u16,
        fid: u32,
        mode: u8,
    },
    Ropen {
        tag: u16,
        qid: Qid,
        iounit: u32,
    },
    Tcreate {
        tag: u16,
        fid: u32,
        name: String,
        perm: u32,
        mode: u8,
    },
    Rcreate {
        tag: u16,
        qid: Qid,
        iounit: u32,
    },
    Tread {
        tag: u16,
        fid: u32,
        offset: u64,
        count: u32,
    },
    Rread {
        tag: u16,
        data: Vec<u8>,
    },
    Twrite {
        tag: u16,
        fid: u32,
        offset: u64,
        data: Vec<u8>,
    },
    Rwrite {
        tag: u16,
        count: u32,
    },
    Tclunk {
        tag: u16,
        fid: u32,
    },
    Rclunk {
        tag: u16,
    },
    Tremove {
        tag: u16,
        fid: u32,
    },
    Rremove {
        tag: u16,
    },
    Tstat {
        tag: u16,
        fid: u32,
    },
    Rstat {
        tag: u16,
        stat: Dir,
    },
    Twstat {
        tag: u16,
        fid: u32,
        stat: Dir,
    },
    Rwstat {
        tag: u16,
    },
}

impl Msg {
    /// The message type byte.
    pub fn typ(&self) -> u8 {
        match self {
            Msg::Tversion { .. } => TVERSION,
            Msg::Rversion { .. } => RVERSION,
            Msg::Tauth { .. } => TAUTH,
            Msg::Rauth { .. } => RAUTH,
            Msg::Tattach { .. } => TATTACH,
            Msg::Rattach { .. } => RATTACH,
            Msg::Rerror { .. } => RERROR,
            Msg::Tflush { .. } => TFLUSH,
            Msg::Rflush { .. } => RFLUSH,
            Msg::Twalk { .. } => TWALK,
            Msg::Rwalk { .. } => RWALK,
            Msg::Topen { .. } => TOPEN,
            Msg::Ropen { .. } => ROPEN,
            Msg::Tcreate { .. } => TCREATE,
            Msg::Rcreate { .. } => RCREATE,
            Msg::Tread { .. } => TREAD,
            Msg::Rread { .. } => RREAD,
            Msg::Twrite { .. } => TWRITE,
            Msg::Rwrite { .. } => RWRITE,
            Msg::Tclunk { .. } => TCLUNK,
            Msg::Rclunk { .. } => RCLUNK,
            Msg::Tremove { .. } => TREMOVE,
            Msg::Rremove { .. } => RREMOVE,
            Msg::Tstat { .. } => TSTAT,
            Msg::Rstat { .. } => RSTAT,
            Msg::Twstat { .. } => TWSTAT,
            Msg::Rwstat { .. } => RWSTAT,
        }
    }

    /// The message tag.
    pub fn tag(&self) -> u16 {
        match self {
            Msg::Tversion { tag, .. }
            | Msg::Rversion { tag, .. }
            | Msg::Tauth { tag, .. }
            | Msg::Rauth { tag, .. }
            | Msg::Tattach { tag, .. }
            | Msg::Rattach { tag, .. }
            | Msg::Rerror { tag, .. }
            | Msg::Tflush { tag, .. }
            | Msg::Rflush { tag, .. }
            | Msg::Twalk { tag, .. }
            | Msg::Rwalk { tag, .. }
            | Msg::Topen { tag, .. }
            | Msg::Ropen { tag, .. }
            | Msg::Tcreate { tag, .. }
            | Msg::Rcreate { tag, .. }
            | Msg::Tread { tag, .. }
            | Msg::Rread { tag, .. }
            | Msg::Twrite { tag, .. }
            | Msg::Rwrite { tag, .. }
            | Msg::Tclunk { tag, .. }
            | Msg::Rclunk { tag, .. }
            | Msg::Tremove { tag, .. }
            | Msg::Rremove { tag, .. }
            | Msg::Tstat { tag, .. }
            | Msg::Rstat { tag, .. }
            | Msg::Twstat { tag, .. }
            | Msg::Rwstat { tag } => *tag,
        }
    }

    /// Serialize to one frame, size-prefixed, under `msize`.
    pub fn serialize(&self, msize: u32) -> Result<Vec<u8>, Error> {
        let mut w = Writer::new(self.typ());
        match self {
            Msg::Tversion { tag, msize: m, version } | Msg::Rversion { tag, msize: m, version } => {
                w.u16(*tag).u32(*m).string(version);
            }
            Msg::Tauth { tag, afid, uname, aname } => {
                w.u16(*tag).u32(*afid).string(uname).string(aname);
            }
            Msg::Rauth { tag, aqid } => {
                w.u16(*tag).qid(aqid);
            }
            Msg::Tattach { tag, fid, afid, uname, aname } => {
                w.u16(*tag).u32(*fid).u32(*afid).string(uname).string(aname);
            }
            Msg::Rattach { tag, aqid } => {
                w.u16(*tag).qid(aqid);
            }
            Msg::Rerror { tag, ename } => {
                w.u16(*tag).string(ename);
            }
            Msg::Tflush { tag, oldtag } => {
                w.u16(*tag).u16(*oldtag);
            }
            Msg::Rflush { tag } => {
                w.u16(*tag);
            }
            Msg::Twalk { tag, fid, newfid, wnames } => {
                if wnames.len() > MAX_WELEM {
                    return Err(Error::BadField {
                        op: "Twalk",
                        why: format!("{} walk elements, limit is {MAX_WELEM}", wnames.len()),
                    });
                }
                w.u16(*tag).u32(*fid).u32(*newfid).u16(wnames.len() as u16);
                for name in wnames {
                    w.string(name);
                }
            }
            Msg::Rwalk { tag, wqids } => {
                if wqids.len() > MAX_WELEM {
                    return Err(Error::BadField {
                        op: "Rwalk",
                        why: format!("{} qids, limit is {MAX_WELEM}", wqids.len()),
                    });
                }
                w.u16(*tag).u16(wqids.len() as u16);
                for q in wqids {
                    w.qid(q);
                }
            }
            Msg::Topen { tag, fid, mode } => {
                w.u16(*tag).u32(*fid).u8(*mode);
            }
            Msg::Ropen { tag, qid, iounit } | Msg::Rcreate { tag, qid, iounit } => {
                w.u16(*tag).qid(qid).u32(*iounit);
            }
            Msg::Tcreate { tag, fid, name, perm, mode } => {
                w.u16(*tag).u32(*fid).string(name).u32(*perm).u8(*mode);
            }
            Msg::Tread { tag, fid, offset, count } => {
                w.u16(*tag).u32(*fid).u64(*offset).u32(*count);
            }
            Msg::Rread { tag, data } => {
                w.u16(*tag);
                w.blob(data)?;
            }
            Msg::Twrite { tag, fid, offset, data } => {
                if data.len() > (msize as usize).saturating_sub(8 + 8 + 4 + 2 + 4 + 1) {
                    return Err(Error::Oversize {
                        op: "Twrite",
                        limit: msize,
                        got: data.len() as u32,
                    });
                }
                w.u16(*tag).u32(*fid).u64(*offset);
                w.blob(data)?;
            }
            Msg::Rwrite { tag, count } => {
                w.u16(*tag).u32(*count);
            }
            Msg::Tclunk { tag, fid } | Msg::Tremove { tag, fid } => {
                w.u16(*tag).u32(*fid);
            }
            Msg::Rclunk { tag } | Msg::Rremove { tag } => {
                w.u16(*tag);
            }
            Msg::Tstat { tag, fid } => {
                w.u16(*tag).u32(*fid);
            }
            Msg::Rstat { tag, stat } => {
                w.u16(*tag);
                w.blob(&stat.encode()?)?;
            }
            Msg::Twstat { tag, fid, stat } => {
                w.u16(*tag).u32(*fid);
                w.blob(&stat.encode()?)?;
            }
            Msg::Rwstat { tag } => {
                w.u16(*tag);
            }
        }
        w.finish(msize)
    }

    /// Parse one message body (everything after the 4-byte size prefix).
    pub fn parse(body: &[u8]) -> Result<Msg, Error> {
        let mut r = Reader::new("parse", body);
        let typ = r.u8()?;
        let tag = r.u16()?;
        let msg = match typ {
            TVERSION | RVERSION => {
                let msize = r.u32()?;
                let version = r.string()?;
                if typ == TVERSION {
                    Msg::Tversion { tag, msize, version }
                } else {
                    Msg::Rversion { tag, msize, version }
                }
            }
            TAUTH => Msg::Tauth { tag, afid: r.u32()?, uname: r.string()?, aname: r.string()? },
            RAUTH => Msg::Rauth { tag, aqid: r.qid()? },
            TATTACH => Msg::Tattach {
                tag,
                fid: r.u32()?,
                afid: r.u32()?,
                uname: r.string()?,
                aname: r.string()?,
            },
            RATTACH => Msg::Rattach { tag, aqid: r.qid()? },
            RERROR => Msg::Rerror { tag, ename: r.string()? },
            TFLUSH => Msg::Tflush { tag, oldtag: r.u16()? },
            RFLUSH => Msg::Rflush { tag },
            TWALK => {
                let fid = r.u32()?;
                let newfid = r.u32()?;
                let nwname = r.u16()? as usize;
                if nwname > MAX_WELEM {
                    return Err(Error::BadField {
                        op: "Twalk",
                        why: format!("{nwname} walk elements, limit is {MAX_WELEM}"),
                    });
                }
                let mut wnames = Vec::with_capacity(nwname);
                for _ in 0..nwname {
                    wnames.push(r.string()?);
                }
                Msg::Twalk { tag, fid, newfid, wnames }
            }
            RWALK => {
                let nwqid = r.u16()? as usize;
                if nwqid > MAX_WELEM {
                    return Err(Error::BadField {
                        op: "Rwalk",
                        why: format!("{nwqid} qids, limit is {MAX_WELEM}"),
                    });
                }
                let mut wqids = Vec::with_capacity(nwqid);
                for _ in 0..nwqid {
                    wqids.push(r.qid()?);
                }
                Msg::Rwalk { tag, wqids }
            }
            TOPEN => Msg::Topen { tag, fid: r.u32()?, mode: r.u8()? },
            ROPEN | RCREATE => {
                let qid = r.qid()?;
                let iounit = r.u32()?;
                if typ == ROPEN {
                    Msg::Ropen { tag, qid, iounit }
                } else {
                    Msg::Rcreate { tag, qid, iounit }
                }
            }
            TCREATE => Msg::Tcreate {
                tag,
                fid: r.u32()?,
                name: r.string()?,
                perm: r.u32()?,
                mode: r.u8()?,
            },
            TREAD => Msg::Tread { tag, fid: r.u32()?, offset: r.u64()?, count: r.u32()? },
            RREAD => {
                let len = r.u16()? as usize;
                let data = r.bytes(len)?.to_vec();
                Msg::Rread { tag, data }
            }
            TWRITE => {
                let fid = r.u32()?;
                let offset = r.u64()?;
                let len = r.u16()? as usize;
                let data = r.bytes(len)?.to_vec();
                Msg::Twrite { tag, fid, offset, data }
            }
            RWRITE => Msg::Rwrite { tag, count: r.u32()? },
            TCLUNK => Msg::Tclunk { tag, fid: r.u32()? },
            RCLUNK => Msg::Rclunk { tag },
            TREMOVE => Msg::Tremove { tag, fid: r.u32()? },
            RREMOVE => Msg::Rremove { tag },
            TSTAT => Msg::Tstat { tag, fid: r.u32()? },
            RSTAT => Msg::Rstat { tag, stat: Dir::decode(r.blob2("Rstat")?)? },
            TWSTAT => {
                let fid = r.u32()?;
                let stat = Dir::decode(r.blob2("Twstat")?)?;
                Msg::Twstat { tag, fid, stat }
            }
            RWSTAT => Msg::Rwstat { tag },
            _ => {
                return Err(Error::BadType { op: "parse", got: typ });
            }
        };
        r.finish()?;
        Ok(msg)
    }
}

/// A decoded Plan 9 directory entry (the stat structure of fcall.h).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Dir {
    /// Server type (2 bytes on the wire; unused by this stack).
    pub typ: u16,
    /// Server device (4 bytes on the wire; unused by this stack).
    pub dev: u32,
    /// The qid of the file.
    pub qid: Qid,
    /// Permissions and DMDIR and friends.
    pub mode: u32,
    /// Last access, seconds since the epoch.
    pub atime: u32,
    /// Last modification, seconds since the epoch.
    pub mtime: u32,
    /// Length in bytes.
    pub length: u64,
    /// Leaf name.
    pub name: String,
    /// Owning user.
    pub uid: String,
    /// Owning group.
    pub gid: String,
    /// Last user who modified.
    pub muid: String,
}

impl Dir {
    /// Fixed wire size: type(2) + dev(4) + qid(13) + mode(4) + atime(4)
    /// + mtime(4) + length(8) = 39 bytes before the four strings.
    pub fn fixed_size() -> u32 {
        39
    }

    /// Encode into the wire stat blob (u16 size prefix + payload).
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let strings_len =
            2 + self.name.len() + 2 + self.uid.len() + 2 + self.gid.len() + 2 + self.muid.len();
        // the size field counts itself, as plan9's convS2M does: a
        // directory reader steps through entries with pos += size
        let total = 2 + Self::fixed_size() as usize + strings_len;
        if total > u16::MAX as usize {
            return Err(Error::Oversize { op: "stat", limit: u16::MAX as u32, got: total as u32 });
        }
        let mut body: Vec<u8> = Vec::with_capacity(total);
        body.extend_from_slice(&(total as u16).to_le_bytes());
        body.extend_from_slice(&self.typ.to_le_bytes());
        body.extend_from_slice(&self.dev.to_le_bytes());
        body.push(self.qid.typ);
        body.extend_from_slice(&self.qid.vers.to_le_bytes());
        body.extend_from_slice(&self.qid.path.to_le_bytes());
        body.extend_from_slice(&self.mode.to_le_bytes());
        body.extend_from_slice(&self.atime.to_le_bytes());
        body.extend_from_slice(&self.mtime.to_le_bytes());
        body.extend_from_slice(&self.length.to_le_bytes());
        for s in [&self.name, &self.uid, &self.gid, &self.muid] {
            body.extend_from_slice(&(s.len() as u16).to_le_bytes());
            body.extend_from_slice(s.as_bytes());
        }
        Ok(body)
    }

    /// Decode from a u16-prefixed wire stat blob.
    pub fn decode(raw: &[u8]) -> Result<Dir, Error> {
        if raw.len() < 2 {
            return Err(Error::ShortRead { op: "stat", want: 2, got: raw.len() });
        }
        let declared = u16::from_le_bytes([raw[0], raw[1]]) as usize;
        if declared != raw.len() {
            return Err(Error::BadField {
                op: "stat",
                why: format!("stat size {declared} does not match blob length {}", raw.len()),
            });
        }
        let mut r = Reader::new("stat", raw);
        let _size = r.u16()?;
        let typ = r.u16()?;
        let dev = r.u32()?;
        let qid = r.qid()?;
        let mode = r.u32()?;
        let atime = r.u32()?;
        let mtime = r.u32()?;
        let length = r.u64()?;
        let name = r.string()?;
        let uid = r.string()?;
        let gid = r.string()?;
        let muid = r.string()?;
        r.finish()?;
        Ok(Dir { typ, dev, qid, mode, atime, mtime, length, name, uid, gid, muid })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: Msg, msize: u32) -> Msg {
        let frame = msg.serialize(msize).expect("serialize");
        assert!(frame.len() as u32 <= msize);
        let body = &frame[4..];
        assert_eq!(body[0], msg.typ(), "type byte");
        Msg::parse(body).expect("parse")
    }

    #[test]
    fn every_message_round_trips() {
        let q = Qid { typ: QTDIR, vers: 3, path: 0x1234_5678_9ABC_DEF0 };
        let d = Dir {
            typ: 1,
            dev: 2,
            qid: q,
            mode: DMDIR | 0o755,
            atime: 1_700_000_000,
            mtime: 1_700_000_100,
            length: 4096,
            name: "src".into(),
            uid: "bootes".into(),
            gid: "sys".into(),
            muid: "glenda".into(),
        };
        let cases = vec![
            Msg::Tversion { tag: NOTAG, msize: 8192, version: VERSION_9P2000.into() },
            Msg::Rversion { tag: NOTAG, msize: 8192, version: VERSION_9P2000.into() },
            Msg::Tauth { tag: 1, afid: 2, uname: "glenda".into(), aname: "".into() },
            Msg::Rauth { tag: 1, aqid: q },
            Msg::Tattach { tag: 1, fid: 3, afid: NOFID, uname: "glenda".into(), aname: "".into() },
            Msg::Rattach { tag: 1, aqid: q },
            Msg::Rerror { tag: 1, ename: estr_here() },
            Msg::Tflush { tag: 2, oldtag: 1 },
            Msg::Rflush { tag: 2 },
            Msg::Twalk { tag: 3, fid: 3, newfid: 4, wnames: vec!["sys".into(), "src".into()] },
            Msg::Rwalk { tag: 3, wqids: vec![q, q] },
            Msg::Topen { tag: 4, fid: 4, mode: OREAD },
            Msg::Ropen { tag: 4, qid: q, iounit: 8168 },
            Msg::Tcreate { tag: 5, fid: 4, name: "new".into(), perm: 0o644, mode: ORDWR },
            Msg::Rcreate { tag: 5, qid: q, iounit: 8168 },
            Msg::Tread { tag: 6, fid: 4, offset: 128, count: 8168 },
            Msg::Rread { tag: 6, data: b"hello plan9\n".to_vec() },
            Msg::Twrite { tag: 7, fid: 4, offset: 0, data: b"abc".to_vec() },
            Msg::Rwrite { tag: 7, count: 3 },
            Msg::Tclunk { tag: 8, fid: 4 },
            Msg::Rclunk { tag: 8 },
            Msg::Tremove { tag: 9, fid: 4 },
            Msg::Rremove { tag: 9 },
            Msg::Tstat { tag: 10, fid: 4 },
            Msg::Rstat { tag: 10, stat: d.clone() },
            Msg::Twstat { tag: 11, fid: 4, stat: d },
            Msg::Rwstat { tag: 11 },
        ];
        for case in cases {
            let back = roundtrip(case.clone(), 8192);
            assert_eq!(back, case, "roundtrip of {:?}", type_name(case.typ()));
        }
    }

    fn estr_here() -> String {
        "file does not exist".into()
    }

    #[test]
    fn walk_over_limit_is_rejected_before_the_wire() {
        let msg = Msg::Twalk { tag: 1, fid: 2, newfid: 3, wnames: vec!["x".into(); MAX_WELEM + 1] };
        let err = msg.serialize(8192).expect_err("over the walk limit");
        assert!(matches!(err, Error::BadField { .. }), "got {err:?}");
    }

    #[test]
    fn truncated_body_errors_do_not_panic() {
        let frame = Msg::Tstat { tag: 1, fid: 2 }.serialize(1024).expect("fits");
        for cut in 4..frame.len() {
            let _ = Msg::parse(&frame[4..cut]); // may error, must not panic
        }
    }

    #[test]
    fn dir_blob_size_is_consistent() {
        let d = Dir {
            qid: Qid { typ: QTFILE, vers: 0, path: 1 },
            mode: 0o644,
            name: "a".into(),
            uid: "n".into(),
            gid: "n".into(),
            muid: String::new(),
            ..Default::default()
        };
        let blob = d.encode().expect("encode");
        let back = Dir::decode(&blob).expect("decode");
        assert_eq!(d, back);
        // size field (2) + fixed part + four length-prefixed strings
        let strings = (2 + 1) + (2 + 1) + (2 + 1) + 2;
        let expect = 2 + Dir::fixed_size() as usize + strings;
        assert_eq!(blob.len(), expect, "wire stat length");
        let declared = u16::from_le_bytes([blob[0], blob[1]]) as usize;
        assert_eq!(declared, blob.len(), "size counts itself");
    }

    #[test]
    fn unknown_type_is_named() {
        let body = [200u8, 0, 0]; // 200 is outside the 9P2000 range
        let err = Msg::parse(&body).expect_err("unknown type");
        match err {
            Error::BadType { got, .. } => assert_eq!(got, 200),
            other => panic!("expected BadType, got {other:?}"),
        }
    }
}
