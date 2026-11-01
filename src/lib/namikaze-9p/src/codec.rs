// SPDX-License-Identifier: MPL-2.0
//! Bounds-checked reader and writer for the 9P2000 little-endian wire
//! format. Every accessor returns a [`Result`]: a malformed frame can
//! never panic, never over-read, and every failure names the protocol
//! operation it happened in.

use crate::error::Error;
use crate::proto::Qid;

/// Sequential reader over one message body.
pub struct Reader<'a> {
    op: &'static str,
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader for one message body, labelled with the operation name
    /// used in every diagnostic.
    pub fn new(op: &'static str, buf: &'a [u8]) -> Reader<'a> {
        Reader { op, buf, pos: 0 }
    }

    /// Bytes still unread.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Fail unless exactly `n` unread bytes remain (no trailing garbage).
    pub fn finish(&self) -> Result<(), Error> {
        let left = self.remaining();
        if left == 0 {
            Ok(())
        } else {
            Err(Error::BadField {
                op: self.op,
                why: format!("{left} trailing bytes after the message"),
            })
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let left = self.remaining();
        if left < n {
            return Err(Error::ShortRead { op: self.op, want: n, got: left });
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// One unsigned byte.
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    /// Little-endian u16.
    pub fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Little-endian u32.
    pub fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Little-endian u64.
    pub fn u64(&mut self) -> Result<u64, Error> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// Exactly `n` raw bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        self.take(n)
    }

    /// A u16-length-prefixed string, validated as UTF-8.
    pub fn string(&mut self) -> Result<String, Error> {
        let len = self.u16()? as usize;
        let raw = self.take(len)?;
        match std::str::from_utf8(raw) {
            Ok(s) => Ok(s.to_string()),
            Err(e) => Err(Error::BadString {
                op: self.op,
                why: format!("invalid UTF-8 at byte {}: {e}", e.valid_up_to()),
            }),
        }
    }

    /// A 13-byte qid.
    pub fn qid(&mut self) -> Result<Qid, Error> {
        let typ = self.u8()?;
        let vers = self.u32()?;
        let path = self.u64()?;
        Ok(Qid { typ, vers, path })
    }

    /// A u16-length-prefixed raw blob, labelled with `op` for diagnostics.
    pub fn blob2(&mut self, op: &'static str) -> Result<&'a [u8], Error> {
        let len = self.u16()? as usize;
        let left = self.remaining();
        if left < len {
            return Err(Error::ShortRead { op, want: len, got: left });
        }
        let out = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }
}

/// Accumulating writer for one message; [`Writer::finish`] prefixes the
/// frame size and enforces the negotiated `msize`.
#[derive(Debug)]
pub struct Writer {
    body: Vec<u8>,
}

impl Writer {
    /// Start a message of the given type; the type byte is the first
    /// thing written, the 4-byte size prefix is added by `finish`.
    pub fn new(typ: u8) -> Writer {
        Writer { body: vec![typ] }
    }

    /// One unsigned byte.
    pub fn u8(&mut self, v: u8) -> &mut Writer {
        self.body.push(v);
        self
    }

    /// Little-endian u16.
    pub fn u16(&mut self, v: u16) -> &mut Writer {
        self.body.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Little-endian u32.
    pub fn u32(&mut self, v: u32) -> &mut Writer {
        self.body.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Little-endian u64.
    pub fn u64(&mut self, v: u64) -> &mut Writer {
        self.body.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// A u16-length-prefixed string.
    pub fn string(&mut self, s: &str) -> &mut Writer {
        self.u16(s.len() as u16);
        self.body.extend_from_slice(s.as_bytes());
        self
    }

    /// A 13-byte qid.
    pub fn qid(&mut self, q: &Qid) -> &mut Writer {
        self.u8(q.typ).u32(q.vers).u64(q.path);
        self
    }

    /// A u16-length-prefixed raw blob (Rread payload, stat blobs).
    pub fn blob(&mut self, data: &[u8]) -> Result<&mut Writer, Error> {
        if data.len() > u16::MAX as usize {
            return Err(Error::Oversize {
                op: "blob",
                limit: u16::MAX as u32,
                got: data.len() as u32,
            });
        }
        self.u16(data.len() as u16);
        self.body.extend_from_slice(data);
        Ok(self)
    }

    /// Finish the message: prepend the 4-byte size and check `msize`.
    pub fn finish(mut self, limit: u32) -> Result<Vec<u8>, Error> {
        // 4-byte size field + body
        let total = (self.body.len() + 4) as u32;
        if total > limit {
            return Err(Error::Oversize { op: "finish", limit, got: total });
        }
        let mut out = Vec::with_capacity(total as usize);
        out.extend_from_slice(&total.to_le_bytes());
        out.append(&mut self.body);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OP: &str = "Ttest";

    #[test]
    fn round_trip_scalars() {
        let mut w = Writer::new(100);
        w.u8(7).u16(0xBEEF).u32(0xDEAD_BEEF).u64(0x0123_4567_89AB_CDEF);
        let frame = w.finish(1024).expect("small frame fits");
        let size = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
        assert_eq!(size, frame.len() as u32, "size prefix counts itself");
        assert_eq!(size, 1 + 1 + 2 + 4 + 8 + 4);
        let mut r = Reader::new(OP, &frame[4..]);
        assert_eq!(r.u8().expect("type first"), 100);
        assert_eq!(r.u8().expect("u8"), 7);
        assert_eq!(r.u16().expect("u16"), 0xBEEF);
        assert_eq!(r.u32().expect("u32"), 0xDEAD_BEEF);
        assert_eq!(r.u64().expect("u64"), 0x0123_4567_89AB_CDEF);
        r.finish().expect("nothing left");
    }

    #[test]
    fn short_read_is_reported_with_operation() {
        let payload = [1u8, 0]; // two bytes, a u32 wants four
        let mut r = Reader::new(OP, &payload);
        let err = r.u32().expect_err("only 2 bytes available");
        match err {
            Error::ShortRead { op, want, got } => {
                assert_eq!(op, OP);
                assert_eq!((want, got), (4, 2));
            }
            other => panic!("expected ShortRead, got {other:?}"),
        }
    }

    #[test]
    fn bad_utf8_is_named_byte_precise() {
        // u16 length 4, then four bytes that break UTF-8 immediately
        let payload = [4u8, 0, 0x80, 0x83, 0x80, 0x80];
        let mut r = Reader::new(OP, &payload);
        let err = r.string().expect_err("corrupted utf8");
        match err {
            Error::BadString { op, why } => {
                assert_eq!(op, OP);
                assert!(why.contains("invalid UTF-8"), "got: {why}");
                assert!(why.contains("byte 0"), "got: {why}");
            }
            other => panic!("expected BadString, got {other:?}"),
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let payload = [1u8, 2];
        let mut r = Reader::new(OP, &payload);
        assert_eq!(r.u8().expect("first"), 1);
        let err = r.finish().expect_err("one byte left");
        assert!(matches!(err, Error::BadField { .. }), "got {err:?}");
    }

    #[test]
    fn finish_enforces_msize() {
        let mut w = Writer::new(100);
        let data = vec![0u8; 128];
        w.blob(&data).expect("blob fits");
        let err = w.finish(16).expect_err("frame exceeds msize");
        match err {
            Error::Oversize { limit, got, .. } => {
                assert_eq!((limit, got), (16, 128 + 4 + 2 + 1));
            }
            other => panic!("expected Oversize, got {other:?}"),
        }
    }

    #[test]
    fn blob_over_u16_is_refused() {
        let mut w = Writer::new(100);
        let data = vec![0u8; u16::MAX as usize + 1];
        let err = w.blob(&data).expect_err("blob over u16");
        match err {
            Error::Oversize { limit, got, .. } => {
                assert_eq!((limit, got), (u16::MAX as u32, u16::MAX as u32 + 1));
            }
            other => panic!("expected Oversize, got {other:?}"),
        }
    }

    #[test]
    fn blob2_reads_the_declared_prefix() {
        // u16 length 3, then three bytes
        let payload = [3u8, 0, 0xAA, 0xBB, 0xCC];
        let mut r = Reader::new(OP, &payload);
        let blob = r.blob2("Rstat").expect("blob");
        assert_eq!(blob, &[0xAA, 0xBB, 0xCC]);
        r.finish().expect("nothing left");
        let err = r.blob2("Rstat").expect_err("length past the end");
        assert!(matches!(err, Error::ShortRead { .. }), "got {err:?}");
    }
}
