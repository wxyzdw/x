// SPDX-License-Identifier: MPL-2.0
//! Deep error taxonomy for the 9P2000 stack, grounded in Plan 9's
//! `/sys/src/9/port/error.h` (4th edition): the wire carries a human
//! readable `Rerror` string, the canonical errno strings of the kernel
//! catalogue classify it, and every protocol layer wraps the errors of
//! the layer below with context instead of erasing them. `Error::Chain`
//! keeps the whole ladder inspectable; the leaf errno survives any
//! number of wraps. `ReadOnly` is a Namikaze addition for read-only
//! backends; every other wire string is the stock Plan 9 wording.

use std::fmt;

/// Canonical result alias for the whole 9P stack.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The classified failure of a 9P operation, mirroring the Plan 9
/// kernel errno catalogue of `/sys/src/9/port/error.h`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Errno {
    /// Enonexist: "file does not exist"
    NotFound,
    /// Eperm: "permission denied"
    Permission,
    /// Eexist: "file already exists"
    Exists,
    /// Enotdir: "not a directory"
    NotADirectory,
    /// Eisdir: "file is a directory"
    IsDirectory,
    /// the u9fs/lib9p convention for a stale or never-attached fid:
    /// "unknown fid"
    BadFid,
    /// Ebadusefd: "inappropriate use of fd" - fid not open, wrong
    /// open direction, walking an open fid
    BadUseFd,
    /// Einuse: "device or object already in use" - fid or tag collision
    InUse,
    /// Ebadfd: "fd out of range or not open"
    BadFd,
    /// Ebadarg: "bad arg in system call" - malformed fields
    BadArg,
    /// Etoobig: "read or write too large"
    TooBig,
    /// Eshort: "i/o count too small"
    TooSmall,
    /// Enomem: "kernel allocate failed"
    NoMem,
    /// Enofd: "no free file descriptors"
    NoFd,
    /// Eintr: "interrupted"
    Interrupted,
    /// Enegoff: "negative i/o offset"
    NegOffset,
    /// Edirseek: "seek in directory"
    DirSeek,
    /// Ebadspec: "bad attach specifier"
    BadSpec,
    /// Enoattach: "mount/attach disallowed"
    NoAttach,
    /// Ebadstat: "malformed stat buffer"
    BadStat,
    /// Eshortstat: "stat buffer too small"
    ShortStat,
    /// the 9P convention when a server demands authentication
    AuthRequired,
    /// Eio: "i/o error"
    Io,
    /// Ehungup: "i/o on hungup channel"
    Hungup,
    /// Etimedout: "connection timed out"
    TimedOut,
    /// Econrefused: "connection refused"
    ConnRefused,
    /// Namikaze extension for read-only backends
    ReadOnly,
    /// anything else, with the raw string kept
    Other(String),
}

impl Errno {
    /// Map an `Rerror` string onto the catalogue. Substring matching
    /// keeps this robust against servers that append paths or detail
    /// to the canonical message (fossil does exactly that).
    pub fn classify(why: &str) -> Errno {
        let low = why.to_ascii_lowercase();
        let has = |pat: &str| low.contains(pat);
        if has("does not exist") || has("no such file") || has("no such user") {
            return Errno::NotFound;
        }
        if has("permission denied") || has("not in group") || has("not a member") {
            return Errno::Permission;
        }
        if has("already exists") {
            return Errno::Exists;
        }
        if has("not a directory") {
            return Errno::NotADirectory;
        }
        if has("is a directory") || has("is a file") {
            return Errno::IsDirectory;
        }
        // stat-specific wording must win over the generic too-small rule
        if has("stat buffer too small") {
            return Errno::ShortStat;
        }
        if has("malformed stat") {
            return Errno::BadStat;
        }
        if has("unknown fid") || has("fid out of range") {
            return Errno::BadFid;
        }
        if has("inappropriate use") {
            return Errno::BadUseFd;
        }
        if has("already in use") || has("in use") {
            return Errno::InUse;
        }
        if has("out of range or not open") || has("fd out of range") {
            return Errno::BadFd;
        }
        if has("bad arg") {
            return Errno::BadArg;
        }
        if has("too large") || has("too big") {
            return Errno::TooBig;
        }
        if has("too small") {
            return Errno::TooSmall;
        }
        if has("kernel allocate failed") || has("out of memory") {
            return Errno::NoMem;
        }
        if has("no free file descriptors") {
            return Errno::NoFd;
        }
        if has("interrupt") {
            return Errno::Interrupted;
        }
        if has("negative i/o offset") || has("negative offset") {
            return Errno::NegOffset;
        }
        if has("seek in directory") {
            return Errno::DirSeek;
        }
        if has("attach specifier") {
            return Errno::BadSpec;
        }
        if has("attach disallowed") {
            return Errno::NoAttach;
        }
        if has("authentication") || has("auth") {
            return Errno::AuthRequired;
        }
        if has("read-only") || has("read only") {
            return Errno::ReadOnly;
        }
        if has("hungup") {
            return Errno::Hungup;
        }
        if has("timed out") {
            return Errno::TimedOut;
        }
        if has("refused") {
            return Errno::ConnRefused;
        }
        if has("i/o error") || has("io error") {
            return Errno::Io;
        }
        Errno::Other(why.to_string())
    }

    /// The canonical wire string this errno answers with.
    pub fn wire(&self) -> String {
        match self {
            Errno::NotFound => "file does not exist".into(),
            Errno::Permission => "permission denied".into(),
            Errno::Exists => "file already exists".into(),
            Errno::NotADirectory => "not a directory".into(),
            Errno::IsDirectory => "file is a directory".into(),
            Errno::BadFid => "unknown fid".into(),
            Errno::BadUseFd => "inappropriate use of fd".into(),
            Errno::InUse => "device or object already in use".into(),
            Errno::BadFd => "fd out of range or not open".into(),
            Errno::BadArg => "bad arg in system call".into(),
            Errno::TooBig => "read or write too large".into(),
            Errno::TooSmall => "i/o count too small".into(),
            Errno::NoMem => "kernel allocate failed".into(),
            Errno::NoFd => "no free file descriptors".into(),
            Errno::Interrupted => "interrupted".into(),
            Errno::NegOffset => "negative i/o offset".into(),
            Errno::DirSeek => "seek in directory".into(),
            Errno::BadSpec => "bad attach specifier".into(),
            Errno::NoAttach => "mount/attach disallowed".into(),
            Errno::BadStat => "malformed stat buffer".into(),
            Errno::ShortStat => "stat buffer too small".into(),
            Errno::AuthRequired => "authentication required".into(),
            Errno::Io => "i/o error".into(),
            Errno::Hungup => "i/o on hungup channel".into(),
            Errno::TimedOut => "connection timed out".into(),
            Errno::ConnRefused => "connection refused".into(),
            Errno::ReadOnly => "read-only file system".into(),
            Errno::Other(raw) => raw.clone(),
        }
    }

    /// Classify a local protocol-level error as if it had come over the
    /// wire: used by the server to answer malformed input and by tests
    /// that want the leaf of an error ladder.
    pub fn leaf(err: &Error) -> Errno {
        match err {
            Error::Server(e) => e.clone(),
            Error::Chain { source, .. } => Errno::leaf(source),
            Error::State { .. } => Errno::BadUseFd,
            Error::BadField { .. } | Error::BadType { .. } | Error::BadString { .. } => {
                Errno::BadArg
            }
            Error::ShortRead { .. } => Errno::TooSmall,
            Error::Oversize { .. } => Errno::TooBig,
            Error::Version { .. } => Errno::Other(err.to_string()),
            Error::Io(_) => Errno::Io,
        }
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Errno::Other(raw) => write!(f, "{raw}"),
            other => write!(f, "{}", other.wire()),
        }
    }
}

/// Every failure mode of the 9P2000 stack, each carrying the protocol
/// operation it happened in (`op`) so messages read like
/// `walk_path "top/nope": walk stopped at element 1 "nope"` chained
/// onto `server: file does not exist`.
#[derive(Debug)]
pub enum Error {
    /// Transport failure.
    Io(std::io::Error),
    /// The wire ran out of bytes mid-message.
    ShortRead { op: &'static str, want: usize, got: usize },
    /// A length field or the frame size exceeded its limit.
    Oversize { op: &'static str, limit: u32, got: u32 },
    /// A string field was not valid UTF-8.
    BadString { op: &'static str, why: String },
    /// An unknown message type arrived.
    BadType { op: &'static str, got: u8 },
    /// A field was present but semantically wrong.
    BadField { op: &'static str, why: String },
    /// The peer answered with `Rerror`.
    Server(Errno),
    /// The local state machine was violated (stale fid, tag mismatch,
    /// walking an open fid, unattached session...).
    State { op: &'static str, why: String },
    /// Version negotiation failed: the peer speaks a dialect we refuse.
    Version { got: String },
    /// One layer wrapped the failure of the layer below with context.
    Chain { ctx: String, source: Box<Error> },
}

impl Error {
    /// Wrap `self` with one more layer of context, keeping the leaf intact.
    pub fn with_ctx(self, ctx: impl Into<String>) -> Error {
        Error::Chain { ctx: ctx.into(), source: Box::new(self) }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::ShortRead { op, want, got } => {
                write!(f, "{op}: short read: want {want} bytes, got {got}")
            }
            Error::Oversize { op, limit, got } => {
                write!(f, "{op}: frame or field of {got} bytes exceeds the limit of {limit}")
            }
            Error::BadString { op, why } => write!(f, "{op}: bad string: {why}"),
            Error::BadType { op, got } => write!(f, "{op}: unknown message type {got}"),
            Error::BadField { op, why } => write!(f, "{op}: bad field: {why}"),
            Error::Server(e) => write!(f, "server: {e}"),
            Error::State { op, why } => write!(f, "{op}: bad state: {why}"),
            Error::Version { got } => {
                write!(f, "version negotiation failed: peer offered \"{got}\"")
            }
            Error::Chain { ctx, source } => write!(f, "{ctx}: {source}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<Errno> for Error {
    fn from(e: Errno) -> Self {
        Error::Server(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_the_kernel_error_h_catalogue() {
        // the exact strings of /sys/src/9/port/error.h
        assert_eq!(Errno::classify("file does not exist"), Errno::NotFound);
        assert_eq!(Errno::classify("file already exists"), Errno::Exists);
        assert_eq!(Errno::classify("not a directory"), Errno::NotADirectory);
        assert_eq!(Errno::classify("file is a directory"), Errno::IsDirectory);
        assert_eq!(Errno::classify("permission denied"), Errno::Permission);
        assert_eq!(Errno::classify("inappropriate use of fd"), Errno::BadUseFd);
        assert_eq!(Errno::classify("device or object already in use"), Errno::InUse);
        assert_eq!(Errno::classify("fd out of range or not open"), Errno::BadFd);
        assert_eq!(Errno::classify("bad arg in system call"), Errno::BadArg);
        assert_eq!(Errno::classify("read or write too large"), Errno::TooBig);
        assert_eq!(Errno::classify("i/o count too small"), Errno::TooSmall);
        assert_eq!(Errno::classify("kernel allocate failed"), Errno::NoMem);
        assert_eq!(Errno::classify("no free file descriptors"), Errno::NoFd);
        assert_eq!(Errno::classify("interrupted"), Errno::Interrupted);
        assert_eq!(Errno::classify("negative i/o offset"), Errno::NegOffset);
        assert_eq!(Errno::classify("seek in directory"), Errno::DirSeek);
        assert_eq!(Errno::classify("bad attach specifier"), Errno::BadSpec);
        assert_eq!(Errno::classify("mount/attach disallowed"), Errno::NoAttach);
        assert_eq!(Errno::classify("malformed stat buffer"), Errno::BadStat);
        assert_eq!(Errno::classify("stat buffer too small"), Errno::ShortStat);
        assert_eq!(Errno::classify("i/o error"), Errno::Io);
        assert_eq!(Errno::classify("i/o on hungup channel"), Errno::Hungup);
        assert_eq!(Errno::classify("connection timed out"), Errno::TimedOut);
        assert_eq!(Errno::classify("connection refused"), Errno::ConnRefused);
    }

    #[test]
    fn classification_survives_server_detail() {
        // fossil appends the path to the canonical message
        assert_eq!(Errno::classify("file does not exist: /usr/glenda/todo"), Errno::NotFound);
        assert_eq!(Errno::classify("walk /n/other: no such file"), Errno::NotFound);
        // "already exists" must win over "in use" ordering traps
        assert_eq!(Errno::classify("file already exists, object in use"), Errno::Exists);
    }

    #[test]
    fn unknown_strings_round_trip() {
        let e = Errno::classify("channel is wedged");
        assert_eq!(e, Errno::Other("channel is wedged".into()));
        assert_eq!(e.wire(), "channel is wedged");
    }

    #[test]
    fn every_errno_has_a_wire_string() {
        let all = [
            Errno::NotFound,
            Errno::Permission,
            Errno::Exists,
            Errno::NotADirectory,
            Errno::IsDirectory,
            Errno::BadFid,
            Errno::BadUseFd,
            Errno::InUse,
            Errno::BadFd,
            Errno::BadArg,
            Errno::TooBig,
            Errno::TooSmall,
            Errno::NoMem,
            Errno::NoFd,
            Errno::Interrupted,
            Errno::NegOffset,
            Errno::DirSeek,
            Errno::BadSpec,
            Errno::NoAttach,
            Errno::BadStat,
            Errno::ShortStat,
            Errno::AuthRequired,
            Errno::Io,
            Errno::Hungup,
            Errno::TimedOut,
            Errno::ConnRefused,
            Errno::ReadOnly,
        ];
        for errno in all {
            let wire = errno.wire();
            assert!(!wire.is_empty(), "{errno:?} has an empty wire string");
            // classification is stable for every catalogue entry
            assert_eq!(Errno::classify(&wire), errno, "{errno:?} does not classify to itself");
        }
    }

    #[test]
    fn leaf_errno_survives_deep_chains() {
        let err = Error::Server(Errno::NotFound)
            .with_ctx("walk stopped at element 1 \"nope\"")
            .with_ctx("walk_path \"top/nope\"");
        assert_eq!(Errno::leaf(&err), Errno::NotFound);
        assert_eq!(
            err.to_string(),
            "walk_path \"top/nope\": walk stopped at element 1 \"nope\": server: file does not exist"
        );
    }

    #[test]
    fn local_protocol_errors_classify_too() {
        assert_eq!(
            Errno::leaf(&Error::State { op: "Twalk", why: "fid 2 is open".into() }),
            Errno::BadUseFd
        );
        assert_eq!(
            Errno::leaf(&Error::BadType { op: "parse", got: 200 }),
            Errno::BadArg
        );
        assert_eq!(
            Errno::leaf(&Error::Oversize { op: "read_frame", limit: 8192, got: 99_999 }),
            Errno::TooBig
        );
    }
}
