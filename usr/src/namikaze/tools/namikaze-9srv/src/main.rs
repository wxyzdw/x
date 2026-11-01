// SPDX-License-Identifier: MPL-2.0
//! namikaze-9srv: serve a directory over 9P2000, or probe a 9P server
//! from the command line.
//!
//!   namikaze-9srv serve --addr 127.0.0.1:5640 --root /some/dir
//!   namikaze-9srv probe --addr 127.0.0.1:5640 [--trace] [--walk a/b]
//!                       [--read FILE] [--stat PATH] [--msize N]
//!
//! The probe performs a full session - version, attach, walk, open,
//! read, stat - and prints every frame when --trace is set, so a
//! misbehaving peer is visible wire message by wire message.

#![forbid(unsafe_code)]

use namikaze_9srv::dirfs;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::exit;

use namikaze_9p::error::{Errno, Error};
use namikaze_9p::proto::{self, Msg};

const USAGE: &str = "namikaze-9srv: 9P2000 file server and probe

usage:
  namikaze-9srv serve --addr HOST:PORT --root DIR
  namikaze-9srv probe --addr HOST:PORT [--trace] [--walk PATH]
                      [--read FILE] [--stat PATH] [--msize N]

serve exports DIR read-only over 9P2000; probe runs a full session
(version, attach, walk, open, read, stat) and reports every failure
with the Plan 9 errno of the wire error. --trace prints both frames.";

fn fail(msg: &str) -> ! {
    eprintln!("namikaze-9srv: {msg}");
    exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("-h" | "--help") | None => {
            println!("{USAGE}");
            exit(if args.is_empty() { 2 } else { 0 });
        }
        Some("serve") => serve(&args[1..]),
        Some("probe") => probe(&args[1..]),
        Some(other) => fail(&format!("unknown subcommand {other}")),
    }
}

fn opt_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn serve(args: &[String]) {
    let addr = opt_value(args, "--addr").unwrap_or_else(|| fail("serve needs --addr HOST:PORT"));
    let root = opt_value(args, "--root").unwrap_or_else(|| fail("serve needs --root DIR"));
    // validate the export point before accepting anything
    dirfs::DirFs::new(&PathBuf::from(&root)).unwrap_or_else(|e| fail(&e.to_string()));
    let listener = namikaze_9p::server::listen(&addr)
        .unwrap_or_else(|e| fail(&format!("cannot listen on {addr}: {e}")));
    eprintln!("namikaze-9srv: serving {root} read-only on 9P2000 at {addr}");
    namikaze_9p::server::serve(listener, move || {
        // a fresh DirFs per connection: node ids stay per-connection
        Box::new(dirfs::DirFs::new(&PathBuf::from(&root)).expect("rechecked root"))
    });
}

/// One traced raw exchange.
fn rpc<S: Read + Write>(
    sock: &mut S,
    msize: u32,
    msg: Msg,
    trace: bool,
) -> Result<Msg, Error> {
    let frame = msg.serialize(msize)?;
    if trace {
        eprintln!("-> {:?} {}", proto::type_name(msg.typ()), describe(&msg));
    }
    sock.write_all(&frame)?;
    sock.flush()?;
    let mut size_buf = [0u8; 4];
    sock.read_exact(&mut size_buf)?;
    let size = u32::from_le_bytes(size_buf) as usize;
    if size < 7 || size > msize as usize {
        return Err(Error::BadField {
            op: "probe",
            why: format!("reply frame of {size} bytes outside [7, {msize}]"),
        });
    }
    let mut body = vec![0u8; size - 4];
    sock.read_exact(&mut body)?;
    let reply = Msg::parse(&body)?;
    if trace {
        eprintln!("<- {:?} {}", proto::type_name(reply.typ()), describe(&reply));
    }
    match &reply {
        Msg::Rerror { ename, .. } => {
            Err(Error::Server(Errno::classify(ename)).with_ctx(proto::type_name(msg.typ())))
        }
        other if other.typ() != msg.typ() + 1 => Err(Error::BadField {
            op: "probe",
            why: format!(
                "expected {} for {}, got {}",
                proto::type_name(msg.typ() + 1),
                proto::type_name(msg.typ()),
                proto::type_name(other.typ())
            ),
        }),
        _ => Ok(reply),
    }
}

fn describe(msg: &Msg) -> String {
    match msg {
        Msg::Tversion { msize, version, .. } | Msg::Rversion { msize, version, .. } => {
            format!("msize={msize} version={version}")
        }
        Msg::Tattach { fid, uname, aname, .. } => {
            format!("fid={fid} uname={uname} aname={aname:?}")
        }
        Msg::Twalk { fid, newfid, wnames, .. } => {
            format!("fid={fid} newfid={newfid} names={wnames:?}")
        }
        Msg::Rwalk { wqids, .. } => format!("{} qids", wqids.len()),
        Msg::Topen { fid, mode, .. } => format!("fid={fid} mode={mode}"),
        Msg::Rread { data, .. } => format!("{} bytes", data.len()),
        Msg::Rstat { stat, .. } => format!("name={}", stat.name),
        Msg::Rerror { ename, .. } => format!("ename={ename:?}"),
        other => format!("tag={}", other.tag()),
    }
}

fn probe(args: &[String]) {
    let addr = opt_value(args, "--addr").unwrap_or_else(|| fail("probe needs --addr HOST:PORT"));
    let trace = args.iter().any(|a| a == "--trace");
    let walk = opt_value(args, "--walk");
    let read = opt_value(args, "--read");
    let stat_path = opt_value(args, "--stat");
    let msize = opt_value(args, "--msize")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(8192)
        .clamp(16, proto::MAX_MSIZE);

    let mut sock =
        TcpStream::connect(&addr).unwrap_or_else(|e| fail(&format!("cannot dial {addr}: {e}")));

    let reply = rpc(&mut sock, msize, Msg::Tversion {
        tag: proto::NOTAG,
        msize,
        version: proto::VERSION_9P2000.into(),
    }, trace)
    .unwrap_or_else(|e| fail(&e.to_string()));
    match &reply {
        Msg::Rversion { version, .. } if version == proto::VERSION_9P2000 => {}
        Msg::Rversion { version, .. } => {
            fail(&format!("the peer speaks {version:?}, this probe requires 9P2000"));
        }
        _ => fail("the peer answered the version request with something else"),
    }

    let reply = rpc(&mut sock, msize, Msg::Tattach {
        tag: 1,
        fid: 2,
        afid: proto::NOFID,
        uname: whoami(),
        aname: String::new(),
    }, trace)
    .unwrap_or_else(|e| fail(&e.to_string()));
    let root_qid = match reply {
        Msg::Rattach { aqid, .. } => aqid,
        _ => fail("no Rattach"),
    };
    println!("attached: root qid type={:#x} path={}", root_qid.typ, root_qid.path);

    if let Some(path) = stat_path {
        let dir = dir_of(&path);
        let leaf = leaf_of(&path);
        let qids = walk_path(&mut sock, msize, trace, &dir, &leaf);
        let reply = rpc(&mut sock, msize, Msg::Tstat { tag: 20, fid: 3 }, trace)
            .unwrap_or_else(|e| fail(&e.to_string()));
        if let Msg::Rstat { stat, .. } = reply {
            println!(
                "stat {}: mode={:#o} length={} uid={} qid.path={}",
                stat.name, stat.mode, stat.length, stat.uid, stat.qid.path
            );
        }
        let _ = qids;
    }

    if let Some(path) = read {
        let dir = dir_of(&path);
        let leaf = leaf_of(&path);
        walk_path(&mut sock, msize, trace, &dir, &leaf);
        let reply = rpc(&mut sock, msize, Msg::Topen { tag: 30, fid: 3, mode: proto::OREAD }, trace)
            .unwrap_or_else(|e| fail(&e.to_string()));
        let iounit = match reply {
            Msg::Ropen { iounit, .. } => iounit.min(msize.saturating_sub(proto::IOHDRSZ)),
            _ => fail("no Ropen"),
        };
        let mut all = Vec::new();
        let mut offset = 0u64;
        loop {
            let reply = rpc(&mut sock, msize, Msg::Tread {
                tag: 31,
                fid: 3,
                offset,
                count: iounit,
            }, trace)
            .unwrap_or_else(|e| fail(&e.to_string()));
            let data = match reply {
                Msg::Rread { data, .. } => data,
                _ => fail("no Rread"),
            };
            let n = data.len() as u64;
            if n == 0 {
                break;
            }
            all.extend_from_slice(&data);
            offset += n;
        }
        use std::io::Write;
        let mut out = std::io::stdout();
        let _ = out.write_all(&all);
        let _ = out.flush();
        rpc(&mut sock, msize, Msg::Tclunk { tag: 39, fid: 3 }, trace)
            .unwrap_or_else(|e| fail(&e.to_string()));
    } else if let Some(path) = walk {
        let dir = dir_of(&path);
        let leaf = leaf_of(&path);
        let qids = walk_path(&mut sock, msize, trace, &dir, &leaf);
        if !qids.is_empty() {
            println!("walked {} element(s), leaf qid path={}", qids.len(), qids[qids.len() - 1].path);
        }
    }

    rpc(&mut sock, msize, Msg::Tclunk { tag: 99, fid: 2 }, trace)
        .unwrap_or_else(|e| fail(&e.to_string()));
}

/// Walk the directory elements of `dir` from fid 2, then the optional
/// leaf into fid 3. Returns the leaf qids.
fn walk_path(
    sock: &mut TcpStream,
    msize: u32,
    trace: bool,
    dir: &str,
    leaf: &str,
) -> Vec<namikaze_9p::Qid> {
    let dir_elems: Vec<String> =
        dir.split('/').filter(|p| !p.is_empty() && *p != ".").map(String::from).collect();
    if dir_elems.len() > proto::MAX_WELEM {
        fail(&format!("the directory part of the path is {} elements deep; the protocol walks at most {} per request", dir_elems.len(), proto::MAX_WELEM));
    }
    if !dir_elems.is_empty() {
        // walk the directory part in place on fid 2, then the leaf on
        // a fresh fid 3
        let reply = rpc(sock, msize, Msg::Twalk {
            tag: 10,
            fid: 2,
            newfid: 2,
            wnames: dir_elems,
        }, trace)
        .unwrap_or_else(|e| fail(&e.to_string()));
        if let Msg::Rwalk { wqids, .. } = reply {
            if leaf.is_empty() {
                return wqids;
            }
            let leaf_reply = rpc(sock, msize, Msg::Twalk {
                tag: 11,
                fid: 2,
                newfid: 3,
                wnames: vec![leaf.to_string()],
            }, trace)
            .unwrap_or_else(|e| fail(&e.to_string()));
            return match leaf_reply {
                Msg::Rwalk { wqids, .. } => wqids,
                _ => fail("no Rwalk"),
            };
        }
    }
    if leaf.is_empty() {
        return Vec::new();
    }
    let reply = rpc(sock, msize, Msg::Twalk {
        tag: 11,
        fid: 2,
        newfid: 3,
        wnames: vec![leaf.to_string()],
    }, trace)
    .unwrap_or_else(|e| fail(&e.to_string()));
    match reply {
        Msg::Rwalk { wqids, .. } => wqids,
        _ => fail("no Rwalk"),
    }
}

fn dir_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(idx) => path[..idx].to_string(),
        None => String::new(),
    }
}

fn leaf_of(path: &str) -> String {
    match path.rfind('/') {
        Some(idx) => path[idx + 1..].to_string(),
        None => path.to_string(),
    }
}

fn whoami() -> String {
    std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_else(|_| "nobody".into())
}

