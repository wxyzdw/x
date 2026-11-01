// SPDX-License-Identifier: MPL-2.0
//! End-to-end tests: a real Synth server over a Unix socket pair,
//! exercised by the real Conn client, with the deep error paths probed
//! the way a hostile or buggy peer would trigger them.

use std::os::unix::net::UnixStream;
use std::thread;

use namikaze_9p::proto::{DMDIR, ORDWR, OREAD, OWRITE};
use namikaze_9p::{Conn, Errno, Msg, Synth};

fn demo_synth() -> Synth {
    let mut s = Synth::new();
    let top = s.dir(0, "top").expect("dir top");
    s.file(top, "hello", b"hi from plan9\n").expect("file hello");
    s.dynamic(top, "clock", || b"12:00:00\n".to_vec()).expect("dynamic clock");
    s.dir(top, "sub").expect("dir sub");
    s
}

fn connected() -> (Conn<UnixStream>, thread::JoinHandle<()>) {
    let (a, b) = UnixStream::pair().expect("socket pair");
    let fsys: Box<dyn namikaze_9p::Fsys> = Box::new(demo_synth());
    let server = thread::spawn(move || {
        namikaze_9p::serve_conn(b, fsys).expect("server loop");
    });
    let conn = Conn::new(a).expect("client handshake");
    (conn, server)
}

#[test]
fn full_read_session_over_real_wire() {
    let (mut conn, server) = connected();
    let root = conn.attach(1, namikaze_9p::proto::NOFID, "glenda", "").expect("attach");
    assert!(root.is_dir(), "the root is a directory");

    let qids = conn.walk_path(1, 2, "top/hello").expect("walk top/hello");
    assert_eq!(qids.len(), 2, "one qid per element");

    let (qid, iounit) = conn.open(2, OREAD).expect("open hello");
    assert!(!qid.is_dir());
    assert!(iounit > 0);

    let data = conn.read_all(2).expect("read hello");
    assert_eq!(data, b"hi from plan9\n");

    conn.clunk(2).expect("clunk hello");
    drop(conn);
    server.join().expect("server exits cleanly on EOF");
}

#[test]
fn directory_listing_round_trips() {
    let (mut conn, _srv) = connected();
    conn.attach(1, namikaze_9p::proto::NOFID, "glenda", "").expect("attach");
    conn.walk_path(1, 2, "top").expect("walk top");
    conn.open(2, OREAD).expect("open dir");

    let blob = conn.read_all(2).expect("read dir stream");
    let mut names = Vec::new();
    let mut pos = 0;
    while pos < blob.len() {
        let len = u16::from_le_bytes([blob[pos], blob[pos + 1]]) as usize;
        let d = namikaze_9p::Dir::decode(&blob[pos..pos + len]).expect("whole stat entry");
        names.push((d.name.clone(), d.mode & DMDIR != 0));
        pos += len;
    }
    assert_eq!(
        names,
        vec![("hello".to_string(), false), ("clock".to_string(), false), ("sub".to_string(), true),]
    );
}

#[test]
fn stat_names_and_shows_the_qid_type() {
    let (mut conn, _srv) = connected();
    conn.attach(1, namikaze_9p::proto::NOFID, "glenda", "").expect("attach");
    conn.walk_path(1, 2, "top/clock").expect("walk clock");
    let stat = conn.stat(2).expect("stat clock");
    assert_eq!(stat.name, "clock");
    assert_eq!(stat.uid, "namikaze");
    assert!(stat.mode & DMDIR == 0);
}

#[test]
fn missing_element_is_named_in_the_error() {
    let (mut conn, _srv) = connected();
    conn.attach(1, namikaze_9p::proto::NOFID, "glenda", "").expect("attach");
    let err = conn.walk_path(1, 2, "top/nope/deeper").expect_err("missing element");
    assert_eq!(Errno::leaf(&err), Errno::NotFound);
    let text = err.to_string();
    assert!(text.contains("nope"), "error names the element: {text}");
    assert!(text.contains("walk_path"), "error carries the context chain: {text}");
}

#[test]
fn partial_walk_prefix_is_reported_by_the_client() {
    // a spec-compliant server may answer a failing walk with the
    // successful prefix; the client must translate that into the
    // exact failing element
    let (a, b) = UnixStream::pair().expect("socket pair");
    let server = thread::spawn(move || {
        namikaze_9p::serve_conn(b, Box::new(demo_synth())).expect("serve");
    });
    let mut conn = Conn::new(a).expect("handshake");
    conn.attach(1, namikaze_9p::proto::NOFID, "glenda", "").expect("attach");

    // bypass walk_path: walk top then a missing child in one Twalk
    let names = vec!["top".to_string(), "void".to_string()];
    let err = conn.walk(1, 2, &names).expect_err("second element missing");
    assert_eq!(Errno::leaf(&err), Errno::NotFound);
    let text = err.to_string();
    assert!(text.contains("element 1 \"void\""), "client names the failing element: {text}");
    drop(conn);
    server.join().expect("server clean");
}

#[test]
fn walk_wire_semantics_follow_walk5() {
    // walk(5): a failure on the first element is Rerror on the wire,
    // never an empty Rwalk; a failure on a later element is a partial
    // Rwalk and the new fid is NOT established (clunking it answers
    // "unknown fid")
    let (mut conn, _srv) = connected();
    conn.attach(1, namikaze_9p::proto::NOFID, "glenda", "").expect("attach");

    let twalk = Msg::Twalk { tag: 60, fid: 1, newfid: 3, wnames: vec!["void".to_string()] };
    let frame = twalk.serialize(conn.msize()).expect("fits one frame");
    conn.send_raw(&frame).expect("send first-element walk");
    let msg = Msg::parse(&conn.recv_raw().expect("reply")).expect("parse reply");
    match msg {
        Msg::Rerror { tag, ename, .. } => {
            assert_eq!(tag, 60);
            assert_eq!(ename, "file does not exist", "the plan9 wording");
        }
        other => panic!(
            "first-element failure must be Rerror, got {}",
            namikaze_9p::proto::type_name(other.typ())
        ),
    }

    let twalk = Msg::Twalk {
        tag: 61,
        fid: 1,
        newfid: 3,
        wnames: vec!["top".to_string(), "void".to_string()],
    };
    let frame = twalk.serialize(conn.msize()).expect("fits one frame");
    conn.send_raw(&frame).expect("send partial walk");
    let msg = Msg::parse(&conn.recv_raw().expect("reply")).expect("parse reply");
    match msg {
        Msg::Rwalk { wqids, .. } => assert_eq!(wqids.len(), 1, "the prefix walked"),
        other => panic!(
            "a later-element failure is a partial Rwalk, got {}",
            namikaze_9p::proto::type_name(other.typ())
        ),
    }

    // the partial walk left no fid 3 behind
    let tclunk = Msg::Tclunk { tag: 62, fid: 3 };
    let frame = tclunk.serialize(conn.msize()).expect("fits one frame");
    conn.send_raw(&frame).expect("send clunk of newfid");
    let msg = Msg::parse(&conn.recv_raw().expect("reply")).expect("parse reply");
    match msg {
        Msg::Rerror { ename, .. } => {
            assert_eq!(ename, "unknown fid", "newfid was never established")
        }
        other => panic!(
            "clunking an unestablished newfid must fail, got {}",
            namikaze_9p::proto::type_name(other.typ())
        ),
    }
    conn.clunk(1).expect("the walk source fid is untouched");
}

#[test]
fn mutating_a_read_only_server_fails_cleanly() {
    let (mut conn, _srv) = connected();
    conn.attach(1, namikaze_9p::proto::NOFID, "glenda", "").expect("attach");
    conn.walk_path(1, 2, "top/hello").expect("walk");

    // writing to a fid opened for reading is refused with the
    // canonical Ebadusefd string of error.h
    let err = conn.write(2, 0, b"patch").expect_err("fid opened OREAD");
    assert_eq!(Errno::leaf(&err), Errno::BadUseFd);
    assert!(err.to_string().contains("inappropriate use of fd"), "got {err}");

    // opening a read-only file for writing is refused by the backend
    conn.clunk(2).expect("clunk");
    conn.walk_path(1, 2, "top/hello").expect("walk again");
    let err = conn.open(2, OWRITE).expect_err("read-only file");
    assert_eq!(Errno::leaf(&err), Errno::Permission);

    // ORDWR is also a write open
    conn.clunk(2).expect("clunk");
    conn.walk_path(1, 2, "top/hello").expect("walk again");
    let err = conn.open(2, ORDWR).expect_err("ORDWR on read-only");
    assert_eq!(Errno::leaf(&err), Errno::Permission);
}

#[test]
fn using_a_clunked_fid_reports_unknown_fid() {
    let (mut conn, _srv) = connected();
    conn.attach(1, namikaze_9p::proto::NOFID, "glenda", "").expect("attach");
    conn.walk_path(1, 2, "top/hello").expect("walk");
    conn.clunk(2).expect("clunk");
    let err = conn.stat(2).expect_err("fid is gone");
    assert_eq!(Errno::leaf(&err), Errno::BadFid);
    assert!(err.to_string().contains("unknown fid"), "got {err}");
}

#[test]
fn walking_an_open_fid_is_refused() {
    let (mut conn, _srv) = connected();
    conn.attach(1, namikaze_9p::proto::NOFID, "glenda", "").expect("attach");
    conn.walk_path(1, 2, "top/hello").expect("walk");
    conn.open(2, OREAD).expect("open");
    let names = vec!["sub".to_string()];
    let err = conn.walk(2, 3, &names).expect_err("walk on open fid");
    // the wire carries the canonical string only; the server keeps the
    // detailed chain in its own log
    assert_eq!(Errno::leaf(&err), Errno::BadUseFd);
    assert!(err.to_string().contains("inappropriate use of fd"), "got {err}");
}

#[test]
fn oversized_read_count_is_refused() {
    let (mut conn, _srv) = connected();
    conn.attach(1, namikaze_9p::proto::NOFID, "glenda", "").expect("attach");
    conn.walk_path(1, 2, "top/hello").expect("walk");
    conn.open(2, OREAD).expect("open");
    // the client clamps silently to iounit, so force the raw path:
    // a Tread at the protocol limit minus one is fine; an absurd
    // count through a hand-built message must be refused by the server
    let tag = 99;
    let raw = Msg::Tread { tag, fid: 2, offset: 0, count: u32::MAX / 2 };
    let frame = raw.serialize(conn.msize()).expect("fits one frame");
    conn.send_raw(&frame).expect("send raw Tread");
    let reply = conn.recv_raw().expect("recv reply");
    let msg = Msg::parse(&reply).expect("parse reply");
    match msg {
        Msg::Rerror { ename, .. } => {
            assert_eq!(Errno::classify(&ename), Errno::TooBig, "ename: {ename}");
        }
        other => panic!("expected Rerror, got {}", namikaze_9p::proto::type_name(other.typ())),
    }
}

#[test]
fn hostile_frame_is_answered_with_rerror_and_the_session_survives() {
    let (mut conn, _srv) = connected();
    conn.attach(1, namikaze_9p::proto::NOFID, "glenda", "").expect("attach");
    // an unknown message type with a valid tag: the server must
    // answer Rerror (same tag) and keep serving the next request
    let hostile = [200u8, 42, 0]; // type 200, tag 42 (little-endian)
    let mut frame = (hostile.len() as u32 + 4).to_le_bytes().to_vec();
    frame.extend_from_slice(&hostile);
    conn.send_raw(&frame).expect("send hostile frame");
    let reply = conn.recv_raw().expect("server still answers");
    let msg = Msg::parse(&reply).expect("parse Rerror");
    match msg {
        Msg::Rerror { tag, .. } => assert_eq!(tag, 42, "the salvaged tag is used"),
        other => panic!("expected Rerror, got {}", namikaze_9p::proto::type_name(other.typ())),
    }
    // the session continues
    conn.walk_path(1, 2, "top/hello").expect("session survives");
}
