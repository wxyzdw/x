// SPDX-License-Identifier: MPL-2.0
//! End-to-end: the real DirFs served over a real TCP socket,
//! exercised by the 9P client of namikaze-9p - the whole stack, no
//! mocks.

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;

use namikaze_9p::proto::{NOFID, OREAD};
use namikaze_9p::{Conn, Errno};
use namikaze_9srv::dirfs::DirFs;

fn served_tree() -> (PathBuf, TcpStream, thread::JoinHandle<()>) {
    let dir = std::env::temp_dir().join(format!("srv-e2e-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("docs")).expect("mkdir");
    fs::write(dir.join("README"), b"welcome to the export\n").expect("write");
    fs::write(dir.join("docs/plan9.txt"), b"everything is a file\n").expect("write");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind :0");
    let addr = listener.local_addr().expect("addr");
    let root = dir.clone();
    let server = thread::spawn(move || {
        namikaze_9p::server::serve(listener, move || {
            Box::new(DirFs::new(&root).expect("valid root"))
        });
    });
    let sock = TcpStream::connect(addr).expect("dial");
    (dir, sock, server)
}

#[test]
fn full_session_over_tcp_with_the_real_dirfs() {
    let (dir, sock, _server) = served_tree();
    let mut conn = Conn::new(sock).expect("handshake");
    assert_eq!(conn.msize(), 8192);

    conn.attach(2, NOFID, "glenda", "").expect("attach");

    // walk, open and read a real file through the wire
    let ids = conn
        .walk(2, 3, &["docs".to_string(), "plan9.txt".to_string()])
        .expect("walk docs/plan9.txt");
    assert_eq!(ids.len(), 2);
    conn.open(3, OREAD).expect("open");
    let data = conn.read_all(3).expect("read all");
    assert_eq!(data, b"everything is a file\n");

    // the directory stream lists real entries as stat blobs
    conn.clunk(3).expect("clunk");
    conn.walk(2, 3, &["docs".to_string()]).expect("walk docs");
    conn.open(3, OREAD).expect("open dir");
    let blob = conn.read_all(3).expect("read dir stream");
    let mut names = Vec::new();
    let mut pos = 0;
    while pos < blob.len() {
        let len = u16::from_le_bytes([blob[pos], blob[pos + 1]]) as usize;
        let d = namikaze_9p::Dir::decode(&blob[pos..pos + len]).expect("whole entry");
        names.push(d.name);
        pos += len;
    }
    assert_eq!(names, vec!["plan9.txt"]);

    // a missing element surfaces the canonical errno
    let err = conn.walk(2, 4, &["void".to_string()]).expect_err("missing element");
    assert_eq!(Errno::leaf(&err), Errno::NotFound);
    assert!(err.to_string().contains("void"), "the element is named: {err}");

    // writes are refused read-only, with the plan9 errno on the wire
    conn.clunk(3).expect("clunk");
    conn.walk(2, 3, &["README".to_string()]).expect("walk README");
    let err = conn.write(3, 0, b"vandalism").expect_err("read-only");
    assert_eq!(Errno::leaf(&err), Errno::ReadOnly);
    assert_eq!(fs::read_to_string(dir.join("README")).expect("read"), "welcome to the export\n");

    // stat reports the real file name and length
    conn.clunk(3).expect("clunk");
    conn.walk(2, 3, &["README".to_string()]).expect("walk README again");
    let stat = conn.stat(3).expect("stat");
    assert_eq!(stat.name, "README");
    assert_eq!(stat.length, 22);

    drop(conn);
    let _ = fs::remove_dir_all(&dir);
}
