// SPDX-License-Identifier: MPL-2.0
//! The plumber's file interface over 9P2000: the Rust transcription
//! of `src/cmd/plumb/fsys.c`, served on the `namikaze-9p` stack
//! instead of the C hand-rolled fcall loop.
//!
//! The export is the shape `plumber(4)` describes: a directory with
//! two pre-defined files and one read-only file per port.
//!
//! - `send` (write-only): a written plumb message is unpacked - an
//!   incomplete write is buffered until the rest arrives, a malformed
//!   one answers `bad plumb message format` - and routed through the
//!   rules in order. No rule matching and no destination answers
//!   `no matching plumb rule`; a destination naming an unknown port
//!   is silently dropped, exactly as in `dispose`.
//! - `rules` (read/write, writing exclusive): reads show the active
//!   rules; writes append rules through the incremental parser;
//!   opening with OTRUNC wipes the rule set. Ports survive.
//! - each port (read-only): every client holding the port open
//!   receives a copy of each routed message; reads block until one
//!   arrives. A message routed to a port nobody holds open is
//!   offered to the matching ruleset's `plumb start` / `plumb client`
//!   action; a client message is held until the port opens, and with
//!   no action the sender gets `no start action for plumb message`.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use namikaze_9p::error::{Errno, Error, Result};
use namikaze_9p::proto::{Dir, Qid, DMDIR, QTDIR, QTFILE};
use namikaze_9p::server::Fsys;

use crate::matcher::{self, Exec};
use crate::msg::{unpack_partial, Plumbmsg, UnpackError};
use crate::rules::{RulesParser, Ruleset};

/// Node numbering mirrors the C dirtab: `.`, `rules`, `send`, then
/// one entry per port in creation order.
const ROOT: u64 = 0;
const RULES: u64 = 1;
const SEND: u64 = 2;

const PERM_ROOT: u32 = 0o500 | DMDIR;
const PERM_RULES: u32 = 0o600;
const PERM_SEND: u32 = 0o200;
const PERM_PORT: u32 = 0o400;

/// 9P open mode bits (fcall.h).
const OREAD: u8 = 0;
const OWRITE: u8 = 1;
const ORDWR: u8 = 2;
const OEXEC: u8 = 3;
const OTRUNC: u8 = 0x10;
const OCEXEC: u8 = 0x20;
const ORCLOSE: u8 = 0x40;

fn other(msg: &str) -> Error {
    Error::Server(Errno::Other(msg.to_string()))
}

struct Receiver {
    mailbox: VecDeque<Vec<u8>>,
    /// Message currently being read, with the consumed cursor.
    current: Option<(Vec<u8>, usize)>,
}

impl Receiver {
    fn new() -> Receiver {
        Receiver { mailbox: VecDeque::new(), current: None }
    }

    fn take(&mut self, count: u32) -> Vec<u8> {
        if self.current.is_none() {
            if let Some(packed) = self.mailbox.pop_front() {
                self.current = Some((packed, 0));
            }
        }
        match &mut self.current {
            None => Vec::new(),
            Some((buf, consumed)) => {
                let end = (*consumed + count as usize).min(buf.len());
                let out = buf[*consumed..end].to_vec();
                *consumed = end;
                if *consumed >= buf.len() {
                    self.current = None;
                }
                out
            }
        }
    }
}

#[derive(Default)]
struct PortState {
    held: Vec<Plumbmsg>,
    receivers: Vec<(u64, Receiver)>,
    nopen: u32,
}

/// The plumber state shared by every connection: the rules, the
/// ports, their queues. The C original guarded the same state with
/// `qlock(&queue)`; here one mutex plus a condvar for blocking reads.
pub struct Plumber {
    pub parser: RulesParser,
    /// Port name -> node id, in creation order (the C dirtab tail).
    port_nodes: Vec<(String, u64)>,
    state: HashMap<u64, PortState>,
    next_node: u64,
    next_receiver: u64,
    rules_write_open: bool,
}

impl Default for Plumber {
    fn default() -> Self {
        Plumber {
            parser: RulesParser::new(),
            port_nodes: Vec::new(),
            state: HashMap::new(),
            next_node: SEND + 1,
            next_receiver: 0,
            rules_write_open: false,
        }
    }
}

impl Plumber {
    pub fn new() -> Plumber {
        Plumber::default()
    }

    /// Load the initial rules file and create its ports.
    pub fn load_rules(&mut self, path: &str) -> Result<(), String> {
        self.parser.parse_file(path)?;
        self.parser.make_ports();
        self.sync_ports();
        Ok(())
    }

    /// Give every port the parser knows a stable node id.
    fn sync_ports(&mut self) {
        for name in self.parser.ports.clone() {
            if !self.port_nodes.iter().any(|(n, _)| n == &name) {
                let node = self.next_node;
                self.next_node += 1;
                self.port_nodes.push((name, node));
                self.state.insert(node, PortState::default());
            }
        }
    }

    fn node_of(&self, name: &str) -> Option<u64> {
        self.port_nodes.iter().find(|(n, _)| n == name).map(|(_, node)| *node)
    }

    fn is_port(&self, node: u64) -> bool {
        node > SEND && self.state.contains_key(&node)
    }

    fn name_of(&self, node: u64) -> Option<String> {
        match node {
            ROOT => Some(".".to_string()),
            RULES => Some("rules".to_string()),
            SEND => Some("send".to_string()),
            _ => self.port_nodes.iter().find(|(_, n)| *n == node).map(|(n, _)| n.clone()),
        }
    }

    /// Route one message (`fsyswrite` send case). Returns the error
    /// string for the sender, if any.
    fn route(&mut self, msg: &mut Plumbmsg) -> Option<String> {
        let rulesets: Vec<Ruleset> = self.parser.rulesets.clone();
        let vars = self.parser.vars.clone();
        for rs in &rulesets {
            match matcher::match_ruleset(msg, rs, &vars) {
                Ok(Some(exec)) => return self.dispose(msg, Some(rs), exec),
                Ok(None) => {}
                Err(e) => return Some(e),
            }
        }
        if !msg.dst.is_empty() {
            let exec = Exec::new(msg);
            return self.dispose(msg, None, exec);
        }
        Some("no matching plumb rule".to_string())
    }

    /// `dispose`: deliver, hold, start a command, or reject - with
    /// the C original's exact outcomes per destination state.
    fn dispose(&mut self, msg: &Plumbmsg, rs: Option<&Ruleset>, mut exec: Exec) -> Option<String> {
        let dst = msg.dst.clone();
        if dst.is_empty() {
            // no destination: a start rule still runs (its success
            // silences the error), a client rule has no port to hold on
            match matcher::find_action(rs, &mut exec, &self.parser.vars) {
                Ok(action) => {
                    matcher::perform(action);
                    None
                }
                Err(e) => Some(e),
            }
        } else if let Some(node) = self.node_of(&dst) {
            let st = self.state.get_mut(&node).unwrap();
            if st.nopen == 0 {
                match matcher::find_action(rs, &mut exec, &self.parser.vars) {
                    Ok(action) => {
                        if exec.holdforclient {
                            st.held.push(msg.clone());
                        }
                        matcher::perform(action);
                        None
                    }
                    Err(e) => Some(e),
                }
            } else {
                let packed = msg.pack();
                for (_, recv) in &mut st.receivers {
                    recv.mailbox.push_back(packed.clone());
                }
                None
            }
        } else {
            // the destination names no port: dropped with a successful
            // write - the C dispose loop simply falls through
            None
        }
    }

    /// A client opened a port: register its receiver and release any
    /// held messages to every open receiver (`fsysopen`+`queueheld`).
    fn open_port(&mut self, node: u64) -> u64 {
        self.next_receiver += 1;
        let id = self.next_receiver;
        let st = self.state.entry(node).or_default();
        st.nopen += 1;
        st.receivers.push((id, Receiver::new()));
        if !st.held.is_empty() {
            let held = std::mem::take(&mut st.held);
            for msg in held {
                let packed = msg.pack();
                for (_, recv) in &mut st.receivers {
                    recv.mailbox.push_back(packed.clone());
                }
            }
        }
        id
    }

    fn close_port(&mut self, node: u64, id: u64) {
        if let Some(st) = self.state.get_mut(&node) {
            st.nopen = st.nopen.saturating_sub(1);
            st.receivers.retain(|(rid, _)| *rid != id);
        }
    }

    /// Append to the rules file; refresh the port table afterwards.
    fn write_rules(&mut self, text: &str) -> Result<(), String> {
        let r = self.parser.write_rules(text);
        self.sync_ports();
        r
    }
}

/// One connection's view of the plumber. The 9P server owns one
/// instance per socket; the shared [`Plumber`] carries the state.
pub struct PlumberFsys {
    core: Arc<Mutex<Plumber>>,
    cond: Arc<Condvar>,
    /// Port node -> receiver id for this connection's open fids.
    my_receivers: HashMap<u64, u64>,
    /// Partial `send` write, keyed by connection like the C fid
    /// write buffer (one send fid per connection is the usage).
    send_buf: Vec<u8>,
    uname: String,
}

impl PlumberFsys {
    pub fn shared() -> (Arc<Mutex<Plumber>>, Arc<Condvar>, PlumberFsys) {
        let core = Arc::new(Mutex::new(Plumber::new()));
        let cond = Arc::new(Condvar::new());
        let fsys = PlumberFsys {
            core: Arc::clone(&core),
            cond: Arc::clone(&cond),
            my_receivers: HashMap::new(),
            send_buf: Vec::new(),
            uname: String::new(),
        };
        (core, cond, fsys)
    }

    pub fn for_core(core: Arc<Mutex<Plumber>>, cond: Arc<Condvar>) -> PlumberFsys {
        PlumberFsys {
            core,
            cond,
            my_receivers: HashMap::new(),
            send_buf: Vec::new(),
            uname: String::new(),
        }
    }
}

fn qid_of(node: u64) -> Qid {
    match node {
        ROOT => Qid { typ: QTDIR, vers: 0, path: ROOT },
        _ => Qid { typ: QTFILE, vers: 0, path: node },
    }
}

fn perm_of(node: u64) -> u32 {
    match node {
        ROOT => PERM_ROOT,
        RULES => PERM_RULES,
        SEND => PERM_SEND,
        _ => PERM_PORT,
    }
}

fn dir_of(node: u64, name: String) -> Dir {
    Dir {
        typ: 0,
        dev: 0,
        qid: qid_of(node),
        mode: perm_of(node),
        atime: 0,
        mtime: 0,
        length: 0,
        name,
        uid: "plumber".to_string(),
        gid: "plumber".to_string(),
        muid: "plumber".to_string(),
    }
}

impl Fsys for PlumberFsys {
    fn attach(&mut self, uname: &str, _aname: &str) -> Result<(u64, Qid)> {
        self.uname = uname.to_string();
        Ok((ROOT, qid_of(ROOT)))
    }

    fn walk(&mut self, node: u64, name: &str) -> Result<(u64, Qid)> {
        if node != ROOT {
            return Err(other("not a directory"));
        }
        match name {
            ".." | "." => Ok((ROOT, qid_of(ROOT))),
            "rules" => Ok((RULES, qid_of(RULES))),
            "send" => Ok((SEND, qid_of(SEND))),
            other_name => {
                let core = self.core.lock().unwrap();
                match core.node_of(other_name) {
                    Some(node) => Ok((node, qid_of(node))),
                    None => Err(other("plumb file does not exist")),
                }
            }
        }
    }

    fn open(&mut self, node: u64, mode: u8) -> Result<(Qid, u32)> {
        let mut clearrules = false;
        if mode & OTRUNC != 0 {
            if node != RULES {
                return Err(other("permission denied"));
            }
            clearrules = true;
        }
        // can't truncate (handled above) or execute or remove
        let mode = mode & !(OTRUNC | OCEXEC);
        if mode == OEXEC || mode & ORCLOSE != 0 {
            return Err(other("permission denied"));
        }
        let need: u32 = match mode {
            OREAD => 0o400,
            OWRITE => 0o200,
            ORDWR => 0o600,
            _ => return Err(other("permission denied")),
        };
        let perm = perm_of(node) & !DMDIR;
        if perm & need != need {
            return Err(other("permission denied"));
        }
        if node == ROOT {
            // the export root: readable, not writable
        } else if node == RULES {
            let mut core = self.core.lock().unwrap();
            if need & 0o200 != 0 {
                // exclusive write handle on the rules file
                if core.rules_write_open {
                    return Err(other("file already open"));
                }
                core.rules_write_open = true;
            }
            if clearrules {
                core.parser.clear_rules();
            }
        } else if node == SEND {
            // nothing to register; writes carry their own buffer
        } else {
            let mut core = self.core.lock().unwrap();
            if !core.is_port(node) {
                return Err(other("plumb file does not exist"));
            }
            let id = core.open_port(node);
            self.my_receivers.insert(node, id);
            self.cond.notify_all();
        }
        Ok((qid_of(node), 0))
    }

    fn read(&mut self, node: u64, offset: u64, count: u32) -> Result<Vec<u8>> {
        if node == RULES {
            let core = self.core.lock().unwrap();
            let text = core.parser.print_rules();
            let bytes = text.into_bytes();
            let start = offset as usize;
            if start >= bytes.len() {
                return Ok(Vec::new());
            }
            let end = (start + count as usize).min(bytes.len());
            return Ok(bytes[start..end].to_vec());
        }
        if !self.my_receivers.contains_key(&node) {
            return Err(other("plumb file does not exist"));
        }
        if count == 0 {
            return Ok(Vec::new());
        }
        // Block until this port's receiver has a message, exactly the
        // C read-side: the request parks until a send wakes it.
        loop {
            {
                let mut core = self.core.lock().unwrap();
                if let Some(id) = self.my_receivers.get(&node) {
                    if let Some((_, recv)) = core
                        .state
                        .get_mut(&node)
                        .and_then(|st| st.receivers.iter_mut().find(|(rid, _)| rid == id))
                    {
                        let out = recv.take(count);
                        if !out.is_empty() {
                            return Ok(out);
                        }
                    } else {
                        return Err(other("plumb file does not exist"));
                    }
                }
            }
            let _guard =
                self.cond.wait_timeout(self.core.lock().unwrap(), Duration::from_millis(500));
            // loop until a message arrives; the connection thread
            // parks here, which is what a blocking read means
        }
    }

    fn read_dir(&mut self, node: u64, offset: u64, count: u32) -> Result<Vec<u8>> {
        if node != ROOT {
            return Err(other("not a directory"));
        }
        let mut out = Vec::new();
        {
            let core = self.core.lock().unwrap();
            let mut entries: Vec<Dir> = Vec::new();
            if let Some(name) = core.name_of(RULES) {
                entries.push(dir_of(RULES, name));
            }
            if let Some(name) = core.name_of(SEND) {
                entries.push(dir_of(SEND, name));
            }
            for (name, node) in &core.port_nodes {
                entries.push(dir_of(*node, name.clone()));
            }
            for d in entries {
                out.extend_from_slice(&d.encode()?);
            }
        }
        let start = offset as usize;
        if start >= out.len() {
            return Ok(Vec::new());
        }
        let end = (start + count as usize).min(out.len());
        Ok(out[start..end].to_vec())
    }

    fn write(&mut self, node: u64, _offset: u64, data: &[u8]) -> Result<u32> {
        if node == RULES {
            let text = String::from_utf8_lossy(data).into_owned();
            let mut core = self.core.lock().unwrap();
            return match core.write_rules(&text) {
                Ok(()) => Ok(data.len() as u32),
                Err(e) => Err(other(&e)),
            };
        }
        if node == SEND {
            // the C fid buffer: a fresh write at offset zero starts a
            // message, anything else continues the pending one
            if self.send_buf.is_empty() {
                self.send_buf = data.to_vec();
            } else {
                self.send_buf.extend_from_slice(data);
            }
            match unpack_partial(&self.send_buf) {
                Ok(mut msg) => {
                    self.send_buf.clear();
                    let mut core = self.core.lock().unwrap();
                    match core.route(&mut msg) {
                        None => Ok(data.len() as u32),
                        Some(e) => Err(other(&e)),
                    }
                }
                Err(UnpackError::NeedMore(_)) => Ok(data.len() as u32),
                Err(UnpackError::Bad) => {
                    self.send_buf.clear();
                    Err(other("bad plumb message format"))
                }
            }
        } else {
            Err(other("permission denied"))
        }
    }

    fn stat(&mut self, node: u64) -> Result<Dir> {
        let core = self.core.lock().unwrap();
        match core.name_of(node) {
            Some(name) => Ok(dir_of(node, name)),
            None => Err(other("plumb file does not exist")),
        }
    }

    fn wstat(&mut self, _node: u64, _stat: &Dir) -> Result<()> {
        Err(other("permission denied"))
    }

    fn remove(&mut self, _node: u64) -> Result<()> {
        Err(other("permission denied"))
    }

    fn clunk(&mut self, node: u64) -> Result<()> {
        let mut core = self.core.lock().unwrap();
        if node == RULES && core.rules_write_open {
            // flush the pending text; parse errors are lost here,
            // "unless last write ended with a blank line" as the C
            // comment puts it
            let _ = core.parser.flush_rules();
            core.rules_write_open = false;
        }
        if let Some(id) = self.my_receivers.remove(&node) {
            core.close_port(node, id);
            self.cond.notify_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use namikaze_9p::client::Conn;
    use std::net::TcpListener;
    use std::thread;

    /// Serve one plumber on a fresh port with the given rules.
    fn spawn(rules: &str) -> (String, Arc<Mutex<Plumber>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (core, cond, _probe) = PlumberFsys::shared();
        {
            let mut c = core.lock().unwrap();
            if !rules.is_empty() {
                c.parser.parse_text("test", rules).unwrap();
                c.parser.make_ports();
                c.sync_ports();
            }
        }
        let core2 = Arc::clone(&core);
        let cond2 = Arc::clone(&cond);
        thread::spawn(move || {
            namikaze_9p::server::serve(listener, move || {
                Box::new(PlumberFsys::for_core(Arc::clone(&core2), Arc::clone(&cond2)))
            });
        });
        (addr, core)
    }

    fn attach_and_walk_send(addr: &str) -> Conn<std::net::TcpStream> {
        let mut conn = Conn::dial(addr).unwrap();
        conn.attach(0, 0xffffffff, "plumber", "").unwrap();
        conn.walk_path(0, 1, "send").unwrap();
        conn.open(1, OWRITE).unwrap();
        conn
    }

    fn open_port(addr: &str, port: &str) -> Conn<std::net::TcpStream> {
        let mut conn = Conn::dial(addr).unwrap();
        conn.attach(0, 0xffffffff, "plumber", "").unwrap();
        conn.walk_path(0, 1, port).unwrap();
        conn.open(1, OREAD).unwrap();
        conn
    }

    fn pack(src: &str, dst: &str, data: &str) -> Vec<u8> {
        let mut m = Plumbmsg::new();
        m.src = src.into();
        m.dst = dst.into();
        m.typ = "text".into();
        m.data = data.as_bytes().to_vec();
        m.pack()
    }

    const RULES: &str = "data matches '[a-zA-Z0-9_./]+'\nplumb to edit\n\n";

    #[test]
    fn send_routed_to_open_port() {
        let (addr, _core) = spawn(RULES);
        let mut reader = open_port(&addr, "edit");
        // read parks until the send arrives; give it a thread
        let handle = thread::spawn(move || reader.read(1, 0, 8192).unwrap());
        thread::sleep(std::time::Duration::from_millis(150));
        let mut sender = attach_and_walk_send(&addr);
        sender.write(1, 0, &pack("plumb", "", "/etc/hosts")).unwrap();
        let got = handle.join().unwrap();
        let m = unpack_partial(&got).unwrap();
        assert_eq!(m.dst, "edit");
        assert_eq!(m.data, b"/etc/hosts");
    }

    #[test]
    fn send_without_listener_without_action_errors() {
        let (addr, _core) = spawn(RULES);
        let mut sender = attach_and_walk_send(&addr);
        let err = sender.write(1, 0, &pack("plumb", "", "/etc/hosts")).unwrap_err();
        assert_eq!(Errno::leaf(&err).wire(), "no start action for plumb message");
    }

    #[test]
    fn client_rule_holds_until_port_opens() {
        let rules = "data matches '.*'\nplumb client viewer\nplumb to show\n\n";
        let (addr, _core) = spawn(rules);
        let mut sender = attach_and_walk_send(&addr);
        // no listener: the client rule holds the message, write succeeds
        sender.write(1, 0, &pack("plumb", "", "held.txt")).unwrap();
        // now open the port: the held message arrives
        let mut reader = open_port(&addr, "show");
        let got = reader.read(1, 0, 8192).unwrap();
        assert_eq!(unpack_partial(&got).unwrap().data, b"held.txt");
    }

    #[test]
    fn no_matching_rule_is_an_error() {
        let (addr, _core) = spawn("");
        let mut sender = attach_and_walk_send(&addr);
        let err = sender.write(1, 0, &pack("plumb", "", "x")).unwrap_err();
        assert_eq!(Errno::leaf(&err).wire(), "no matching plumb rule");
    }

    #[test]
    fn unknown_port_destination_is_dropped_silently() {
        // faithful to dispose: a dst that names no port succeeds
        // and the message goes nowhere
        let (addr, core) = spawn("");
        let mut sender = attach_and_walk_send(&addr);
        sender.write(1, 0, &pack("plumb", "nosuchport", "x")).unwrap();
        let c = core.lock().unwrap();
        assert!(c.parser.ports.is_empty());
    }

    #[test]
    fn malformed_send_is_rejected() {
        let (addr, _core) = spawn(RULES);
        let mut sender = attach_and_walk_send(&addr);
        let err = sender.write(1, 0, b"not a plumb message at all").unwrap_err();
        assert_eq!(Errno::leaf(&err).wire(), "bad plumb message format");
        // the buffer was reset; a good message still works after it
        let mut reader = open_port(&addr, "edit");
        let handle = thread::spawn(move || reader.read(1, 0, 8192).unwrap());
        thread::sleep(std::time::Duration::from_millis(150));
        sender.write(1, 0, &pack("plumb", "", "/y")).unwrap();
        assert_eq!(unpack_partial(&handle.join().unwrap()).unwrap().data, b"/y");
    }

    #[test]
    fn partial_sends_accumulate() {
        let (addr, _core) = spawn(RULES);
        let mut sender = attach_and_walk_send(&addr);
        let full = pack("plumb", "", "/partial");
        // split after the six header lines, inside the data
        let (a, b) = full.split_at(full.len() - 6);
        sender.write(1, 0, a).unwrap(); // buffered, success
        let mut reader = open_port(&addr, "edit");
        let handle = thread::spawn(move || reader.read(1, 0, 8192).unwrap());
        thread::sleep(std::time::Duration::from_millis(150));
        sender.write(1, 0, b).unwrap(); // completes the message
        let got = handle.join().unwrap();
        assert_eq!(unpack_partial(&got).unwrap().data, b"/partial");
    }

    #[test]
    fn rules_file_roundtrip() {
        let (addr, _core) = spawn(RULES);
        let mut conn = Conn::dial(&addr).unwrap();
        conn.attach(0, 0xffffffff, "plumber", "").unwrap();
        conn.walk_path(0, 1, "rules").unwrap();
        conn.open(1, OREAD).unwrap();
        let view = String::from_utf8(conn.read_all(1).unwrap()).unwrap();
        assert!(view.contains("data\tmatches\t'[a-zA-Z0-9_./]+'\n"));
        assert!(view.contains("plumb\tto\tedit\n"));
        assert!(view.contains("plumb to edit\n"));
        conn.clunk(1).unwrap();

        // append a new rule by writing to the rules file
        conn.walk_path(0, 1, "rules").unwrap();
        conn.open(1, OWRITE).unwrap();
        conn.write(1, 0, b"data matches 'hello.*'\nplumb to greet\n\n").unwrap();
        conn.clunk(1).unwrap();

        // a second write-handle is refused while the first is open
        conn.walk_path(0, 1, "rules").unwrap();
        conn.open(1, OWRITE).unwrap();
        let err = {
            let mut conn2 = Conn::dial(&addr).unwrap();
            conn2.attach(0, 0xffffffff, "plumber", "").unwrap();
            conn2.walk_path(0, 1, "rules").unwrap();
            conn2.open(1, OWRITE).unwrap_err()
        };
        assert_eq!(Errno::leaf(&err).wire(), "file already open");
        conn.clunk(1).unwrap();

        // the new port now exists and routes
        let mut sender = attach_and_walk_send(&addr);
        let mut reader = open_port(&addr, "greet");
        let handle = thread::spawn(move || reader.read(1, 0, 8192).unwrap());
        thread::sleep(std::time::Duration::from_millis(150));
        sender.write(1, 0, &pack("plumb", "", "hello there")).unwrap();
        let got = handle.join().unwrap();
        assert_eq!(unpack_partial(&got).unwrap().data, b"hello there");
    }

    #[test]
    fn truncating_rules_clears_rulesets_but_keeps_ports() {
        let (addr, core) = spawn(RULES);
        let mut conn = Conn::dial(&addr).unwrap();
        conn.attach(0, 0xffffffff, "plumber", "").unwrap();
        // OTRUNC = OREAD | OTRUNC on the rules file
        conn.walk_path(0, 1, "rules").unwrap();
        conn.open(1, OREAD | OTRUNC).unwrap();
        conn.clunk(1).unwrap();
        let c = core.lock().unwrap();
        assert!(c.parser.rulesets.is_empty());
        // ports are never deleted dynamically
        assert_eq!(c.parser.ports, vec!["edit".to_string()]);
    }

    #[test]
    fn open_modes_enforced() {
        let (addr, _core) = spawn(RULES);
        let mut conn = Conn::dial(&addr).unwrap();
        conn.attach(0, 0xffffffff, "plumber", "").unwrap();
        // send is write-only
        conn.walk_path(0, 1, "send").unwrap();
        let err = conn.open(1, OREAD).unwrap_err();
        assert_eq!(Errno::leaf(&err).wire(), "permission denied");
        conn.clunk(1).unwrap();
        // ports are read-only
        conn.walk_path(0, 1, "edit").unwrap();
        let err2 = conn.open(1, OWRITE).unwrap_err();
        assert_eq!(Errno::leaf(&err2).wire(), "permission denied");
        conn.clunk(1).unwrap();
        // walking through a file is not a directory
        conn.walk_path(0, 1, "send").unwrap();
        let err3 = conn.walk(1, 2, &["rules".to_string()]).unwrap_err();
        assert_eq!(Errno::leaf(&err3).wire(), "not a directory");
        conn.clunk(1).unwrap();
        // unknown names
        // the wire carries the plumber's exact "plumb file does not
        // exist"; the client's errno catalogue classifies it back to
        // the canonical NotFound wording
        let err4 = conn.walk_path(0, 1, "nosuch").unwrap_err();
        assert_eq!(Errno::leaf(&err4).wire(), "file does not exist");
    }

    #[test]
    fn directory_lists_rules_send_and_ports() {
        let (addr, _core) = spawn(RULES);
        let mut conn = Conn::dial(&addr).unwrap();
        conn.attach(0, 0xffffffff, "plumber", "").unwrap();
        conn.open(0, OREAD).unwrap();
        let raw = conn.read(0, 0, 8192).unwrap();
        // walk the stat stream: each entry is u16-size prefixed, and
        // the leaf name sits after the 41 fixed bytes (2+2+4+1+4+8+
        // 4+4+4+8, then the name's u16 length)
        let mut names: Vec<String> = Vec::new();
        let mut i = 0usize;
        while i + 2 <= raw.len() {
            let sz = u16::from_le_bytes([raw[i], raw[i + 1]]) as usize;
            if sz < 43 || i + sz > raw.len() {
                panic!("bad stat entry at {i}");
            }
            let nlen = u16::from_le_bytes([raw[i + 41], raw[i + 42]]) as usize;
            names.push(String::from_utf8_lossy(&raw[i + 43..i + 43 + nlen]).into_owned());
            i += sz;
        }
        assert!(names.contains(&"rules".to_string()));
        assert!(names.contains(&"send".to_string()));
        assert!(names.contains(&"edit".to_string()));
    }

    #[test]
    fn start_rule_fires_and_errors_when_unsplittable() {
        // plumb start with an empty command argument list
        let rules = "data matches '.*'\nplumb start ''\nplumb to p\n\n";
        let (addr, _core) = spawn(rules);
        let mut sender = attach_and_walk_send(&addr);
        let err = sender.write(1, 0, &pack("plumb", "", "x")).unwrap_err();
        assert_eq!(Errno::leaf(&err).wire(), "empty argument list");
    }

    #[test]
    fn start_rule_runs_the_command() {
        // the classic plumbing: showdata messages feed a command;
        // use a command that always exists and succeeds
        let rules =
            "type is text\ndata matches '.*'\narg isdir .\nplumb start true\nplumb to p\n\n";
        let (addr, _core) = spawn(rules);
        let mut sender = attach_and_walk_send(&addr);
        // no listener + start rule: the command runs, write succeeds
        sender.write(1, 0, &pack("plumb", "", "whatever")).unwrap();
    }

    #[test]
    fn rule_with_no_start_action_names_the_error() {
        let rules = "data matches '.*'\nplumb to p\n\n";
        let (addr, _core) = spawn(rules);
        let mut sender = attach_and_walk_send(&addr);
        let err = sender.write(1, 0, &pack("plumb", "", "x")).unwrap_err();
        assert_eq!(Errno::leaf(&err).wire(), "no start action for plumb message");
    }

    #[test]
    fn matching_can_rewrite_and_reroute() {
        // the message is routed to "show" by the set, not by a port
        let rules = "data matches '.*'\ndst set show\nplumb to show\n\n";
        let (addr, _core) = spawn(rules);
        let mut reader = open_port(&addr, "show");
        let handle = thread::spawn(move || reader.read(1, 0, 8192).unwrap());
        thread::sleep(std::time::Duration::from_millis(150));
        let mut sender = attach_and_walk_send(&addr);
        sender.write(1, 0, &pack("plumb", "", "hello")).unwrap();
        let got = handle.join().unwrap();
        assert_eq!(unpack_partial(&got).unwrap().dst, "show");
    }
}
