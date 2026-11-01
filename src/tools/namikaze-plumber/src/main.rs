// SPDX-License-Identifier: MPL-2.0
//! namikaze-plumber: the Plan 9 plumber of NamikazeOS.
//!
//!   namikaze-plumber serve [--addr 127.0.0.1:5640] [--rules FILE]
//!   namikaze-plumber check [--rules FILE]
//!   namikaze-plumber plumb [--addr HOST:PORT] [-d dst] [-t type]
//!                          [-s src] [-w wdir] [-a 'k=v' ...] (-i | data...)
//!
//! `serve` loads the plumbing rules (default `$HOME/lib/plumbing`)
//! and exports the plumber's file interface over 9P2000: `send` to
//! deliver messages, `rules` to view and edit the rule set live, and
//! one read-only file per port. `check` parses a rules file and
//! prints the plumber's own view of it. `plumb` is the client of
//! `plumb(1)`: one message per argument, or the whole of stdin with
//! `-i` (which adds `action=showdata` unless an action is given).

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::process::exit;
use std::sync::{Arc, Condvar, Mutex};

use namikaze_9p::client::Conn;
use namikaze_plumber::msg::Plumbmsg;
use namikaze_plumber::plumbfs::{Plumber, PlumberFsys};

const USAGE: &str = "namikaze-plumber: the Plan 9 plumber over 9P2000

usage:
  namikaze-plumber serve [--addr HOST:PORT] [--rules FILE]
  namikaze-plumber check [--rules FILE]
  namikaze-plumber plumb [--addr HOST:PORT] [-d DST] [-t TYPE] [-s SRC]
                         [-w WDIR] [-a NAME=VALUE ...] (-i | DATA...)

serve loads the plumbing rules (default $HOME/lib/plumbing) and
exports send, rules and the ports over 9P2000. check parses the
rules file and prints the plumber's view of it. plumb sends messages:
one per argument, or stdin with -i (which defaults the action
attribute to showdata, as plumb(1) does).";

fn fail(msg: &str) -> ! {
    eprintln!("namikaze-plumber: {msg}");
    exit(2);
}

fn opt_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn opt_values(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn rules_path(args: &[String]) -> String {
    match opt_value(args, "--rules") {
        Some(p) => p,
        None => match std::env::var("HOME") {
            Ok(home) => format!("{home}/lib/plumbing"),
            Err(_) => fail("no --rules FILE and $HOME is not set"),
        },
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("-h" | "--help") | None => {
            println!("{USAGE}");
            exit(if args.is_empty() { 2 } else { 0 });
        }
        Some("serve") => serve(&args[1..]),
        Some("check") => check(&args[1..]),
        Some("plumb") => plumb(&args[1..]),
        Some(other) => fail(&format!("unknown subcommand {other}")),
    }
}

/// Load a plumber with its initial rules.
fn load(rules: &str) -> Result<(Arc<Mutex<Plumber>>, Arc<Condvar>), String> {
    let (core, cond, _probe) = PlumberFsys::shared();
    {
        let mut c = core.lock().unwrap();
        c.load_rules(rules)?;
    }
    Ok((core, cond))
}

fn serve(args: &[String]) {
    let addr = opt_value(args, "--addr").unwrap_or_else(|| "127.0.0.1:5640".to_string());
    let rules = rules_path(args);
    let (core, cond) = match load(&rules) {
        Ok(x) => x,
        Err(e) => fail(&format!("can't load rules: {e}")),
    };
    let listener = match std::net::TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => fail(&format!("can't listen on {addr}: {e}")),
    };
    eprintln!("namikaze-plumber: serving plumb on {addr}, rules from {rules}");
    namikaze_9p::server::serve(listener, move || {
        Box::new(PlumberFsys::for_core(Arc::clone(&core), Arc::clone(&cond)))
            as Box<dyn namikaze_9p::server::Fsys>
    });
}

fn check(args: &[String]) {
    let rules = rules_path(args);
    let (core, _cond) = match load(&rules) {
        Ok(x) => x,
        Err(e) => fail(&format!("can't load rules: {e}")),
    };
    let c = core.lock().unwrap();
    print!("{}", c.parser.print_rules());
}

/// The `plumb(1)` client: defaults src=plumb, wdir=cwd, type=text.
fn plumb(args: &[String]) {
    let addr = opt_value(args, "--addr").unwrap_or_else(|| "127.0.0.1:5640".to_string());
    let dst = opt_value(args, "-d").unwrap_or_default();
    let typ = opt_value(args, "-t").unwrap_or_else(|| "text".to_string());
    let src = opt_value(args, "-s").unwrap_or_else(|| "plumb".to_string());
    let wdir = match opt_value(args, "-w") {
        Some(w) => w,
        None => {
            std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
        }
    };
    let mut msg = Plumbmsg::new();
    msg.src = src;
    msg.dst = dst;
    msg.wdir = wdir;
    msg.typ = typ;
    for pair in opt_values(args, "-a") {
        for attr in namikaze_plumber::msg::unpack_attr(&pair) {
            msg.attr.push(attr);
        }
    }

    let read_stdin = args.iter().any(|a| a == "-i");
    let mut rest: Vec<String> = Vec::new();
    let mut skip_next = false;
    for a in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if matches!(a.as_str(), "-a" | "-d" | "-t" | "-s" | "-w" | "--addr") {
            skip_next = true;
            continue;
        }
        if a == "-i" {
            continue;
        }
        rest.push(a.clone());
    }

    if read_stdin && !rest.is_empty() {
        fail("usage: -i excludes data arguments");
    }

    let mut conn = match Conn::dial(&addr) {
        Ok(c) => c,
        Err(e) => fail(&format!("can't open plumb file: {e}")),
    };
    if conn.attach(0, 0xffffffff, "plumb", "").is_err() {
        fail("can't attach to plumber");
    }
    if conn.walk_path(0, 1, "send").is_err() {
        fail("plumber has no send file");
    }
    if conn.open(1, 1).is_err() {
        fail("can't open plumb/send for writing");
    }

    let mut send = |msg: &Plumbmsg| {
        if let Err(e) = conn.write(1, 0, &msg.pack()) {
            eprintln!("plumb: can't send message: {}", namikaze_9p::error::Errno::leaf(&e).wire());
            exit(1);
        }
    };

    if read_stdin {
        let mut data = Vec::new();
        if std::io::stdin().read_to_end(&mut data).is_err() {
            fail("i/o error on input");
        }
        msg.data = data;
        if msg.attr("action").is_none() {
            msg.add_attr("action", "showdata");
        }
        send(&msg);
        return;
    }
    if rest.is_empty() {
        fail("nothing to send: give data arguments or -i");
    }
    for arg in rest {
        msg.data = arg.as_bytes().to_vec();
        send(&msg);
    }
    let _ = std::io::stdout().flush();
}
