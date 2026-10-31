// SPDX-License-Identifier: MPL-2.0
//! namikaze-decoy: deception services (honeypot layer).
//!
//! Runs deliberately boring fake services (SSH banner, HTTP 404) so port
//! scans waste time on decoys instead of surfacing real attack surface.
//! Purely passive by design: it never executes input, never touches disk,
//! and only logs connection metadata.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use namikaze_common::init_tracing;
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-decoy: deception services for NamikazeOS (passive honeypots)",
    "",
    "usage:",
    "  namikaze-decoy [--ports ssh:22,http:8080] [--duration SECS]",
];

fn handle_stream(mut stream: TcpStream, kind: &str) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());
    namikaze_rt::log_warn!("decoy connection {kind} from {peer}");
    match kind {
        "ssh" => {
            let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.6p1\r\n");
            let mut buf = [0u8; 512];
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = stream.read(&mut buf);
        }
        _ => {
            let body = "<html><body>404 not found</body></html>";
            let resp = format!(
                "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    }
}

fn serve(port: u16, kind: &'static str) {
    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => {
            namikaze_rt::log_error!("decoy port {port} bind failed: {e}");
            return;
        }
    };
    namikaze_rt::log_info!("decoy {kind} listening on {port}");
    for stream in listener.incoming().flatten() {
        thread::spawn(move || handle_stream(stream, kind));
    }
}

fn main() {
    init_tracing("warn");
    let cli = Cli::capture();
    if cli.wants_help() {
        cli.usage_exit(USAGE);
    }
    let ports = cli.value_or("ports", "22,8080");
    let duration: u64 = cli.value_parse("duration").ok().flatten().unwrap_or(0);
    let mut threads = Vec::new();
    for spec in ports.split(',') {
        let (kind, port) = match spec.split_once(':') {
            Some(("ssh", p)) => ("ssh", p),
            Some(("http", p)) => ("http", p),
            _ => ("http", spec),
        };
        let Ok(port) = port.parse::<u16>() else { continue };
        threads.push(thread::spawn(move || serve(port, kind)));
    }
    if duration > 0 {
        thread::sleep(Duration::from_secs(duration));
        std::process::exit(0);
    }
    for t in threads {
        let _ = t.join();
    }
}
