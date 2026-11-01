// SPDX-License-Identifier: MPL-2.0
//! namikaze-share: ephemeral anonymous file sharing.
//!
//! Publishes a read-only HTTP server on loopback and exposes it as an
//! ephemeral onion v3 service through the Tor control port. The service
//! dies with the process: no hidden service key is ever stored.
//!
//! Safety rules: path traversal and dotfiles are rejected; nothing is
//! written to disk; requests are logged to stdout only.

#![forbid(unsafe_code)]

use std::io::Read;
use std::path::{Path, PathBuf};

use namikaze_common::{init_tracing, Error, Result};
use namikaze_rt::args::Cli;
use namikaze_rt::http::{Request, Response, Server};

const USAGE: &[&str] = &[
    "namikaze-share: share files anonymously over a temporary onion service",
    "",
    "usage:",
    "  namikaze-share --dir PATH [--port 8900] [--onion-port 80]",
];

fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("") {
        "html" | "htm" => "text/html",
        "txt" | "md" => "text/plain",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

/// Resolve a request path inside the share root with traversal protection.
fn resolve(root: &Path, req: &str) -> Option<PathBuf> {
    let rel = req.trim_start_matches('/');
    if rel.is_empty() {
        return None;
    }
    let candidate = Path::new(rel);
    for comp in candidate.components() {
        use std::path::Component;
        match comp {
            Component::Normal(c) if !c.to_string_lossy().starts_with('.') => {}
            _ => return None,
        }
    }
    let full = root.join(candidate);
    if full.is_file() {
        Some(full)
    } else {
        None
    }
}

fn handle(req: &Request, root: &Path) -> Response {
    let method = req.method.as_str();
    if method != "GET" && method != "HEAD" {
        return Response::text(405, "method not allowed");
    }
    namikaze_rt::log_warn!("GET {}", req.path);
    match resolve(root, &req.path) {
        Some(file) => {
            let mut data = Vec::new();
            let ok = std::fs::File::open(&file).and_then(|mut f| f.read_to_end(&mut data)).is_ok();
            if ok {
                let name =
                    file.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                return Response::bytes(200, content_type(&name), data);
            }
            Response::text(404, "not found")
        }
        None => Response::text(404, "not found"),
    }
}

fn main() -> Result<()> {
    init_tracing("warn");
    let cli = Cli::capture();
    if cli.wants_help() {
        cli.usage_exit(USAGE);
    }
    let dir = std::path::PathBuf::from(cli.value("dir").unwrap_or_else(|| ".".into()));
    let root = dir.canonicalize().map_err(|e| Error::Other(format!("bad dir: {e}")))?;
    if !root.is_file() && !root.is_dir() {
        return Err(Error::Other("share target must be a file or directory".into()));
    }
    let port: u16 = cli.value_parse("port").ok().flatten().unwrap_or(8900);
    let onion_port: u16 = cli.value_parse("onion-port").ok().flatten().unwrap_or(80);

    let mut tor = namikaze_anon::connect_authenticated()?;
    let target = format!("127.0.0.1:{port}");
    let service_id = tor.add_onion(onion_port, &target)?;
    println!("onion service live: http://{service_id}.onion:{onion_port}");
    println!("ephemeral: close this process and the service disappears");

    let share_root = root.clone();
    let server = Server::bind("127.0.0.1", port)?;
    server.serve(move |req| handle(req, &share_root))?;
    let _ = tor.del_onion(&service_id);
    Ok(())
}
