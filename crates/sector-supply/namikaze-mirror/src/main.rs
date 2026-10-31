// SPDX-License-Identifier: MPL-2.0
//! namikaze-mirror: local package mirror over the rt HTTP server.
//!
//! `index` walks a package directory and writes index.json (sha256 per
//! file); `serve` publishes the directory plus the generated index on a
//! loopback or LAN address. The binhost convergence path (namikaze-pkg)
//! can point at this mirror for a fully offline update flow.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use namikaze_common::{init_tracing, Error, Result};
use namikaze_rt::args::Cli;
use namikaze_rt::fsutil::walk_files;
use namikaze_rt::http::{Request, Response, Server};
use namikaze_rt::json::{obj, Value};
use namikaze_rt::sha256::sha256_file_hex;

const USAGE: &[&str] = &[
    "namikaze-mirror: local package mirror (index + serve)",
    "",
    "usage:",
    "  namikaze-mirror index [--dir PATH]           regenerate index.json",
    "  namikaze-mirror serve [--dir PATH] [--port 8901] [--addr 127.0.0.1]",
];

fn build_index(dir: &Path) -> Result<Value> {
    let mut files = Vec::new();
    for path in walk_files(dir) {
        if path.file_name().map(|n| n == "index.json").unwrap_or(false) {
            continue;
        }
        let digest = sha256_file_hex(&path)?;
        let rel = path
            .strip_prefix(dir)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        let size = path.metadata().map(|m| m.len()).unwrap_or(0);
        files.push(obj(&[
            ("path", Value::Str(rel)),
            ("sha256", Value::Str(digest)),
            ("size", Value::Int(size as i64)),
        ]));
    }
    Ok(obj(&[("files", Value::Arr(files))]))
}

fn cmd_index(dir: &Path) -> Result<()> {
    let index = build_index(dir)?;
    let out = dir.join("index.json");
    std::fs::write(&out, index.to_pretty())?;
    let n = index.get("files").and_then(|f| f.as_arr()).map(|a| a.len()).unwrap_or(0);
    println!("index written: {} ({} file(s))", out.display(), n);
    Ok(())
}

fn serve(dir: PathBuf, addr: String, port: u16) -> Result<()> {
    let index = build_index(&dir)?;
    println!("serving {} on {addr}:{port}", dir.display());
    let server = Server::bind(&addr, port)?;
    server.serve(move |req: &Request| {
        if req.path == "/index.json" {
            return Response::bytes(200, "application/json", index.to_pretty().into_bytes());
        }
        let rel = req.path.trim_start_matches('/');
        if rel.is_empty() || rel.contains("..") || rel.contains("//") {
            return Response::text(403, "forbidden");
        }
        let full = dir.join(rel);
        match std::fs::read(&full) {
            Ok(data) => Response::bytes(200, "application/octet-stream", data),
            Err(_) => Response::text(404, "not found"),
        }
    })
    .map_err(Error::from)
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let dir = PathBuf::from(cli.value_or("dir", "/var/lib/namikaze/mirror"));
    if !dir.is_dir() {
        return Err(Error::Other(format!("mirror dir missing: {}", dir.display())));
    }
    match cli.sub().unwrap_or_default() {
        "index" => cmd_index(&dir),
        "serve" => {
            let addr = cli.value_or("addr", "127.0.0.1");
            let port: u16 = cli.value_parse("port").ok().flatten().unwrap_or(8901);
            serve(dir, addr, port)
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
}
