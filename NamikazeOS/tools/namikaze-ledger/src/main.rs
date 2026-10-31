// SPDX-License-Identifier: MPL-2.0
//! namikaze-ledger: tamper-evident audit trail.
//!
//! Security-relevant events (persist volume opens, LUKS rekeys, policy
//! changes, updates applied) are appended to a JSONL file in which every
//! record carries the SHA-256 of the previous record, forming a hash chain.
//! Any later edit, deletion or reordering breaks the chain and `verify`
//! reports the exact record number where the history diverges. The ledger
//! is privacy-first: it records events and coarse facts, never passphrases,
//! keystrokes or file contents. Writes are single-writer by convention; the
//! file lives under /var/lib/namikaze with 0600 semantics managed by tmpfiles.

#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use namikaze_common::{init_tracing, Result};
use namikaze_rt::args::Cli;

pub mod chain;

use chain::Ledger;

const USAGE: &[&str] = &[
    "namikaze-ledger: append-only hash chain of system events",
    "",
    "usage:",
    "  namikaze-ledger --file PATH append <kind> [fact]",
    "  namikaze-ledger --file PATH verify",
    "  namikaze-ledger --file PATH show [--last N]",
];

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let file_arg = cli.value_or("file", "/var/lib/namikaze/ledger.jsonl");
    let path = Path::new(&file_arg);

    match cli.sub().unwrap_or_default() {
        "append" => {
            let free = cli.free(&[]);
            let kind = free.get(1).cloned().unwrap_or_default();
            let fact = free.get(2).cloned().unwrap_or_default();
            let raw = fs::read_to_string(path).unwrap_or_default();
            let records = Ledger::parse_text(&raw);
            // Appending onto a broken history would legitimize the tampering.
            if let Err(e) = Ledger::verify_text(&raw) {
                return Err(namikaze_common::Error::Other(format!(
                    "refusing to append: chain broken at record {}",
                    e.seq()
                )));
            }
            let seq = records.len() + 1;
            let prev = records.last().map(|r| r.hash.clone()).unwrap_or_else(|| "0".repeat(64));
            let record = chain::Record {
                seq,
                kind: kind.clone(),
                fact: fact.clone(),
                hash: chain::record_hash(seq, &kind, &fact, &prev),
                prev,
            };
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = OpenOptions::new().create(true).append(true).open(path)?;
            writeln!(file, "{}", chain::record_to_json(&record))?;
            file.sync_all()?;
            println!("appended record {} ({kind})", record.seq);
        }
        "verify" => {
            let raw = fs::read_to_string(path)
                .map_err(|e| namikaze_common::Error::Other(format!("{}: {e}", path.display())))?;
            match Ledger::verify_text(&raw) {
                Ok(count) => println!("ledger intact: {count} record(s)"),
                Err(e) => {
                    println!("BROKEN record {}: {}", e.seq(), e.reason());
                    std::process::exit(2);
                }
            }
        }
        "show" => {
            let last: usize = cli.value_parse("last").ok().flatten().unwrap_or(20);
            let raw = fs::read_to_string(path)
                .map_err(|e| namikaze_common::Error::Other(format!("{}: {e}", path.display())))?;
            let records = Ledger::parse_text(&raw);
            let skip = records.len().saturating_sub(last);
            for r in &records[skip..] {
                println!("{:>4}  {}  {}  {}", r.seq, r.kind, r.fact, &r.hash[..16]);
            }
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
