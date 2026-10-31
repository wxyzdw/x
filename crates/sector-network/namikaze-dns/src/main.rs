// SPDX-License-Identifier: MPL-2.0
//! namikaze-dns: encrypted DNS policy and resolver configuration.
//!
//! The system never sends plaintext DNS to random resolvers. One TOML
//! policy file describes the only upstreams allowed (DNS over TLS / DNS
//! over HTTPS), their Server Name Indication pin and the tracker zones
//! that must never resolve. `apply` renders the resolver-facing artifacts
//! from that policy:
//!   - /run/namikaze/dns/resolv.conf      (127.0.0.1 loopback stub)
//!   - /run/namikaze/dns/upstreams.conf   (resolver drop-in, rendered)
//! and refuses to emit anything when the policy would leak plaintext DNS.

#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use namikaze_common::{init_tracing, Result, ETC_DIR, RUN_DIR};
use namikaze_rt::args::Cli;

pub mod policy;

use policy::DnsPolicy;

const USAGE: &[&str] = &[
    "namikaze-dns: encrypted-DNS policy engine (DoT/DoH, plaintext rejected)",
    "",
    "usage:",
    "  namikaze-dns plan     [--policy /etc/namikaze/dns.toml]   render, no writes",
    "  namikaze-dns apply    [--policy ...]   write artifacts under /run/namikaze/dns",
    "  namikaze-dns doctor   [--policy ...]   validate and report",
];

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let policy_path = cli.value_or("policy", &format!("{ETC_DIR}/dns.toml"));
    let raw = fs::read_to_string(&policy_path)
        .map_err(|e| namikaze_common::Error::Config(format!("{}: {e}", policy_path)))?;
    let pol = DnsPolicy::parse(&raw)?;

    match cli.sub().unwrap_or_default() {
        "plan" => {
            println!("{}", pol.render_upstreams());
            println!("resolv.conf:\n{}", pol.render_resolv());
        }
        "apply" => {
            let dir = Path::new(RUN_DIR).join("dns");
            fs::create_dir_all(&dir)?;
            fs::write(dir.join("upstreams.conf"), pol.render_upstreams())?;
            fs::write(dir.join("resolv.conf"), pol.render_resolv())?;
            println!(
                "applied: {} upstream(s), {} blocked zone(s) -> {}",
                pol.upstreams.len(),
                pol.blocklist.len(),
                dir.display()
            );
        }
        "doctor" => {
            let problems = pol.problems();
            if problems.is_empty() {
                println!(
                    "dns policy: healthy ({} upstream(s), {} blocked zone(s))",
                    pol.upstreams.len(),
                    pol.blocklist.len()
                );
            } else {
                for p in &problems {
                    eprintln!("PROBLEM {p}");
                }
                std::process::exit(1);
            }
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
