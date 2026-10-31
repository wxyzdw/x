// SPDX-License-Identifier: MPL-2.0
//! namikaze-anon CLI: status | newnym | onion | close.

#![forbid(unsafe_code)]

use namikaze_common::{init_tracing, Result};
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-anon: Tor status and onion services",
    "",
    "usage:",
    "  namikaze-anon status                    print Tor readiness",
    "  namikaze-anon newnym                    request a fresh circuit",
    "  namikaze-anon onion --target HOST:PORT [--port 80]",
];

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let mut tor = namikaze_anon::connect_authenticated()?;
    match cli.sub().unwrap_or_default() {
        "status" => {
            let ver = tor.get_info("version").unwrap_or_else(|_| "?".into());
            let circ = tor
                .get_info("status/circuit-established")
                .unwrap_or_else(|_| "0".into());
            println!("tor version:            {ver}");
            println!("circuit established:    {circ}");
        }
        "newnym" => {
            tor.signal("NEWNYM")?;
            println!("new circuit requested");
        }
        "onion" => {
            let target = cli
                .value("target")
                .ok_or_else(|| namikaze_common::Error::Other("missing --target HOST:PORT".into()))?;
            let port: u16 = cli.value_parse("port").ok().flatten().unwrap_or(80);
            let id = tor.add_onion(port, &target)?;
            println!("onion service active: {id}.onion:{port} -> {target}");
            println!("this service is ephemeral: it disappears when the process exits");
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
