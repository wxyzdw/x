// SPDX-License-Identifier: MPL-2.0
//! namikaze-macspin: MAC address randomization for anonymity.
//!
//! Generates locally-administered, unicast MACs (bit 1 of the first octet
//! set, bit 0 clear) and applies them via `ip link set dev X address ...`.
//! --print mode is the safe default for scripts; --apply requires root.
//! Interface names containing dots (VLAN notation) are handled verbatim.

#![forbid(unsafe_code)]

use std::process::Command;

use namikaze_common::{init_tracing, Error, Result};
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-macspin: per-boot MAC randomization",
    "",
    "usage:",
    "  namikaze-macspin print [--iface NAME]    print a plan (default)",
    "  namikaze-macspin apply [--iface NAME]    apply with ip(8) (root)",
];

fn random_mac() -> Result<String> {
    let mut b = [0u8; 6];
    namikaze_rt::random::fill(&mut b)?;
    b[0] = (b[0] & 0xFC) | 0x02; // locally administered, unicast
    Ok(b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":"))
}

fn physical_interfaces() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else { return vec![] };
    entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n != "lo")
        .collect()
}

fn current_mac(iface: &str) -> String {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() {
        cli.usage_exit(USAGE);
    }
    let ifaces: Vec<String> = match cli.value("iface") {
        Some(name) => vec![name],
        None => physical_interfaces(),
    };
    let mode = cli.sub().unwrap_or("print");
    if !matches!(mode, "print" | "apply") {
        eprintln!("unknown subcommand: {mode}");
        cli.usage_exit(USAGE);
    }
    let mut plan = Vec::new();
    for iface in ifaces {
        plan.push((iface.clone(), random_mac()?));
    }
    for (iface, mac) in &plan {
        println!("{iface}: {} -> {mac}", current_mac(iface));
    }
    if mode == "apply" {
        for (iface, mac) in &plan {
            let down = Command::new("/usr/sbin/ip")
                .args(["link", "set", "dev", iface, "down"])
                .status();
            let set = Command::new("/usr/sbin/ip")
                .args(["link", "set", "dev", iface, "address", mac])
                .status();
            let up = Command::new("/usr/sbin/ip")
                .args(["link", "set", "dev", iface, "up"])
                .status();
            let ok = down.map(|s| s.success()).unwrap_or(false)
                && set.map(|s| s.success()).unwrap_or(false)
                && up.map(|s| s.success()).unwrap_or(false);
            if !ok {
                return Err(Error::Other(format!("failed to spin {iface}")));
            }
        }
        println!("applied to {} interface(s)", plan.len());
    } else {
        println!("(print mode: nothing applied)");
    }
    Ok(())
}
