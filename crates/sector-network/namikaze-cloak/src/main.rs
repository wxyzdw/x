// SPDX-License-Identifier: MPL-2.0
//! namikaze-cloak: identity randomization.
//!
//! - Random, locally-administered MAC per interface (ip link set address)
//! - Random hostname per boot (word pairs + hex suffix)
//! - Ephemeral machine-id (fresh random 32 hex chars every boot)
//!
//! Randomization happens per boot, never persisted: a persistent system can
//! still be anonymous at the identity layer.

#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;
use std::process::Command;

use namikaze_common::{init_tracing, Result};
use namikaze_rt::args::Cli;

const ADJECTIVES: &[&str] = &[
    "swift", "calm", "bold", "quiet", "amber", "north", "east", "storm",
    "river", "cedar", "iron", "glass", "fern", "salt", "dawn", "dusk",
];
const NOUNS: &[&str] = &[
    "otter", "falcon", "maple", "harbor", "meadow", "canyon", "willow",
    "granite", "copper", "juniper", "lantern", "beacon", "tundra", "basalt",
];

const USAGE: &[&str] = &[
    "namikaze-cloak: randomize identity leaks (MAC, hostname, machine-id)",
    "",
    "usage:",
    "  namikaze-cloak apply       randomize everything",
    "  namikaze-cloak mac         randomize MAC addresses only",
    "  namikaze-cloak hostname    randomize hostname only",
    "  namikaze-cloak machine-id  refresh machine-id only",
];

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    namikaze_rt::random::fill(&mut buf).expect("system rng");
    buf
}

/// Generate a locally-administered, unicast MAC.
fn random_mac() -> String {
    let mut b = random_bytes(6);
    b[0] = (b[0] & 0xFC) | 0x02;
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")
}

fn physical_interfaces() -> Vec<String> {
    let Ok(entries) = fs::read_dir("/sys/class/net") else { return vec![] };
    entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n != "lo")
        .collect()
}

fn run_mac() {
    for iface in physical_interfaces() {
        let mac = random_mac();
        let status = Command::new("/sbin/ip")
            .args(["link", "set", "dev", &iface, "address", &mac])
            .status();
        match status {
            Ok(s) if s.success() => println!("mac {iface} -> {mac}"),
            _ => println!("mac {iface} -> FAILED (interface busy?)"),
        }
    }
}

fn run_hostname() -> Result<()> {
    let a = ADJECTIVES[(random_bytes(1)[0] as usize) % ADJECTIVES.len()];
    let n = NOUNS[(random_bytes(1)[0] as usize) % NOUNS.len()];
    let hex: String = random_bytes(2).iter().map(|x| format!("{x:02x}")).collect();
    let host = format!("{a}-{n}-{hex}");
    std::fs::write("/proc/sys/kernel/hostname", format!("{host}\n"))
        .map_err(|e| namikaze_common::Error::Other(format!("sethostname: {e}")))?;
    println!("hostname -> {host}");
    Ok(())
}

fn run_machine_id() -> Result<()> {
    let id: String = random_bytes(16).iter().map(|x| format!("{x:02x}")).collect();
    let target = Path::new("/etc/machine-id");
    if !Path::new("/etc").exists() {
        return Ok(());
    }
    fs::write(target, id + "\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(target, fs::Permissions::from_mode(0o0444))?;
    }
    println!("machine-id refreshed (ephemeral)");
    Ok(())
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    match cli.sub().unwrap_or_default() {
        "apply" => {
            run_mac();
            run_hostname()?;
            run_machine_id()?;
        }
        "mac" => run_mac(),
        "hostname" => run_hostname()?,
        "machine-id" => run_machine_id()?,
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
