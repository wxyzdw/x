// SPDX-License-Identifier: MPL-2.0
//! namikaze-guard: nftables policy engine.
//!
//! Generates and applies the NamikazeOS firewall:
//!   - input: loopback + established accepted, everything else dropped
//!   - forward: dropped
//!   - output: default-drop; Tor daemon (uid) may open circuits; everything
//!     from other users is transparently redirected into the Tor ports;
//!     DNS is force-redirected into the Tor DNS port. The result is a
//!     kernel-enforced kill switch: no process can bypass Tor.
//!
//! This crate only emits and applies nftables text; it never mutates state
//! outside /run/namikaze and the nftables kernel tables.

#![forbid(unsafe_code)]

use std::path::Path;
use std::process::Command;

use namikaze_common::{Error, Result};
use namikaze_rt::log_info;

/// Runtime parameters for the ruleset.
#[derive(Debug, Clone)]
pub struct GuardParams {
    /// Tor daemon UID (resolved from the passwd database)
    pub tor_uid: u32,
    /// Tor TransPort
    pub trans_port: u16,
    /// Tor DNSPort
    pub dns_port: u16,
    /// Whether non-Tor egress is hard-blocked after redirection
    pub kill_switch: bool,
}

/// Resolve a user's uid from /etc/passwd (no nix/libc user database).
pub fn uid_of(user: &str) -> Result<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd")
        .map_err(|e| Error::Other(format!("cannot read /etc/passwd: {e}")))?;
    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 && fields[0] == user {
            return fields[2].parse().map_err(|e| Error::Other(format!("bad uid for {user}: {e}")));
        }
    }
    Err(Error::Other(format!("user {user} not found")))
}

impl GuardParams {
    pub fn resolve(
        tor_user: &str,
        trans_port: u16,
        dns_port: u16,
        kill_switch: bool,
    ) -> Result<Self> {
        let tor_uid = uid_of(tor_user)?;
        Ok(Self { tor_uid, trans_port, dns_port, kill_switch })
    }
}

/// Build the full nftables ruleset text.
pub fn build_ruleset(p: &GuardParams) -> String {
    let kill = if p.kill_switch { "drop" } else { "accept" };
    format!(
        r#"#!/usr/sbin/nft -f
# NamikazeOS guard ruleset (generated; do not edit)
add table inet namikaze
delete table inet namikaze

table inet namikaze {{
    chain input {{
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept
    }}

    chain forward {{
        type filter hook forward priority 0; policy drop;
    }}

    chain output {{
        type filter hook output priority 0; policy {kill};
        oif "lo" accept
        ct state established,related accept

        # Tor daemon may open circuits directly
        meta skuid {tor_uid} accept

        # Force DNS into the Tor DNS port
        meta skuid != {tor_uid} udp dport 53 redirect to :{dns_port}
        meta skuid != {tor_uid} tcp dport 53 redirect to :{dns_port}

        # Transparently proxy all other traffic into Tor
        meta skuid != {tor_uid} tcp dport {{ 80, 443 }} redirect to :{trans_port}
        meta skuid != {tor_uid} udp dport {{ 80, 443 }} redirect to :{trans_port}

        # Kill switch: nothing else leaves the machine
        meta skuid != {tor_uid} drop
    }}
}}
"#,
        tor_uid = p.tor_uid,
        dns_port = p.dns_port,
        trans_port = p.trans_port,
        kill = kill,
    )
}

/// Write the ruleset to the runtime directory (returns the file path).
pub fn write_ruleset(p: &GuardParams) -> Result<std::path::PathBuf> {
    let path = std::path::Path::new(namikaze_common::RUN_DIR).join("guard.nft");
    std::fs::create_dir_all(std::path::Path::new(namikaze_common::RUN_DIR))?;
    std::fs::write(&path, build_ruleset(p))?;
    Ok(path)
}

/// Apply the ruleset with nft(8).
pub fn apply(p: &GuardParams) -> Result<()> {
    let path = write_ruleset(p)?;
    let status = Command::new("/usr/sbin/nft").arg("-f").arg(&path).status()?;
    if !status.success() {
        return Err(Error::Other("nft -f failed".into()));
    }
    log_info!("guard ruleset applied");
    Ok(())
}

/// Verify the ruleset parses without applying it.
pub fn check(p: &GuardParams) -> Result<()> {
    let path = write_ruleset(p)?;
    let status = Command::new("/usr/sbin/nft").args(["-c", "-f"]).arg(&path).status()?;
    if !status.success() {
        return Err(Error::Other("nft check failed".into()));
    }
    println!("ruleset OK: {}", Path::new(&path).display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> GuardParams {
        GuardParams { tor_uid: 27, trans_port: 9040, dns_port: 5353, kill_switch: true }
    }

    #[test]
    fn ruleset_has_default_drop_and_redirects() {
        let rs = build_ruleset(&params());
        assert!(rs.contains("policy drop;"), "input policy must drop");
        assert!(rs.contains("redirect to :9040"));
        assert!(rs.contains("redirect to :5353"));
        assert!(rs.contains("meta skuid 27 accept"));
    }

    #[test]
    fn kill_switch_toggle() {
        let mut p = params();
        p.kill_switch = false;
        let rs = build_ruleset(&p);
        assert!(rs.contains("policy accept;"));
    }
}
