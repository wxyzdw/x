// SPDX-License-Identifier: MPL-2.0
//! namikaze-ntp: SNTPv4 client (RFC 4330) over UDP with no dependencies.
//!
//! Queries a pool of servers, validates the response (li, version, mode,
//! stratum, kiss-of-death codes) and reports the clock offset. Stepping the
//! system clock is intentionally out of scope for the daemon default: the
//! offset is published to /run/namikaze/ntp for the tune service to apply
//! via `date`-free kernel calls when running as root.

#![forbid(unsafe_code)]

use std::net::UdpSocket;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use namikaze_common::{Error, Result};
use namikaze_rt::args::Cli;

/// NTP era offset: seconds between 1900 (NTP epoch) and 1970.
const NTP_ERA_OFFSET: u64 = 2_208_988_800;

/// The 48-byte SNTP packet.
#[derive(Debug, Clone, Copy)]
pub struct SntpPacket(pub [u8; 48]);

impl SntpPacket {
    /// A client request: LI=0, VN=4, Mode=3.
    pub fn request() -> Self {
        let mut p = [0u8; 48];
        p[0] = 0b00_100_011;
        Self(p)
    }

    pub fn li(&self) -> u8 {
        self.0[0] >> 6
    }

    pub fn version(&self) -> u8 {
        (self.0[0] >> 3) & 0b111
    }

    pub fn mode(&self) -> u8 {
        self.0[0] & 0b111
    }

    pub fn stratum(&self) -> u8 {
        self.0[1]
    }

    /// NTP timestamp at bytes 40..48 (server transmit time).
    pub fn transmit_ts(&self) -> u64 {
        let mut v = [0u8; 8];
        v.copy_from_slice(&self.0[40..48]);
        u64::from_be_bytes(v)
    }

    /// Reference id (kiss-of-death code when stratum == 0).
    pub fn reference_id(&self) -> [u8; 4] {
        [self.0[12], self.0[13], self.0[14], self.0[15]]
    }
}

/// The measurement produced by one exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measurement {
    /// Server clock minus local clock, in seconds (positive = we are behind).
    pub offset_secs: i64,
    /// Round-trip time in milliseconds.
    pub rtt_ms: u32,
    pub stratum: u8,
}

/// Validate an SNTP response per RFC 4330 sanity rules.
pub fn validate(resp: &SntpPacket) -> Result<()> {
    if resp.mode() != 4 {
        return Err(Error::Other(format!("not a server reply (mode {})", resp.mode())));
    }
    if resp.version() != 4 {
        return Err(Error::Other(format!("unexpected version {}", resp.version())));
    }
    if resp.stratum() == 0 {
        let kod: String = resp
            .reference_id()
            .iter()
            .map(|b| *b as char)
            .collect();
        return Err(Error::Other(format!("kiss of death: {kod}")));
    }
    if resp.li() == 3 {
        return Err(Error::Other("server not synchronized (li=3)".into()));
    }
    Ok(())
}

/// One request/response exchange against `server:123` (or custom port).
pub fn query(server: &str, timeout: Duration) -> Result<Measurement> {
    let addr = if server.contains(':') {
        server.to_string()
    } else {
        format!("{server}:123")
    };
    let socket = UdpSocket::bind(if ipv6_target(&addr) { "[::]:0" } else { "0.0.0.0:0" })?;
    socket.set_read_timeout(Some(timeout))?;
    socket.connect(&addr)?;

    let req = SntpPacket::request();
    let t1 = Instant::now();
    socket.send(&req.0)?;
    let mut buf = [0u8; 48];
    let (n, _) = socket
        .recv_from(&mut buf)
        .map_err(|e| Error::Other(format!("ntp reply: {e}")))?;
    let t4 = t1.elapsed();
    if n < 48 {
        return Err(Error::Other("short ntp reply".into()));
    }
    let resp = SntpPacket(buf);
    validate(&resp)?;

    let local_recv = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let server_ts = resp.transmit_ts() >> 32; // whole seconds
    let server_secs = server_ts as i64 - NTP_ERA_OFFSET as i64;
    let local_secs = local_recv as i64;
    Ok(Measurement {
        offset_secs: server_secs - local_secs,
        rtt_ms: t4.as_millis().min(u32::MAX as u128) as u32,
        stratum: resp.stratum(),
    })
}

fn ipv6_target(addr: &str) -> bool {
    addr.rsplit(':').next().map(|h| h.contains(':')).unwrap_or(false)
        || addr.starts_with('[')
}

/// Best measurement across a server list; first success wins with the
/// smallest RTT recorded.
pub fn measure_best(servers: &[&str], timeout: Duration) -> Result<Measurement> {
    let mut best: Option<Measurement> = None;
    let mut last_err = None;
    for s in servers {
        match query(s, timeout) {
            Ok(m) => {
                if best.map(|b: Measurement| m.rtt_ms < b.rtt_ms).unwrap_or(true) {
                    best = Some(m);
                }
            }
            Err(e) => last_err = Some(e),
        }
        if best.is_some() {
            break;
        }
    }
    best.ok_or_else(|| {
        last_err.unwrap_or_else(|| Error::Other("no ntp servers configured".into()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_packet_shape() {
        let p = SntpPacket::request();
        assert_eq!(p.li(), 0);
        assert_eq!(p.version(), 4);
        assert_eq!(p.mode(), 3);
        assert_eq!(p.0.len(), 48);
    }

    #[test]
    fn validate_rejects_kod() {
        let mut p = SntpPacket::request();
        p.0[0] = 0b00_100_100; // mode 4 (server)
        p.0[1] = 0; // stratum 0
        p.0[12..16].copy_from_slice(b"RATE");
        let err = validate(&p).unwrap_err();
        assert!(err.to_string().contains("RATE"));
    }

    #[test]
    fn validate_accepts_server() {
        let mut p = SntpPacket::request();
        p.0[0] = 0b00_100_100; // mode 4
        p.0[1] = 2; // stratum 2
        assert!(validate(&p).is_ok());
    }

    #[test]
    fn era_offset_is_correct() {
        // 1900-01-01T00:00:00Z == unix -2208988800
        assert_eq!(NTP_ERA_OFFSET, 2_208_988_800);
    }
}

const USAGE: &[&str] = &[
    "namikaze-ntp: SNTPv4 time sync client",
    "",
    "usage:",
    "  namikaze-ntp query [--server HOST]...       one measurement per server",
    "  namikaze-ntp daemon [--server HOST]... [--interval SECS] [--file PATH]",
    "",
    "default servers: pool servers under /etc/namikaze/ntp.toml or pool.ntp.org",
];

fn main() {
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let mut servers: Vec<String> = cli.free(&[]).into_iter().skip(1).collect();
    if servers.is_empty() {
        servers = vec![
            "0.pool.ntp.org".into(),
            "1.pool.ntp.org".into(),
            "2.pool.ntp.org".into(),
        ];
    }
    let refs: Vec<&str> = servers.iter().map(String::as_str).collect();
    match cli.sub().unwrap_or_default() {
        "query" => match measure_best(&refs, std::time::Duration::from_secs(5)) {
            Ok(m) => {
                println!(
                    "offset={}s rtt={}ms stratum={}",
                    m.offset_secs, m.rtt_ms, m.stratum
                );
            }
            Err(e) => {
                eprintln!("namikaze-ntp: {e}");
                std::process::exit(1);
            }
        },
        "daemon" => {
            let interval = cli.value_parse::<u64>("interval").ok().flatten().unwrap_or(600);
            let file = cli.value_or("file", "/run/namikaze/ntp/offset.json");
            loop {
                if let Ok(m) = measure_best(&refs, std::time::Duration::from_secs(5)) {
                    let v = namikaze_rt::json::obj(&[
                        ("ts", namikaze_rt::json::Value::Int(now_secs())),
                        ("offset_secs", namikaze_rt::json::Value::Int(m.offset_secs)),
                        ("rtt_ms", namikaze_rt::json::Value::Int(m.rtt_ms as i64)),
                        ("stratum", namikaze_rt::json::Value::Int(m.stratum as i64)),
                    ]);
                    if let Some(parent) = std::path::Path::new(&file).parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::write(&file, v.to_compact());
                    namikaze_rt::log_info!("ntp offset {}s rtt {}ms", m.offset_secs, m.rtt_ms);
                }
                std::thread::sleep(std::time::Duration::from_secs(interval));
            }
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
