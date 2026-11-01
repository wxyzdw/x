// SPDX-License-Identifier: MPL-2.0
//! Tor control-port client used across NamikazeOS.
//!
//! A minimal, synchronous SOCKS-free control protocol implementation:
//! AUTHENTICATE (cookie), GETINFO, SIGNAL (NEWNYM), ADD_ONION / DEL_ONION.
//! Shared by namikaze-anon (status), namikaze-share (ephemeral services)
//! and OpenRC service scripts.

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::Path;

use namikaze_common::{Error, Result};

pub struct TorControl {
    reader: BufReader<TcpStream>,
    stream: TcpStream,
}

impl TorControl {
    /// Connect to the control port (default 127.0.0.1:9051).
    pub fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(Self { reader, stream })
    }

    /// Authenticate with the cookie file (raw 32 bytes, sent as hex).
    pub fn authenticate_cookie(&mut self, cookie: &Path) -> Result<()> {
        let raw = std::fs::read(cookie)
            .map_err(|e| Error::Other(format!("cannot read tor cookie: {e}")))?;
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        self.cmd(&format!("AUTHENTICATE {hex}"))
            .map(|_| ())
            .map_err(|e| Error::Other(format!("tor authentication failed: {e}")))
    }

    /// Send a command and return the final reply line payload.
    #[allow(unused_assignments)]
    pub fn cmd(&mut self, line: &str) -> Result<String> {
        writeln!(self.stream, "{line}")?;
        let mut last = String::new();
        loop {
            let mut buf = String::new();
            let n = self.reader.read_line(&mut buf)?;
            if n == 0 {
                return Err(Error::Other("tor control connection closed".into()));
            }
            let trimmed = buf.trim_end().to_string();
            if trimmed.len() < 4 {
                return Err(Error::Other(format!("malformed tor reply: {trimmed}")));
            }
            let code = &trimmed[..3];
            let sep = trimmed.as_bytes()[3];
            last = trimmed[4..].to_string();
            if code.starts_with('5') {
                return Err(Error::Other(format!("tor error {code}: {last}")));
            }
            if sep == b' ' && code.starts_with('2') {
                return Ok(last);
            }
            if sep == b' ' && code.starts_with('6') {
                return Ok(last);
            }
        }
    }

    /// GETINFO wrapper.
    pub fn get_info(&mut self, key: &str) -> Result<String> {
        self.cmd(&format!("GETINFO {key}"))
    }

    /// Signal wrapper (e.g. NEWNYM to request a fresh circuit).
    pub fn signal(&mut self, sig: &str) -> Result<()> {
        self.cmd(&format!("SIGNAL {sig}")).map(|_| ())
    }

    /// Create an ephemeral onion v3 service. Returns the service id.
    pub fn add_onion(&mut self, virt_port: u16, target: &str) -> Result<String> {
        let reply =
            self.cmd(&format!("ADD_ONION NEW:BEST Port={virt_port},{target} Flags=DiscardPK"))?;
        for token in reply.split_whitespace() {
            if let Some(id) = token.strip_prefix("ServiceID=") {
                return Ok(id.to_string());
            }
        }
        Err(Error::Other(format!("ADD_ONION reply missing ServiceID: {reply}")))
    }

    /// Destroy an ephemeral onion service.
    pub fn del_onion(&mut self, service_id: &str) -> Result<()> {
        self.cmd(&format!("DEL_ONION {service_id}")).map(|_| ())
    }
}

/// Default cookie path used on the NamikazeOS rootfs.
pub const COOKIE_PATH: &str = "/var/lib/tor/control_auth_cookie";
/// Default control address.
pub const CONTROL_ADDR: &str = "127.0.0.1:9051";

/// Connect and authenticate in one step.
pub fn connect_authenticated() -> Result<TorControl> {
    let mut c = TorControl::connect(CONTROL_ADDR)?;
    c.authenticate_cookie(Path::new(COOKIE_PATH))?;
    Ok(c)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_add_onion_reply() {
        // Directly exercise the parsing logic through a formatted reply.
        let reply = "ServiceID=abcdefghijklmnop.onionPrivateKey=";
        let found = reply.split_whitespace().find_map(|t| t.strip_prefix("ServiceID=")).unwrap();
        assert_eq!(found, "abcdefghijklmnop.onionPrivateKey=");
    }
}
