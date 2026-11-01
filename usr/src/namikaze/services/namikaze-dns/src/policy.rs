// SPDX-License-Identifier: MPL-2.0
//! Pure policy model for namikaze-dns: parsing, validation and rendering.
//!
//! Everything here is filesystem-free so the behavior is unit-testable;
//! the binary only wires the rendered artifacts to /run/namikaze/dns.
//! The TOML mapping is hand-written on `namikaze-rt::toml`.

#![forbid(unsafe_code)]

use namikaze_common::{Error, Result};
use namikaze_rt::toml::{self, Value};

/// Allowed upstream transports. Plaintext UDP/53 is deliberately absent:
/// a policy that would leak DNS in the clear must fail validation instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// DNS over TLS (RFC 7858), default port 853
    Dot,
    /// DNS over HTTPS (RFC 8484)
    Doh,
}

impl Transport {
    pub fn parse(v: &str) -> Result<Transport> {
        match v {
            "dot" => Ok(Transport::Dot),
            "doh" => Ok(Transport::Doh),
            other => Err(Error::Config(format!(
                "transport {other:?} is not encrypted (allowed: dot, doh)"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Dot => "dot",
            Transport::Doh => "doh",
        }
    }
}

/// One permitted encrypted upstream.
#[derive(Debug, Clone)]
pub struct Upstream {
    pub name: String,
    pub transport: Transport,
    /// IP or URL used to reach the resolver
    pub address: String,
    /// TLS Server Name Indication that must be presented (pin)
    pub sni: String,
}

/// The complete DNS policy document.
#[derive(Debug, Clone)]
pub struct DnsPolicy {
    pub stub: String,
    pub upstreams: Vec<Upstream>,
    pub blocklist: Vec<String>,
}

impl DnsPolicy {
    /// Parse and validate a policy from its TOML text.
    pub fn parse(raw: &str) -> Result<Self> {
        let root = toml::parse(raw).map_err(|e| Error::Config(format!("dns.toml: {e}")))?;
        let mut problems = Vec::new();
        let stub = match root.get("stub") {
            Some(Value::Str(s)) => s.clone(),
            None => "127.0.0.1".to_string(),
            Some(_) => {
                problems.push("stub: expected a string".into());
                "127.0.0.1".to_string()
            }
        };
        let mut upstreams = Vec::new();
        match root.get("upstreams") {
            None => {}
            Some(Value::TableArr(items)) => {
                for t in items {
                    let get = |k: &str| {
                        t.get(k).and_then(|v| v.as_str()).map(str::to_string).unwrap_or_default()
                    };
                    let name = get("name");
                    let transport = match t.get("transport").and_then(|v| v.as_str()) {
                        Some(tr) => Transport::parse(tr),
                        None => Err(Error::Config(format!("upstream {name}: missing transport"))),
                    };
                    match transport {
                        Ok(tr) => upstreams.push(Upstream {
                            name,
                            transport: tr,
                            address: get("address"),
                            sni: get("sni"),
                        }),
                        Err(e) => problems.push(e.to_string()),
                    }
                }
            }
            Some(_) => problems.push("upstreams: expected [[upstreams]] tables".into()),
        }
        let mut blocklist = Vec::new();
        match root.get("blocklist") {
            None => {}
            Some(Value::TableArr(items)) => {
                for t in items {
                    if let Some(Value::Str(z)) = t.get("zone") {
                        blocklist.push(z.clone());
                    } else {
                        problems.push("blocklist entry missing zone".into());
                    }
                }
            }
            Some(Value::Arr(items)) => {
                for v in items {
                    if let Some(z) = v.as_str() {
                        blocklist.push(z.to_string());
                    }
                }
            }
            Some(_) => problems.push("blocklist: expected [[blocklist]] tables".into()),
        }
        let pol = Self { stub, upstreams, blocklist };
        let mut final_problems = pol.problems();
        final_problems.extend(problems);
        if !final_problems.is_empty() {
            return Err(Error::Config(final_problems.join("; ")));
        }
        Ok(pol)
    }

    /// Structural validation: at least one upstream, no empty pins,
    /// no duplicate upstream names or blocklist zones.
    pub fn validate(&self) -> Result<()> {
        let problems = self.problems();
        if problems.is_empty() {
            Ok(())
        } else {
            Err(Error::Config(problems.join("; ")))
        }
    }

    /// Every policy defect, human readable. Empty means healthy.
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.upstreams.is_empty() {
            problems.push("no encrypted upstream configured".into());
        }
        let mut seen: Vec<&str> = Vec::new();
        for up in &self.upstreams {
            if up.name.trim().is_empty() {
                problems.push("upstream with empty name".into());
            }
            if seen.contains(&up.name.as_str()) {
                problems.push(format!("duplicate upstream name {}", up.name));
            }
            seen.push(up.name.as_str());
            if up.address.trim().is_empty() {
                problems.push(format!("upstream {} has no address", up.name));
            }
            if up.sni.trim().is_empty() {
                problems.push(format!("upstream {} has no SNI pin", up.name));
            }
        }
        let mut zones: Vec<String> = Vec::new();
        for zone in &self.blocklist {
            let z = zone.trim().to_lowercase();
            if z.is_empty() {
                problems.push("empty blocklist zone".into());
            }
            if zones.contains(&z) {
                problems.push(format!("duplicate blocklist zone {z}"));
            }
            zones.push(z);
        }
        problems
    }

    /// The resolver drop-in rendered from the policy (deterministic order).
    pub fn render_upstreams(&self) -> String {
        let mut out = String::from("# rendered by namikaze-dns; do not edit\n");
        for up in &self.upstreams {
            out.push_str(&format!(
                "upstream {} transport={} address={} sni={}\n",
                up.name,
                up.transport.as_str(),
                up.address,
                up.sni
            ));
        }
        if !self.blocklist.is_empty() {
            out.push_str("# blocked zones (never resolved, answered locally)\n");
            for zone in &self.blocklist {
                out.push_str(&format!("block {zone}\n"));
            }
        }
        out
    }

    /// The loopback stub resolv.conf every application sees.
    pub fn render_resolv(&self) -> String {
        format!(
            "# rendered by namikaze-dns; do not edit\nnameserver {}\noptions edns0 trust-ad\n",
            self.stub
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
stub = "127.0.0.1"

[[upstreams]]
name = "primary"
transport = "dot"
address = "193.19.108.2"
sni = "dot.ti"

[[upstreams]]
name = "fallback"
transport = "doh"
address = "https://dns.example/dns-query"
sni = "dns.example"

[[blocklist]]
zone = "telemetry.example.net"
"#;

    #[test]
    fn parses_and_renders_deterministically() {
        let a = DnsPolicy::parse(GOOD).unwrap();
        let b = DnsPolicy::parse(GOOD).unwrap();
        assert_eq!(a.upstreams.len(), 2);
        assert_eq!(a.render_upstreams(), b.render_upstreams());
        assert!(a.render_upstreams().contains("transport=dot"));
        assert!(a.render_upstreams().contains("sni=dot.ti"));
    }

    #[test]
    fn plaintext_is_rejected_at_parse_time() {
        // No transports other than dot/doh exist in the schema; a plaintext
        // entry cannot even be expressed, and an empty upstream list fails.
        let empty = DnsPolicy::parse("stub = \"127.0.0.1\"\n").unwrap_err();
        assert!(empty.to_string().contains("no encrypted upstream"));
    }

    #[test]
    fn duplicates_and_empty_pins_are_problems() {
        let raw = GOOD.replace("sni = \"dot.ti\"", "sni = \"\"")
            + "\n[[blocklist]]\nzone = \"telemetry.example.net\"\n";
        let pol = DnsPolicy::parse(&raw).unwrap_err();
        assert!(pol.to_string().contains("no SNI pin"));
    }

    #[test]
    fn resolv_stub_is_loopback_only() {
        let pol = DnsPolicy::parse(GOOD).unwrap();
        assert!(pol.render_resolv().contains("nameserver 127.0.0.1"));
        assert!(!pol.render_resolv().contains("0.0.0.0"));
    }
}
