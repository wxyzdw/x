// SPDX-License-Identifier: MPL-2.0
//! Hiraishin no Jutsu - the Flying Thunder God technique.
//!
//! The one sanctioned way anything leaves its sandbox: the operator
//! **marks** an application in `etc/namikaze/sandbox.allow`, the
//! master switch in `etc/namikaze/sandbox.toml` is armed, and only
//! then does the gate issue a **ticket** - the kunai - an HMAC-SHA256
//! seal over (app, realm, nonce) with the gate key. The launcher
//! verifies the ticket and only then spawns the application with the
//! escalated realm. Anything else - an unmarked app, a tampered
//! ticket, an unknown realm, a disarmed gate - is refused, fail-closed.
//!
//! Realms:
//! - `desktop` - the app may reach the session desktop (wayland
//!   socket, session dbus); it still never sees the host.
//! - `system`  - the app may reach the host directly. This is the
//!   full teleport, reserved for the tools that administer the box.
//!
//! The gate key lives in `etc/namikaze/hiraishin.key` (0600, 32-byte
//! hex); firstboot generates it. Without the key nothing issues and
//! nothing verifies - the technique is inert.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use namikaze_common::{Error, Result};
use namikaze_rt::hmac::hmac_sha256;

/// The realms an application can be marked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Realm {
    /// Session desktop access (wayland socket, session dbus).
    Desktop,
    /// Direct host access. The full teleport.
    System,
}

impl Realm {
    pub fn parse(raw: &str) -> Result<Realm> {
        match raw.trim() {
            "desktop" => Ok(Realm::Desktop),
            "system" => Ok(Realm::System),
            other => {
                Err(Error::Config(format!("hiraishin: unknown realm {other:?} (desktop|system)")))
            }
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Realm::Desktop => "desktop",
            Realm::System => "system",
        }
    }
}

/// The ticket: nonce + HMAC seal. Rendered `"<nonce>.<hex-hmac>"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub app: String,
    pub realm: Realm,
    pub nonce: String,
    pub seal: [u8; 32],
}

fn seal_of(key: &[u8], app: &str, realm: &Realm, nonce: &str) -> [u8; 32] {
    hmac_sha256(key, format!("hiraishin/v1/{app}/{}/{nonce}", realm.name()).as_bytes())
}

impl Ticket {
    /// Issue a ticket for one app+realm with an explicit nonce (the
    /// caller supplies entropy; `random::id_hex` is what production
    /// uses). Refuses nothing here - policy is [`Grants`]'s job.
    pub fn issue(key: &[u8], app: &str, realm: Realm, nonce: &str) -> Ticket {
        Ticket {
            app: app.to_string(),
            realm,
            nonce: nonce.to_string(),
            seal: seal_of(key, app, &realm, nonce),
        }
    }

    /// The ticket text: `"<app>@<realm>/<nonce>.<hex>"`.
    pub fn render(&self) -> String {
        let hex: String = self.seal.iter().map(|b| format!("{b:02x}")).collect();
        format!("{}@{}/{}.{}", self.app, self.realm.name(), self.nonce, hex)
    }

    /// Parse and fully verify a rendered ticket against the gate key.
    /// Tampering with any field breaks the seal.
    pub fn open(key: &[u8], text: &str) -> Result<Ticket> {
        let bad = || Error::Crypto("hiraishin: ticket rejected".into());
        let (head, seal_hex) = text.rsplit_once('.').ok_or_else(bad)?;
        let (app_realm, nonce) = head.split_once('/').ok_or_else(bad)?;
        let (app, realm_raw) = app_realm.split_once('@').ok_or_else(bad)?;
        if app.is_empty() || nonce.is_empty() {
            return Err(bad());
        }
        let realm = Realm::parse(realm_raw)?;
        let mut seal = [0u8; 32];
        if seal_hex.len() != 64 {
            return Err(bad());
        }
        for (i, byte) in seal.as_mut_slice().iter_mut().enumerate() {
            *byte = u8::from_str_radix(&seal_hex[i * 2..i * 2 + 2], 16).map_err(|_| bad())?;
        }
        let ticket = Ticket { app: app.to_string(), realm, nonce: nonce.to_string(), seal };
        if ticket.seal != seal_of(key, &ticket.app, &ticket.realm, &ticket.nonce) {
            return Err(bad());
        }
        Ok(ticket)
    }
}

/// The marks: which applications are allowed to teleport, and to
/// where. Parsed from `etc/namikaze/sandbox.allow`
/// (`<app> <realm>` per line, `#` comments); a missing file marks
/// nothing, which is the default and the safe direction.
#[derive(Debug, Clone, Default)]
pub struct Grants {
    pub marks: BTreeMap<String, Vec<Realm>>,
}

impl Grants {
    pub fn parse(raw: &str) -> Result<Grants> {
        let mut marks = BTreeMap::new();
        for (n, line) in raw.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (app, realm_raw) = line
                .split_ascii_whitespace()
                .collect::<Vec<_>>()
                .split_first()
                .and_then(|(a, rest)| rest.first().map(|r| (*a, *r)))
                .ok_or_else(|| {
                    Error::Config(format!("sandbox.allow line {}: expected `<app> <realm>`", n + 1))
                })?;
            let realm = Realm::parse(realm_raw)
                .map_err(|e| Error::Config(format!("sandbox.allow line {}: {e}", n + 1)))?;
            marks.entry(app.to_string()).or_insert_with(Vec::new).push(realm);
        }
        Ok(Grants { marks })
    }

    /// Is this app marked for the realm?
    pub fn marked(&self, app: &str, realm: Realm) -> bool {
        self.marks.get(app).map(|list| list.contains(&realm)).unwrap_or(false)
    }
}

/// The gate decision. `Ok(ticket)` teleports; every Err is a
/// different way of saying no.
pub fn request(
    policy_enabled: bool,
    grants: &Grants,
    key: &[u8],
    app: &str,
    realm: Realm,
    nonce: &str,
) -> Result<Ticket> {
    if !policy_enabled {
        return Err(Error::Config(
            "hiraishin: the gate is disarmed (hiraishin_enabled = false)".into(),
        ));
    }
    if !grants.marked(app, realm) {
        return Err(Error::Config(
            "hiraishin: the application carries no mark for this realm".into(),
        ));
    }
    if nonce.trim().is_empty() {
        return Err(Error::Config("hiraishin: empty nonce".into()));
    }
    Ok(Ticket::issue(key, app, realm, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        b"gate-key-for-tests-only".to_vec()
    }

    #[test]
    fn ticket_roundtrip_and_tamper_rejection() {
        let t = Ticket::issue(&key(), "files", Realm::Desktop, "abc123");
        let text = t.render();
        let back = Ticket::open(&key(), &text).unwrap();
        assert_eq!(back, t);
        assert_eq!(back.app, "files");
        assert_eq!(back.realm, Realm::Desktop);

        // any field flip breaks the seal
        assert!(Ticket::open(&key(), &text.replace("files", "filez")).is_err());
        assert!(Ticket::open(&key(), &text.replace("desktop", "system")).is_err());
        let mut flipped = text.clone();
        let at = flipped.len() - 2;
        flipped.replace_range(at..at + 1, if &flipped[at..at + 1] == "0" { "1" } else { "0" });
        assert!(Ticket::open(&key(), &flipped).is_err());
        assert!(Ticket::open(b"other-key", &text).is_err());
    }

    #[test]
    fn grants_parse_and_default_deny() {
        let g = Grants::parse("# comment\n\nfiles desktop\npkg system\nfiles system\n").unwrap();
        assert!(g.marked("files", Realm::Desktop));
        assert!(g.marked("files", Realm::System));
        assert!(g.marked("pkg", Realm::System));
        assert!(!g.marked("pkg", Realm::Desktop));
        assert!(!g.marked("random", Realm::Desktop));
        let empty = Grants::parse("").unwrap();
        assert!(!empty.marked("anything", Realm::System));
        assert!(Grants::parse("onlyname\n").is_err());
        assert!(Grants::parse("app nope\n").is_err());
    }

    #[test]
    fn gate_is_fail_closed() {
        let g = Grants::parse("files desktop\n").unwrap();
        // disarmed -> even a marked app is refused
        let e = request(false, &g, &key(), "files", Realm::Desktop, "n1").unwrap_err();
        assert!(format!("{e}").contains("disarmed"));
        // armed but unmarked -> refused
        let e = request(true, &g, &key(), "other", Realm::System, "n1").unwrap_err();
        assert!(format!("{e}").contains("no mark"));
        // armed + marked + nonce -> the kunai flies
        let t = request(true, &g, &key(), "files", Realm::Desktop, "nonce-1").unwrap();
        assert_eq!(t.app, "files");
        assert!(Ticket::open(&key(), &t.render()).is_ok());
    }
}
