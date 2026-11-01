// SPDX-License-Identifier: MPL-2.0
//! The confinement level model: the ladder every application sits on.
//!
//! - **level 0 - desktop**: the user session's own bubble. The desktop
//!   itself (compositor, shell, portals) runs sealed off from the
//!   system services; it can show windows but not touch the host.
//! - **level 1 - app**: every application, always. Deny-by-default
//!   filesystem view, no network, no desktop bus. This is the default.
//! - **level 2 - networked**: an application sandbox that may open
//!   network sockets - still no desktop, still no host paths beyond
//!   its profile grants.
//! - **level 3 - escalated**: desktop or host access. Only reachable
//!   through a Hiraishin grant (`etc/namikaze/sandbox.allow` plus the
//!   master switch in `etc/namikaze/sandbox.toml`); the profile never
//!   gains anything by asking - a grant must exist.
//!
//! Levels only ever *clamp* a profile, never widen it: deny-by-default
//! survives every level transition, which is the whole security model.

#![forbid(unsafe_code)]

use namikaze_common::{Error, Result};
use namikaze_rt::toml::{self, Value};

use super::profile::AppProfile;

/// The four confinement levels, lowest to highest exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// The desktop bubble itself.
    Desktop,
    /// Plain application sandbox (the default).
    App,
    /// Application sandbox with network access.
    Networked,
    /// Escalated: desktop or host access via a Hiraishin grant.
    Escalated,
}

impl Level {
    /// Parse a level from its number (0..=3) or name.
    pub fn parse(raw: &str) -> Result<Level> {
        match raw.trim() {
            "0" | "desktop" => Ok(Level::Desktop),
            "1" | "app" => Ok(Level::App),
            "2" | "networked" => Ok(Level::Networked),
            "3" | "escalated" => Ok(Level::Escalated),
            other => Err(Error::Config(format!(
                "sandbox: unknown level {other:?} (0..3 or desktop/app/networked/escalated)"
            ))),
        }
    }

    /// The numeric level.
    pub fn number(&self) -> u8 {
        match self {
            Level::Desktop => 0,
            Level::App => 1,
            Level::Networked => 2,
            Level::Escalated => 3,
        }
    }

    /// Human title + the policy it enforces.
    pub fn description(&self) -> &'static str {
        match self {
            Level::Desktop => "desktop bubble: session sealed off from system services",
            Level::App => "application sandbox: deny-by-default, no network, no desktop",
            Level::Networked => "application sandbox with network sockets",
            Level::Escalated => "desktop/host access - requires a Hiraishin grant",
        }
    }

    /// The system-wide sandbox policy file, parsed from
    /// `etc/namikaze/sandbox.toml`.
    pub fn load_policy(raw: &str) -> Result<Policy> {
        let root = toml::parse(raw).map_err(|e| Error::Config(format!("sandbox.toml: {e}")))?;
        let table = match root.get("sandbox") {
            Some(Value::Table(t)) => t,
            _ => return Err(Error::Config("sandbox.toml: missing [sandbox] table".into())),
        };
        let str_of = |k: &str| -> Result<String> {
            match table.get(k) {
                None => Ok(String::new()),
                Some(Value::Str(s)) => Ok(s.clone()),
                Some(Value::Int(n)) => Ok(n.to_string()),
                Some(_) => Err(Error::Config(format!("sandbox.{k}: expected a string or integer"))),
            }
        };
        let bool_of = |k: &str, default: bool| -> Result<bool> {
            match table.get(k) {
                None => Ok(default),
                Some(Value::Bool(b)) => Ok(*b),
                Some(_) => Err(Error::Config(format!("sandbox.{k}: expected a boolean"))),
            }
        };
        let default = str_of("default_level")?;
        let default_level = if default.is_empty() { Level::App } else { Level::parse(&default)? };
        Ok(Policy {
            default_level,
            hiraishin_enabled: bool_of("hiraishin_enabled", false)?,
            allow_file: str_of("allow_file")
                .unwrap_or_else(|_| "/etc/namikaze/sandbox.allow".into()),
        })
    }
}

/// The system-wide sandbox policy (the [sandbox] table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Level applications get when their profile says nothing.
    pub default_level: Level,
    /// The Hiraishin master switch: false means nothing ever escapes.
    pub hiraishin_enabled: bool,
    /// Where the per-application grants live.
    pub allow_file: String,
}

/// Reconcile one application profile with its level: the level clamps
/// the grants down, it never adds. Level 1 strips network and dbus,
/// level 2 keeps network, level 3 keeps whatever the profile grants -
/// and even level 3 refuses dbus unless the caller proved a Hiraishin
/// grant for the desktop realm.
pub fn clamp(prof: &mut AppProfile, level: Level, hiraishin_granted: bool) {
    if level < Level::Networked {
        prof.network = false;
    }
    if level < Level::Escalated || !hiraishin_granted {
        prof.dbus = false;
    }
    if level == Level::Desktop {
        // the desktop bubble keeps its grants (it is the session
        // itself); nothing to clamp beyond the services isolation,
        // which the kernel policy (etc/sysctl) enforces
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
[sandbox]
default_level = 1
hiraishin_enabled = false
allow_file = "/etc/namikaze/sandbox.allow"
"#;

    #[test]
    fn levels_parse_from_numbers_and_names() {
        assert_eq!(Level::parse("0").unwrap(), Level::Desktop);
        assert_eq!(Level::parse("app").unwrap(), Level::App);
        assert_eq!(Level::parse("2").unwrap(), Level::Networked);
        assert_eq!(Level::parse("escalated").unwrap(), Level::Escalated);
        assert!(Level::parse("4").is_err());
        assert!(Level::parse("nine-tails").is_err());
    }

    #[test]
    fn ladder_orders_by_exposure() {
        assert!(Level::Desktop < Level::App);
        assert!(Level::App < Level::Networked);
        assert!(Level::Networked < Level::Escalated);
        assert_eq!(Level::Networked.number(), 2);
    }

    #[test]
    fn policy_defaults_are_fail_closed() {
        let p = Level::load_policy(POLICY).unwrap();
        assert_eq!(p.default_level, Level::App);
        assert!(!p.hiraishin_enabled, "the master switch defaults to disarmed");
        assert_eq!(p.allow_file, "/etc/namikaze/sandbox.allow");
        let empty = Level::load_policy("[sandbox]\n").unwrap();
        assert!(!empty.hiraishin_enabled);
    }

    #[test]
    fn clamp_strips_network_below_level_two() {
        let raw = "exec = \"/usr/bin/tool\"\nnetwork = true\ndbus = true\n";
        let mut prof = AppProfile::parse(raw).unwrap();
        clamp(&mut prof, Level::App, false);
        assert!(!prof.network);
        assert!(!prof.dbus);

        let mut prof = AppProfile::parse(raw).unwrap();
        clamp(&mut prof, Level::Networked, false);
        assert!(prof.network);
        assert!(!prof.dbus);

        // even at level 3, dbus needs the grant
        let mut prof = AppProfile::parse(raw).unwrap();
        clamp(&mut prof, Level::Escalated, false);
        assert!(!prof.dbus);
        let mut prof = AppProfile::parse(raw).unwrap();
        clamp(&mut prof, Level::Escalated, true);
        assert!(prof.dbus);
    }
}
