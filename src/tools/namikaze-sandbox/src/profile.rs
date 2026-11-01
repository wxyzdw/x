// SPDX-License-Identifier: MPL-2.0
//! Pure confinement model: profile parsing, validation and rendering.
//!
//! deny-by-default: a profile that grants nothing still produces a runnable
//! recipe (tmpfs-only view, no network, empty environment). Anything an
//! application needs must be granted explicitly. The TOML mapping is
//! hand-written on `namikaze-rt::toml` (zero third-party crates).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use namikaze_common::{Error, Result};
use namikaze_rt::toml::{self, Value};

/// One read-only or read-write filesystem grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathGrant {
    pub path: String,
    pub read_only: bool,
}

/// A complete application confinement profile.
#[derive(Debug, Clone, Default)]
pub struct AppProfile {
    /// Binary launched inside the sandbox
    pub exec: String,
    /// Filesystem grants (empty = only a private tmpfs)
    pub paths: Vec<PathGrant>,
    /// May the app open network sockets at all?
    pub network: bool,
    /// May the app talk to the session D-Bus?
    pub dbus: bool,
    /// Environment variables forwarded into the sandbox
    pub env: Vec<String>,
    /// Private /tmp and /dev inside the sandbox (recommended, default true)
    pub private_tmp: bool,
}

const ABSOLUTE_FORBIDDEN: &[&str] = &["/proc", "/sys", "/dev"];

fn toml_str(t: &BTreeMap<String, Value>, key: &str) -> Result<String> {
    t.get(key)
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| Error::Config(format!("profile.{key}: expected a string")))
        })
        .unwrap_or_else(|| Ok(String::new()))
}

fn toml_bool(t: &BTreeMap<String, Value>, key: &str, default: bool) -> Result<bool> {
    match t.get(key) {
        None => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(Error::Config(format!("profile.{key}: expected a boolean"))),
    }
}

fn toml_str_list(t: &BTreeMap<String, Value>, key: &str) -> Result<Vec<String>> {
    match t.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Arr(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| Error::Config(format!("profile.{key}: expected strings")))
            })
            .collect(),
        Some(_) => Err(Error::Config(format!("profile.{key}: expected an array"))),
    }
}

impl AppProfile {
    pub fn parse(raw: &str) -> Result<Self> {
        let root = toml::parse(raw).map_err(|e| Error::Config(format!("profile: {e}")))?;
        let exec = toml_str(&root, "exec")?;
        let network = toml_bool(&root, "network", false)?;
        let dbus = toml_bool(&root, "dbus", false)?;
        let env = toml_str_list(&root, "env")?;
        let private_tmp = toml_bool(&root, "private_tmp", true)?;
        let mut paths = Vec::new();
        match root.get("paths") {
            None => {}
            Some(Value::TableArr(items)) => {
                for t in items {
                    let path = toml_str(t, "path")?;
                    let read_only = toml_bool(t, "read_only", false)?;
                    paths.push(PathGrant { path, read_only });
                }
            }
            Some(_) => {
                return Err(Error::Config(
                    "profile.paths: expected an array of tables ([[paths]] entries)".into(),
                ))
            }
        }
        Ok(Self { exec, paths, network, dbus, env, private_tmp })
    }

    /// Every profile defect. Empty means the profile is valid.
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.exec.trim().is_empty() {
            problems.push("no exec declared".into());
        }
        if !self.exec.starts_with('/') && !self.exec.is_empty() {
            problems.push("exec must be an absolute path".into());
        }
        let mut seen: Vec<&str> = Vec::new();
        for g in &self.paths {
            if !g.path.starts_with('/') {
                problems.push(format!("path {} must be absolute", g.path));
                continue;
            }
            if ABSOLUTE_FORBIDDEN.contains(&g.path.as_str()) {
                problems.push(format!("path {} is never grantable", g.path));
            }
            if seen.contains(&g.path.as_str()) {
                problems.push(format!("path {} granted twice", g.path));
            }
            seen.push(g.path.as_str());
        }
        for e in &self.env {
            if e.trim().is_empty() || !e.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                problems.push(format!("env {e} must be UPPER_SNAKE"));
            }
        }
        problems
    }

    /// The launch argv, deterministic and reviewable.
    pub fn render_argv(&self) -> String {
        let mut argv = String::from("namikaze-sandbox-launch");
        if self.private_tmp {
            argv.push_str(" --private-tmp");
        }
        if !self.network {
            argv.push_str(" --unshare-net");
        }
        if !self.dbus {
            argv.push_str(" --no-dbus");
        }
        for g in &self.paths {
            let flag = if g.read_only {
                format!(" --ro-bind {} {}", g.path, g.path)
            } else {
                format!(" --bind {} {}", g.path, g.path)
            };
            argv.push_str(&flag);
        }
        for e in &self.env {
            argv.push_str(&format!(" --env {e}"));
        }
        argv.push_str(" -- ");
        argv.push_str(&self.exec);
        argv
    }

    /// The Landlock-style ruleset summary (what the kernel will enforce).
    pub fn render_ruleset(&self) -> String {
        let mut out = String::from("ruleset: deny-by-default\n");
        for g in &self.paths {
            out.push_str(&format!(
                "  fs {} -> {}\n",
                g.path,
                if g.read_only { "read" } else { "read+write" }
            ));
        }
        out.push_str(&format!("  net -> {}\n", if self.network { "allow" } else { "deny" }));
        out.push_str(&format!("  ipc(dbus) -> {}\n", if self.dbus { "allow" } else { "deny" }));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
exec = "/usr/bin/example"
network = false
dbus = true
env = ["LANG"]

[[paths]]
path = "/usr/share/example"
read_only = true

[[paths]]
path = "/var/lib/example"
"#;

    #[test]
    fn deny_by_default_recipe_unshares_network() {
        let p = AppProfile::parse("exec = \"/usr/bin/tool\"\n").unwrap();
        assert!(p.render_argv().contains("--unshare-net"));
        assert!(p.render_argv().contains("--private-tmp"));
        assert!(p.render_ruleset().contains("net -> deny"));
    }

    #[test]
    fn grants_render_exactly_once_in_order() {
        let p = AppProfile::parse(GOOD).unwrap();
        let argv = p.render_argv();
        assert!(argv.contains("--ro-bind /usr/share/example /usr/share/example"));
        assert!(argv.contains("--bind /var/lib/example /var/lib/example"));
        assert!(p.render_ruleset().contains("fs /var/lib/example -> read+write"));
    }

    #[test]
    fn dangerous_paths_are_rejected() {
        let raw = GOOD.replace("/usr/share/example", "/proc");
        let p = AppProfile::parse(&raw).unwrap();
        assert!(p.problems().iter().any(|x| x.contains("never grantable")));
    }

    #[test]
    fn relative_exec_is_rejected() {
        let p = AppProfile::parse("exec = \"tool\"\n").unwrap();
        assert!(p.problems().iter().any(|x| x.contains("absolute")));
    }

    #[test]
    fn deterministic_output() {
        let a = AppProfile::parse(GOOD).unwrap();
        let b = AppProfile::parse(GOOD).unwrap();
        assert_eq!(a.render_argv(), b.render_argv());
        assert_eq!(a.render_ruleset(), b.render_ruleset());
    }
}
