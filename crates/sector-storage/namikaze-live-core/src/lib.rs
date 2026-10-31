// SPDX-License-Identifier: MPL-2.0
//! Pure logic for the NamikazeOS live boot stage.
//!
//! Shared by the initramfs (`namikaze-init`) and the userspace tool
//! (`namikaze-live`). Contains no syscalls and no I/O: command line
//! parsing, persistence allowlist validation and mount plan assembly.

#![forbid(unsafe_code)]

use namikaze_common::Error;
use namikaze_common::Result;

/// Live boot mode selected with `namikaze.live=` on the kernel command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LiveMode {
    /// Upper layer stored on the encrypted persist volume (default target).
    #[default]
    Persist,
    /// Upper layer in tmpfs, discarded at shutdown. Leaves no trace.
    Volatile,
    /// Copy the system squashfs to RAM and release the boot media.
    Ram,
    /// Persist to RAM during the session, flush to the persist volume on
    /// clean shutdown. Eject-safe usage on shared machines.
    Session,
}

/// Parsed `namikaze.*` boot options relevant to the live stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveOptions {
    pub mode: LiveMode,
    pub bootid: Option<String>,
    pub persist_uuid: Option<String>,
    pub conf_path: String,
    pub fallback_volatile: bool,
    pub trim: bool,
    pub verity_hash: Option<String>,
    pub recovery: bool,
}

impl Default for LiveOptions {
    fn default() -> Self {
        LiveOptions {
            mode: LiveMode::Persist,
            bootid: None,
            persist_uuid: None,
            conf_path: "/run/persist/persistence.conf".to_string(),
            fallback_volatile: true,
            trim: false,
            verity_hash: None,
            recovery: false,
        }
    }
}

/// Parse a raw `/proc/cmdline` string into live options. Unknown keys are
/// ignored; recognized keys follow the `namikaze.` prefix convention.
pub fn parse_cmdline(cmdline: &str) -> LiveOptions {
    let mut o = LiveOptions::default();
    for arg in cmdline.split_ascii_whitespace() {
        let Some((key, value)) = arg.split_once('=') else {
            continue;
        };
        match key {
            "namikaze.live" => {
                o.mode = match value {
                    "persist" => LiveMode::Persist,
                    "volatile" => LiveMode::Volatile,
                    "ram" => LiveMode::Ram,
                    "session" => LiveMode::Session,
                    _ => LiveMode::default(),
                };
            }
            "namikaze.bootid" => o.bootid = Some(value.to_string()),
            "namikaze.persist.uuid" => o.persist_uuid = Some(value.to_string()),
            "namikaze.persist.conf" => o.conf_path = value.to_string(),
            "namikaze.persist.trim" => o.trim = value == "on" || value == "yes",
            "namikaze.persist.fallback" => o.fallback_volatile = value != "panic",
            "namikaze.verity" => o.verity_hash = Some(value.to_string()),
            "namikaze.recovery" => o.recovery = value != "0" && value != "no",
            _ => {}
        }
    }
    o
}

/// How a persisted path is attached to the merged root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountKind {
    /// Direct bind mount of a directory from the persist volume.
    Bind,
    /// Overlayfs with the read-only root path as the lower layer.
    Overlay,
}

/// One validated allowlist entry from `persistence.conf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub path: String,
    pub kind: MountKind,
    pub optional: bool,
}

/// Paths that may never be persisted. The system stays sealed by dm-verity;
/// persistence is allowlist-only and `/usr` changes flow exclusively through
/// signed image layers managed by `namikaze-pkg`.
const DENIED_PREFIXES: [&str; 6] = ["/usr", "/boot", "/lib", "/lib64", "/bin", "/sbin"];

/// Errors from allowlist parsing, with the offending path when relevant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfError {
    Line(usize),
    DeniedPath(String),
    NotAbsolute(String),
    Traversal(String),
}

impl std::fmt::Display for ConfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfError::Line(n) => write!(f, "invalid syntax at line {n}"),
            ConfError::DeniedPath(p) => write!(f, "path is not persistable: {p}"),
            ConfError::NotAbsolute(p) => write!(f, "path must be absolute: {p}"),
            ConfError::Traversal(p) => write!(f, "path traversal rejected: {p}"),
        }
    }
}

/// Parse and validate a `persistence.conf` document. Every entry must be
/// absolute, canonical (no `..`), outside the denied prefixes and one of
/// exactly two kinds (`bind` or `overlay`), with an optional trailing
/// `optional` marker. Duplicates are dropped silently.
pub fn parse_persistence_conf(text: &str) -> std::result::Result<Vec<MountEntry>, ConfError> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        let path = fields.next().ok_or(ConfError::Line(idx + 1))?;
        let kind = fields.next().ok_or(ConfError::Line(idx + 1))?;
        let third = fields.next();
        let optional = matches!(third, Some("optional"));
        // exactly one optional trailing word is allowed, and it must be
        // the literal "optional"
        if third.is_some() && !optional || fields.next().is_some() {
            return Err(ConfError::Line(idx + 1));
        }
        if !path.starts_with('/') {
            return Err(ConfError::NotAbsolute(path.to_string()));
        }
        if path.split('/').any(|c| c == "..") {
            return Err(ConfError::Traversal(path.to_string()));
        }
        if DENIED_PREFIXES
            .iter()
            .any(|d| path == *d || (path.starts_with(d) && path[d.len()..].starts_with('/')))
        {
            return Err(ConfError::DeniedPath(path.to_string()));
        }
        let kind = match kind {
            "bind" => MountKind::Bind,
            "overlay" => MountKind::Overlay,
            _ => return Err(ConfError::Line(idx + 1)),
        };
        let entry = MountEntry {
            path: path.to_string(),
            kind,
            optional,
        };
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    Ok(out)
}

/// Default allowlist applied when the persist volume carries no file.
pub const DEFAULT_CONF: &str = "\
# NamikazeOS persistence allowlist
# bind    - directory content lives on the persist volume
# overlay - path is merged over the read-only system image
/home bind
/etc overlay
/var bind
/root bind
/usr/local overlay
";

/// The concrete mount actions derived from options plus allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountPlan {
    pub root_upper_on_persist: bool,
    pub entries: Vec<MountEntry>,
}

/// Build the mount plan. In `Session` mode the root upper layer stays in
/// tmpfs (flushed at shutdown), so only `Persist` puts it on the volume.
pub fn build_plan(options: &LiveOptions, entries: &[MountEntry]) -> MountPlan {
    MountPlan {
        root_upper_on_persist: options.mode == LiveMode::Persist,
        entries: entries.to_vec(),
    }
}

/// Compose the overlayfs `data` option string for a merged root.
/// `lowers` are lower-layer paths in stack order (first = highest priority).
pub fn overlay_options(lowers: &[String], upper: &str, work: &str) -> Result<String> {
    if lowers.is_empty() {
        return Err(Error::Config(
            "overlay needs at least one lower layer".into(),
        ));
    }
    if upper == work {
        return Err(Error::Config("overlay upper and work must differ".into()));
    }
    Ok(format!(
        "lowerdir={},upperdir={},workdir={}",
        lowers.join(":"),
        upper,
        work
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmdline_defaults_to_persist() {
        let o = parse_cmdline("quiet namikaze.bootid=0123456789abcdef");
        assert_eq!(o.mode, LiveMode::Persist);
        assert_eq!(o.bootid.as_deref(), Some("0123456789abcdef"));
        assert!(o.fallback_volatile);
    }

    #[test]
    fn cmdline_modes_and_flags() {
        let o = parse_cmdline(
            "namikaze.live=session namikaze.persist.trim=on namikaze.persist.fallback=panic",
        );
        assert_eq!(o.mode, LiveMode::Session);
        assert!(o.trim);
        assert!(!o.fallback_volatile);
    }

    #[test]
    fn allowlist_parses_and_validates() {
        let conf = parse_persistence_conf("/home bind\n/etc overlay\n").unwrap();
        assert_eq!(conf.len(), 2);
        assert_eq!(conf[0].kind, MountKind::Bind);
    }

    #[test]
    fn allowlist_rejects_denied_and_relative() {
        assert!(parse_persistence_conf("/usr bind\n").is_err());
        assert!(parse_persistence_conf("../home bind\n").is_err());
        assert!(parse_persistence_conf("/home bake\n").is_err());
        assert!(parse_persistence_conf("/home bind extra\n").is_err());
    }

    #[test]
    fn allowlist_rejects_traversal() {
        assert!(parse_persistence_conf("/home/../../etc bind\n").is_err());
    }

    #[test]
    fn overlay_options_join() {
        let lowers = vec!["/run/firmware".to_string(), "/run/root".to_string()];
        let s = overlay_options(&lowers, "/run/persist/upper", "/run/persist/work").unwrap();
        assert!(s.starts_with("lowerdir=/run/firmware:/run/root,"));
    }
}
