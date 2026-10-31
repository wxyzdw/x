// SPDX-License-Identifier: MPL-2.0
//! desk-guard: fail if the Niri session files disagree across the tree.

use std::path::Path;

use namikaze_common::{Error, Result};

use crate::util::violations_report;

const DESK_DRIFT_PAIRS: &[(&str, &str)] = &[
    ("sysroot/usr/bin/namikaze-session", "overlay/sys-namikaze/desk/files/namikaze-session"),
    ("sysroot/etc/greetd/config.toml", "overlay/sys-namikaze/desk/files/greetd-config.toml"),
    ("sysroot/etc/init.d/namikaze-desk", "overlay/sys-namikaze/desk/files/namikaze-desk.initd"),
    ("sysroot/etc/init.d/greetd", "overlay/sys-namikaze/desk/files/greetd.initd"),
    ("sysroot/etc/pam.d/greetd", "overlay/sys-namikaze/desk/files/greetd.pamd"),
    ("sysroot/etc/pam.d/swaylock", "overlay/sys-namikaze/desk/files/swaylock.pamd"),
];

pub(crate) fn run(root: &Path) -> Result<()> {
    let mut problems: Vec<String> = Vec::new();

    let sysconf = root.join("sysroot/etc/namikaze/system.toml");
    let sysconf_text = std::fs::read_to_string(&sysconf)
        .map_err(|e| Error::Other(format!("cannot read {}: {e}", sysconf.display())))?;
    let mut in_desktop = false;
    let mut environment: Option<String> = None;
    for line in sysconf_text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_desktop = line == "[desktop]";
            continue;
        }
        if in_desktop && line.starts_with("environment") {
            if let Some(eq) = line.find('=') {
                let rest = &line[eq + 1..];
                if let Some(start) = rest.find('"') {
                    if let Some(end) = rest[start + 1..].find('"') {
                        environment = Some(rest[start + 1..start + 1 + end].to_string());
                    }
                }
            }
        }
    }
    match environment.as_deref() {
        Some("niri") => {}
        Some(other) => {
            problems.push(format!("system.toml [desktop] environment = {other} (must be niri)"))
        }
        None => problems.push("system.toml [desktop] has no environment key".into()),
    }

    let session = root.join("sysroot/usr/bin/namikaze-session");
    let session_text = std::fs::read_to_string(&session)
        .map_err(|e| Error::Other(format!("cannot read {}: {e}", session.display())))?;
    if !session_text.contains("SPDX-License-Identifier: MPL-2.0") {
        problems.push("namikaze-session lacks the MPL-2.0 SPDX tag".into());
    }
    if !session_text.contains("dbus-run-session -- niri") {
        problems.push("namikaze-session does not end in the niri exec".into());
    }

    let greetd_conf = root.join("sysroot/etc/greetd/config.toml");
    let greetd_text = std::fs::read_to_string(&greetd_conf)
        .map_err(|e| Error::Other(format!("cannot read {}: {e}", greetd_conf.display())))?;
    if !greetd_text.contains("/usr/bin/namikaze-session") {
        problems.push("greetd config.toml does not launch namikaze-session".into());
    }

    for (orig, copy) in DESK_DRIFT_PAIRS {
        let a = std::fs::read(root.join(orig));
        let b = std::fs::read(root.join(copy));
        match (a, b) {
            (Ok(a), Ok(b)) if a == b => {}
            (Ok(_), Ok(_)) => problems.push(format!("drift: {orig} differs from {copy}")),
            (Ok(_), Err(_)) => problems.push(format!("missing overlay copy: {copy}")),
            (Err(_), _) => problems.push(format!("missing sysroot file: {orig}")),
        }
    }

    let set = root.join("overlay/package.sets/desktop");
    let set_text = std::fs::read_to_string(&set)
        .map_err(|e| Error::Other(format!("cannot read {}: {e}", set.display())))?;
    if !set_text.lines().any(|l| l.trim() == "gui-wm/niri") {
        problems.push("overlay/package.sets/desktop does not pin gui-wm/niri".into());
    }

    if !root.join("crates/sector-desk/namikaze-desk/docs/DESKTOP.md").is_file() {
        problems.push("namikaze-desk/docs/DESKTOP.md missing".into());
    }

    violations_report("desk-guard (Niri session consistent across the tree)", &problems)
}
