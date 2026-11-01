// SPDX-License-Identifier: MPL-2.0
//! namikaze-desk: factory for the NamikazeOS Niri Wayland session.
//!
//! Every desktop artifact is rendered from structured defaults so the
//! compositor, bar, launcher, notifications and portals stay consistent
//! and reviewable in one place. Rendering never shells out; `apply` only
//! writes plain files under a target config root (default /etc/skel).
//!
//! Session stack (Wayland-native, packaged via the ::namikaze overlay):
//!   niri       scrollable-tiling Wayland compositor (the one session)
//!   foot       terminal emulator
//!   fuzzel     application launcher
//!   waybar     status bar (niri/workspaces + niri/window modules)
//!   mako       notification daemon
//!   swaylock   screen lock, driven by swayidle timers
//!   greetd     greeter (agreety) or optional autologin session
//!
//! Only actions listed in ALLOWED_ACTIONS are ever rendered; the keybind
//! table is plain data, so a renamed action fails a unit test instead of
//! the whole session.

#![forbid(unsafe_code)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Tunables mirrored from the `[desktop]` table of
/// /etc/namikaze/system.toml (kept in sync by namikaze-config tests).
#[derive(Debug, Clone)]
pub struct DeskOptions {
    pub terminal: &'static str,
    pub launcher: &'static str,
    pub bar: &'static str,
    pub notifications: &'static str,
    pub lock: &'static str,
    pub kb_layout: &'static str,
    pub gap: u32,
}

impl Default for DeskOptions {
    fn default() -> Self {
        Self {
            terminal: "foot",
            launcher: "fuzzel",
            bar: "waybar",
            notifications: "mako",
            lock: "swaylock",
            kb_layout: "us",
            gap: 12,
        }
    }
}

/// A rendered keybind. `Spawn` carries the full argv; `ActionArg` renders a
/// quoted string argument; `ActionIndex` renders a bare numeric argument.
#[derive(Debug, Clone)]
pub enum Bind {
    Action(&'static str),
    ActionArg(&'static str, &'static str),
    ActionIndex(&'static str, u8),
    Spawn(Vec<&'static str>),
}

/// The only niri actions the generated config may reference. Keep this list
/// in sync with the packaged niri release; anything outside it is a test
/// failure, never a broken session.
pub const ALLOWED_ACTIONS: &[&str] = &[
    "close-window",
    "quit",
    "fullscreen-window",
    "center-column",
    "toggle-window-floating",
    "focus-column-left",
    "focus-column-right",
    "focus-window-up",
    "focus-window-down",
    "move-column-left",
    "move-column-right",
    "move-window-up",
    "move-window-down",
    "focus-workspace-up",
    "focus-workspace-down",
    "move-workspace-up",
    "move-workspace-down",
    "move-column-to-workspace-up",
    "move-column-to-workspace-down",
    "focus-workspace",
    "move-column-to-workspace",
    "set-column-width",
    "screenshot",
    "screenshot-screen",
    "screenshot-window",
];

/// The full keybind table: Mod equals Super. Volume keys call wpctl
/// (wireplumber) and brightness keys call brightnessctl.
pub fn key_binds(o: &DeskOptions) -> Vec<(String, Bind)> {
    let mut v: Vec<(String, Bind)> = Vec::new();
    let mut push = |k: String, b: Bind| v.push((k, b));

    push("Mod+Return".into(), Bind::Spawn(vec![o.terminal]));
    push("Mod+T".into(), Bind::Spawn(vec![o.terminal]));
    push("Mod+D".into(), Bind::Spawn(vec![o.launcher]));
    push("Mod+Q".into(), Bind::Action("close-window"));
    push("Mod+F".into(), Bind::Action("fullscreen-window"));
    push("Mod+C".into(), Bind::Action("center-column"));
    push("Mod+V".into(), Bind::Action("toggle-window-floating"));
    push("Mod+Shift+E".into(), Bind::Action("quit"));
    push("Mod+Shift+L".into(), Bind::Spawn(vec![o.lock, "-f"]));

    push("Mod+Left".into(), Bind::Action("focus-column-left"));
    push("Mod+Right".into(), Bind::Action("focus-column-right"));
    push("Mod+Up".into(), Bind::Action("focus-window-up"));
    push("Mod+Down".into(), Bind::Action("focus-window-down"));
    push("Mod+H".into(), Bind::Action("focus-column-left"));
    push("Mod+L".into(), Bind::Action("focus-column-right"));
    push("Mod+Ctrl+Left".into(), Bind::Action("move-column-left"));
    push("Mod+Ctrl+Right".into(), Bind::Action("move-column-right"));
    push("Mod+Ctrl+Up".into(), Bind::Action("move-window-up"));
    push("Mod+Ctrl+Down".into(), Bind::Action("move-window-down"));

    push("Mod+Page_Up".into(), Bind::Action("focus-workspace-up"));
    push("Mod+Page_Down".into(), Bind::Action("focus-workspace-down"));
    push("Mod+Ctrl+Page_Up".into(), Bind::Action("move-workspace-up"));
    push("Mod+Ctrl+Page_Down".into(), Bind::Action("move-workspace-down"));
    push("Mod+Shift+Page_Up".into(), Bind::Action("move-column-to-workspace-up"));
    push("Mod+Shift+Page_Down".into(), Bind::Action("move-column-to-workspace-down"));

    for i in 1u8..=9 {
        push(format!("Mod+{i}"), Bind::ActionIndex("focus-workspace", i));
    }
    for i in 1u8..=9 {
        push(format!("Mod+Shift+{i}"), Bind::ActionIndex("move-column-to-workspace", i));
    }

    push("Mod+Minus".into(), Bind::ActionArg("set-column-width", "-10%"));
    push("Mod+Equal".into(), Bind::ActionArg("set-column-width", "+10%"));
    push("Mod+Shift+Equal".into(), Bind::ActionArg("set-column-width", "100%"));

    push("Print".into(), Bind::Action("screenshot-screen"));
    push("Ctrl+Print".into(), Bind::Action("screenshot"));
    push("Alt+Print".into(), Bind::Action("screenshot-window"));

    push(
        "XF86AudioRaiseVolume".into(),
        Bind::Spawn(vec!["wpctl", "set-volume", "-l", "1.0", "@DEFAULT_AUDIO_SINK@", "5%+"]),
    );
    push(
        "XF86AudioLowerVolume".into(),
        Bind::Spawn(vec!["wpctl", "set-volume", "-l", "1.0", "@DEFAULT_AUDIO_SINK@", "5%-"]),
    );
    push(
        "XF86AudioMute".into(),
        Bind::Spawn(vec!["wpctl", "set-mute", "@DEFAULT_AUDIO_SINK@", "toggle"]),
    );
    push(
        "XF86AudioMicMute".into(),
        Bind::Spawn(vec!["wpctl", "set-mute", "@DEFAULT_AUDIO_SOURCE@", "toggle"]),
    );
    push("XF86MonBrightnessUp".into(), Bind::Spawn(vec!["brightnessctl", "set", "5%+"]));
    push("XF86MonBrightnessDown".into(), Bind::Spawn(vec!["brightnessctl", "set", "5%-"]));

    v
}

fn render_bind(key: &str, bind: &Bind) -> String {
    match bind {
        Bind::Action(a) => format!("    {key} {{ {a}; }}\n"),
        Bind::ActionArg(a, arg) => format!("    {key} {{ {a} \"{arg}\"; }}\n"),
        Bind::ActionIndex(a, n) => format!("    {key} {{ {a} {n}; }}\n"),
        Bind::Spawn(argv) => {
            let mut line = format!("    {key} {{ spawn");
            for arg in argv {
                line.push_str(&format!(" \"{arg}\""));
            }
            line.push_str("; }\n");
            line
        }
    }
}

/// Render the complete niri config.kdl.
pub fn render_niri_kdl(o: &DeskOptions) -> String {
    let mut s = String::new();
    s.push_str("// NamikazeOS Niri session (generated by namikaze-desk).\n");
    s.push_str("// Validate after manual edits: niri validate -c <this file>\n");
    s.push_str("// Mod equals the Super key. Gaps are logical pixels.\n\n");

    s.push_str("input {\n");
    s.push_str("    keyboard {\n");
    s.push_str("        xkb {\n");
    s.push_str(&format!("            layout \"{}\"\n", o.kb_layout));
    s.push_str("        }\n");
    s.push_str("    }\n");
    s.push_str("    touchpad {\n");
    s.push_str("        tap\n");
    s.push_str("        dwt\n");
    s.push_str("        natural-scroll\n");
    s.push_str("    }\n");
    s.push_str("    mouse {\n");
    s.push_str("        accel-profile \"flat\"\n");
    s.push_str("    }\n");
    s.push_str("    warp-mouse-to-focus\n");
    s.push_str("    focus-follows-cursor\n");
    s.push_str("}\n\n");

    s.push_str("layout {\n");
    s.push_str(&format!("    gap {}\n", o.gap));
    s.push_str("    center-focused-column \"never\"\n");
    s.push_str("    default-column-width {\n");
    s.push_str("        proportion 0.5\n");
    s.push_str("    }\n");
    s.push_str("    focus-ring {\n");
    s.push_str("        width 2\n");
    s.push_str("        active-color \"#7aa2f7\"\n");
    s.push_str("        inactive-color \"#3b4261\"\n");
    s.push_str("    }\n");
    s.push_str("}\n\n");

    s.push_str("hotkey-overlay {\n");
    s.push_str("    skip-at-startup\n");
    s.push_str("}\n\n");

    s.push_str(
        "screenshot-path \"~/Pictures/Screenshots/Screenshot from %Y-%m-%d %H-%M-%S.png\"\n\n",
    );

    s.push_str("environment {\n");
    s.push_str("    QT_WAYLAND_DISABLE_WINDOWDECORATION \"1\"\n");
    s.push_str("    ELECTRON_OZONE_PLATFORM_HINT \"wayland\"\n");
    s.push_str("}\n\n");

    s.push_str(&format!("spawn-at-startup \"{}\"\n", o.bar));
    s.push_str(&format!("spawn-at-startup \"{}\"\n", o.notifications));
    s.push_str(&format!(
        "spawn-at-startup \"swayidle\" \"-w\" \"timeout\" \"900\" \"{} -f\" \"before-sleep\" \"{} -f\"\n\n",
        o.lock, o.lock
    ));

    s.push_str("binds {\n");
    for (key, bind) in key_binds(o) {
        s.push_str(&render_bind(&key, &bind));
    }
    s.push_str("}\n");
    s
}

/// Waybar status bar config. The niri modules require waybar 0.10 or newer.
pub const WAYBAR_JSON: &str = r#"{
  "layer": "top",
  "position": "top",
  "height": 30,
  "modules-left": ["niri/workspaces", "niri/window"],
  "modules-center": ["clock"],
  "modules-right": ["tray", "network", "pulseaudio", "battery"],
  "niri/workspaces": {},
  "niri/window": { "max-length": 48 },
  "clock": { "format": "%H:%M  %Y-%m-%d" },
  "tray": { "icon-size": 16 },
  "network": {
    "format-wifi": "{essid} {signalStrength}%",
    "format-ethernet": "{ifname}",
    "format-disconnected": "offline",
    "tooltip-format": "{ifname} {ipaddr}"
  },
  "pulseaudio": { "format": "{volume}%" },
  "battery": { "format": "{capacity}% {state}" }
}
"#;

pub const WAYBAR_CSS: &str = r#"/* NamikazeOS waybar style (generated by namikaze-desk). */
* { font-family: monospace; font-size: 13px; }
window#waybar {
    background: #1a1b26;
    color: #c0caf5;
    border-bottom: 2px solid #3b4261;
}
#workspaces button { padding: 0 6px; color: #565f89; }
#workspaces button.focused { color: #7aa2f7; }
#window { margin-left: 8px; }
#clock, #tray, #network, #pulseaudio, #battery { margin: 0 6px; }
"#;

pub const FUZZEL_INI: &str = r#"# NamikazeOS fuzzel config (generated by namikaze-desk).
[main]
font=monospace:size=11
terminal=foot -e
prompt=run:
icons=no
layer=top

[colors]
background=1a1b26f2
text=c0caf5ff
match=7aa2f7ff
selection=3b4261e6
selection-text=c0caf5ff
border=7aa2f7ff

[border]
width=2
radius=6
"#;

pub const MAKO_CONF: &str = r#"# NamikazeOS mako config (generated by namikaze-desk).
font=monospace 10
background-color=#1a1b26
text-color=#c0caf5
border-color=#7aa2f7
border-size=2
default-timeout=6000
icons=0
max-visible=5
anchor=top-right
"#;

pub const FOOT_INI: &str = r#"# NamikazeOS foot config (generated by namikaze-desk).
[main]
font=monospace:size=11
pad=8x8

[scrollback]
lines=10000

[colors]
alpha=0.96
background=1a1b26
foreground=c0caf5
"#;

/// Portal wiring recommended for niri: gtk covers most backends, the gnome
/// backend implements ScreenCast and Screenshot for niri.
pub const PORTALS_CONF: &str = r#"# NamikazeOS xdg-desktop-portal wiring (generated by namikaze-desk).
[preferred]
default=gtk;
org.freedesktop.impl.portal.ScreenCast=gnome;
org.freedesktop.impl.portal.Screenshot=gnome;
"#;

/// Session entry point installed as /usr/bin/namikaze-session. Started by
/// greetd (agreety --cmd) or the [initial_session] autologin hook.
pub const SESSION_SCRIPT: &str = r#"#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# namikaze-session: Niri session entry point for NamikazeOS (OpenRC, no
# systemd dependency). Started by greetd (agreety --cmd) or the
# [initial_session] autologin hook.
set -eu

: "${HOME:?namikaze-session requires HOME}"

export XDG_SESSION_TYPE=wayland
export XDG_SESSION_DESKTOP=niri
export XDG_CURRENT_DESKTOP=niri
export DESKTOP_SESSION=niri
export MOZ_ENABLE_WAYLAND=1
export QT_QPA_PLATFORM=wayland
export QT_WAYLAND_DISABLE_WINDOWDECORATION=1
export ELECTRON_OZONE_PLATFORM_HINT=wayland

mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}" "$HOME/Pictures/Screenshots"

# dbus-run-session guarantees a session bus even before any login manager
# environment sync; niri inherits it and portals attach to the same bus.
exec dbus-run-session -- niri
"#;

/// Render /etc/greetd/config.toml. With autologin enabled greetd starts the
/// session for `autouser` on vt 7 and agreety only serves other logins.
pub fn render_greetd_toml(autologin: bool, autouser: &str) -> String {
    let mut s = String::new();
    s.push_str("# NamikazeOS greetd config (generated by namikaze-desk).\n\n");
    s.push_str("[terminal]\nvt = 7\n\n");
    if autologin {
        s.push_str("[initial_session]\n");
        s.push_str("command = \"/usr/bin/namikaze-session\"\n");
        s.push_str(&format!("user = \"{autouser}\"\n\n"));
    }
    s.push_str("[default_session]\n");
    s.push_str("command = \"agreety --cmd /usr/bin/namikaze-session\"\n");
    s.push_str("user = \"greeter\"\n");
    s
}

/// All per-user artifacts, as (path relative to a home root, content) pairs.
pub fn artifacts(o: &DeskOptions) -> Vec<(PathBuf, String)> {
    vec![
        (".config/niri/config.kdl".into(), render_niri_kdl(o)),
        (".config/waybar/config.json".into(), WAYBAR_JSON.to_string()),
        (".config/waybar/style.css".into(), WAYBAR_CSS.to_string()),
        (".config/fuzzel/fuzzel.ini".into(), FUZZEL_INI.to_string()),
        (".config/mako/config".into(), MAKO_CONF.to_string()),
        (".config/foot/foot.ini".into(), FOOT_INI.to_string()),
        (".config/xdg-desktop-portal/portals.conf".into(), PORTALS_CONF.to_string()),
    ]
}

/// Write every artifact under `target` (a home root, e.g. /etc/skel).
/// Returns the number of files written.
pub fn apply(target: &Path) -> io::Result<usize> {
    let o = DeskOptions::default();
    let mut written = 0;
    for (rel, content) in artifacts(&o) {
        let path = target.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, content)?;
        written += 1;
    }
    Ok(written)
}

fn in_path(bin: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    std::env::split_paths(&path).map(|dir| dir.join(bin)).any(|p| p.is_file())
}

/// Presence checks for every binary the session needs, with an install hint.
pub fn doctor() -> Vec<(String, bool, String)> {
    let checks: &[(&str, &str)] = &[
        ("niri", "compositor (gui-wm/niri)"),
        ("foot", "terminal emulator"),
        ("fuzzel", "application launcher"),
        ("waybar", "status bar"),
        ("mako", "notification daemon"),
        ("swaylock", "screen lock"),
        ("swayidle", "idle daemon"),
        ("grim", "screenshot capture"),
        ("slurp", "region selection"),
        ("wl-copy", "clipboard utilities (wl-clipboard)"),
        ("dbus-run-session", "session bus bootstrap"),
        ("agreety", "greetd greeter (gui-apps/greetd)"),
        ("wpctl", "volume control (media-sound/wireplumber)"),
        ("brightnessctl", "backlight control"),
    ];
    checks
        .iter()
        .map(|(bin, what)| {
            (
                format!("{bin} - {what}"),
                in_path(bin),
                format!("install the package providing {bin}"),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn niri_kdl_braces_balance() {
        let kdl = render_niri_kdl(&DeskOptions::default());
        assert_eq!(kdl.matches('{').count(), kdl.matches('}').count());
        assert_eq!(kdl.matches('(').count(), kdl.matches(')').count());
        assert_eq!(kdl.matches('[').count(), kdl.matches(']').count());
    }

    #[test]
    fn niri_kdl_contains_core_sections() {
        let kdl = render_niri_kdl(&DeskOptions::default());
        for needle in [
            "input {",
            "layout {",
            "binds {",
            "spawn-at-startup \"waybar\"",
            "spawn-at-startup \"mako\"",
            "screenshot-path",
            "close-window",
            "fullscreen-window",
            "set-column-width",
            "layout \"us\"",
            "gap 12",
        ] {
            assert!(kdl.contains(needle), "missing fragment: {needle}");
        }
    }

    #[test]
    fn keybinds_use_known_actions_only() {
        let binds = key_binds(&DeskOptions::default());
        assert_eq!(binds.len(), 55);
        let mut seen = std::collections::HashSet::new();
        for (key, bind) in binds {
            assert!(seen.insert(key.clone()), "duplicate bind key {key}");
            match bind {
                Bind::Action(a) | Bind::ActionArg(a, _) | Bind::ActionIndex(a, _) => {
                    assert!(ALLOWED_ACTIONS.contains(&a), "action outside the allowlist: {a}");
                }
                Bind::Spawn(argv) => assert!(!argv.is_empty()),
            }
        }
    }

    #[test]
    fn options_flow_into_rendered_kdl() {
        let o = DeskOptions { gap: 24, kb_layout: "tr", ..DeskOptions::default() };
        let kdl = render_niri_kdl(&o);
        assert!(kdl.contains("gap 24"));
        assert!(kdl.contains("layout \"tr\""));
    }

    #[test]
    fn waybar_json_is_wellformed() {
        assert!(WAYBAR_JSON.trim_start().starts_with('{'));
        assert!(WAYBAR_JSON.trim_end().ends_with('}'));
        assert!(WAYBAR_JSON.contains("niri/workspaces"));
        assert!(WAYBAR_JSON.contains("niri/window"));
        assert_eq!(WAYBAR_JSON.matches('{').count(), WAYBAR_JSON.matches('}').count());
        assert_eq!(WAYBAR_JSON.matches('[').count(), WAYBAR_JSON.matches(']').count());
    }

    #[test]
    fn portals_wire_screencast_to_gnome() {
        assert!(PORTALS_CONF.contains("default=gtk;"));
        assert!(PORTALS_CONF.contains("ScreenCast=gnome;"));
        assert!(PORTALS_CONF.contains("Screenshot=gnome;"));
    }

    #[test]
    fn greetd_renders_both_modes() {
        let greeter = render_greetd_toml(false, "");
        assert!(greeter.contains("[default_session]"));
        assert!(greeter.contains("agreety --cmd /usr/bin/namikaze-session"));
        assert!(!greeter.contains("initial_session"));

        let auto = render_greetd_toml(true, "namikaze");
        assert!(auto.contains("[initial_session]"));
        assert!(auto.contains("user = \"namikaze\""));
    }

    #[test]
    fn session_script_is_wellformed() {
        assert!(SESSION_SCRIPT.starts_with("#!/bin/sh\n"));
        assert!(SESSION_SCRIPT.contains("dbus-run-session -- niri"));
        assert!(SESSION_SCRIPT.contains("SPDX-License-Identifier: MPL-2.0"));
        assert!(SESSION_SCRIPT.is_ascii());
    }

    #[test]
    fn all_rendered_artifacts_are_ascii() {
        let o = DeskOptions::default();
        let mut all: Vec<String> = artifacts(&o).into_iter().map(|(_, c)| c).collect();
        all.push(render_greetd_toml(true, "namikaze"));
        all.push(WAYBAR_CSS.to_string());
        for text in all {
            assert!(text.is_ascii(), "non-ASCII byte in rendered artifact");
        }
    }

    #[test]
    fn apply_writes_every_artifact() {
        let root = std::env::temp_dir().join(format!("namikaze-desk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let n = apply(&root).expect("apply must succeed");
        assert_eq!(n, 7);
        for (rel, _) in artifacts(&DeskOptions::default()) {
            assert!(root.join(&rel).is_file(), "missing {}", rel.display());
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
