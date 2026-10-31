// SPDX-License-Identifier: MPL-2.0
//! namikaze-desk CLI: render the Niri session, print artifacts, run doctor.
//!
//!   namikaze-desk apply [TARGET]   write all per-user config (default /etc/skel)
//!   namikaze-desk print <ARTIFACT> dump one artifact to stdout
//!   namikaze-desk doctor           check every session binary is present

#![forbid(unsafe_code)]

use std::path::Path;
use std::process::exit;

use namikaze_desk::{
    apply, doctor, render_greetd_toml, render_niri_kdl, DeskOptions, FOOT_INI, FUZZEL_INI,
    MAKO_CONF, PORTALS_CONF, SESSION_SCRIPT, WAYBAR_CSS, WAYBAR_JSON,
};

const USAGE: &str = "usage: namikaze-desk <apply [TARGET]> | print <niri|waybar|waybar-css|fuzzel|mako|foot|portals|greetd|session> | doctor";

fn print_artifact(name: &str) -> bool {
    let o = DeskOptions::default();
    let text = match name {
        "niri" => render_niri_kdl(&o),
        "waybar" => WAYBAR_JSON.to_string(),
        "waybar-css" => WAYBAR_CSS.to_string(),
        "fuzzel" => FUZZEL_INI.to_string(),
        "mako" => MAKO_CONF.to_string(),
        "foot" => FOOT_INI.to_string(),
        "portals" => PORTALS_CONF.to_string(),
        "greetd" => render_greetd_toml(false, ""),
        "session" => SESSION_SCRIPT.to_string(),
        _ => {
            eprintln!("namikaze-desk: unknown artifact: {name}");
            return false;
        }
    };
    print!("{text}");
    true
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("apply") => {
            let target = args.get(1).map(String::as_str).unwrap_or("/etc/skel");
            match apply(Path::new(target)) {
                Ok(n) => println!("namikaze-desk: wrote {n} artifact(s) under {target}"),
                Err(e) => {
                    eprintln!("namikaze-desk: apply failed: {e}");
                    exit(1);
                }
            }
        }
        Some("print") => match args.get(1) {
            Some(name) if print_artifact(name) => {}
            _ => {
                eprintln!("{USAGE}");
                exit(2);
            }
        },
        Some("doctor") => {
            let mut missing = 0;
            for (label, ok, hint) in doctor() {
                if ok {
                    println!("ok      {label}");
                } else {
                    println!("MISSING {label}  hint: {hint}");
                    missing += 1;
                }
            }
            if missing > 0 {
                exit(1);
            }
        }
        _ => {
            println!("{USAGE}");
            exit(2);
        }
    }
}
