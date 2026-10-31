// SPDX-License-Identifier: MPL-2.0
//! namikaze-firstboot: welcome and consent wizard (TUI).
//!
//! Walks the user through language, anonymity level and the sentinel consent
//! (KVKK/GDPR-informed). Writes /etc/namikaze/system.toml and a done marker.
//! The GUI wizard (GTK4) reuses this exact flow; TUI ships first so the ISO
//! works everywhere including serial consoles.

#![forbid(unsafe_code)]

use std::path::Path;

use namikaze_common::{etc_path, init_tracing, var_path, Result};
use namikaze_rt::args::Cli;
use namikaze_rt::prompt;

const DONE_MARKER: &str = "firstboot.done";

const USAGE: &[&str] = &[
    "namikaze-firstboot: welcome and consent wizard (TUI)",
    "",
    "usage: namikaze-firstboot [--force]",
];

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() {
        cli.usage_exit(USAGE);
    }
    let marker = var_path(DONE_MARKER);
    if marker.exists() && !cli.flag("force") {
        println!("first boot already completed (use --force to re-run)");
        return Ok(());
    }

    println!("Welcome to NamikazeOS. Privacy and anonymity, by default.");
    println!("--------------------------------------------------------");

    let languages = ["en (English)", "tr (Turkce)", "de (Deutsch)", "ar (Arabic, RTL)"];
    let language = prompt::choose("Language", &languages, 0);
    let lang_code = ["en", "tr", "de", "ar"][language];

    let levels = [
        "standard (Tor available, permissive defaults)",
        "hardened (transparent Tor, random identity, recommended)",
        "maximum (Tor-only egress, decoys on, IPv6 off)",
    ];
    let level = prompt::choose("Anonymity level", &levels, 1);
    let level_code = ["standard", "hardened", "maximum"][level];

    println!();
    println!("Optional: login tamper protection. After 3 wrong password attempts");
    println!("inside 5 minutes, the system can store a locally encrypted webcam");
    println!("frame. Images never leave this machine. Requires your explicit");
    println!("consent under KVKK/GDPR and a working camera.");
    let sentinel = prompt::confirm("Enable sentinel capture (opt-in)?", false);

    let hostname_mode = loop {
        let v = prompt::ask("Hostname mode (random|fixed)");
        if v.is_empty() {
            break "random".to_string();
        }
        if v == "random" || v == "fixed" {
            break v;
        }
        println!("  please answer random or fixed");
    };

    let mut cfg = namikaze_config::SystemConfig::default();
    cfg.anonymity.level = level_code.to_string();
    cfg.anonymity.block_non_tor_egress = !level_code.eq("standard");
    cfg.privacy.hostname_mode = hostname_mode;
    if sentinel {
        cfg.sentinel.enabled = true;
        std::fs::create_dir_all(etc_path("sentinel"))?;
        std::fs::write(etc_path("sentinel/consent"), "granted-by-user\n")?;
    }

    let toml_out = cfg.to_toml()?;
    let target = Path::new(namikaze_common::ETC_DIR).join("system.toml");
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&target, toml_out)?;
    std::fs::write(&marker, format!("language={lang_code}\n"))?;
    println!("configuration written to {}", target.display());
    println!("NamikazeOS is ready. Stay private.");
    Ok(())
}
