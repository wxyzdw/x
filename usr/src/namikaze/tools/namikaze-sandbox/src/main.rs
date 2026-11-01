// SPDX-License-Identifier: MPL-2.0
//! namikaze-sandbox: the confinement ladder and the application
//! confinement profile compiler.
//!
//! Every application runs on a level (see `level`): 0 is the desktop
//! bubble, 1 is the deny-by-default application sandbox (the
//! default), 2 adds network, 3 is escalated desktop/host access -
//! reachable only through Hiraishin no Jutsu (`hiraishin`): an
//! application marked in `etc/namikaze/sandbox.allow` gets a
//! gate-issued HMAC ticket when the master switch is armed; the
//! launcher verifies the ticket before it spawns anything outside.
//! One TOML profile per application declares the filesystem paths it
//! may read or write; levels clamp profiles, they never widen them.
//!
//! ```sh
//! namikaze-sandbox compile <app> --level 1   print the launch recipe
//! namikaze-sandbox levels                    print the level model
//! namikaze-sandbox hiraishin <app> --realm desktop
//! namikaze-sandbox doctor                    validate profiles + policy
//! ```

#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use namikaze_common::{init_tracing, Result, ETC_DIR};
use namikaze_rt::args::Cli;

pub mod hiraishin;
pub mod level;
pub mod profile;

use hiraishin::{Grants, Realm};
use level::{clamp, Level, Policy};
use profile::AppProfile;

const POLICY_FILE: &str = "/etc/namikaze/sandbox.toml";

const USAGE: &[&str] = &[
    "namikaze-sandbox: confinement levels, profiles and Hiraishin",
    "",
    "usage:",
    "  namikaze-sandbox compile <app> [--level N] [--dir D]   clamped launch recipe",
    "  namikaze-sandbox apply <app>   [--level N] [--dir D]   store it under /run",
    "  namikaze-sandbox levels                                print the level model",
    "  namikaze-sandbox hiraishin <app> [--realm R] [--nonce N]",
    "                                                         issue an escape ticket",
    "  namikaze-sandbox verify <ticket>                       verify a ticket",
    "  namikaze-sandbox doctor        [--dir D]               validate everything",
];

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let dir_arg = cli.value_or("dir", &format!("{ETC_DIR}/sandbox"));
    let dir = Path::new(&dir_arg);
    let app_arg = || cli.free(&[]).get(1).cloned().unwrap_or_default();

    match cli.sub().unwrap_or_default() {
        "compile" => {
            let mut prof = load(dir, &app_arg())?;
            let (_, grants) = load_policy()?;
            let lvl = Level::parse(&cli.value_or("level", "1"))?;
            clamp(&mut prof, lvl, grants.marked(&app_arg(), Realm::Desktop));
            println!("level {} ({})", lvl.number(), lvl.description());
            println!("{}", prof.render_argv());
            println!("{}", prof.render_ruleset());
        }
        "apply" => {
            let app = app_arg();
            let mut prof = load(dir, &app)?;
            let (policy, grants) = load_policy()?;
            let lvl =
                Level::parse(&cli.value_or("level", &policy.default_level.number().to_string()))?;
            clamp(&mut prof, lvl, grants.marked(&app, Realm::Desktop));
            let out = Path::new(namikaze_common::RUN_DIR).join("sandbox");
            fs::create_dir_all(&out)?;
            let file = out.join(format!("{app}.recipe"));
            fs::write(
                &file,
                format!(
                    "level {}\n{}\n{}",
                    lvl.number(),
                    prof.render_argv(),
                    prof.render_ruleset()
                ),
            )?;
            println!("recipe written: {}", file.display());
        }
        "levels" => {
            for raw in ["0", "1", "2", "3"] {
                let lvl = Level::parse(raw).unwrap();
                println!("level {}: {}", lvl.number(), lvl.description());
            }
            let (policy, _) = load_policy()?;
            println!(
                "default level {}, hiraishin {}",
                policy.default_level.number(),
                if policy.hiraishin_enabled { "ARMED" } else { "disarmed" }
            );
        }
        "hiraishin" => {
            let app = app_arg();
            let realm = Realm::parse(&cli.value_or("realm", "desktop"))?;
            let (policy, grants) = load_policy()?;
            let key = gate_key()?;
            let nonce = cli.value_or("nonce", &namikaze_rt::random::id_hex()?);
            match hiraishin::request(policy.hiraishin_enabled, &grants, &key, &app, realm, &nonce) {
                Ok(ticket) => println!("{}", ticket.render()),
                Err(e) => {
                    eprintln!("hiraishin: {e}");
                    std::process::exit(1);
                }
            }
        }
        "verify" => {
            let ticket = cli.free(&[]).get(1).cloned().unwrap_or_default();
            let key = gate_key()?;
            match hiraishin::Ticket::open(&key, &ticket) {
                Ok(t) => {
                    println!("valid: {} -> realm {} (nonce {})", t.app, t.realm.name(), t.nonce)
                }
                Err(e) => {
                    eprintln!("hiraishin: {e}");
                    std::process::exit(1);
                }
            }
        }
        "doctor" => {
            let mut bad = 0;
            let (policy, grants) = load_policy()?;
            println!(
                "policy: default level {}, hiraishin {}",
                policy.default_level.number(),
                if policy.hiraishin_enabled { "ARMED" } else { "disarmed" }
            );
            let entries = match fs::read_dir(dir) {
                // a missing profiles dir on a build host means
                // nothing to validate - on the booted system it exists
                Err(_) if !dir.exists() => {
                    println!("profiles: none ({} missing)", dir.display());
                    Vec::new()
                }
                other => other
                    .map_err(|e| namikaze_common::Error::Other(format!("{}: {e}", dir.display())))?
                    .map(|e| e.map_err(namikaze_common::Error::Io))
                    .collect::<std::result::Result<Vec<_>, namikaze_common::Error>>()?,
            };
            for entry in entries {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                    continue;
                }
                let raw = fs::read_to_string(&path)?;
                let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("?");
                match AppProfile::parse(&raw) {
                    Ok(p) => {
                        let problems = p.problems();
                        if problems.is_empty() {
                            println!("PASS {name}");
                        } else {
                            bad += 1;
                            for pr in &problems {
                                println!("FAIL {name}: {pr}");
                            }
                        }
                    }
                    Err(e) => {
                        bad += 1;
                        println!("FAIL {name}: {e}");
                    }
                }
            }
            for (app, realms) in &grants.marks {
                let list = realms.iter().map(|r| r.name()).collect::<Vec<_>>().join(",");
                println!("MARK {app} -> {list}");
            }
            if bad > 0 {
                std::process::exit(1);
            }
            println!("sandbox: all valid");
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}

fn load(dir: &Path, app: &str) -> Result<AppProfile> {
    let file = dir.join(format!("{app}.toml"));
    let raw = fs::read_to_string(&file)
        .map_err(|e| namikaze_common::Error::Config(format!("{}: {e}", file.display())))?;
    AppProfile::parse(&raw)
}

/// The system policy + the Hiraishin marks, both fail-closed: a
/// missing policy file means "level 1, gate disarmed", a missing
/// allow file marks nobody.
fn load_policy() -> Result<(Policy, Grants)> {
    let policy = match fs::read_to_string(POLICY_FILE) {
        Ok(raw) => Level::load_policy(&raw)?,
        Err(_) => Policy {
            default_level: Level::App,
            hiraishin_enabled: false,
            allow_file: format!("{ETC_DIR}/sandbox.allow"),
        },
    };
    let grants = match fs::read_to_string(&policy.allow_file) {
        // a missing allow file marks nobody - the fail-closed default
        Err(_) => Grants::parse("").unwrap(),
        // a present but broken one is config drift and must fail loudly
        Ok(raw) => Grants::parse(&raw)?,
    };
    Ok((policy, grants))
}

/// The Hiraishin gate key. Missing key = the technique is inert
/// (nothing issues, nothing verifies) - fail-closed by construction.
fn gate_key() -> Result<Vec<u8>> {
    let path = format!("{ETC_DIR}/namikaze/hiraishin.key");
    let raw = fs::read_to_string(&path).map_err(|_| {
        namikaze_common::Error::Config(
            "hiraishin: gate key missing (etc/namikaze/hiraishin.key); the technique is inert"
                .into(),
        )
    })?;
    let hex = raw.trim();
    if hex.len() != 64 {
        return Err(namikaze_common::Error::Config(
            "hiraishin: gate key must be 32 hex bytes".into(),
        ));
    }
    (0..32)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16))
        .collect::<std::result::Result<Vec<u8>, _>>()
        .map_err(|_| namikaze_common::Error::Config("hiraishin: gate key is not hex".into()))
}
