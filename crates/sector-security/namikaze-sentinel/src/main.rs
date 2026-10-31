// SPDX-License-Identifier: MPL-2.0
//! namikaze-sentinel CLI: decide | capture | verify-chain | flag.

#![forbid(unsafe_code)]

use namikaze_common::{init_tracing, Result};
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-sentinel: tamper detection and response",
    "",
    "usage:",
    "  namikaze-sentinel decide [FAILURES]   simulate N failures and print decisions",
    "  namikaze-sentinel capture             attempt a consent-guarded frame capture",
    "  namikaze-sentinel verify-chain        verify the audit hash chain",
    "  namikaze-sentinel flag <reason>       seal a tamper flag for the next session",
];

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    match cli.sub().unwrap_or_default() {
        "decide" => {
            let failures: u32 = cli
                .free(&[])
                .get(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(4);
            let policy = namikaze_sentinel::FailurePolicy::new(3, 300);
            let mut state = namikaze_sentinel::load_state();
            let t = now();
            for i in 0..failures {
                let decision = policy.decide(&state, t + u64::from(i));
                state.failures.push(t + u64::from(i));
                println!("failure {} -> {decision:?}", i + 1);
                let _ = namikaze_sentinel::audit_append(&mut state, "simulate", &format!("failure {i}"));
            }
            namikaze_sentinel::store_state(&state)?;
        }
        "capture" => match namikaze_sentinel::capture_image() {
            Ok(path) => println!("frame stored: {}", path.display()),
            Err(e) => println!("capture refused: {e}"),
        },
        "verify-chain" => {
            let (count, valid) = namikaze_sentinel::audit_verify()?;
            if valid {
                println!("audit chain OK ({count} events)");
            } else {
                println!("audit chain BROKEN ({count} events)");
                std::process::exit(1);
            }
        }
        "flag" => {
            let reason = cli
                .free(&[])
                .get(1)
                .cloned()
                .unwrap_or_else(|| "unspecified".to_string());
            let mut state = namikaze_sentinel::load_state();
            state.tamper_flags += 1;
            namikaze_sentinel::audit_append(&mut state, "flag", &reason)?;
            namikaze_sentinel::store_state(&state)?;
            println!("tamper flag sealed: {reason}");
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
