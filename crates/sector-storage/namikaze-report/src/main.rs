// SPDX-License-Identifier: MPL-2.0
//! namikaze-report: security and privacy posture report.
//!
//! Collects detection, configuration, hardening sysctls, storage state and
//! the sentinel audit chain into one text or HTML report. Designed for the
//! "am I actually protected?" question and for compliance evidence.

#![forbid(unsafe_code)]

use namikaze_common::{init_tracing, Result};
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-report: self-audit report (encryption posture, hardening, audit chain)",
    "",
    "usage:",
    "  namikaze-report text   plain-text report",
    "  namikaze-report html   self-contained HTML report",
];

fn sysctl(path: &str) -> String {
    namikaze_common::read_first_line(&std::path::Path::new("/proc/sys").join(path))
        .unwrap_or_default()
}

fn storage_state() -> Vec<(String, String)> {
    let mut rows = Vec::new();
    rows.push((
        "crypttab present".into(),
        std::path::Path::new("/etc/crypttab").exists().to_string(),
    ));
    let dm = std::path::Path::new("/sys/block");
    if let Ok(entries) = std::fs::read_dir(dm) {
        let n = entries
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("dm-"))
            .count();
        rows.push(("device-mapper volumes".into(), n.to_string()));
    }
    rows
}

fn text_report() {
    let cfg = namikaze_config::SystemConfig::load_or_default();
    let det = namikaze_detect::detect();
    println!("NamikazeOS posture report");
    println!("=========================");
    println!("version:          {}", namikaze_common::VERSION);
    println!("machine/profile:  {} / {}", det.machine, det.profile.as_label());
    println!("anonymity level:  {}", cfg.anonymity.level);
    println!("storage mode:     {} (tier {})", cfg.storage.mode, cfg.storage.boot_tier);
    println!();
    println!("hardening sysctls:");
    for (k, v) in [
        ("kernel.kptr_restrict", sysctl("kernel/kptr_restrict")),
        ("kernel.dmesg_restrict", sysctl("kernel/dmesg_restrict")),
        ("kernel.yama.ptrace_scope", sysctl("kernel/yama/ptrace_scope")),
        ("vm.swappiness", sysctl("vm/swappiness")),
    ] {
        println!("  {k:32} = {v}");
    }
    println!();
    println!("storage:");
    for (k, v) in storage_state() {
        println!("  {k:32} = {v}");
    }
    let (events, valid) = namikaze_sentinel::audit_verify().unwrap_or((0, false));
    println!();
    println!("sentinel audit chain: {events} events, valid={valid}");
    println!("destructive tools:    {}", cfg.privacy.destructive_tools);
}

fn html_report() -> Result<()> {
    let cfg = namikaze_config::SystemConfig::load_or_default();
    let det = namikaze_detect::detect();
    let mut html = String::new();
    html.push_str("<!doctype html><meta charset=\"utf-8\"><title>NamikazeOS Report</title>");
    html.push_str("<style>body{font-family:sans-serif;max-width:760px;margin:2rem auto}");
    html.push_str("table{border-collapse:collapse}td,th{border:1px solid #999;padding:4px 8px}");
    html.push_str("h1{border-bottom:2px solid #333}</style><h1>NamikazeOS posture report</h1>");
    html.push_str(&format!("<p>version {}</p>", namikaze_common::VERSION));
    html.push_str(&format!(
        "<table><tr><th>Item</th><th>Value</th></tr>\
         <tr><td>machine</td><td>{}</td></tr>\
         <tr><td>profile</td><td>{}</td></tr>\
         <tr><td>anonymity</td><td>{}</td></tr>\
         <tr><td>storage</td><td>tier {} ({})</td></tr>\
         <tr><td>destructive tools</td><td>{}</td></tr></table>",
        det.machine,
        det.profile.as_label(),
        cfg.anonymity.level,
        cfg.storage.boot_tier,
        cfg.storage.mode,
        cfg.privacy.destructive_tools
    ));
    html.push_str("<table><tr><th>Sysctl</th><th>Value</th></tr>");
    for (k, v) in [
        ("kernel.kptr_restrict", sysctl("kernel/kptr_restrict")),
        ("kernel.dmesg_restrict", sysctl("kernel/dmesg_restrict")),
        ("kernel.yama.ptrace_scope", sysctl("kernel/yama/ptrace_scope")),
        ("vm.swappiness", sysctl("vm/swappiness")),
    ] {
        html.push_str(&format!("<tr><td>{k}</td><td>{v}</td></tr>"));
    }
    html.push_str("</table>");
    let (events, valid) = namikaze_sentinel::audit_verify().unwrap_or((0, false));
    html.push_str(&format!(
        "<p>sentinel audit chain: {events} events, valid={valid}</p>"
    ));
    std::fs::write("namikaze-report.html", html)?;
    println!("written: namikaze-report.html");
    Ok(())
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    match cli.sub().unwrap_or_default() {
        "text" => text_report(),
        "html" => html_report()?,
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
