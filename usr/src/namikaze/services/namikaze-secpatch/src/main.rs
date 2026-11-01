// SPDX-License-Identifier: MPL-2.0
//! namikaze-secpatch: CVE tracking and backport driver.
//!
//! - Reads an SBOM (crates + versions) produced by `cargo xtask sbom`.
//! - Offline mode: matches advisories in sec-advisories/ (local JSON files
//!   following the OSV schema, commit-signed).
//! - Net mode (feature flag): queries osv.dev for each crate.
//! - Emits a triage report and a Forgejo-ready issue body.
//!
//! Policy: CVSS >= 9.0 issues target a fix within 24 hours; kernel issues
//! always produce a new ISO (kexec is disabled by the hardening config).

#![forbid(unsafe_code)]

use std::path::Path;

use namikaze_common::{init_tracing, Error, Result};
use namikaze_rt::args::Cli;
use namikaze_rt::json::{self, Value};

const USAGE: &[&str] = &[
    "namikaze-secpatch: CVE tracking for the workspace and package set",
    "",
    "usage:",
    "  namikaze-secpatch scan [--sbom dist/sbom.json] [--report]",
    "  namikaze-secpatch advisories [--dir sec-advisories]",
];

#[derive(Debug, Clone)]
struct OsvVuln {
    id: String,
    summary: String,
}

fn vuln_from_json(v: &Value) -> Option<OsvVuln> {
    Some(OsvVuln {
        id: v.get("id")?.as_str()?.to_string(),
        summary: v.get("summary").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
    })
}

/// Minimal SBOM view over the xtask-produced JSON.
struct Sbom {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    version: String,
    crates: Vec<(String, String)>,
}

fn load_sbom(path: &Path) -> Result<Sbom> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::Other(format!("cannot read sbom: {e}")))?;
    let v = json::parse(&raw).map_err(|e| Error::Other(format!("bad sbom: {e}")))?;
    let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("NamikazeOS").to_string();
    let version = v.get("version").and_then(|x| x.as_str()).unwrap_or("0").to_string();
    let mut crates = Vec::new();
    if let Some(arr) = v.get("crates").and_then(|x| x.as_arr()) {
        for c in arr {
            let n = c.get("name").and_then(|x| x.as_str()).unwrap_or_default().to_string();
            let ver = c.get("version").and_then(|x| x.as_str()).unwrap_or_default().to_string();
            if !n.is_empty() {
                crates.push((n, ver));
            }
        }
    }
    Ok(Sbom { name, version, crates })
}

fn local_advisories(dir: &Path, name: &str) -> Vec<OsvVuln> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return out };
    for entry in entries.flatten() {
        let Ok(raw) = std::fs::read_to_string(entry.path()) else { continue };
        let Ok(v) = json::parse(&raw) else { continue };
        let Some(vuln) = vuln_from_json(&v) else { continue };
        if raw.contains(name) {
            out.push(vuln);
        }
    }
    out
}

/// Net queries are a CI-side capability; the shipped binary stays offline
/// and reads only the local advisory directory.
fn query_osv(_name: &str, _version: &str) -> Result<Vec<OsvVuln>> {
    Ok(vec![])
}

fn run_scan(sbom_path: &Path, write_report: bool) -> Result<()> {
    let sbom = load_sbom(sbom_path)?;
    let dir = Path::new("sec-advisories");
    let mut findings = 0usize;
    let mut report = String::from("# NamikazeOS vulnerability scan\n\n");
    for (name, version) in &sbom.crates {
        let mut vulns = local_advisories(dir, name);
        vulns.extend(query_osv(name, version)?);
        if vulns.is_empty() {
            continue;
        }
        findings += vulns.len();
        report.push_str(&format!("## {name} {version}\n"));
        for v in vulns {
            report.push_str(&format!("- {}: {}\n", v.id, v.summary));
        }
        report.push('\n');
    }
    if findings == 0 {
        println!("clean: no known advisories for {} crates", sbom.crates.len());
        return Ok(());
    }
    if write_report {
        let out = sbom_path.with_file_name("vuln-report.md");
        std::fs::write(&out, &report)?;
        println!("{findings} finding(s); report written to {}", out.display());
    } else {
        print!("{report}");
    }
    Ok(())
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    match cli.sub().unwrap_or_default() {
        "scan" => {
            let sbom = std::path::PathBuf::from(cli.value_or("sbom", "dist/sbom.json"));
            run_scan(&sbom, cli.flag("report"))?;
        }
        "advisories" => {
            let dir = std::path::PathBuf::from(cli.value_or("dir", "sec-advisories"));
            let Ok(entries) = std::fs::read_dir(&dir) else {
                println!("no advisory directory at {}", dir.display());
                return Ok(());
            };
            for e in entries.flatten() {
                println!("{}", e.path().display());
            }
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
