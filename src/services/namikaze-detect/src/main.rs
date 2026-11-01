// SPDX-License-Identifier: MPL-2.0
//! namikaze-detect CLI: report and tune.

#![forbid(unsafe_code)]

use namikaze_common::{init_tracing, Result};
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-detect: CPU/firmware/virtualization detection",
    "",
    "usage:",
    "  namikaze-detect [--json]   print the detection report",
    "  namikaze-detect tune       apply governor and IO scheduler tuning",
    "  namikaze-detect label      print the profile label only",
];

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() {
        cli.usage_exit(USAGE);
    }
    let report = namikaze_detect::detect();
    match cli.sub().unwrap_or_default() {
        "tune" => {
            namikaze_detect::apply_tuning()?;
            println!("tuning applied for profile {}", report.profile.as_label());
        }
        "label" => {
            println!("{}", report.profile.as_label());
        }
        _ => {
            if cli.flag("json") {
                println!("{}", report.to_json().to_pretty());
            } else {
                println!("machine:      {}", report.machine);
                println!("profile:      {}", report.profile.as_label());
                println!("vendor:       {}", report.vendor);
                println!("product:      {}", report.product);
                println!("guest:        {:?}", report.guest);
                println!("virtio:       {}", report.virtio);
            }
        }
    }
    Ok(())
}
