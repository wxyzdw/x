// SPDX-License-Identifier: MPL-2.0
//! namikaze-hal command line interface.
//!
//! apply          - write the hardware plan for the running machine
//! list           - list all board profiles in the database
//! firmware-plan  - print linux-firmware subdirectories for a board
//! report         - print the detected hardware report as JSON

#![forbid(unsafe_code)]

use namikaze_common::{init_tracing, Result};
use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-hal: hardware adaptation layer (OneISO, every machine)",
    "",
    "usage:",
    "  namikaze-hal apply [--run-dir /run/namikaze] [--from-env]   write the hardware plan",
    "  namikaze-hal list                                           list every board profile",
    "  namikaze-hal firmware-plan <board>                          linux-firmware dir set",
    "  namikaze-hal report                                         detected hardware as JSON",
];

fn main() {
    init_tracing("info");
    if let Err(e) = run() {
        eprintln!("[namikaze-hal] error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let free = cli.free(&[]);
    match cli.sub().unwrap_or_default() {
        "apply" => {
            let run_dir = std::path::PathBuf::from(cli.value_or("run-dir", "/run/namikaze"));
            let from_env = cli.flag("from-env");
            let report = if from_env {
                match namikaze_hal::HardwareReport::from_env_file(&run_dir.join("hardware.env")) {
                    Ok(r) => r,
                    Err(_) => namikaze_hal::HardwareReport::from_sysfs()?,
                }
            } else {
                namikaze_hal::HardwareReport::from_sysfs()?
            };
            let plan = namikaze_hal::apply(&report, &run_dir)?;
            println!(
                "board={} arch={} gpu={} wifi={}",
                plan.board, plan.arch, plan.gpu_driver, plan.wifi_driver
            );
        }
        "list" => {
            for b in namikaze_hal::board_db::BOARDS {
                println!(
                    "{:<20} {:<10} dtb={}",
                    b.id,
                    b.arch.as_str(),
                    if b.dtb.is_empty() { "(firmware)" } else { b.dtb }
                );
            }
        }
        "firmware-plan" => {
            let board = free.get(1).cloned().unwrap_or_default();
            for dir in namikaze_hal::firmware_plan(&board)? {
                println!("{dir}");
            }
        }
        "report" => {
            let r = namikaze_hal::HardwareReport::from_sysfs()?;
            println!("{}", hal_report_json(&r).to_pretty());
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}

fn hal_report_json(r: &namikaze_hal::HardwareReport) -> namikaze_rt::json::Value {
    use namikaze_rt::json::{obj, Value};
    obj(&[
        ("arch", r.arch.map(|a| Value::Str(a.as_tag().to_string())).unwrap_or(Value::Null)),
        (
            "dt_compatibles",
            Value::Arr(r.dt_compatibles.iter().map(|s| Value::Str(s.clone())).collect()),
        ),
        ("dmi_board_name", r.dmi_board_name.clone().map(Value::Str).unwrap_or(Value::Null)),
        ("dmi_board_vendor", r.dmi_board_vendor.clone().map(Value::Str).unwrap_or(Value::Null)),
        ("cpu_model", r.cpu_model.clone().map(Value::Str).unwrap_or(Value::Null)),
        ("ram_kb", Value::Int(r.ram_kb as i64)),
    ])
}
