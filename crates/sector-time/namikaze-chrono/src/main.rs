// SPDX-License-Identifier: MPL-2.0
//! namikaze-chrono CLI: date/now helpers for scripts.

#![forbid(unsafe_code)]

use namikaze_rt::args::Cli;

const USAGE: &[&str] = &[
    "namikaze-chrono: dependency-free civil time helpers",
    "",
    "usage:",
    "  namikaze-chrono now               current UTC time, ISO-8601",
    "  namikaze-chrono unix              unix seconds",
    "  namikaze-chrono parse <ISO>       ISO-8601 -> unix seconds",
    "  namikaze-chrono format <UNIX>     unix seconds -> ISO-8601",
    "  namikaze-chrono local [--zone PATH]   local time via TZif",
];

fn main() {
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let now: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let free = cli.free(&[]);
    match cli.sub().unwrap_or_default() {
        "now" => println!("{}", namikaze_chrono::format_iso(now)),
        "unix" => println!("{now}"),
        "parse" => match free.get(1).and_then(|s| namikaze_chrono::parse_iso(s)) {
            Some(v) => println!("{v}"),
            None => {
                eprintln!("cannot parse input");
                std::process::exit(1);
            }
        },
        "format" => match free.get(1).and_then(|s| s.parse::<i64>().ok()) {
            Some(v) => println!("{}", namikaze_chrono::format_iso(v)),
            None => {
                eprintln!("cannot parse unix seconds");
                std::process::exit(1);
            }
        },
        "local" => {
            let zone_path = cli
                .value("zone")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from("/etc/localtime"));
            let zone = namikaze_chrono::zone_from_tzif(&zone_path, now)
                .unwrap_or(namikaze_chrono::Zone { offset_secs: 0 });
            let c = zone.local(now);
            println!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+{:02}:{:02}",
                c.year,
                c.month,
                c.day,
                c.hour,
                c.minute,
                c.second,
                zone.offset_secs.abs() / 3600,
                (zone.offset_secs.abs() % 3600) / 60
            );
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
}
