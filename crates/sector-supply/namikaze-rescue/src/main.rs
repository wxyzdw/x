// SPDX-License-Identifier: MPL-2.0
//! namikaze-rescue: offline rescue environment planner.
//!
//! When the sealed system cannot boot, rescue work must still start from a
//! verified, offline environment. This tool plans and emits that
//! environment: the Limine menu entry pointing at the rescue tree, the
//! chroot recipe for repairing a broken slot, and the ordering constraints
//! (dm-verity disabled, persist volume closed by default, network absent).
//! The plan is pure output; nothing is executed without --yes-style
//! confirmation by the operator.

#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use namikaze_common::{init_tracing, Result, VAR_DIR};
use namikaze_rt::args::Cli;

pub mod plan;

use plan::{RescuePlan, RescueTarget};

const USAGE: &[&str] = &[
    "namikaze-rescue: boot a known-good update slot from the rescue shell",
    "",
    "usage:",
    "  namikaze-rescue plan [TREE]    print the rescue plan (boot tree + slots)",
    "  namikaze-rescue emit [TREE]    write the entry + chroot recipe to /run",
];

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }

    let target = RescueTarget {
        tree: cli.free(&[]).get(1).cloned().unwrap_or_else(|| "x86-64".into()),
        slots_dir: format!("{VAR_DIR}/namikaze/updates"),
    };

    match cli.sub().unwrap_or_default() {
        "plan" => {
            let plan = RescuePlan::build(&target);
            println!("{}", plan.render_entry());
            println!("{}", plan.render_recipe());
        }
        "emit" => {
            let plan = RescuePlan::build(&target);
            let out = Path::new(namikaze_common::RUN_DIR).join("rescue");
            fs::create_dir_all(&out)?;
            fs::write(out.join("rescue-entry.conf"), plan.render_entry())?;
            fs::write(out.join("repair-recipe.sh"), plan.render_recipe())?;
            println!("rescue artifacts written to {}", out.display());
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
