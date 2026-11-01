// SPDX-License-Identifier: MPL-2.0
//! bootid: the boot seal id (dist/bootid).
//!
//! A per-build random hex id the bootloader menu and the dist
//! manifest carry; the ISO era used it to stamp the El Torito menu,
//! the disk-image era uses it as the build's identity anchor.

use std::path::Path;

use namikaze_common::Result;

pub fn run(root: &Path) -> Result<()> {
    std::fs::create_dir_all(namikaze_common::util::workspace_dir(root).join("dist"))?;
    let id = namikaze_rt::random::id_hex()?;
    std::fs::write(namikaze_common::util::workspace_dir(root).join("dist/bootid"), id.clone())?;
    println!("bootid: {id} (written to dist/bootid)");
    Ok(())
}
