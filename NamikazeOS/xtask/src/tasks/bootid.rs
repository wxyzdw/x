// SPDX-License-Identifier: MPL-2.0
//! bootid: generate the boot seal id (dist/bootid).

use std::path::Path;

use namikaze_common::Result;

pub(crate) fn run(root: &Path) -> Result<()> {
    std::fs::create_dir_all(root.join("dist"))?;
    let id = namikaze_rt::random::id_hex()?;
    std::fs::write(root.join("dist/bootid"), id.clone())?;
    println!("bootid: {id} (written to dist/bootid)");
    Ok(())
}
