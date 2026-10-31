// SPDX-License-Identifier: MPL-2.0
//! iso: stage per-arch inputs and print the OneISO command.

use std::path::Path;

use namikaze_common::{Error, Result};

pub(crate) fn run(root: &Path) -> Result<()> {
    let manifest = root.join("iso/manifest/oneiso.toml");
    if !manifest.exists() {
        return Err(Error::Other("iso/manifest/oneiso.toml missing".into()));
    }
    let staging = root.join("dist/iso-staging");
    std::fs::create_dir_all(&staging)?;
    println!("staging at {}", staging.display());
    println!("copy per-arch inputs per manifest (CI supplies dist/ inputs)");
    println!("+ genisoimage -o NamikazeOS-{}-unified.iso \\", namikaze_common::VERSION);
    println!("    -c boot/boot.cat -b limine-bios-cd.bin -no-emul-boot \\");
    println!("    -boot-load-size 4 -boot-info-table \\");
    println!("    -eltorito-alt-boot -e limine-uefi-cd.bin -no-emul-boot \\");
    println!("    -isohybrid-gpt-basdat -V NAMIKAZE_ISO {}", staging.display());
    println!("+ limine bios-install <image>  (hybrid MBR seal)");
    println!("(execution happens in CI once the forge is unfrozen)");
    Ok(())
}
