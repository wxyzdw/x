// SPDX-License-Identifier: MPL-2.0
//! release: package the source tree as a zip artifact with its SHA-256.

use std::path::Path;

use namikaze_common::{Error, Result};
use namikaze_rt::sha256::sha256_file_hex;

pub fn run(root: &Path, out: &Path) -> Result<()> {
    std::fs::create_dir_all(out)?;
    let ver = namikaze_common::VERSION;
    let zip_path = out.join(format!("NamikazeOS-{ver}-source.zip"));
    let status = std::process::Command::new("zip")
        .arg("-rq")
        .arg(&zip_path)
        .arg(".")
        .arg("-x")
        .arg(".git/*")
        .arg("target/*")
        .arg("dist/*")
        .arg("*.zip")
        .arg("skills/*")
        .arg("upload/*")
        .arg("download/*")
        .arg("scripts/*")
        .arg(".env")
        .current_dir(root)
        .status()
        .map_err(|e| Error::Other(format!("zip unavailable: {e}")))?;
    if !status.success() {
        return Err(Error::Other("zip failed".into()));
    }
    let digest = sha256_file_hex(&zip_path)?;
    std::fs::write(
        out.join(format!("NamikazeOS-{ver}-rust-workspace.zip.sha256")),
        format!("{digest}  {}\n", zip_path.file_name().unwrap_or_default().to_string_lossy()),
    )?;
    println!("release: {}", zip_path.display());
    println!("sha256:  {digest}");
    Ok(())
}
