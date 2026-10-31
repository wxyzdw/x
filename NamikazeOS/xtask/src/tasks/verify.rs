// SPDX-License-Identifier: MPL-2.0
//! verify: emit SHA256SUMS for dist artifacts (own SHA-256).

use std::path::{Path, PathBuf};

use namikaze_common::Result;
use namikaze_rt::fsutil::walk_files;
use namikaze_rt::sha256::sha256_file_hex;

pub(crate) fn run(root: &Path) -> Result<()> {
    let dist = root.join("dist");
    let mut lines = Vec::new();
    let mut files: Vec<PathBuf> = walk_files(&dist)
        .into_iter()
        .filter(|p| p.file_name().map(|n| n != "SHA256SUMS").unwrap_or(true))
        .collect();
    files.sort();
    for f in &files {
        let digest = sha256_file_hex(f)?;
        let rel = f.strip_prefix(&dist).unwrap_or(f).display().to_string();
        lines.push(format!("{digest}  {rel}"));
    }
    std::fs::write(dist.join("SHA256SUMS"), lines.join("\n") + "\n")?;
    println!("SHA256SUMS written over {} file(s)", lines.len());
    Ok(())
}
