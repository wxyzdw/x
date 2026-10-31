// SPDX-License-Identifier: MPL-2.0
//! sbom: emit the dist/sbom.json inventory of workspace crates.

use std::path::Path;

use namikaze_common::Result;
use namikaze_rt::fsutil::walk_files;
use namikaze_rt::json::{obj, Value};

pub(crate) fn workspace_crates(root: &Path) -> Result<Value> {
    let mut crates = Vec::new();
    let mut manifests = Vec::new();
    for group in ["lib", "services", "tools"] {
        manifests.extend(walk_files(&root.join(group)));
    }
    manifests.sort();
    for manifest in manifests {
        if manifest.file_name().map(|n| n != "Cargo.toml").unwrap_or(true) {
            continue;
        }
        let raw = std::fs::read_to_string(&manifest)?;
        let name = raw
            .lines()
            .find(|l| l.trim_start().starts_with("name = "))
            .map(|l| l.trim_start().trim_start_matches("name = ").trim_matches('"').to_string())
            .unwrap_or_default();
        let group = manifest
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        crates.push(obj(&[
            ("name", Value::Str(name)),
            ("group", Value::Str(group)),
            ("version", Value::Str(namikaze_common::VERSION.to_string())),
        ]));
    }
    Ok(obj(&[
        ("name", Value::Str("NamikazeOS".into())),
        ("version", Value::Str(namikaze_common::VERSION.into())),
        ("license", Value::Str("MPL-2.0".into())),
        ("third_party_dependencies", Value::Int(0)),
        ("crates", Value::Arr(crates)),
    ]))
}

pub(crate) fn run(root: &Path) -> Result<()> {
    std::fs::create_dir_all(root.join("dist"))?;
    let v = workspace_crates(root)?;
    let count = v.get("crates").and_then(|c| c.as_arr()).map(|a| a.len()).unwrap_or(0);
    std::fs::write(root.join("dist/sbom.json"), v.to_pretty())?;
    println!("sbom written: dist/sbom.json ({count} crates)");
    Ok(())
}
