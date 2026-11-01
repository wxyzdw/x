// SPDX-License-Identifier: MPL-2.0
//! pipeline: the one-pass release build, expressed as a declarative
//! stage table.
//!
//! A plain `cargo build` at the workspace root executes
//! [`full_build`] through the `namikaze` tool's build script; the
//! stage table below is the single description of what that means.
//! Each stage is idempotent and deterministic; rerunning the build
//! produces byte-identical artifacts (the bootid is reused from
//! dist/bootid once it exists).
//!
//! 1. guards   - the ten tree guards (ascii .. modes) must pass
//! 2. sbom     - dist/sbom.json inventory refresh
//! 3. kernel   - bare-metal kernel: build, validate, stage dist/kernel
//! 4. namfs    - the deterministic demo volume under dist/namfs
//! 5. img      - NamikazeIMG: the single-partition fully-encrypted
//!    disk image, dist/NamikazeOS-<version>-oneimg.img
//! 6. audit    - independent re-parse of the image vs the tree
//! 7. manifest - dist/manifest.json: the build report (version, GUIDs,
//!    every artifact with its SHA-256)
//! 8. checksums- dist/SHA256SUMS over every produced artifact
//!

use std::path::Path;
use std::time::Instant;

use namikaze_common::{Error, Result};
use namikaze_rt::sha256::sha256;

use crate::{rust_kernel, verify};

/// One pipeline stage: a stable name, a human title, and the single
/// implementation behind it (the `namikaze` CLI's subcommands call
/// the same functions).
#[derive(Debug, Clone, Copy)]
pub struct Stage {
    pub name: &'static str,
    pub title: &'static str,
    pub run: fn(&Path) -> Result<()>,
}

/// The release pipeline, in execution order.
pub const STAGES: &[Stage] = &[
    Stage { name: "guards", title: "tree guards", run: |root| namikaze_guards::verify_all(root) },
    Stage { name: "sbom", title: "SBOM inventory", run: |root| namikaze_common::sbom::run(root) },
    Stage { name: "kernel", title: "bare-metal kernel", run: |root| rust_kernel::run(root) },
    Stage { name: "namfs", title: "NamFS demo volume", run: demo_stage },
    Stage {
        name: "img",
        title: "NamikazeIMG disk image",
        run: |root| namikaze_img::run(root).map(|_| ()),
    },
    Stage { name: "audit", title: "independent image audit", run: audit_stage },
    Stage { name: "manifest", title: "build manifest", run: manifest_stage },
    Stage { name: "checksums", title: "SHA256SUMS", run: |root| verify::run(root) },
];

/// Run the complete dist pipeline. `root` is the workspace root
/// (the filesystem root).
pub fn full_build(root: &Path) -> Result<()> {
    let version = namikaze_common::VERSION;
    println!("namikaze-pipeline: root {}, version {version}", root.display());
    let started = Instant::now();
    for (i, stage) in STAGES.iter().enumerate() {
        let t = Instant::now();
        println!("pipeline [{}/{}]: {}", i + 1, STAGES.len(), stage.title);
        (stage.run)(root)
            .map_err(|e| Error::Other(format!("pipeline stage {}: {e}", stage.name)))?;
        println!(
            "pipeline [{}/{}]: {} done in {:.2}s",
            i + 1,
            STAGES.len(),
            stage.title,
            t.elapsed().as_secs_f64()
        );
    }
    println!("pipeline: dist complete in {:.2}s", started.elapsed().as_secs_f64());
    Ok(())
}

fn demo_stage(root: &Path) -> Result<()> {
    demo_volume(root, namikaze_common::VERSION)
}

fn audit_stage(root: &Path) -> Result<()> {
    let img_path = namikaze_common::util::workspace_dir(root)
        .join("dist")
        .join(format!("NamikazeOS-{}-oneimg.img", namikaze_common::VERSION));
    let failures = namikaze_img::audit::run(&img_path, root)?;
    if failures > 0 {
        return Err(Error::Other(format!("pipeline: audit reported {failures} failure(s)")));
    }
    Ok(())
}

fn manifest_stage(root: &Path) -> Result<()> {
    write_manifest(root)
}

/// Deterministic NamFS demo volume for the persistent layer.
///
/// Salt, uuid and timestamp derive from the version string, the
/// passphrase is documented (`namikaze-demo`) and the contents come
/// from the airootfs tree, so the volume is byte reproducible.
/// Inspect it with:
/// `NAMFS_PASSPHRASE=namikaze-demo namikaze-fstool info <volume>`.
pub fn demo_volume(root: &Path, version: &str) -> Result<()> {
    let out_dir = namikaze_common::util::workspace_dir(root).join("dist/namfs");
    std::fs::create_dir_all(&out_dir)?;
    let volume = out_dir.join("namikaze-demo.namfs");

    let digest = sha256(format!("namikaze/namfs/demo/{version}").as_bytes());
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&digest[..32]);
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&digest[16..32]);

    let airootfs = root.join("etc/namikaze");
    let read = |name: &str| -> Result<Vec<u8>> {
        std::fs::read(airootfs.join(name))
            .map_err(|e| Error::Other(format!("pipeline: etc/namikaze/{name} missing: {e}")))
    };
    let motd = read("motd")?;
    let conf = read("namfs.conf")?;
    let tab = read("namfs.tab")?;
    let readme = format!(
        "NamikazeOS {version} - NamFS demo volume\n\n\
         This container is the persistent layer demo of the airootfs\n\
         system. Passphrase: namikaze-demo (documented in the\n\
         release notes; this is a demo, real volumes prompt for a\n\
         secret passphrase).\n\n\
         Inspect with:\n  \
         NAMFS_PASSPHRASE=namikaze-demo namikaze-fstool info namikaze-demo.namfs\n"
    );

    let opts = namikaze_fs::CreateOptions {
        size_bytes: 1024 * 1024,
        label: "namikaze-demo".into(),
        iterations: namikaze_fs::DEMO_ITERATIONS,
        salt: Some(salt),
        uuid: Some(uuid),
        created: 0,
    };
    let pass = b"namikaze-demo";
    namikaze_fs::create(&volume, pass, &opts)?;
    namikaze_fs::put(&volume, pass, "etc/namikaze/motd", &motd)?;
    namikaze_fs::put(&volume, pass, "etc/namikaze/namfs.conf", &conf)?;
    namikaze_fs::put(&volume, pass, "etc/namikaze/namfs.tab", &tab)?;
    namikaze_fs::put(&volume, pass, "README.txt", readme.as_bytes())?;
    let entries = namikaze_fs::verify(&volume, pass)?;
    println!(
        "pipeline: NamFS demo volume {} ({} entries, deterministic)",
        volume.display(),
        entries
    );
    Ok(())
}

/// Write dist/manifest.json: the build report - version, image, disk
/// and partition GUIDs, and every artifact with its SHA-256. The
/// checksum stage covers the manifest itself, so the report is bound
/// into SHA256SUMS like any other artifact.
pub fn write_manifest(root: &Path) -> Result<()> {
    let version = namikaze_common::VERSION;
    let dist = namikaze_common::util::workspace_dir(root).join("dist");
    let image_name = format!("NamikazeOS-{version}-oneimg.img");

    let mut artifacts: Vec<(String, String)> = Vec::new();
    for path in namikaze_rt::fsutil::walk_files(&dist) {
        let rel = path.strip_prefix(&dist).unwrap_or(&path).to_string_lossy().replace('\\', "/");
        if rel == "manifest.json" || rel == "SHA256SUMS" {
            continue;
        }
        let digest = namikaze_rt::sha256::sha256_file_hex(&path)?;
        artifacts.push((rel, digest));
    }
    artifacts.sort();

    let bootid = std::fs::read_to_string(dist.join("bootid"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"name\": \"NamikazeOS\",\n");
    out.push_str(&format!("  \"version\": \"{version}\",\n"));
    out.push_str(&format!("  \"image\": \"{image_name}\",\n"));
    if let Ok(stats) = std::fs::metadata(dist.join(&image_name)) {
        out.push_str(&format!("  \"image_bytes\": {},\n", stats.len()));
    }
    if !bootid.is_empty() {
        out.push_str(&format!("  \"bootid\": \"{bootid}\",\n"));
    }
    out.push_str("  \"artifacts\": [\n");
    for (i, (rel, digest)) in artifacts.iter().enumerate() {
        let comma = if i + 1 == artifacts.len() { "" } else { "," };
        out.push_str(&format!("    {{\"path\": \"{rel}\", \"sha256\": \"{digest}\"}}{comma}\n"));
    }
    out.push_str("  ]\n}\n");
    std::fs::write(dist.join("manifest.json"), out)?;
    println!("manifest: dist/manifest.json over {} artifact(s)", artifacts.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_demo_tree(dir: &Path) {
        std::fs::create_dir_all(dir.join("etc/namikaze")).unwrap();
        std::fs::write(dir.join("etc/namikaze/motd"), "demo motd\n").unwrap();
        std::fs::write(dir.join("etc/namikaze/namfs.conf"), "mode = \"persistent\"\n").unwrap();
        std::fs::write(dir.join("etc/namikaze/namfs.tab"), "# demo\n").unwrap();
    }

    #[test]
    fn stage_table_is_ordered_and_named() {
        let names: Vec<&str> = STAGES.iter().map(|s| s.name).collect();
        assert_eq!(
            names,
            vec!["guards", "sbom", "kernel", "namfs", "img", "audit", "manifest", "checksums"]
        );
    }

    #[test]
    fn demo_volume_is_deterministic_and_openable() {
        let dir = std::env::temp_dir().join("namfs-demo-test");
        let _ = std::fs::remove_dir_all(&dir);
        seed_demo_tree(&dir);
        demo_volume(&dir, "1.0.0-test").unwrap();
        let first =
            std::fs::read(dir.join("usr/src/namikaze/dist/namfs/namikaze-demo.namfs")).unwrap();
        std::fs::remove_file(dir.join("usr/src/namikaze/dist/namfs/namikaze-demo.namfs")).unwrap();
        demo_volume(&dir, "1.0.0-test").unwrap();
        let second =
            std::fs::read(dir.join("usr/src/namikaze/dist/namfs/namikaze-demo.namfs")).unwrap();
        assert_eq!(first, second, "demo volume must be byte-deterministic");
        let opened = namikaze_fs::list(
            &dir.join("usr/src/namikaze/dist/namfs/namikaze-demo.namfs"),
            b"namikaze-demo",
        )
        .unwrap();
        assert_eq!(opened.len(), 4);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn demo_volume_changes_with_version() {
        let dir = std::env::temp_dir().join("namfs-demo-version-test");
        let _ = std::fs::remove_dir_all(&dir);
        seed_demo_tree(&dir);
        demo_volume(&dir, "1.0.0-a").unwrap();
        let a = std::fs::read(dir.join("usr/src/namikaze/dist/namfs/namikaze-demo.namfs")).unwrap();
        std::fs::remove_file(dir.join("usr/src/namikaze/dist/namfs/namikaze-demo.namfs")).unwrap();
        demo_volume(&dir, "1.0.0-b").unwrap();
        let b = std::fs::read(dir.join("usr/src/namikaze/dist/namfs/namikaze-demo.namfs")).unwrap();
        assert_ne!(a, b, "different versions must seal differently");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
