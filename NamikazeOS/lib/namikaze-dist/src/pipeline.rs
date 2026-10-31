// SPDX-License-Identifier: MPL-2.0
//! pipeline: the one-pass release build.
//!
//! `full_build` is what a plain `cargo build` at the workspace root
//! executes through the `namikaze` tool's build script. Order matters:
//!
//! 1. guards - the ten tree guards (ascii .. modes) must pass
//! 2. sbom - dist/sbom.json inventory refresh
//! 3. kernel - bare-metal kernel: build, validate ELF + Limine markers,
//!    stage under dist/kernel
//! 4. namfs - the deterministic demo volume (airootfs config, sealed
//!    with the documented passphrase) under dist/namfs
//! 5. iso - staging tree + ISO9660/El Torito image + .sha256
//! 6. audit - independent deep audit of the finished image
//! 7. checksums - dist/SHA256SUMS over every produced artifact
//!
//! Every step is idempotent and deterministic; rerunning the build
//! produces byte-identical artifacts (bootid is reused from dist/bootid
//! once it exists).

use std::path::Path;

use namikaze_common::{Error, Result};
use namikaze_rt::sha256::sha256;

use crate::{rust_kernel, verify};

/// Run the complete dist pipeline. `root` is the workspace root
/// (NamikazeOS/).
pub fn full_build(root: &Path) -> Result<()> {
    let version = namikaze_common::VERSION;
    println!("namikaze-pipeline: root {}, version {version}", root.display());

    println!("pipeline [1/7]: tree guards");
    namikaze_guards::verify_all(root)?;

    println!("pipeline [2/7]: sbom");
    namikaze_common::sbom::run(root)?;

    println!("pipeline [3/7]: bare-metal kernel");
    rust_kernel::run(root)?;

    println!("pipeline [4/7]: NamFS demo volume");
    demo_volume(root, version)?;

    println!("pipeline [5/7]: OneISO image");
    namikaze_iso::run(root)?;

    println!("pipeline [6/7]: deep audit");
    let iso = root.join("dist").join(format!("NamikazeOS-{version}-oneiso.iso"));
    let staging = root.join("dist/iso-staging");
    let failures = namikaze_iso::audit::run(&iso, &staging)?;
    if failures > 0 {
        return Err(Error::Other(format!("pipeline: audit reported {failures} failure(s)")));
    }

    println!("pipeline [7/7]: checksums");
    verify::run(root)?;

    println!("pipeline: dist complete");
    Ok(())
}

/// Deterministic NamFS demo volume for the airootfs persistent layer.
///
/// Salt, uuid and timestamp derive from the version string, the
/// passphrase is documented (`namikaze-demo`) and the contents come from
/// the airootfs tree, so the volume - and therefore the ISO - is byte
/// reproducible. Inspect it with:
/// `NAMFS_PASSPHRASE=namikaze-demo namikaze-fstool info <volume>`.
pub fn demo_volume(root: &Path, version: &str) -> Result<()> {
    let out_dir = root.join("dist/namfs");
    std::fs::create_dir_all(&out_dir)?;
    let volume = out_dir.join("namikaze-demo.namfs");

    let digest = sha256(format!("namikaze/namfs/demo/{version}").as_bytes());
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&digest[..32]);
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&digest[16..32]);

    let airootfs = root.join("airootfs/etc/namikaze");
    let read = |name: &str| -> Result<Vec<u8>> {
        std::fs::read(airootfs.join(name)).map_err(|e| {
            Error::Other(format!("pipeline: airootfs/etc/namikaze/{name} missing: {e}"))
        })
    };
    let motd = read("motd")?;
    let conf = read("namfs.conf")?;
    let tab = read("namfs.tab")?;
    let readme = format!(
        "NamikazeOS {version} - NamFS demo volume\n\n\
         This container is the persistent layer demo of the airootfs\n\
         live system. Passphrase: namikaze-demo (documented in the\n\
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

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_demo_tree(dir: &Path) {
        std::fs::create_dir_all(dir.join("airootfs/etc/namikaze")).unwrap();
        std::fs::write(dir.join("airootfs/etc/namikaze/motd"), "demo motd\n").unwrap();
        std::fs::write(dir.join("airootfs/etc/namikaze/namfs.conf"), "mode = \"persistent\"\n")
            .unwrap();
        std::fs::write(dir.join("airootfs/etc/namikaze/namfs.tab"), "# demo\n").unwrap();
    }

    #[test]
    fn demo_volume_is_deterministic_and_openable() {
        let dir = std::env::temp_dir().join("namfs-demo-test");
        let _ = std::fs::remove_dir_all(&dir);
        seed_demo_tree(&dir);
        demo_volume(&dir, "1.0.0-test").unwrap();
        let first = std::fs::read(dir.join("dist/namfs/namikaze-demo.namfs")).unwrap();
        std::fs::remove_file(dir.join("dist/namfs/namikaze-demo.namfs")).unwrap();
        demo_volume(&dir, "1.0.0-test").unwrap();
        let second = std::fs::read(dir.join("dist/namfs/namikaze-demo.namfs")).unwrap();
        assert_eq!(first, second, "demo volume must be byte-deterministic");
        let opened =
            namikaze_fs::list(&dir.join("dist/namfs/namikaze-demo.namfs"), b"namikaze-demo")
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
        let a = std::fs::read(dir.join("dist/namfs/namikaze-demo.namfs")).unwrap();
        std::fs::remove_file(dir.join("dist/namfs/namikaze-demo.namfs")).unwrap();
        demo_volume(&dir, "1.0.0-b").unwrap();
        let b = std::fs::read(dir.join("dist/namfs/namikaze-demo.namfs")).unwrap();
        assert_ne!(a, b, "different versions must seal differently");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
