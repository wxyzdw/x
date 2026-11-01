// SPDX-License-Identifier: MPL-2.0
//! The independent audit of a NamikazeIMG image, in the spirit of the
//! OneISO audit: parse everything back from the bytes on disk and
//! compare against the source tree, reporting every mismatch instead
//! of trusting the writer.
//!
//! Layers verified, outermost first:
//!
//! 1. the disk: protective MBR, both GPT headers (signature, CRC,
//!    cross-agreement), the entry array on both sides (CRC, equality),
//!    exactly one partition of the NamikazeOS type;
//! 2. the volume: the partition bytes authenticate as NamFS v1 with
//!    the pipeline passphrase and pass the full per-file hash pass;
//! 3. the rootfs: the `rootfs.nampack` entry unpacks with every
//!    inner SHA-256 intact, and the file set - names, modes, content
//!    hashes - matches the repository tree exactly.

use std::path::Path;

use namikaze_common::{Error, Result};
use namikaze_rt::sha256::{sha256, sha256_file_hex};

use crate::gpt;
use crate::img;
use crate::pack;

/// Audit one image against the source tree. Returns the number of
/// failures (0 = clean); every failure is printed as it is found.
pub fn run(img_path: &Path, root: &Path) -> Result<usize> {
    let mut failures = 0usize;
    let mut problem = |msg: String| {
        failures += 1;
        println!("img-audit: FAIL {msg}");
    };

    let pass = img::passphrase();
    let blob = std::fs::read(img_path)
        .map_err(|e| Error::Other(format!("img-audit: cannot read {}: {e}", img_path.display())))?;
    println!(
        "img-audit: {} ({} bytes, sha256 {})",
        img_path.display(),
        blob.len(),
        sha256_file_hex(img_path)?
    );

    // 1. the disk
    let info = match gpt::parse(&blob) {
        Ok(info) => {
            println!(
                "img-audit: GPT ok - partlabel {}, partition guid {}, disk guid {}",
                info.partlabel,
                info.partition_guid.to_hyphenated(),
                info.disk_guid.to_hyphenated()
            );
            info
        }
        Err(e) => {
            problem(format!("GPT: {e}"));
            return Ok(failures);
        }
    };
    let version = namikaze_common::VERSION;
    if info.disk_guid != gpt::Guid::from_seed(&format!("namikaze/img/disk/{version}")) {
        problem("disk guid does not match the version seed".into());
    }
    if info.partition_guid != gpt::Guid::from_seed(&format!("namikaze/img/part/{version}")) {
        problem("partition guid does not match the version seed".into());
    }

    // 2. the volume
    let (span_at, span_len) = info.layout.partition_span();
    let volume_bytes = &blob[span_at as usize..(span_at + span_len) as usize];
    let temp = std::env::temp_dir().join(format!(
        "namikaze-img-audit-{}-{}.namfs",
        std::process::id(),
        timestamp_component()
    ));
    std::fs::write(&temp, volume_bytes)
        .map_err(|e| Error::Other(format!("img-audit: cannot stage the partition: {e}")))?;
    let audit = (|| -> Result<usize> {
        let entries =
            namikaze_fs::verify(&temp, &pass).map_err(|e| Error::Other(format!("volume: {e}")))?;
        println!("img-audit: NamFS ok - {entries} entries, every sector hash verified");
        Ok(entries)
    })();
    let entries = match audit {
        Ok(n) => n,
        Err(e) => {
            problem(format!("{e}"));
            std::fs::remove_file(&temp).ok();
            return Ok(failures);
        }
    };

    // 3. the rootfs: expected set from the tree, actual set from the pack
    let expected = img::collect(root)?;
    let pack_blob = match namikaze_fs::get(&temp, &pass, img::PACK_ENTRY) {
        Ok(b) => b,
        Err(e) => {
            problem(format!("volume: missing {}: {e}", img::PACK_ENTRY));
            std::fs::remove_file(&temp).ok();
            return Ok(failures);
        }
    };
    let actual = match pack::read(&pack_blob) {
        Ok(a) => a,
        Err(e) => {
            problem(format!("pack: {e}"));
            std::fs::remove_file(&temp).ok();
            return Ok(failures);
        }
    };
    std::fs::remove_file(&temp).ok();

    if actual.len() != expected.len() {
        problem(format!(
            "rootfs: pack has {} files, the tree has {}",
            actual.len(),
            expected.len()
        ));
    }
    let mut rootfs_bytes = 0u64;
    for (want, got) in expected.iter().zip(actual.iter()) {
        rootfs_bytes += got.contents.len() as u64;
        if want.name != got.name {
            problem(format!("rootfs: name order mismatch {} vs {}", want.name, got.name));
            continue;
        }
        if want.mode != got.mode {
            problem(format!(
                "rootfs: mode drift on {} ({:o} vs {:o})",
                want.name, want.mode, got.mode
            ));
        }
        if sha256(&want.contents) != sha256(&got.contents) {
            problem(format!("rootfs: content drift on {}", want.name));
        }
    }
    println!(
        "img-audit: rootfs ok - {}/{} files, {rootfs_bytes} bytes, modes and hashes match the tree",
        actual.len(),
        expected.len()
    );
    let _ = entries;

    if failures == 0 {
        println!("img-audit: clean - 0 failures");
    } else {
        println!("img-audit: {failures} failure(s)");
    }
    Ok(failures)
}

fn timestamp_component() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_reports_drift() {
        let dir = std::env::temp_dir().join("namikaze-img-audit-drift");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("etc/one"), "one\n").unwrap();
        std::env::remove_var("NAMIKAZE_IMG_PASSPHRASE");
        let stats = img::write(&dir).unwrap();
        // clean now
        assert_eq!(run(&stats.path, &dir).unwrap(), 0);
        // the tree grew after the image was written -> a content set
        // mismatch must be reported
        std::fs::write(dir.join("etc/two"), "two\n").unwrap();
        let failures = run(&stats.path, &dir).unwrap();
        assert!(failures > 0);
        std::fs::remove_dir_all(&dir).ok();
    }
}
