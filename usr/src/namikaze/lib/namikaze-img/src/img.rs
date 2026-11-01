// SPDX-License-Identifier: MPL-2.0
//! The NamikazeIMG assembler: the repository's filesystem tree, sealed
//! into one fully-encrypted single-partition disk image.
//!
//! The shape of the artifact, and the reason it replaces the live ISO
//! as the release image:
//!
//! - **one partition** - a GPT disk whose single partition is typed
//!   NamikazeOS-NamFS and labelled `NAMIKAZE_ROOT`; there is no boot
//!   partition, no swap, no second copy of anything to leak;
//! - **everything encrypted** - the partition is one NamFS v1
//!   container, every 4096-byte sector sealed with XTS-AES-256, the
//!   header bound to the passphrase by HMAC and a PBKDF2 gate; inside
//!   it, the rootfs rides as one `rootfs.nampack` stream whose every
//!   file carries its own SHA-256;
//! - **byte-reproducible** - salt, UUID, disk GUID, partition GUID
//!   and size all derive from the version string and the tree, the
//!   timestamp is zero, so the same checkout builds the same image.
//!
//! The default passphrase is the documented demo seal
//! (`namikaze-demo`, the same convention the demo volume and the old
//! ISO used); `NAMIKAZE_IMG_PASSPHRASE` overrides it for a private
//! build (at the documented cost of reproducibility). Real
//! deployments create their own volume with
//! `namikaze-fstool create`; a shipped image is a reproducible
//! reference artifact, not a secret.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use namikaze_common::{Error, Result};
use namikaze_rt::sha256::{sha256, sha256_file_hex};

use crate::gpt::{self, Guid, Layout};
use crate::pack::{self, File};

/// The top-level trees the image carries. `usr/src` (the build
/// sources) and the workspace `target`/`dist` trees are build-side
/// state and are deliberately excluded, exactly like the release zip
/// draws its own boundary.
const ROOTFS_DIRS: [&str; 6] = ["etc", "boot", "usr/bin", "lib", "root", "var"];

/// The documented demo seal; override with `NAMIKAZE_IMG_PASSPHRASE`.
pub const DEMO_PASSPHRASE: &[u8] = b"namikaze-demo";

pub(crate) fn passphrase() -> Vec<u8> {
    std::env::var("NAMIKAZE_IMG_PASSPHRASE")
        .map(|p| p.into_bytes())
        .unwrap_or_else(|_| DEMO_PASSPHRASE.to_vec())
}

/// Gather the rootfs: name (slash-separated, root-relative), POSIX
/// mode, content. Sorted, deterministic, regular files only.
pub fn collect(root: &Path) -> Result<Vec<File>> {
    let mut files: BTreeMap<String, File> = BTreeMap::new();
    for dir in ROOTFS_DIRS {
        let base = root.join(dir);
        if !base.exists() {
            continue;
        }
        walk(&base, root, &mut files)?;
    }
    if files.is_empty() {
        return Err(Error::Other("img: the rootfs tree is empty".into()));
    }
    Ok(files.into_values().collect())
}

fn walk(dir: &Path, root: &Path, files: &mut BTreeMap<String, File>) -> Result<()> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .map(|e| e.path())
        .collect();
    entries.sort();
    for path in entries {
        let meta = std::fs::metadata(&path)
            .map_err(|e| Error::Other(format!("img: cannot stat {}: {e}", path.display())))?;
        if meta.is_dir() {
            walk(&path, root, files)?;
            continue;
        }
        if !meta.is_file() {
            // symlinks and specials are not packable
            continue;
        }
        let name = path
            .strip_prefix(root)
            .map_err(|_| Error::Other(format!("img: {} outside the root", path.display())))?
            .to_string_lossy()
            .replace('\\', "/");
        let mode = meta.permissions().mode() & 0o7777;
        let contents = std::fs::read(&path)
            .map_err(|e| Error::Other(format!("img: cannot read {}: {e}", path.display())))?;
        files.insert(name.clone(), File { name, mode, contents });
    }
    Ok(())
}

/// Size the NamFS container for the pack: the pack's data units plus
/// one MiB of headroom, the whole volume aligned to one MiB so the
/// GPT geometry stays clean.
fn volume_size(pack_len: usize) -> u64 {
    let data_offset = 512 + namikaze_fs::xts::DATA_UNIT as u64;
    let needed = data_offset
        + pack_len.div_ceil(namikaze_fs::xts::DATA_UNIT) as u64
            * namikaze_fs::xts::DATA_UNIT as u64;
    let mib = 1024 * 1024;
    needed.div_ceil(mib) * mib + mib
}

/// What `write` produced, for the pipeline log and the manifest.
#[derive(Debug, Clone)]
pub struct ImgStats {
    pub path: PathBuf,
    pub sha256: String,
    pub files: usize,
    pub rootfs_bytes: u64,
    pub volume_bytes: u64,
    pub disk_bytes: u64,
    pub partition_guid: Guid,
    pub disk_guid: Guid,
}

/// Build `dist/NamikazeOS-<version>-oneimg.img` (+ `.sha256`).
pub fn write(root: &Path) -> Result<ImgStats> {
    let version = namikaze_common::VERSION;
    let files = collect(root)?;
    let rootfs_bytes: u64 = files.iter().map(|f| f.contents.len() as u64).sum();
    let pack = pack::write(&files);

    let dist = namikaze_common::util::workspace_dir(root).join("dist");
    std::fs::create_dir_all(&dist)?;
    let volume_path = dist.join("namfs/oneimg.namfs");
    std::fs::create_dir_all(volume_path.parent().unwrap())?;

    let digest = sha256(format!("namikaze/img/namfs/{version}").as_bytes());
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&digest[..32]);
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&digest[16..32]);

    let size = volume_size(pack.len());
    let opts = namikaze_fs::CreateOptions {
        size_bytes: size,
        label: "NAMIKAZE_ROOT".into(),
        iterations: namikaze_fs::DEMO_ITERATIONS,
        salt: Some(salt),
        uuid: Some(uuid),
        created: 0,
    };
    let pass = passphrase();
    namikaze_fs::create(&volume_path, &pass, &opts)?;
    namikaze_fs::put_all(&volume_path, &pass, &[(PACK_ENTRY, &pack)])?;
    namikaze_fs::verify(&volume_path, &pass)?;

    // Assemble the disk: MBR + headers + entry arrays + the volume in
    // the partition; everything else zero.
    let layout = Layout::for_volume(size);
    let disk_guid = Guid::from_seed(&format!("namikaze/img/disk/{version}"));
    let part_guid = Guid::from_seed(&format!("namikaze/img/part/{version}"));
    let entries = gpt::entry_array(&layout, &part_guid);
    let entries_crc = crate::crc32::crc32(&entries);

    let mut img = vec![0u8; layout.disk_bytes() as usize];
    img[..512].copy_from_slice(&gpt::protective_mbr(&layout));
    let at = gpt::SECTOR as usize;
    img[at..at + 512].copy_from_slice(&gpt::header(&layout, &disk_guid, entries_crc, true));
    let at = (gpt::SECTOR * 2) as usize;
    img[at..at + entries.len()].copy_from_slice(&entries);
    let (span_at, span_len) = layout.partition_span();
    let volume = std::fs::read(&volume_path)?;
    if volume.len() as u64 != span_len {
        return Err(Error::Other(format!(
            "img: volume {} bytes != partition span {span_len}",
            volume.len()
        )));
    }
    img[span_at as usize..(span_at + span_len) as usize].copy_from_slice(&volume);
    let at = (gpt::SECTOR * layout.backup_entries) as usize;
    img[at..at + entries.len()].copy_from_slice(&entries);
    let at = (gpt::SECTOR * layout.backup_header) as usize;
    img[at..at + 512].copy_from_slice(&gpt::header(&layout, &disk_guid, entries_crc, false));

    let name = format!("NamikazeOS-{version}-oneimg.img");
    let out = dist.join(&name);
    let mut f = std::fs::File::create(&out)?;
    f.write_all(&img)?;
    f.sync_all()?;
    let sha = sha256_file_hex(&out)?;
    std::fs::write(dist.join(format!("{name}.sha256")), format!("{sha}  {name}\n"))?;
    std::fs::remove_file(&volume_path).ok();

    println!(
        "img: {} ({} files / {} rootfs bytes in a {} MiB encrypted partition, disk {} MiB)",
        out.display(),
        files.len(),
        rootfs_bytes,
        size / (1024 * 1024),
        layout.disk_bytes() / (1024 * 1024),
    );
    println!(
        "img: partlabel NAMIKAZE_ROOT, partition guid {}, disk guid {}, sha256 {sha}",
        part_guid.to_hyphenated(),
        disk_guid.to_hyphenated(),
    );
    Ok(ImgStats {
        path: out,
        sha256: sha,
        files: files.len(),
        rootfs_bytes,
        volume_bytes: size,
        disk_bytes: layout.disk_bytes(),
        partition_guid: part_guid,
        disk_guid,
    })
}

/// The pack entry names inside the volume.
pub const PACK_ENTRY: &str = "rootfs.nampack";

/// The SHA-256 of the pack blob, as stored in the volume entry table.
pub fn pack_digest(pack: &[u8]) -> [u8; 32] {
    sha256(pack)
}

/// Human-readable structure report for one image: the GPT layer, then
/// the NamFS layer with its entry list (the `imginfo` subcommand).
pub fn inspect(img_path: &Path) -> Result<String> {
    let blob = std::fs::read(img_path)
        .map_err(|e| Error::Other(format!("imginfo: cannot read {}: {e}", img_path.display())))?;
    let info = gpt::parse(&blob)?;
    let (span_at, span_len) = info.layout.partition_span();
    let temp = std::env::temp_dir().join(format!(
        "namikaze-imginfo-{}-{}.namfs",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    ));
    std::fs::write(&temp, &blob[span_at as usize..(span_at + span_len) as usize])
        .map_err(|e| Error::Other(format!("imginfo: cannot stage the partition: {e}")))?;
    let report = (|| -> Result<String> {
        let pass = passphrase();
        let vinfo = namikaze_fs::info(&temp, &pass)?;
        let mut out = String::new();
        out.push_str(&format!("image:       {} ({} bytes)\n", img_path.display(), blob.len()));
        out.push_str(&format!(
            "partition:   LBA {}..{}, {} MiB, partlabel {}\n",
            info.layout.partition_first,
            info.layout.partition_last,
            span_len / (1024 * 1024),
            info.partlabel
        ));
        out.push_str(&format!("disk guid:       {}\n", info.disk_guid.to_hyphenated()));
        out.push_str(&format!("partition guid:  {}\n", info.partition_guid.to_hyphenated()));
        out.push_str(&format!(
            "volume:     label {:?}, uuid {}, created {}, PBKDF2 {} iterations\n",
            vinfo.label, vinfo.uuid_hex, vinfo.created, vinfo.iterations
        ));
        out.push_str(&format!(
            "container:  {} bytes, {} data units, {} entries:\n",
            vinfo.total_size,
            vinfo.data_units,
            vinfo.entries.len()
        ));
        for (name, size) in &vinfo.entries {
            out.push_str(&format!("  {name} ({size} bytes)\n"));
        }
        Ok(out)
    })();
    std::fs::remove_file(&temp).ok();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_root(dir: &Path) {
        for rel in [
            "etc/os-release",
            "etc/init.d/greetd",
            "boot/limine.conf",
            "root/.profile",
            "usr/bin/namikaze-session",
            "var/lib/namikaze/state",
        ] {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, format!("{rel}\n")).unwrap();
        }
        // executable bit on the session script
        let mut perm =
            std::fs::metadata(dir.join("usr/bin/namikaze-session")).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(dir.join("usr/bin/namikaze-session"), perm).unwrap();
    }

    #[test]
    fn collect_walks_the_trees_with_modes() {
        let dir = std::env::temp_dir().join("namikaze-img-collect");
        let _ = std::fs::remove_dir_all(&dir);
        seed_root(&dir);
        let files = collect(&dir).unwrap();
        assert_eq!(files.len(), 6);
        assert_eq!(files[0].name, "boot/limine.conf"); // sorted
        let session = files.iter().find(|f| f.name == "usr/bin/namikaze-session").unwrap();
        assert_eq!(session.mode & 0o111, 0o111);
        let osrel = files.iter().find(|f| f.name == "etc/os-release").unwrap();
        assert_eq!(osrel.mode, 0o644);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn volume_size_is_deterministic_and_aligned() {
        let a = volume_size(1000);
        let b = volume_size(1000);
        let c = volume_size(1001);
        assert_eq!(a, b);
        assert!(a % (1024 * 1024) == 0);
        assert!(a >= 1024 * 1024 * 2);
        assert!(c >= a);
    }

    #[test]
    fn full_image_is_reproducible_and_audits_clean() {
        let dir = std::env::temp_dir().join("namikaze-img-build");
        let _ = std::fs::remove_dir_all(&dir);
        seed_root(&dir);
        // the pipeline resolves dist under <root>/usr/src/namikaze
        std::env::remove_var("NAMIKAZE_IMG_PASSPHRASE");
        let stats = write(&dir).unwrap();
        let first = std::fs::read(&stats.path).unwrap();
        std::fs::remove_file(&stats.path).unwrap();
        let stats2 = write(&dir).unwrap();
        let second = std::fs::read(&stats2.path).unwrap();
        assert_eq!(first, second, "the image must be byte-reproducible");
        assert_eq!(stats.sha256, stats2.sha256);

        // the independent audit passes against the same tree
        let failures = crate::audit::run(&stats2.path, &dir).unwrap();
        assert_eq!(failures, 0);
        std::fs::remove_dir_all(&dir).ok();
    }
}
