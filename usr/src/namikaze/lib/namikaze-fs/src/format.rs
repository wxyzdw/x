// SPDX-License-Identifier: MPL-2.0
//! format: the NamFS v2 container.
//!
//! NamFS is the NamikazeOS encrypted persistent volume format: a single
//! file (or block device) that holds a small set of named, integrity-
//! checked files, every sector sealed with XTS-AES-256 and the whole
//! header HMAC-bound to the passphrase. It backs the persistent layer of
//! the live system: `mode=persistent` in the etc/namikaze persistence
//! policy points at a NamFS volume, and `namikaze-fstool`
//! (or the `namikaze` pipeline) creates and inspects it.
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! 0    .. 512    header (plaintext, HMAC-protected)
//! 512  .. 4608   superblock: 1 XTS data unit, tweak 0 (entry table)
//! 4608 .. total  data area: XTS units, tweak = unit index
//! ```
//!
//! The 512-byte header carries magic, KDF iteration count, KDF salt, a
//! passphrase verifier (HMAC over a known constant), volume uuid, creation
//! timestamp, label, geometry and `header_hmac` over bytes 0..472. The
//! master key is `PBKDF2-HMAC-SHA256(passphrase, salt, iters, 96)` split
//! into XTS data key (32) + XTS tweak key (32) + MAC key (32). A wrong
//! passphrase therefore fails before any data is touched.
//!
//! v2 (alpha.9) aligns the XTS tweaks with IEEE 1619: every data unit is
//! numbered by its position in the volume, so identical plaintext at
//! different offsets seals differently and the superblock shares the
//! numbering instead of borrowing tweak 0. v1 volumes (per-entry
//! numbering) are rejected by the magic, never mis-decrypted.
//!
//! v2 is deliberately simple: entries are rewrite-on-put (the superblock
//! and data area are rebuilt from memory), capacity is bounded by the
//! volume size given at creation, and integrity is per-file SHA-256 plus
//! the HMAC-anchored header. The deterministic constructor (fixed salt,
//! zero timestamp) exists so the release pipeline can ship a byte-stable
//! demo volume and the sealed partition inside the NamikazeIMG disk
//! image.

use std::path::Path;

use namikaze_common::{Error, Result};
use namikaze_rt::hmac::{hmac_sha256, pbkdf2_hmac_sha256};
use namikaze_rt::sha256::sha256;

use crate::aes::Aes256;
use crate::xts::{decrypt_unit, encrypt_unit, DATA_UNIT};

/// Container magic: `NamFS` + format version 2 (global IEEE 1619 tweak
/// numbering; v1 volumes are rejected, never mis-read).
pub const MAGIC: [u8; 8] = *b"NamFS\x02\x00\x00";
const HEADER_LEN: usize = 512;
const SUPERBLOCK_UNITS: u64 = 1;
const DATA_OFFSET: u64 = HEADER_LEN as u64 + SUPERBLOCK_UNITS * DATA_UNIT as u64;
const HEADER_HMAC_OFFSET: usize = 472;
const MAX_ENTRIES: usize = 28;
const ENTRY_LEN: usize = 144;
const NAME_LEN: usize = 96;
const VERIFIER_DOMAIN: &[u8] = b"namfs/v1/verifier";

const OFF_ITERATIONS: usize = 8;
const OFF_SALT: usize = 12;
const OFF_VERIFIER: usize = 44;
const OFF_UUID: usize = 76;
const OFF_CREATED: usize = 92;
const OFF_LABEL: usize = 100;
const OFF_TOTAL: usize = 180;
const OFF_UNITS: usize = 188;

/// Master material derived from the passphrase.
struct Keys {
    data: Aes256,
    tweak: Aes256,
    mac: [u8; 32],
}

fn derive_keys(pass: &[u8], salt: &[u8], iterations: u32) -> Keys {
    let master = pbkdf2_hmac_sha256(pass, salt, iterations, 96);
    let (data_key, tweak_key) = {
        let mut dk = [0u8; 32];
        let mut tk = [0u8; 32];
        dk.copy_from_slice(&master[..32]);
        tk.copy_from_slice(&master[32..64]);
        (dk, tk)
    };
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&master[64..96]);
    Keys { data: Aes256::new(&data_key), tweak: Aes256::new(&tweak_key), mac }
}

/// One sealed file entry.
pub struct Entry {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    digest: [u8; 32],
}

/// An opened volume: parsed header, decrypted entry table, raw bytes.
pub struct Volume {
    keys: Keys,
    header: [u8; 512],
    pub salt: [u8; 32],
    pub uuid: [u8; 16],
    pub created: u64,
    pub label: String,
    pub iterations: u32,
    pub total_size: u64,
    pub data_units: u64,
    data: Vec<u8>,
    entries: Vec<Entry>,
}

impl Volume {
    fn read_verified(&self, entry: &Entry) -> Result<Vec<u8>> {
        let body = self.read_entry(entry)?;
        if sha256(&body) != entry.digest {
            return Err(Error::Crypto(format!(
                "namfs: content hash mismatch for {:?}",
                entry.name
            )));
        }
        Ok(body)
    }

    fn read_entry(&self, entry: &Entry) -> Result<Vec<u8>> {
        let mut out = vec![0u8; entry.size as usize];
        let units = (entry.size as usize).div_ceil(DATA_UNIT);
        for u in 0..units {
            let begin = self.data_at(entry.offset) + u * DATA_UNIT;
            let end = (begin + DATA_UNIT).min(self.data.len());
            let mut unit = self.data[begin..end].to_vec();
            // global tweak: the superblock is data unit 0, the data area
            // continues at 1 (IEEE 1619 numbering over the whole volume)
            let tweak = entry.offset / DATA_UNIT as u64 + u as u64 + 1;
            decrypt_unit(&self.keys.data, &self.keys.tweak, tweak, &mut unit);
            let dst = u * DATA_UNIT;
            let stop = (dst + unit.len()).min(out.len());
            out[dst..stop].copy_from_slice(&unit[..stop - dst]);
        }
        Ok(out)
    }

    fn data_at(&self, entry_offset: u64) -> usize {
        (DATA_OFFSET + entry_offset) as usize
    }

    /// Rebuild the superblock + data area from the current entry list and
    /// write the container back to disk (header preserved verbatim).
    fn persist(mut self, path: &Path, contents: &[(String, Vec<u8>)]) -> Result<()> {
        let mut entries: Vec<Entry> = Vec::new();
        let mut cursor = 0u64;
        for (name, body) in contents {
            let units = body.len().div_ceil(DATA_UNIT);
            let span = units as u64 * DATA_UNIT as u64;
            if cursor + span > self.data_units * DATA_UNIT as u64 {
                return Err(Error::Other(format!(
                    "namfs: volume full storing {name:?} ({} bytes free)",
                    self.data_units * DATA_UNIT as u64 - cursor
                )));
            }
            for u in 0..units {
                let begin = u * DATA_UNIT;
                let mut unit = vec![0u8; DATA_UNIT];
                let take = (body.len() - begin).min(DATA_UNIT);
                unit[..take].copy_from_slice(&body[begin..begin + take]);
                // global tweak (see read_entry): same bytes at a different
                // offset seal differently - the IEEE 1619 position property
                let tweak = cursor / DATA_UNIT as u64 + u as u64 + 1;
                encrypt_unit(&self.keys.data, &self.keys.tweak, tweak, &mut unit);
                let at = self.data_at(cursor) + u * DATA_UNIT;
                self.data[at..at + DATA_UNIT].copy_from_slice(&unit);
            }
            entries.push(Entry {
                name: name.clone(),
                offset: cursor,
                size: body.len() as u64,
                digest: sha256(body),
            });
            cursor += span;
        }
        // zero-encrypt everything past the last entry: free space looks
        // exactly like freshly created space
        let first_free = cursor / DATA_UNIT as u64;
        let mut unit = vec![0u8; DATA_UNIT];
        for rel in first_free..self.data_units {
            let tweak = rel + 1; // global numbering: the superblock is 0
            encrypt_unit(&self.keys.data, &self.keys.tweak, tweak, &mut unit);
            let at = self.data_at(rel * DATA_UNIT as u64);
            self.data[at..at + DATA_UNIT].copy_from_slice(&unit);
        }

        let mut superblock = vec![0u8; DATA_UNIT];
        superblock[..4].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        for (i, entry) in entries.iter().enumerate() {
            let at = 4 + i * ENTRY_LEN;
            superblock[at..at + NAME_LEN].copy_from_slice(&seal_entry_name(&entry.name)?);
            superblock[at + NAME_LEN..at + NAME_LEN + 8]
                .copy_from_slice(&entry.offset.to_le_bytes());
            superblock[at + NAME_LEN + 8..at + NAME_LEN + 16]
                .copy_from_slice(&entry.size.to_le_bytes());
            superblock[at + NAME_LEN + 16..at + ENTRY_LEN].copy_from_slice(&entry.digest);
        }
        encrypt_unit(&self.keys.data, &self.keys.tweak, 0, &mut superblock);
        let sb_at = HEADER_LEN;
        self.data[sb_at..sb_at + DATA_UNIT].copy_from_slice(&superblock);

        std::fs::write(path, &self.data)?;
        Ok(())
    }
}

fn seal_entry_name(name: &str) -> Result<[u8; NAME_LEN]> {
    if name.is_empty() || name.len() > NAME_LEN - 1 || name.as_bytes().contains(&0) {
        return Err(Error::Config(format!("namfs: invalid entry name {name:?}")));
    }
    let mut out = [0u8; NAME_LEN];
    out[..name.len()].copy_from_slice(name.as_bytes());
    Ok(out)
}

/// Open + authenticate a volume: header HMAC, passphrase verifier,
/// superblock decryption. Everything else relies on this gate.
pub fn open(path: &Path, pass: &[u8]) -> Result<Volume> {
    let raw = std::fs::read(path)?;
    if raw.len() < HEADER_LEN + DATA_UNIT || raw[..8] != MAGIC {
        return Err(Error::Crypto("namfs: not a NamFS v2 container".into()));
    }
    let iterations =
        u32::from_le_bytes(raw[OFF_ITERATIONS..OFF_ITERATIONS + 4].try_into().unwrap());
    let salt: [u8; 32] = raw[OFF_SALT..OFF_VERIFIER].try_into().unwrap();
    let keys = derive_keys(pass, &salt, iterations);
    let verifier: [u8; 32] = raw[OFF_VERIFIER..OFF_UUID].try_into().unwrap();
    if hmac_sha256(&keys.mac, VERIFIER_DOMAIN) != verifier {
        return Err(Error::Crypto("namfs: passphrase rejected".into()));
    }
    let stored_hmac: [u8; 32] =
        raw[HEADER_HMAC_OFFSET..HEADER_HMAC_OFFSET + 32].try_into().unwrap();
    if hmac_sha256(&keys.mac, &raw[..HEADER_HMAC_OFFSET]) != stored_hmac {
        return Err(Error::Crypto("namfs: header integrity check failed".into()));
    }
    let uuid: [u8; 16] = raw[OFF_UUID..OFF_CREATED].try_into().unwrap();
    let created = u64::from_le_bytes(raw[OFF_CREATED..OFF_LABEL].try_into().unwrap());
    let label_raw = &raw[OFF_LABEL..OFF_LABEL + 64];
    let label_end = label_raw.iter().position(|b| *b == 0 || *b == b' ').unwrap_or(64);
    let label = String::from_utf8_lossy(&label_raw[..label_end]).into_owned();
    let total_size = u64::from_le_bytes(raw[OFF_TOTAL..OFF_UNITS].try_into().unwrap());
    let data_units = u64::from_le_bytes(raw[OFF_UNITS..OFF_UNITS + 8].try_into().unwrap());
    if raw.len() as u64 != total_size {
        return Err(Error::Crypto(format!(
            "namfs: container size {} != header total {}",
            raw.len(),
            total_size
        )));
    }

    let mut superblock = raw[HEADER_LEN..HEADER_LEN + DATA_UNIT].to_vec();
    decrypt_unit(&keys.data, &keys.tweak, 0, &mut superblock);
    let count = u32::from_le_bytes(superblock[..4].try_into().unwrap()) as usize;
    if count > MAX_ENTRIES {
        return Err(Error::Crypto("namfs: superblock entry count out of range".into()));
    }
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let at = 4 + i * ENTRY_LEN;
        let raw_entry = &superblock[at..at + ENTRY_LEN];
        entries.push(Entry {
            name: {
                let raw_name = &raw_entry[..NAME_LEN];
                let end = raw_name.iter().position(|b| *b == 0).unwrap_or(raw_name.len());
                String::from_utf8_lossy(&raw_name[..end]).into_owned()
            },
            offset: u64::from_le_bytes(raw_entry[NAME_LEN..NAME_LEN + 8].try_into().unwrap()),
            size: u64::from_le_bytes(raw_entry[NAME_LEN + 8..NAME_LEN + 16].try_into().unwrap()),
            digest: raw_entry[NAME_LEN + 16..ENTRY_LEN].try_into().unwrap(),
        });
    }

    Ok(Volume {
        keys,
        header: raw[..HEADER_LEN].try_into().unwrap(),
        salt,
        uuid,
        created,
        label,
        iterations,
        total_size,
        data_units,
        data: raw,
        entries,
    })
}

/// Everything `create` needs; the deterministic demo volume pins every
/// field (salt, uuid, created) so builds stay byte-reproducible.
pub struct CreateOptions {
    /// Total container size in bytes (multiple of [`DATA_UNIT`]).
    pub size_bytes: u64,
    /// Volume label (<= 63 bytes).
    pub label: String,
    /// PBKDF2 iteration count (>= 1000).
    pub iterations: u32,
    /// Explicit 32-byte salt; random when `None`.
    pub salt: Option<[u8; 32]>,
    /// Explicit uuid (16 bytes); random when `None`.
    pub uuid: Option<[u8; 16]>,
    /// Explicit creation unix time; `0` keeps the volume deterministic.
    pub created: u64,
}

impl CreateOptions {
    fn validate(&self) -> Result<()> {
        if self.size_bytes < DATA_OFFSET + DATA_UNIT as u64
            || self.size_bytes % DATA_UNIT as u64 != 0
        {
            return Err(Error::Config(format!(
                "namfs: size must be a multiple of {DATA_UNIT} and at least {DATA_OFFSET}"
            )));
        }
        if self.iterations < 1000 {
            return Err(Error::Config("namfs: PBKDF2 iterations must be >= 1000".into()));
        }
        if self.label.len() > 63 {
            return Err(Error::Config("namfs: label longer than 63 bytes".into()));
        }
        Ok(())
    }
}

/// Create an empty volume. Default options draw salt and uuid from the
/// OS random source; deterministic builds pass both explicitly.
pub fn create(path: &Path, pass: &[u8], opts: &CreateOptions) -> Result<()> {
    opts.validate()?;
    let salt = match opts.salt {
        Some(s) => s,
        None => {
            let mut s = [0u8; 32];
            namikaze_rt::random::fill(&mut s)?;
            s
        }
    };
    let uuid = match opts.uuid {
        Some(u) => u,
        None => {
            let mut u = [0u8; 16];
            namikaze_rt::random::fill(&mut u)?;
            u
        }
    };
    let keys = derive_keys(pass, &salt, opts.iterations);

    let mut header = [0u8; 512];
    header[..8].copy_from_slice(&MAGIC);
    header[OFF_ITERATIONS..OFF_ITERATIONS + 4].copy_from_slice(&opts.iterations.to_le_bytes());
    header[OFF_SALT..OFF_VERIFIER].copy_from_slice(&salt);
    header[OFF_VERIFIER..OFF_UUID].copy_from_slice(&hmac_sha256(&keys.mac, VERIFIER_DOMAIN));
    header[OFF_UUID..OFF_CREATED].copy_from_slice(&uuid);
    header[OFF_CREATED..OFF_LABEL].copy_from_slice(&opts.created.to_le_bytes());
    header[OFF_LABEL..OFF_LABEL + opts.label.len()].copy_from_slice(opts.label.as_bytes());
    let data_units = (opts.size_bytes - DATA_OFFSET) / DATA_UNIT as u64;
    header[OFF_TOTAL..OFF_UNITS].copy_from_slice(&opts.size_bytes.to_le_bytes());
    header[OFF_UNITS..OFF_UNITS + 8].copy_from_slice(&data_units.to_le_bytes());
    let hmac = hmac_sha256(&keys.mac, &header[..HEADER_HMAC_OFFSET]);
    header[HEADER_HMAC_OFFSET..HEADER_HMAC_OFFSET + 32].copy_from_slice(&hmac);

    let mut volume = Volume {
        keys,
        header,
        salt,
        uuid,
        created: opts.created,
        label: opts.label.clone(),
        iterations: opts.iterations,
        total_size: opts.size_bytes,
        data_units,
        data: vec![0u8; opts.size_bytes as usize],
        entries: Vec::new(),
    };
    volume.data[..HEADER_LEN].copy_from_slice(&volume.header);
    volume.persist(path, &[])?;
    Ok(())
}

/// Store (or replace) one named file inside the volume. The superblock
/// and data area are rebuilt; header, salt, uuid and verifier persist.
/// Every kept entry is re-read through its SHA-256 gate first: a stored
/// entry that fails verification is never silently re-sealed.
pub fn put(path: &Path, pass: &[u8], name: &str, contents: &[u8]) -> Result<()> {
    let volume = open(path, pass)?;
    seal_entry_name(name)?;
    let mut kept: Vec<(String, Vec<u8>)> = volume
        .entries
        .iter()
        .filter(|e| e.name != name)
        .map(|e| Ok((e.name.clone(), volume.read_verified(e)?)))
        .collect::<Result<Vec<_>>>()?;
    kept.push((name.to_string(), contents.to_vec()));
    volume.persist(path, &kept)
}

/// Remove one named file from the volume (the entry table and data area
/// are rebuilt without it; free space re-seals as fresh space). Removing
/// a name that does not exist is an error, not a silent no-op.
pub fn remove(path: &Path, pass: &[u8], name: &str) -> Result<()> {
    let volume = open(path, pass)?;
    if !volume.entries.iter().any(|e| e.name == name) {
        return Err(Error::Other(format!("namfs: no entry named {name:?}")));
    }
    let kept: Vec<(String, Vec<u8>)> = volume
        .entries
        .iter()
        .filter(|e| e.name != name)
        .map(|e| Ok((e.name.clone(), volume.read_verified(e)?)))
        .collect::<Result<Vec<_>>>()?;
    volume.persist(path, &kept)
}

/// Replace the whole entry set in one pass: one key derivation, one
/// read, one write. This is the bulk constructor the image assembler
/// uses - N individual `put` calls would re-derive the keys and
/// rewrite the volume N times.
///
/// Duplicate names are rejected; capacity (28 entries in v2) is
/// enforced by the persist step. Returns the number of entries stored.
pub fn put_all(path: &Path, pass: &[u8], entries: &[(&str, &[u8])]) -> Result<usize> {
    let volume = open(path, pass)?;
    let mut names: Vec<&str> = Vec::with_capacity(entries.len());
    for (name, _) in entries {
        seal_entry_name(name)?;
        if names.contains(name) {
            return Err(Error::Other(format!("namfs: duplicate entry name {name:?}")));
        }
        names.push(name);
    }
    let kept: Vec<(String, Vec<u8>)> =
        entries.iter().map(|(name, contents)| ((*name).to_string(), contents.to_vec())).collect();
    let count = kept.len();
    volume.persist(path, &kept)?;
    Ok(count)
}

/// Read one named file back out of the volume, verifying its SHA-256.
pub fn get(path: &Path, pass: &[u8], name: &str) -> Result<Vec<u8>> {
    let volume = open(path, pass)?;
    let entry = volume
        .entries
        .iter()
        .find(|e| e.name == name)
        .ok_or_else(|| Error::Other(format!("namfs: no entry named {name:?}")))?;
    let _ = name;
    volume.read_verified(entry)
}

/// List the volume entries as (name, size).
pub fn list(path: &Path, pass: &[u8]) -> Result<Vec<(String, u64)>> {
    let volume = open(path, pass)?;
    Ok(volume.entries.iter().map(|e| (e.name.clone(), e.size)).collect())
}

/// Volume metadata as reported by [`info`].
pub struct VolumeInfo {
    pub label: String,
    pub uuid_hex: String,
    pub created: u64,
    pub iterations: u32,
    pub total_size: u64,
    pub data_units: u64,
    pub entries: Vec<(String, u64)>,
}

/// Report volume metadata (header-derived, passphrase-checked).
pub fn info(path: &Path, pass: &[u8]) -> Result<VolumeInfo> {
    let volume = open(path, pass)?;
    Ok(VolumeInfo {
        label: volume.label,
        uuid_hex: volume.uuid.iter().map(|b| format!("{b:02x}")).collect(),
        created: volume.created,
        iterations: volume.iterations,
        total_size: volume.total_size,
        data_units: volume.data_units,
        entries: volume.entries.iter().map(|e| (e.name.clone(), e.size)).collect(),
    })
}

/// Full integrity pass: header HMAC, passphrase verifier, superblock and
/// every entry's content hash. Returns the number of entries verified.
pub fn verify(path: &Path, pass: &[u8]) -> Result<usize> {
    let volume = open(path, pass)?;
    let count = volume.entries.len();
    for entry in &volume.entries {
        volume.read_verified(entry)?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> CreateOptions {
        CreateOptions {
            size_bytes: 1024 * 1024,
            label: "test".into(),
            iterations: 1000,
            salt: Some([7u8; 32]),
            uuid: Some([9u8; 16]),
            created: 0,
        }
    }

    #[test]
    fn put_all_matches_sequential_puts() {
        let dir = std::env::temp_dir().join("namfs-put-all");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.namfs");
        let b = dir.join("b.namfs");
        let pass = b"pass";
        create(&a, pass, &opts()).unwrap();
        put(&a, pass, "one", b"first").unwrap();
        put(&a, pass, "two/two", b"second-second").unwrap();
        create(&b, pass, &opts()).unwrap();
        let n = put_all(&b, pass, &[("one", b"first"), ("two/two", b"second-second")]).unwrap();
        assert_eq!(n, 2);
        assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
        assert_eq!(list(&b, pass).unwrap().len(), 2);
        assert_eq!(get(&b, pass, "two/two").unwrap(), b"second-second");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn put_all_rejects_duplicate_names() {
        let dir = std::env::temp_dir().join("namfs-put-all-dup");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let v = dir.join("d.namfs");
        let pass = b"pass";
        create(&v, pass, &opts()).unwrap();
        assert!(put_all(&v, pass, &[("x", b"1"), ("x", b"2")]).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remove_deletes_and_rejects_unknown() {
        let dir = std::env::temp_dir().join("namfs-remove");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let v = dir.join("r.namfs");
        let pass = b"pass";
        create(&v, pass, &opts()).unwrap();
        put(&v, pass, "a", b"alpha").unwrap();
        put(&v, pass, "b", b"beta").unwrap();
        remove(&v, pass, "a").unwrap();
        assert_eq!(list(&v, pass).unwrap(), vec![("b".to_string(), 4)]);
        assert_eq!(get(&v, pass, "b").unwrap(), b"beta");
        assert_eq!(verify(&v, pass).unwrap(), 1);
        assert!(remove(&v, pass, "a").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn put_refuses_to_reseal_corrupted_kept_entries() {
        // put() must re-read kept entries through their hash gate: a
        // flipped ciphertext byte anywhere makes the whole put fail
        // instead of laundering the corruption into the new volume.
        let dir = std::env::temp_dir().join("namfs-put-corrupt");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let v = dir.join("c.namfs");
        let pass = b"pass";
        create(&v, pass, &opts()).unwrap();
        put(&v, pass, "keep", vec![1u8; 9000].as_slice()).unwrap();
        let mut raw = std::fs::read(&v).unwrap();
        // header = 512, superblock = 4096, the first data unit starts at 4608
        raw[4608 + 3] ^= 0x01;
        std::fs::write(&v, &raw).unwrap();
        let err = put(&v, pass, "other", b"x").unwrap_err();
        assert!(err.to_string().contains("hash mismatch"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn same_plaintext_at_different_offsets_seals_differently() {
        // the global tweak numbering is the whole point of v2: two equal
        // entries cannot produce equal ciphertext at different offsets
        let dir = std::env::temp_dir().join("namfs-tweaks");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let v = dir.join("t.namfs");
        let pass = b"pass";
        create(&v, pass, &opts()).unwrap();
        let body = vec![0x5Au8; 3 * DATA_UNIT];
        put(&v, pass, "first", &body).unwrap();
        put(&v, pass, "second", &body).unwrap();
        // "second" lands at a different offset than "first"
        let listed = list(&v, pass).unwrap();
        assert_eq!(listed.len(), 2);
        let raw = std::fs::read(&v).unwrap();
        let a = &raw[DATA_OFFSET as usize..DATA_OFFSET as usize + DATA_UNIT];
        let b = &raw[DATA_OFFSET as usize + DATA_UNIT..DATA_OFFSET as usize + 2 * DATA_UNIT];
        assert_ne!(a, b, "identical plaintext at offset 0 and 1 must differ");
        // and both read back intact
        assert_eq!(get(&v, pass, "first").unwrap(), body);
        assert_eq!(get(&v, pass, "second").unwrap(), body);
        std::fs::remove_dir_all(&dir).ok();
    }
}
