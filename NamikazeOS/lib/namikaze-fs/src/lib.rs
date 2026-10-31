// SPDX-License-Identifier: MPL-2.0
//! namikaze-fs: NamFS, the NamikazeOS encrypted persistent volume format.
//!
//! A NamFS container is a single file that stores a small set of named
//! files under AES-256-XTS sector encryption, with a PBKDF2-HMAC-SHA256
//! passphrase gate and per-file SHA-256 integrity. It is the persistent
//! layer of the airootfs live system (mode=persistent points at a NamFS
//! volume) and the container format the `namikaze` pipeline ships as a
//! byte-stable demo inside every ISO.
//!
//! Everything is implemented in this workspace: the AES-256 core
//! ([`aes`], FIPS-197), the XTS tweakable mode ([`xts`], IEEE 1619) and
//! the container format ([`format`]). Key derivation and HMAC reuse the
//! workspace's own `namikaze-rt` primitives; there are no third-party
//! crates anywhere in the chain.

#![forbid(unsafe_code)]

pub mod aes;
pub mod format;
pub mod xts;

pub use format::{create, get, info, list, open, put, verify, CreateOptions, VolumeInfo, MAGIC};

/// The PBKDF2 iteration count the release pipeline uses for demo volumes
/// (kept modest so builds stay fast; real volumes should raise it).
pub const DEMO_ITERATIONS: u32 = 4096;

#[cfg(test)]
mod tests {
    use super::format::*;

    const PASS: &[u8] = b"namikaze-test-passphrase";
    const SALT: [u8; 32] = [7u8; 32];
    const UUID: [u8; 16] = [9u8; 16];

    fn opts() -> CreateOptions {
        CreateOptions {
            size_bytes: 64 * 1024,
            label: "test".into(),
            iterations: 1000,
            salt: Some(SALT),
            uuid: Some(UUID),
            created: 0,
        }
    }

    #[test]
    fn container_roundtrip() {
        let dir = std::env::temp_dir().join("namfs-test-roundtrip");
        std::fs::create_dir_all(&dir).unwrap();
        let vol = dir.join("test.namfs");
        create(&vol, PASS, &opts()).unwrap();
        put(&vol, PASS, "motd", b"welcome to namikaze\n").unwrap();
        put(&vol, PASS, "etc/namikaze/namfs.conf", b"mode = \"persistent\"\n").unwrap();
        put(&vol, PASS, "big", vec![0xABu8; 10_000].as_slice()).unwrap();
        let listed = list(&vol, PASS).unwrap();
        assert_eq!(listed.len(), 3);
        assert!(listed.iter().any(|(n, s)| n == "big" && *s == 10_000));
        assert_eq!(get(&vol, PASS, "motd").unwrap(), b"welcome to namikaze\n");
        assert_eq!(get(&vol, PASS, "etc/namikaze/namfs.conf").unwrap(), b"mode = \"persistent\"\n");
        assert_eq!(get(&vol, PASS, "big").unwrap().len(), 10_000);
        assert_eq!(verify(&vol, PASS).unwrap(), 3);
        let info = info(&vol, PASS).unwrap();
        assert_eq!(info.label, "test");
        assert_eq!(info.iterations, 1000);
        // replace an entry: same name, new content
        put(&vol, PASS, "motd", b"replaced\n").unwrap();
        assert_eq!(get(&vol, PASS, "motd").unwrap(), b"replaced\n");
        assert_eq!(list(&vol, PASS).unwrap().len(), 3);
        assert_eq!(verify(&vol, PASS).unwrap(), 3);
        std::fs::remove_file(&vol).unwrap();
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let dir = std::env::temp_dir().join("namfs-test-wrongpass");
        std::fs::create_dir_all(&dir).unwrap();
        let vol = dir.join("test.namfs");
        create(&vol, PASS, &opts()).unwrap();
        let err = list(&vol, b"other-passphrase").unwrap_err();
        assert!(err.to_string().contains("passphrase rejected"), "{err}");
        std::fs::remove_file(&vol).unwrap();
    }

    #[test]
    fn tampered_bytes_fail_verification() {
        let dir = std::env::temp_dir().join("namfs-test-tamper");
        std::fs::create_dir_all(&dir).unwrap();
        let vol = dir.join("test.namfs");
        create(&vol, PASS, &opts()).unwrap();
        put(&vol, PASS, "payload", vec![1u8; 5000].as_slice()).unwrap();
        let mut raw = std::fs::read(&vol).unwrap();
        // flip one ciphertext byte inside the payload's first data unit
        // (header = 512, superblock = 4096, so the data area starts at 4608)
        raw[4608 + 5] ^= 0x01;
        std::fs::write(&vol, &raw).unwrap();
        let err = get(&vol, PASS, "payload").unwrap_err();
        assert!(err.to_string().contains("hash mismatch"), "{err}");
        std::fs::remove_file(&vol).unwrap();
    }

    #[test]
    fn deterministic_create_is_byte_stable() {
        let dir = std::env::temp_dir().join("namfs-test-determinism");
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b) = (dir.join("a.namfs"), dir.join("b.namfs"));
        create(&a, PASS, &opts()).unwrap();
        create(&b, PASS, &opts()).unwrap();
        assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
        std::fs::remove_file(&a).unwrap();
        std::fs::remove_file(&b).unwrap();
    }

    #[test]
    fn geometry_is_validated() {
        let dir = std::env::temp_dir().join("namfs-test-geometry");
        std::fs::create_dir_all(&dir).unwrap();
        let bad = CreateOptions { size_bytes: 12345, ..opts() };
        let err = create(&dir.join("x.namfs"), PASS, &bad).unwrap_err();
        assert!(err.to_string().contains("multiple of"), "{err}");
        let short = CreateOptions { iterations: 10, ..opts() };
        let err = create(&dir.join("y.namfs"), PASS, &short).unwrap_err();
        assert!(err.to_string().contains("iterations"), "{err}");
    }
}
