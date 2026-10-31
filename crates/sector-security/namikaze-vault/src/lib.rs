// SPDX-License-Identifier: MPL-2.0
//! namikaze-vault: the encryption core of NamikazeOS tier-3 storage.
//!
//! Container format (single file):
//!
//! ```text
//! bytes 0..8    magic "NKVLT1\0\0"
//! bytes 8..12   header length (u32 LE)
//! bytes 12..    header JSON: { kdf params, nonce (b64) }
//! then          ciphertext = XChaCha20-Poly1305(entries JSON, AAD = magic)
//! ```
//!
//! Entries are (name, bytes) pairs so the vault doubles as an encrypted
//! archive for sentinel evidence and backup payloads. The AEAD, KDF and
//! JSON codec live in `namikaze-rt` (public test vectors in-tree); there
//! are zero third-party dependencies.

#![forbid(unsafe_code)]

use std::path::Path;

use namikaze_common::{Error, Result};
use namikaze_rt::{aead, b64, json, random, sha256};

/// File magic identifying a NamikazeOS vault container.
pub const MAGIC: &[u8; 8] = b"NKVLT1\0\0";

/// PBKDF2-HMAC-SHA256 key derivation parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    /// KDF identifier, always "pbkdf2-hmac-sha256" in v3.
    pub algo: String,
    /// Base64 salt
    pub salt: String,
    /// PBKDF2 iteration count
    pub iterations: u32,
}

impl KdfParams {
    /// Fresh parameters with a random salt. The default iteration count
    /// targets brute-force economics on commodity hardware.
    pub fn generate() -> Result<Self> {
        let mut salt = [0u8; 32];
        random::fill(&mut salt).map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(Self {
            algo: "pbkdf2-hmac-sha256".into(),
            salt: b64::encode(&salt),
            iterations: 600_000,
        })
    }
}

/// Open vault handle. The key lives in RAM only and is zeroized on drop.
pub struct OpenVault {
    key: [u8; 32],
}

impl OpenVault {
    /// Derive a key from a passphrase with PBKDF2-HMAC-SHA256.
    pub fn derive(passphrase: &str, params: &KdfParams) -> Result<Self> {
        if params.algo != "pbkdf2-hmac-sha256" {
            return Err(Error::Crypto(format!("unsupported kdf: {}", params.algo)));
        }
        let salt = b64::decode(&params.salt)
            .ok_or_else(|| Error::Crypto("invalid salt encoding".into()))?;
        let key = namikaze_rt::hmac::pbkdf2_hmac_sha256(
            passphrase.as_bytes(),
            &salt,
            params.iterations.max(1),
            32,
        );
        let mut out = [0u8; 32];
        out.copy_from_slice(&key[..32]);
        Ok(Self { key: out })
    }

    /// Encrypt with XChaCha20-Poly1305; magic bytes act as AAD. Returns
    /// `[24-byte nonce || ciphertext || 16-byte tag]`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        aead::seal(&self.key, plaintext, MAGIC).map_err(|e| Error::Crypto(e.to_string()))
    }

    /// Decrypt an encrypt() output (nonce prefix + ciphertext + tag).
    pub fn decrypt(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        aead::open(&self.key, sealed, MAGIC).map_err(|e| Error::Crypto(e.to_string()))
    }

    /// Lock the key into RAM (best effort; requires root).
    pub fn mlock_key(&self) {
        let _ = namikaze_ffi::mlock(&self.key);
    }
}

// Manual zeroize on drop: key material never lingers after the handle dies.
impl Drop for OpenVault {
    fn drop(&mut self) {
        namikaze_rt::fsutil::zero(&mut self.key);
    }
}

/// Content hash helper (SHA-256 hex) exposed for audit chains and chunk ids.
pub fn hash(data: &[u8]) -> String {
    sha256::sha256_hex(data)
}

fn header_to_json(params: &KdfParams) -> Vec<u8> {
    let v = json::Value::Obj(
        [
            (
                "algo".to_string(),
                json::Value::Str(params.algo.clone()),
            ),
            ("salt".to_string(), json::Value::Str(params.salt.clone())),
            (
                "iterations".to_string(),
                json::Value::Int(params.iterations as i64),
            ),
        ]
        .into_iter()
        .collect(),
    );
    v.to_compact().into_bytes()
}

fn parse_header(bytes: &[u8]) -> Result<KdfParams> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Crypto("vault header is not utf-8".into()))?;
    let v = json::parse(text).map_err(|e| Error::Crypto(format!("bad vault header: {e}")))?;
    let algo = v.get("algo").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let salt = v.get("salt").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let iterations = v.get("iterations").and_then(|x| x.as_i64()).unwrap_or(1) as u32;
    if salt.is_empty() {
        return Err(Error::Crypto("vault header missing salt".into()));
    }
    Ok(KdfParams { algo, salt, iterations })
}

fn entries_to_json(entries: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    let arr: Vec<json::Value> = entries
        .iter()
        .map(|(name, data)| {
            json::obj(&[
                ("name", json::Value::Str(name.clone())),
                ("data", json::Value::Str(b64::encode(data))),
            ])
        })
        .collect();
    Ok(json::Value::Arr(arr).to_compact().into_bytes())
}

fn parse_entries(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Crypto("vault body is not utf-8".into()))?;
    let v = json::parse(text).map_err(|e| Error::Crypto(format!("bad vault body: {e}")))?;
    let arr = v
        .as_arr()
        .ok_or_else(|| Error::Crypto("vault body is not an array".into()))?;
    let mut out = Vec::new();
    for item in arr {
        let name = item
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or_else(|| Error::Crypto("vault entry missing name".into()))?
            .to_string();
        let data = item
            .get("data")
            .and_then(|x| x.as_str())
            .and_then(b64::decode)
            .unwrap_or_default();
        out.push((name, data));
    }
    Ok(out)
}

/// Read a whole container file, decrypt and return its entries.
pub fn read_entries(path: &Path, passphrase: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let raw = std::fs::read(path)?;
    if raw.len() < 12 || &raw[0..8] != MAGIC {
        return Err(Error::Crypto("not a NamikazeOS vault container".into()));
    }
    let header_len = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
    if raw.len() < 12 + header_len {
        return Err(Error::Crypto("truncated vault header".into()));
    }
    let header = parse_header(&raw[12..12 + header_len])?;
    let vault = OpenVault::derive(passphrase, &header)?;
    let plaintext = vault.decrypt(&raw[12 + header_len..])?;
    parse_entries(&plaintext)
}

/// Write entries into a new (or replaced) container file.
pub fn write_entries(path: &Path, passphrase: &str, entries: &[(String, Vec<u8>)]) -> Result<()> {
    let params = KdfParams::generate()?;
    let vault = OpenVault::derive(passphrase, &params)?;
    let plaintext = entries_to_json(entries)?;
    let sealed = vault.encrypt(&plaintext)?;
    let header_json = header_to_json(&params);
    let mut out = Vec::with_capacity(12 + header_json.len() + sealed.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_json);
    out.extend_from_slice(&sealed);
    namikaze_common::write_private(path, &out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_roundtrip() {
        let params = KdfParams {
            algo: "pbkdf2-hmac-sha256".into(),
            salt: b64::encode(&[9u8; 32]),
            iterations: 1000,
        };
        let vault = OpenVault::derive("correct horse", &params).unwrap();
        let sealed = vault.encrypt(b"top secret payload").unwrap();
        let opened = vault.decrypt(&sealed).unwrap();
        assert_eq!(opened, b"top secret payload");
        let wrong = OpenVault::derive("wrong", &params).unwrap();
        assert!(wrong.decrypt(&sealed).is_err());
    }

    #[test]
    fn container_roundtrip_on_disk() {
        let dir = std::env::temp_dir().join(format!("vault-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("t.vault");
        write_entries(&path, "pw", &[("a.txt".into(), b"hello".to_vec())]).unwrap();
        let entries = read_entries(&path, "pw").unwrap();
        assert_eq!(entries, vec![("a.txt".into(), b"hello".to_vec())]);
        assert!(read_entries(&path, "bad").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sha256_helper_is_stable() {
        assert_eq!(hash(b"abc").len(), 64);
        assert_eq!(
            hash(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
