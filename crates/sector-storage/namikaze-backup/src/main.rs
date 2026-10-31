// SPDX-License-Identifier: MPL-2.0
//! namikaze-backup: encrypted, deduplicated local backups.
//!
//! Repo layout:
//! ```text
//! repo/salt.bin        random salt for the passphrase KDF
//! repo/manifest.json   path -> ordered chunk ids
//! repo/chunks/<id>     nkz (LZ4-block) + XChaCha20-Poly1305 encrypted chunk
//! ```
//!
//! Chunking is fixed 64 KiB for the alpha release; content-defined chunking
//! is on the roadmap. Integrity: SHA-256 id of the PLAINTEXT chunk, so any
//! tamper attempt fails authentication before reaching the file content.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use namikaze_common::{init_tracing, Error, Result};
use namikaze_rt::args::Cli;
use namikaze_rt::b64;
use namikaze_rt::fsutil::{walk_files, ZeroBuf};
use namikaze_rt::json::{self, Value};
use namikaze_rt::lz;
use namikaze_rt::random;
use namikaze_rt::sha256::sha256_hex;

const USAGE: &[&str] = &[
    "namikaze-backup: encrypted incremental backups for NamikazeOS",
    "",
    "usage:",
    "  namikaze-backup --repo DIR init",
    "  namikaze-backup --repo DIR put PATH [PATH...]",
    "  namikaze-backup --repo DIR list",
    "  namikaze-backup --repo DIR get PATH OUT",
];

const CHUNK: usize = 64 * 1024;

type Manifest = BTreeMap<String, Vec<String>>;

fn ask_pass() -> Result<ZeroBuf> {
    Ok(ZeroBuf::new(namikaze_ffi::read_password_tty()?))
}

fn salt_path(repo: &Path) -> PathBuf {
    repo.join("salt.bin")
}

fn manifest_path(repo: &Path) -> PathBuf {
    repo.join("manifest.json")
}

fn load_manifest(repo: &Path) -> Manifest {
    std::fs::read(manifest_path(repo))
        .ok()
        .and_then(|raw| {
            let v = json::parse(std::str::from_utf8(&raw).ok()?).ok()?;
            let Value::Obj(map) = v else { return None };
            Some(
                map.into_iter()
                    .map(|(k, v)| {
                        (
                            k,
                            v.as_arr()
                                .map(|a| {
                                    a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()
                                })
                                .unwrap_or_default(),
                        )
                    })
                    .collect::<Manifest>(),
            )
        })
        .unwrap_or_default()
}

fn store_manifest(repo: &Path, m: &Manifest) -> Result<()> {
    let obj = Value::Obj(
        m.iter()
            .map(|(k, ids)| {
                (
                    k.clone(),
                    Value::Arr(ids.iter().map(|i| Value::Str(i.clone())).collect()),
                )
            })
            .collect(),
    );
    std::fs::write(manifest_path(repo), obj.to_pretty().into_bytes())?;
    Ok(())
}

fn derive_key(pass: &str, salt: &[u8]) -> Result<namikaze_vault::OpenVault> {
    let params = namikaze_vault::KdfParams {
        algo: "pbkdf2-hmac-sha256".into(),
        salt: b64::encode(salt),
        iterations: 600_000,
    };
    namikaze_vault::OpenVault::derive(pass, &params)
}

fn run_init(repo: &Path) -> Result<()> {
    std::fs::create_dir_all(repo.join("chunks"))?;
    if salt_path(repo).exists() {
        return Err(Error::Other("repository already initialized".into()));
    }
    let mut salt = [0u8; 32];
    random::fill(&mut salt).map_err(|e| Error::Crypto(e.to_string()))?;
    namikaze_common::write_private(&salt_path(repo), &salt)?;
    store_manifest(repo, &Manifest::default())?;
    println!("repository initialized at {}", repo.display());
    Ok(())
}

fn run_put(repo: &Path, sources: &[PathBuf]) -> Result<()> {
    let pass = ask_pass()?;
    let salt = std::fs::read(salt_path(repo))?;
    let vault = derive_key(std::str::from_utf8(pass.as_slice()).unwrap_or(""), &salt)?;
    vault.mlock_key();
    let mut manifest = load_manifest(repo);
    let mut stored = 0usize;
    for src in sources {
        for entry in walk_files(src) {
            let Ok(data) = std::fs::read(&entry) else { continue };
            let mut ids = Vec::new();
            for chunk in data.chunks(CHUNK) {
                let id = sha256_hex(chunk);
                let chunk_path = repo.join("chunks").join(&id);
                if !chunk_path.exists() {
                    let compressed = lz::compress(chunk);
                    let sealed = vault.encrypt(&compressed)?;
                    namikaze_common::write_private(&chunk_path, &sealed)?;
                    stored += 1;
                }
                ids.push(id);
            }
            let key = entry.display().to_string();
            manifest.insert(key, ids);
        }
    }
    store_manifest(repo, &manifest)?;
    println!("stored {stored} new chunk(s)");
    Ok(())
}

fn run_get(repo: &Path, path: &str, out: &Path) -> Result<()> {
    let pass = ask_pass()?;
    let salt = std::fs::read(salt_path(repo))?;
    let vault = derive_key(std::str::from_utf8(pass.as_slice()).unwrap_or(""), &salt)?;
    let manifest = load_manifest(repo);
    let ids = manifest
        .get(path)
        .ok_or_else(|| Error::Other(format!("path {path} not in repository")))?;
    let mut plain = Vec::new();
    for id in ids {
        let sealed = std::fs::read(repo.join("chunks").join(id))?;
        let compressed = vault.decrypt(&sealed)?;
        let chunk = lz::decompress(&compressed)?;
        plain.extend_from_slice(&chunk);
    }
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out, &plain)?;
    println!("restored {path} -> {}", out.display());
    Ok(())
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let repo = std::path::PathBuf::from(
        cli.value("repo").unwrap_or_else(|| "backup-repo".into()),
    );
    let free = cli.free(&["repo"]);
    match cli.sub().unwrap_or_default() {
        "init" => run_init(&repo)?,
        "put" => {
            let sources: Vec<PathBuf> = free.iter().skip(1).map(PathBuf::from).collect();
            if sources.is_empty() {
                return Err(Error::Other("put needs at least one source path".into()));
            }
            run_put(&repo, &sources)?;
        }
        "list" => {
            for path in load_manifest(&repo).keys() {
                println!("{path}");
            }
        }
        "get" => {
            let path = free
                .get(1)
                .cloned()
                .ok_or_else(|| Error::Other("get needs PATH and OUT".into()))?;
            let out = free
                .get(2)
                .map(PathBuf::from)
                .ok_or_else(|| Error::Other("get needs PATH and OUT".into()))?;
            run_get(&repo, &path, &out)?;
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
