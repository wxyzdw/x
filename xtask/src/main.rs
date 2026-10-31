// SPDX-License-Identifier: MPL-2.0
//! xtask: Rust-native build orchestration for NamikazeOS.
//!
//! All repo automation lives here (std-only, zero third-party crates); the
//! shell scripts of earlier releases were absorbed into these tasks:
//!
//! Guards (CI gate, `cargo xtask verify-all` runs every one):
//!   ascii-guard   - fail if engineering sources contain non-ASCII bytes
//!   naming-guard  - fail if a banned theme codename leaks into the tree
//!   license-guard - fail if a .rs source lacks the MPL-2.0 SPDX tag
//!   gnu-guard     - fail if banned legacy-toolchain tokens leak outside
//!                   the documented allowlist
//!   dep-guard     - fail if any workspace manifest declares a third-party
//!                   dependency (the zero-dep rule, mechanically enforced)
//!   desk-guard    - fail if Niri session files disagree across the tree
//!   tools-guard   - fail if the userland TOOLS file, the Rust registry and
//!                   the overlay ebuild disagree
//!
//! Tasks:
//!   sbom          - emit dist/sbom.json inventory of workspace crates
//!   verify        - emit SHA256SUMS for dist artifacts (own SHA-256)
//!   kernel-check  - fail if a built kernel .config misses mandatory options
//!   kernel-fragments - merge universal fragments into one per-arch config
//!   iso           - stage per-arch inputs and print the OneISO command
//!   ebuilds       - regenerate the ::namikaze overlay packages
//!   bootid        - generate the boot seal id (dist/bootid)
//!   release       - package the source tree as a zip artifact
//!   verify-all    - run every guard in sequence

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use namikaze_common::{Error, Result};
use namikaze_rt::fsutil::walk_files;
use namikaze_rt::json::{obj, Value};
use namikaze_rt::sha256::sha256_file_hex;

const ASCII_EXEMPT: &[&str] = &["locales", "docs-l10n", "vendor", "target", "dist"];

fn is_exempt(path: &Path) -> bool {
    for part in path.components() {
        let name = part.as_os_str().to_string_lossy();
        if ASCII_EXEMPT.iter().any(|e| e == &name) {
            return true;
        }
    }
    // localized prose lives only in the i18n crate's docs directory
    let as_text = path.to_string_lossy().replace('\\', "/");
    as_text.contains("namikaze-i18n/docs")
}

fn ext_of(path: &Path) -> String {
    path.extension()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn collect(root: &Path, exts: &[&str]) -> Vec<PathBuf> {
    walk_files(root)
        .into_iter()
        .filter(|p| !is_exempt(p))
        .filter(|p| exts.contains(&ext_of(p).as_str()))
        .collect()
}

fn violations_report(name: &str, violations: &[String]) -> Result<()> {
    if violations.is_empty() {
        println!("{name}: clean");
        Ok(())
    } else {
        for v in violations {
            println!("VIOLATION {v}");
        }
        Err(Error::Other(format!("{} violation(s) in {name}", violations.len())))
    }
}

// ------------------------------------------------------------ ascii-guard

fn ascii_guard(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    for path in collect(root, &["rs", "toml", "sh", "yml", "md", "conf", "ebuild"]) {
        let Ok(bytes) = std::fs::read(&path) else { continue };
        if let Some(pos) = bytes.iter().position(|b| !b.is_ascii()) {
            violations.push(format!("{}: byte {pos} non-ASCII", path.display()));
        }
    }
    violations_report("ascii-guard", &violations)
}

// ----------------------------------------------------------- naming-guard

const CODENAMES_FILE: &str = "xtask/codenames.txt";

fn naming_guard(root: &Path) -> Result<()> {
    let list: Vec<String> = std::fs::read_to_string(root.join(CODENAMES_FILE))
        .map(|t| {
            t.lines()
                .map(|l| l.trim().to_lowercase())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .map_err(|_| Error::Other(format!("{CODENAMES_FILE} missing or empty")))?;
    let mut violations = Vec::new();
    for path in collect(root, &["rs", "toml", "sh", "yml", "md", "conf", "ebuild", "ftl"]) {
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let lower = text.to_lowercase();
        for name in &list {
            if lower.contains(name) {
                violations.push(format!("{}: codename \"{name}\"", path.display()));
            }
        }
    }
    violations_report(
        &format!("naming-guard ({} codenames checked)", list.len()),
        &violations,
    )
}

// ---------------------------------------------------------- license-guard

fn license_guard(root: &Path) -> Result<()> {
    let mut missing = Vec::new();
    for path in collect(root, &["rs"]) {
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let head: String = text.lines().take(5).collect::<Vec<_>>().join("\n");
        if !head.contains("SPDX-License-Identifier: MPL-2.0") {
            missing.push(path.display().to_string());
        }
    }
    violations_report("license-guard (MPL-2.0)", &missing)
}

// -------------------------------------------------------------- gnu-guard

const GNU_BANNED: &[&str] = &[
    "grub",
    "glibc",
    "coreutils",
    "findutils",
    "diffutils",
    "gawk",
    "binutils",
    "linux-gnu",
    "GNU General Public",
    "GPL-3.0",
];

const GNU_ALLOW_FILES: &[&str] = &[
    "CHANGELOG.md",
    "crates/sector-userland/namikaze-userland/docs/USERLAND.md",
    "xtask/src/main.rs",
];

fn gnu_guard(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    for path in collect(root, &["rs", "toml", "sh", "yml", "md", "conf", "ebuild", "ftl"]) {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if GNU_ALLOW_FILES.iter().any(|a| *a == rel) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let lower = text.to_lowercase();
        for token in GNU_BANNED {
            if lower.contains(token) {
                violations.push(format!("{rel}: token \"{token}\""));
            }
        }
    }
    violations_report(
        &format!(
            "gnu-guard ({} legacy tokens banned, {} documented exceptions)",
            GNU_BANNED.len(),
            GNU_ALLOW_FILES.len()
        ),
        &violations,
    )
}

// ------------------------------------------------------------- dep-guard

/// The zero third-party dependency rule, mechanically enforced: every
/// `[dependencies]` entry in a workspace manifest must be a `namikaze-*`
/// path dependency.
fn dep_guard(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    let mut manifests = walk_files(&root.join("crates"));
    manifests.push(root.join("xtask/Cargo.toml"));
    for manifest in manifests {
        if manifest.file_name().map(|n| n != "Cargo.toml").unwrap_or(true) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&manifest) else { continue };
        let mut in_deps = false;
        for raw in text.lines() {
            let line = raw.trim();
            if line.starts_with('[') {
                in_deps = line == "[dependencies]";
                continue;
            }
            if !in_deps || line.is_empty() || line.starts_with('#') {
                continue;
            }
            let name = line.split('=').next().unwrap_or("").trim();
            if name.is_empty() {
                continue;
            }
            if !name.starts_with("namikaze-") {
                violations.push(format!(
                    "{}: third-party dependency \"{name}\"",
                    manifest
                        .strip_prefix(root)
                        .unwrap_or(&manifest)
                        .display()
                ));
            } else if !line.contains("path =") {
                violations.push(format!(
                    "{}: {name} is not a path dependency",
                    manifest
                        .strip_prefix(root)
                        .unwrap_or(&manifest)
                        .display()
                ));
            }
        }
    }
    violations_report(
        "dep-guard (zero third-party dependencies)",
        &violations,
    )
}

// ------------------------------------------------------------- desk-guard

const DESK_DRIFT_PAIRS: &[(&str, &str)] = &[
    (
        "sysroot/usr/bin/namikaze-session",
        "overlay/sys-namikaze/desk/files/namikaze-session",
    ),
    (
        "sysroot/etc/greetd/config.toml",
        "overlay/sys-namikaze/desk/files/greetd-config.toml",
    ),
    (
        "sysroot/etc/init.d/namikaze-desk",
        "overlay/sys-namikaze/desk/files/namikaze-desk.initd",
    ),
    (
        "sysroot/etc/init.d/greetd",
        "overlay/sys-namikaze/desk/files/greetd.initd",
    ),
    (
        "sysroot/etc/pam.d/greetd",
        "overlay/sys-namikaze/desk/files/greetd.pamd",
    ),
    (
        "sysroot/etc/pam.d/swaylock",
        "overlay/sys-namikaze/desk/files/swaylock.pamd",
    ),
];

fn desk_guard(root: &Path) -> Result<()> {
    let mut problems: Vec<String> = Vec::new();

    let sysconf = root.join("sysroot/etc/namikaze/system.toml");
    let sysconf_text = std::fs::read_to_string(&sysconf).map_err(|e| {
        Error::Other(format!("cannot read {}: {e}", sysconf.display()))
    })?;
    let mut in_desktop = false;
    let mut environment: Option<String> = None;
    for line in sysconf_text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_desktop = line == "[desktop]";
            continue;
        }
        if in_desktop && line.starts_with("environment") {
            if let Some(eq) = line.find('=') {
                let rest = &line[eq + 1..];
                if let Some(start) = rest.find('"') {
                    if let Some(end) = rest[start + 1..].find('"') {
                        environment = Some(rest[start + 1..start + 1 + end].to_string());
                    }
                }
            }
        }
    }
    match environment.as_deref() {
        Some("niri") => {}
        Some(other) => problems.push(format!(
            "system.toml [desktop] environment = {other} (must be niri)"
        )),
        None => problems.push("system.toml [desktop] has no environment key".into()),
    }

    let session = root.join("sysroot/usr/bin/namikaze-session");
    let session_text = std::fs::read_to_string(&session)
        .map_err(|e| Error::Other(format!("cannot read {}: {e}", session.display())))?;
    if !session_text.contains("SPDX-License-Identifier: MPL-2.0") {
        problems.push("namikaze-session lacks the MPL-2.0 SPDX tag".into());
    }
    if !session_text.contains("dbus-run-session -- niri") {
        problems.push("namikaze-session does not end in the niri exec".into());
    }

    let greetd_conf = root.join("sysroot/etc/greetd/config.toml");
    let greetd_text = std::fs::read_to_string(&greetd_conf)
        .map_err(|e| Error::Other(format!("cannot read {}: {e}", greetd_conf.display())))?;
    if !greetd_text.contains("/usr/bin/namikaze-session") {
        problems.push("greetd config.toml does not launch namikaze-session".into());
    }

    for (orig, copy) in DESK_DRIFT_PAIRS {
        let a = std::fs::read(root.join(orig));
        let b = std::fs::read(root.join(copy));
        match (a, b) {
            (Ok(a), Ok(b)) if a == b => {}
            (Ok(_), Ok(_)) => problems.push(format!("drift: {orig} differs from {copy}")),
            (Ok(_), Err(_)) => problems.push(format!("missing overlay copy: {copy}")),
            (Err(_), _) => problems.push(format!("missing sysroot file: {orig}")),
        }
    }

    let set = root.join("overlay/package.sets/desktop");
    let set_text = std::fs::read_to_string(&set)
        .map_err(|e| Error::Other(format!("cannot read {}: {e}", set.display())))?;
    if !set_text.lines().any(|l| l.trim() == "gui-wm/niri") {
        problems.push("overlay/package.sets/desktop does not pin gui-wm/niri".into());
    }

    if !root
        .join("crates/sector-desk/namikaze-desk/docs/DESKTOP.md")
        .is_file()
    {
        problems.push("namikaze-desk/docs/DESKTOP.md missing".into());
    }

    violations_report(
        "desk-guard (Niri session consistent across the tree)",
        &problems,
    )
}

// ------------------------------------------------------------ tools-guard

const TOOLS_FILE: &str = "crates/sector-userland/namikaze-userland/TOOLS";
const REGISTRY_RS: &str = "crates/sector-userland/namikaze-userland/src/registry.rs";
const USERLAND_EBUILD: &str = "overlay/sys-namikaze/userland/namikaze-userland-3.0.0_alpha.3.ebuild";

/// Cross-checks the single source of truth for the tool name set:
/// TOOLS file == registry table == ebuild symlink farm.
fn tools_guard(root: &Path) -> Result<()> {
    let mut problems: Vec<String> = Vec::new();

    let tools: Vec<String> = std::fs::read_to_string(root.join(TOOLS_FILE))
        .map_err(|e| Error::Other(format!("cannot read {TOOLS_FILE}: {e}")))?
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();
    if tools.is_empty() {
        problems.push("TOOLS file is empty".into());
    }

    let registry = std::fs::read_to_string(root.join(REGISTRY_RS))
        .map_err(|e| Error::Other(format!("cannot read {REGISTRY_RS}: {e}")))?;
    for tool in &tools {
        if !registry.contains(&format!("(\"{tool}\"")) {
            problems.push(format!("registry.rs misses tool {tool}"));
        }
    }
    // count entries in the registry table
    let count = registry.matches("),").count();
    let registered = registry
        .lines()
        .filter(|l| l.trim_start().starts_with("(\""))
        .count();
    let _ = count;
    if registered != tools.len() {
        problems.push(format!(
            "registry lists {registered} tools but TOOLS file has {}",
            tools.len()
        ));
    }

    if let Ok(ebuild) = std::fs::read_to_string(root.join(USERLAND_EBUILD)) {
        // the ebuild declares the tool set once, in the symlink loop:
        //   for t in name1 name2 ...; do
        let declared: Vec<&str> = ebuild
            .lines()
            .find(|l| l.trim_start().starts_with("for t in"))
            .map(|l| {
                l.trim_start()
                    .trim_start_matches("for t in")
                    .trim_end_matches("; do")
                    .split_ascii_whitespace()
                    .collect()
            })
            .unwrap_or_default();
        if declared.is_empty() {
            problems.push("userland ebuild has no symlink loop".into());
        } else {
            for tool in &tools {
                if !declared.iter().any(|d| d == tool) {
                    problems.push(format!("userland ebuild misses symlink for {tool}"));
                    break;
                }
            }
            if declared.len() != tools.len() {
                problems.push(format!(
                    "userland ebuild declares {} tools, TOOLS file has {}",
                    declared.len(),
                    tools.len()
                ));
            }
        }
    } else {
        problems.push("userland ebuild missing".into());
    }

    violations_report("tools-guard (userland tool set consistent)", &problems)
}

// ------------------------------------------------------------------ sbom

fn workspace_crates(root: &Path) -> Result<Value> {
    let mut crates = Vec::new();
    let mut manifests = walk_files(&root.join("crates"));
    manifests.sort();
    for manifest in manifests {
        if manifest.file_name().map(|n| n != "Cargo.toml").unwrap_or(true) {
            continue;
        }
        let raw = std::fs::read_to_string(&manifest)?;
        let name = raw
            .lines()
            .find(|l| l.trim_start().starts_with("name = "))
            .map(|l| {
                l.trim_start()
                    .trim_start_matches("name = ")
                    .trim_matches('"')
                    .to_string()
            })
            .unwrap_or_default();
        let sector = manifest
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        crates.push(obj(&[
            ("name", Value::Str(name)),
            ("sector", Value::Str(sector)),
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

fn sbom(root: &Path) -> Result<()> {
    std::fs::create_dir_all(root.join("dist"))?;
    let v = workspace_crates(root)?;
    let count = v.get("crates").and_then(|c| c.as_arr()).map(|a| a.len()).unwrap_or(0);
    std::fs::write(root.join("dist/sbom.json"), v.to_pretty())?;
    println!("sbom written: dist/sbom.json ({count} crates)");
    Ok(())
}

// ---------------------------------------------------------------- verify

fn verify(root: &Path) -> Result<()> {
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

// ---------------------------------------------------------- kernel-check

const KERNEL_REQUIRED: &[&str] = &[
    "CONFIG_SQUASHFS",
    "CONFIG_SQUASHFS_ZSTD",
    "CONFIG_OVERLAY_FS",
    "CONFIG_BLK_DEV_INITRD",
    "CONFIG_RD_GZIP",
    "CONFIG_RD_ZSTD",
    "CONFIG_DEVTMPFS",
    "CONFIG_DEVTMPFS_MOUNT",
    "CONFIG_TMPFS",
    "CONFIG_DM_CRYPT",
    "CONFIG_DM_INTEGRITY",
    "CONFIG_DM_VERITY",
    "CONFIG_CRYPTO_ARGON2",
    "CONFIG_CRYPTO_SHA256",
    "CONFIG_CRYPTO_AES",
    "CONFIG_CRYPTO_XTS",
    "CONFIG_CRYPTO_CRC32C",
    "CONFIG_MD",
    "CONFIG_BLK_DEV_DM",
    "CONFIG_SECURITY",
    "CONFIG_SECURITY_YAMA",
    "CONFIG_SECURITY_LOCKDOWN_LSM",
    "CONFIG_MODULE_SIG",
];

const KERNEL_DISABLED: &[&str] = &[
    "CONFIG_DEVMEM",
    "CONFIG_DEVKMEM",
    "CONFIG_PROC_KCORE",
    "CONFIG_COMPAT",
    "CONFIG_KEXEC",
    "CONFIG_HIBERNATION",
];

fn kernel_check(config: &Path) -> Result<()> {
    let text = std::fs::read_to_string(config).map_err(|e| {
        Error::Other(format!("cannot read kernel config {}: {e}", config.display()))
    })?;
    let mut set = std::collections::HashMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            set.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    let mut missing = Vec::new();
    for key in KERNEL_REQUIRED {
        match set.get(*key) {
            Some(v) if v == "y" || v == "m" => {}
            Some(v) => missing.push(format!("{key}={v} (need y or m)")),
            None => missing.push(format!("{key} missing")),
        }
    }
    for key in KERNEL_DISABLED {
        match set.get(*key) {
            Some(v) if v == "n" => {}
            Some(v) => missing.push(format!("{key}={v} (must be n)")),
            None => {}
        }
    }
    violations_report(
        &format!(
            "kernel-check ({} required, {} disabled options in {})",
            KERNEL_REQUIRED.len(),
            KERNEL_DISABLED.len(),
            config.display()
        ),
        &missing,
    )
}

// ------------------------------------------------------ kernel-fragments

/// Merge the universal fragment with the hardened baseline into one config
/// per architecture under dist/kernel-configs. Pure text merge in merge
/// order: universal < arch-specific < hardened (later wins).
fn kernel_fragments(root: &Path) -> Result<()> {
    let frag_dir = root.join("kernel/configs/fragments");
    let out_dir = root.join("dist/kernel-configs");
    std::fs::create_dir_all(&out_dir)?;
    let universal: Vec<PathBuf> = std::fs::read_dir(&frag_dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| ext_of(p) == "config" && p.file_name().map(|n| n.to_string_lossy().starts_with("universal")).unwrap_or(false))
        .collect();
    let hardened = frag_dir.join("hardened.config");
    let mut count = 0;
    for u in universal {
        let arch = u
            .file_stem()
            .map(|s| s.to_string_lossy().trim_start_matches("universal-").to_string())
            .unwrap_or_default();
        let mut map: Vec<(String, String)> = Vec::new();
        for frag in [&u, &hardened] {
            let Ok(text) = std::fs::read_to_string(frag) else { continue };
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    let key = k.trim().to_string();
                    let val = v.trim().to_string();
                    if let Some(slot) = map.iter_mut().find(|(k, _)| *k == key) {
                        slot.1 = val;
                    } else {
                        map.push((key, val));
                    }
                }
            }
        }
        let mut out = format!(
            "# NamikazeOS merged kernel config for {arch}\n\
             # generated by: cargo xtask kernel-fragments (do not edit)\n"
        );
        for (k, v) in &map {
            out.push_str(&format!("{k}={v}\n"));
        }
        std::fs::write(out_dir.join(format!("{arch}.config")), out)?;
        count += 1;
    }
    println!("kernel-fragments: {count} arch config(s) written to dist/kernel-configs");
    Ok(())
}

// ------------------------------------------------------------------- iso

fn iso(root: &Path) -> Result<()> {
    let manifest = root.join("iso/manifest/oneiso.toml");
    if !manifest.exists() {
        return Err(Error::Other("iso/manifest/oneiso.toml missing".into()));
    }
    let staging = root.join("dist/iso-staging");
    std::fs::create_dir_all(&staging)?;
    println!("staging at {}", staging.display());
    println!("copy per-arch inputs per manifest (CI supplies dist/ inputs)");
    println!("+ genisoimage -o NamikazeOS-{}-unified.iso \\", namikaze_common::VERSION);
    println!("    -c boot/boot.cat -b limine-bios-cd.bin -no-emul-boot \\");
    println!("    -boot-load-size 4 -boot-info-table \\");
    println!("    -eltorito-alt-boot -e limine-uefi-cd.bin -no-emul-boot \\");
    println!("    -isohybrid-gpt-basdat -V NAMIKAZE_ISO {}", staging.display());
    println!("+ limine bios-install <image>  (hybrid MBR seal)");
    println!("(execution happens in CI once the forge is unfrozen)");
    Ok(())
}

// --------------------------------------------------------------- ebuilds

const EBUILD_SECTORS: &[(&str, &str)] = &[
    // (crate, gentoo category dir under overlay/sys-namikaze)
    ("namikaze-rt", "rt"),
    ("namikaze-common", "common"),
    ("namikaze-ffi", "ffi"),
    ("namikaze-i18n", "i18n"),
    ("namikaze-config", "config"),
    ("namikaze-doctor", "doctor"),
    ("namikaze-oomd", "oomd"),
    ("namikaze-detect", "detect"),
    ("namikaze-hal", "hal"),
    ("namikaze-init", "init"),
    ("namikaze-userland", "userland"),
    ("namikaze-sh", "sh"),
    ("namikaze-vault", "vault"),
    ("namikaze-sentinel", "sentinel"),
    ("namikaze-guard", "guard"),
    ("namikaze-seal", "seal"),
    ("namikaze-watch", "watch"),
    ("namikaze-sandbox", "sandbox"),
    ("namikaze-ledger", "ledger"),
    ("namikaze-secupdate", "secupdate"),
    ("namikaze-anon", "anon"),
    ("namikaze-cloak", "cloak"),
    ("namikaze-dns", "dns"),
    ("namikaze-usbguard", "usbguard"),
    ("namikaze-macspin", "macspin"),
    ("namikaze-live-core", "live-core"),
    ("namikaze-live", "live"),
    ("namikaze-persist-core", "persist-core"),
    ("namikaze-persist", "persist"),
    ("namikaze-backup", "backup"),
    ("namikaze-scrub", "scrub"),
    ("namikaze-wipe", "wipe"),
    ("namikaze-share", "share"),
    ("namikaze-decoy", "decoy"),
    ("namikaze-report", "report"),
    ("namikaze-desk", "desk"),
    ("namikaze-tune", "tune"),
    ("namikaze-firstboot", "firstboot"),
    ("namikaze-guest", "guest"),
    ("namikaze-pkg", "pkg"),
    ("namikaze-install", "install"),
    ("namikaze-rescue", "rescue"),
    ("namikaze-secpatch", "secpatch"),
    ("namikaze-mirror", "mirror"),
    ("namikaze-chrono", "chrono"),
    ("namikaze-ntp", "ntp"),
    ("namikaze-logd", "logd"),
    ("namikaze-metrics", "metrics"),
    ("namikaze-trace", "trace"),
    ("namikaze-attest", "attest"),
    ("namikaze-dupe", "dupe"),
];

fn gentoo_version() -> String {
    // 3.0.0-alpha.3 -> 3.0.0_alpha.3 (Gentoo ebuild convention)
    let (main, suffix) = namikaze_common::VERSION.split_once('-').unwrap_or((namikaze_common::VERSION, ""));
    if suffix.is_empty() {
        return main.to_string();
    }
    format!("{main}_{suffix}")
}

fn ebuilds(root: &Path) -> Result<()> {
    let ver = gentoo_version();
    let mut written = 0;
    for (crate_name, dir) in EBUILD_SECTORS {
        let target = root
            .join("overlay/sys-namikaze")
            .join(dir)
            .join(format!("{crate_name}-{ver}.ebuild"));
        if target.exists() {
            continue; // curated ebuilds stay; only missing ones are generated
        }
        std::fs::create_dir_all(target.parent().unwrap())?;
        let body = format!(
            r#"# Generated by cargo xtask ebuilds; edit by hand only with care.
EAPI=8

DESCRIPTION="NamikazeOS {crate_name} component"
HOMEPAGE="https://github.com/wxyzdw/x"
SRC_URI=""

LICENSE="MPL-2.0"
SLOT="0"
KEYWORDS="~amd64 ~arm64"
IUSE=""

DEPEND=""
RDEPEND="${{DEPEND}}"
BDEPEND=""

S="${{WORKDIR}}"

src_install() {{
    # binary is supplied by the workspace release artifact
    exeinto /usr/bin
    newexe "${{FILESDIR}}/placeholder" {crate_name}
}}
"#
        );
        std::fs::write(&target, body)?;
        written += 1;
    }
    println!("ebuilds: {written} generated ({}/{} total known)", EBUILD_SECTORS.len(), EBUILD_SECTORS.len());
    Ok(())
}

// ---------------------------------------------------------------- bootid

fn bootid(root: &Path) -> Result<()> {
    std::fs::create_dir_all(root.join("dist"))?;
    let id = namikaze_rt::random::id_hex()?;
    std::fs::write(root.join("dist/bootid"), id.clone())?;
    println!("bootid: {id} (written to dist/bootid)");
    Ok(())
}

// --------------------------------------------------------------- release

fn release(root: &Path, out: &Path) -> Result<()> {
    std::fs::create_dir_all(out)?;
    let ver = namikaze_common::VERSION;
    let zip_path = out.join(format!("NamikazeOS-{ver}-rust-workspace.zip"));
    let status = std::process::Command::new("zip")
        .arg("-rq")
        .arg(&zip_path)
        .arg(".")
        .arg("-x")
        .arg("target/*")
        .arg("dist/*")
        .arg("*.zip")
        .current_dir(root)
        .status()
        .map_err(|e| Error::Other(format!("zip unavailable: {e}")))?;
    if !status.success() {
        return Err(Error::Other("zip failed".into()));
    }
    let digest = sha256_file_hex(&zip_path)?;
    std::fs::write(
        out.join(format!("NamikazeOS-{ver}-rust-workspace.zip.sha256")),
        format!("{digest}  {}\n", zip_path.file_name().unwrap_or_default().to_string_lossy()),
    )?;
    println!("release: {}", zip_path.display());
    println!("sha256:  {digest}");
    Ok(())
}

// ------------------------------------------------------------ verify-all

fn verify_all(root: &Path) -> Result<()> {
    let mut failed = Vec::new();
    let guards: &[(&str, fn(&Path) -> Result<()>)] = &[
        ("ascii-guard", ascii_guard),
        ("naming-guard", naming_guard),
        ("license-guard", license_guard),
        ("gnu-guard", gnu_guard),
        ("dep-guard", dep_guard),
        ("desk-guard", desk_guard),
        ("tools-guard", tools_guard),
    ];
    for (name, guard) in guards {
        if let Err(e) = guard(root) {
            eprintln!("FAILED {name}: {e}");
            failed.push(*name);
        }
    }
    if failed.is_empty() {
        println!(
            "verify-all: ALL GUARDS PASS ({} guards)",
            guards.len()
        );
        Ok(())
    } else {
        Err(Error::Other(format!("verify-all: {} guard(s) failed", failed.len())))
    }
}

// ------------------------------------------------------------------ main

const USAGE: &[&str] = &[
    "cargo xtask: NamikazeOS build orchestration (std-only)",
    "",
    "guards: ascii-guard | naming-guard | license-guard | gnu-guard | dep-guard",
    "        desk-guard | tools-guard | verify-all",
    "tasks:  sbom | verify | kernel-check [<.config>] | kernel-fragments",
    "        iso | ebuilds | bootid | release <out-dir>",
];

fn main() -> Result<()> {
    let root = std::env::current_dir()?;
    let cli = namikaze_rt::args::Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let args: Vec<String> = cli.free(&[]);
    match cli.sub().unwrap_or_default() {
        "ascii-guard" => ascii_guard(&root),
        "naming-guard" => naming_guard(&root),
        "license-guard" => license_guard(&root),
        "gnu-guard" => gnu_guard(&root),
        "dep-guard" => dep_guard(&root),
        "desk-guard" => desk_guard(&root),
        "tools-guard" => tools_guard(&root),
        "verify-all" => verify_all(&root),
        "sbom" => sbom(&root),
        "verify" => verify(&root),
        "kernel-check" => {
            let config = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join("dist/linux/.config"));
            kernel_check(&config)
        }
        "kernel-fragments" => kernel_fragments(&root),
        "iso" => iso(&root),
        "ebuilds" => ebuilds(&root),
        "bootid" => bootid(&root),
        "release" => {
            let out = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("../download"));
            release(&root, &out)
        }
        other => {
            eprintln!("unknown task: {other}");
            cli.usage_exit(USAGE);
        }
    }
}
