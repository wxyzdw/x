// SPDX-License-Identifier: MPL-2.0
//! NamikazeOS configuration schema and hardening profiles.
//!
//! The single source of truth for `/etc/namikaze/system.toml`. All crates
//! load their tunables through this schema; unknown keys are rejected so
//! config drift fails loudly instead of silently. The TOML mapping is
//! hand-written on top of `namikaze-rt::toml` (zero third-party crates).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;

use namikaze_common::{Error, Result};
use namikaze_rt::toml::Value;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemConfig {
    pub storage: Storage,
    pub anonymity: Anonymity,
    pub sentinel: Sentinel,
    pub memory: Memory,
    pub desktop: Desktop,
    pub privacy: Privacy,
    pub vault: Vault,
    pub live: Live,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Storage {
    /// persistent | live
    pub mode: String,
    /// ext4 | f2fs | btrfs
    pub root_fs: String,
    /// A | B | C (boot security tier)
    pub boot_tier: String,
    pub pbkdf: Pbkdf,
    /// none | optional-usb | required-usb
    pub header_backup: String,
    pub recovery_code: bool,
    pub per_user_encryption: String,
    /// off | pin | auto
    pub tpm_sealing: String,
    pub hibernation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pbkdf {
    pub algo: String,
    pub memory_kb: u32,
    pub iterations: u32,
    pub parallel: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anonymity {
    /// standard | hardened | maximum
    pub level: String,
    pub transparent_tor: bool,
    pub block_non_tor_egress: bool,
    /// off | privacy | full
    pub ipv6: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sentinel {
    pub enabled: bool,
    pub max_failures: u32,
    pub failure_window_secs: u64,
    pub retention_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Memory {
    pub zram: bool,
    pub zram_algorithm: String,
    pub mglru: bool,
    /// always | madvise | never
    pub thp: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desktop {
    /// "niri" is the only supported session in v3.
    pub environment: String,
    pub compositor: bool,
    pub terminal: String,
    pub launcher: String,
    pub bar: String,
    pub notifications: String,
    pub lock: String,
    pub kb_layout: String,
    pub gap: u32,
    pub autologin: bool,
    pub greeter_user: String,
}

/// Live boot policy for the single-ISO medium (consumed by namikaze-init).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Live {
    /// persist | volatile | session
    pub default_mode: String,
    pub persist_label: String,
    pub max_pass_attempts: u32,
    /// volatile | panic
    pub fallback: String,
    pub trim: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Privacy {
    pub destructive_tools: bool,
    pub machine_id_policy: String,
    pub hostname_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vault {
    pub idle_unmount_secs: u64,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            mode: "persistent".into(),
            root_fs: "ext4".into(),
            boot_tier: "A".into(),
            pbkdf: Pbkdf::default(),
            header_backup: "none".into(),
            recovery_code: true,
            per_user_encryption: "fscrypt".into(),
            tpm_sealing: "pin".into(),
            hibernation: false,
        }
    }
}

impl Default for Pbkdf {
    fn default() -> Self {
        Self { algo: "argon2id".into(), memory_kb: 1_048_576, iterations: 4, parallel: 4 }
    }
}

impl Default for Anonymity {
    fn default() -> Self {
        Self {
            level: "hardened".into(),
            transparent_tor: true,
            block_non_tor_egress: true,
            ipv6: "privacy".into(),
        }
    }
}

impl Default for Sentinel {
    fn default() -> Self {
        Self {
            enabled: false,
            max_failures: 3,
            failure_window_secs: 300,
            retention_days: 30,
        }
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self {
            zram: true,
            zram_algorithm: "zstd".into(),
            mglru: true,
            thp: "madvise".into(),
        }
    }
}

impl Default for Desktop {
    fn default() -> Self {
        Self {
            environment: "niri".into(),
            compositor: true,
            terminal: "foot".into(),
            launcher: "fuzzel".into(),
            bar: "waybar".into(),
            notifications: "mako".into(),
            lock: "swaylock".into(),
            kb_layout: "us".into(),
            gap: 12,
            autologin: false,
            greeter_user: "greeter".into(),
        }
    }
}

impl Default for Live {
    fn default() -> Self {
        Self {
            default_mode: "persist".into(),
            persist_label: "namikaze-persist".into(),
            max_pass_attempts: 5,
            fallback: "volatile".into(),
            trim: false,
        }
    }
}

impl Default for Privacy {
    fn default() -> Self {
        Self {
            destructive_tools: false,
            machine_id_policy: "ephemeral".into(),
            hostname_mode: "random".into(),
        }
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self { idle_unmount_secs: 600 }
    }
}

/// Hardening profiles selectable via the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardenProfile {
    CisL1,
    CisL2,
}

// ------------------------------------------------------------ TOML mapping

fn as_str_field(table: &BTreeMap<String, Value>, key: &str, ctx: &str) -> Result<String> {
    match table.get(key) {
        Some(Value::Str(s)) => Ok(s.clone()),
        Some(_) => Err(Error::Config(format!("{ctx}.{key}: expected a string"))),
        None => Err(Error::Config(format!("{ctx}.{key}: missing"))),
    }
}

fn as_bool_field(table: &BTreeMap<String, Value>, key: &str, ctx: &str) -> Result<bool> {
    match table.get(key) {
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(Error::Config(format!("{ctx}.{key}: expected a boolean"))),
        None => Err(Error::Config(format!("{ctx}.{key}: missing"))),
    }
}

fn as_int_field(table: &BTreeMap<String, Value>, key: &str, ctx: &str) -> Result<i64> {
    match table.get(key) {
        Some(Value::Int(i)) => Ok(*i),
        Some(_) => Err(Error::Config(format!("{ctx}.{key}: expected an integer"))),
        None => Err(Error::Config(format!("{ctx}.{key}: missing"))),
    }
}

fn as_table_field<'a>(
    table: &'a BTreeMap<String, Value>,
    key: &str,
    ctx: &str,
) -> Result<&'a BTreeMap<String, Value>> {
    match table.get(key) {
        Some(Value::Table(t)) => Ok(t),
        Some(_) => Err(Error::Config(format!("{ctx}.{key}: expected a table"))),
        None => Err(Error::Config(format!("{ctx}.{key}: missing"))),
    }
}

fn check_keys(table: &BTreeMap<String, Value>, allowed: &[&str], ctx: &str) -> Result<()> {
    for k in table.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(Error::Config(format!("{ctx}.{k}: unknown key")));
        }
    }
    Ok(())
}

fn parse_storage(t: &BTreeMap<String, Value>) -> Result<Storage> {
    check_keys(
        t,
        &[
            "mode",
            "root_fs",
            "boot_tier",
            "pbkdf",
            "header_backup",
            "recovery_code",
            "per_user_encryption",
            "tpm_sealing",
            "hibernation",
        ],
        "storage",
    )?;
    Ok(Storage {
        mode: as_str_field(t, "mode", "storage")?,
        root_fs: as_str_field(t, "root_fs", "storage")?,
        boot_tier: as_str_field(t, "boot_tier", "storage")?,
        pbkdf: parse_pbkdf(as_table_field(t, "pbkdf", "storage")?)?,
        header_backup: as_str_field(t, "header_backup", "storage")?,
        recovery_code: as_bool_field(t, "recovery_code", "storage")?,
        per_user_encryption: as_str_field(t, "per_user_encryption", "storage")?,
        tpm_sealing: as_str_field(t, "tpm_sealing", "storage")?,
        hibernation: as_bool_field(t, "hibernation", "storage")?,
    })
}

fn parse_pbkdf(t: &BTreeMap<String, Value>) -> Result<Pbkdf> {
    check_keys(t, &["algo", "memory_kb", "iterations", "parallel"], "storage.pbkdf")?;
    Ok(Pbkdf {
        algo: as_str_field(t, "algo", "storage.pbkdf")?,
        memory_kb: as_int_field(t, "memory_kb", "storage.pbkdf")? as u32,
        iterations: as_int_field(t, "iterations", "storage.pbkdf")? as u32,
        parallel: as_int_field(t, "parallel", "storage.pbkdf")? as u32,
    })
}

fn parse_anonymity(t: &BTreeMap<String, Value>) -> Result<Anonymity> {
    check_keys(
        t,
        &["level", "transparent_tor", "block_non_tor_egress", "ipv6"],
        "anonymity",
    )?;
    Ok(Anonymity {
        level: as_str_field(t, "level", "anonymity")?,
        transparent_tor: as_bool_field(t, "transparent_tor", "anonymity")?,
        block_non_tor_egress: as_bool_field(t, "block_non_tor_egress", "anonymity")?,
        ipv6: as_str_field(t, "ipv6", "anonymity")?,
    })
}

fn parse_sentinel(t: &BTreeMap<String, Value>) -> Result<Sentinel> {
    check_keys(
        t,
        &["enabled", "max_failures", "failure_window_secs", "retention_days"],
        "sentinel",
    )?;
    Ok(Sentinel {
        enabled: as_bool_field(t, "enabled", "sentinel")?,
        max_failures: as_int_field(t, "max_failures", "sentinel")? as u32,
        failure_window_secs: as_int_field(t, "failure_window_secs", "sentinel")? as u64,
        retention_days: as_int_field(t, "retention_days", "sentinel")? as u32,
    })
}

fn parse_memory(t: &BTreeMap<String, Value>) -> Result<Memory> {
    check_keys(t, &["zram", "zram_algorithm", "mglru", "thp"], "memory")?;
    Ok(Memory {
        zram: as_bool_field(t, "zram", "memory")?,
        zram_algorithm: as_str_field(t, "zram_algorithm", "memory")?,
        mglru: as_bool_field(t, "mglru", "memory")?,
        thp: as_str_field(t, "thp", "memory")?,
    })
}

fn parse_desktop(t: &BTreeMap<String, Value>) -> Result<Desktop> {
    check_keys(
        t,
        &[
            "environment",
            "compositor",
            "terminal",
            "launcher",
            "bar",
            "notifications",
            "lock",
            "kb_layout",
            "gap",
            "autologin",
            "greeter_user",
        ],
        "desktop",
    )?;
    Ok(Desktop {
        environment: as_str_field(t, "environment", "desktop")?,
        compositor: as_bool_field(t, "compositor", "desktop")?,
        terminal: as_str_field(t, "terminal", "desktop")?,
        launcher: as_str_field(t, "launcher", "desktop")?,
        bar: as_str_field(t, "bar", "desktop")?,
        notifications: as_str_field(t, "notifications", "desktop")?,
        lock: as_str_field(t, "lock", "desktop")?,
        kb_layout: as_str_field(t, "kb_layout", "desktop")?,
        gap: as_int_field(t, "gap", "desktop")? as u32,
        autologin: as_bool_field(t, "autologin", "desktop")?,
        greeter_user: as_str_field(t, "greeter_user", "desktop")?,
    })
}

fn parse_live(t: &BTreeMap<String, Value>) -> Result<Live> {
    check_keys(
        t,
        &["default_mode", "persist_label", "max_pass_attempts", "fallback", "trim"],
        "live",
    )?;
    Ok(Live {
        default_mode: as_str_field(t, "default_mode", "live")?,
        persist_label: as_str_field(t, "persist_label", "live")?,
        max_pass_attempts: as_int_field(t, "max_pass_attempts", "live")? as u32,
        fallback: as_str_field(t, "fallback", "live")?,
        trim: as_bool_field(t, "trim", "live")?,
    })
}

fn parse_privacy(t: &BTreeMap<String, Value>) -> Result<Privacy> {
    check_keys(
        t,
        &["destructive_tools", "machine_id_policy", "hostname_mode"],
        "privacy",
    )?;
    Ok(Privacy {
        destructive_tools: as_bool_field(t, "destructive_tools", "privacy")?,
        machine_id_policy: as_str_field(t, "machine_id_policy", "privacy")?,
        hostname_mode: as_str_field(t, "hostname_mode", "privacy")?,
    })
}

fn parse_vault(t: &BTreeMap<String, Value>) -> Result<Vault> {
    check_keys(t, &["idle_unmount_secs"], "vault")?;
    Ok(Vault {
        idle_unmount_secs: as_int_field(t, "idle_unmount_secs", "vault")? as u64,
    })
}

impl SystemConfig {
    /// Load and strictly parse the configuration file.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        Self::from_str(&raw)
    }

    /// Parse configuration text (strict schema, unknown keys rejected).
    pub fn from_str(raw: &str) -> Result<Self> {
        let root = namikaze_rt::toml::parse(raw)?;
        check_keys(
            &root,
            &["storage", "anonymity", "sentinel", "memory", "desktop", "privacy", "vault", "live"],
            "system",
        )?;
        let cfg = SystemConfig {
            storage: parse_storage(as_table_field(&root, "storage", "system")?)?,
            anonymity: parse_anonymity(as_table_field(&root, "anonymity", "system")?)?,
            sentinel: parse_sentinel(as_table_field(&root, "sentinel", "system")?)?,
            memory: parse_memory(as_table_field(&root, "memory", "system")?)?,
            desktop: parse_desktop(as_table_field(&root, "desktop", "system")?)?,
            privacy: parse_privacy(as_table_field(&root, "privacy", "system")?)?,
            vault: parse_vault(as_table_field(&root, "vault", "system")?)?,
            live: parse_live(as_table_field(&root, "live", "system")?)?,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load /etc/namikaze/system.toml, falling back to defaults if absent.
    pub fn load_or_default() -> Self {
        Self::load(Path::new("/etc/namikaze/system.toml")).unwrap_or_default()
    }

    /// Serialize back to TOML text (deterministic section order).
    pub fn to_toml(&self) -> Result<String> {
        let mut out = String::new();
        out.push_str("[storage]\n");
        out.push_str(&format!("mode = \"{}\"\n", self.storage.mode));
        out.push_str(&format!("root_fs = \"{}\"\n", self.storage.root_fs));
        out.push_str(&format!("boot_tier = \"{}\"\n", self.storage.boot_tier));
        out.push_str(&format!("header_backup = \"{}\"\n", self.storage.header_backup));
        out.push_str(&format!("recovery_code = {}\n", self.storage.recovery_code));
        out.push_str(&format!(
            "per_user_encryption = \"{}\"\n",
            self.storage.per_user_encryption
        ));
        out.push_str(&format!("tpm_sealing = \"{}\"\n", self.storage.tpm_sealing));
        out.push_str(&format!("hibernation = {}\n", self.storage.hibernation));
        out.push_str("\n[storage.pbkdf]\n");
        out.push_str(&format!("algo = \"{}\"\n", self.storage.pbkdf.algo));
        out.push_str(&format!("memory_kb = {}\n", self.storage.pbkdf.memory_kb));
        out.push_str(&format!("iterations = {}\n", self.storage.pbkdf.iterations));
        out.push_str(&format!("parallel = {}\n", self.storage.pbkdf.parallel));
        out.push_str("\n[anonymity]\n");
        out.push_str(&format!("level = \"{}\"\n", self.anonymity.level));
        out.push_str(&format!("transparent_tor = {}\n", self.anonymity.transparent_tor));
        out.push_str(&format!(
            "block_non_tor_egress = {}\n",
            self.anonymity.block_non_tor_egress
        ));
        out.push_str(&format!("ipv6 = \"{}\"\n", self.anonymity.ipv6));
        out.push_str("\n[sentinel]\n");
        out.push_str(&format!("enabled = {}\n", self.sentinel.enabled));
        out.push_str(&format!("max_failures = {}\n", self.sentinel.max_failures));
        out.push_str(&format!(
            "failure_window_secs = {}\n",
            self.sentinel.failure_window_secs
        ));
        out.push_str(&format!("retention_days = {}\n", self.sentinel.retention_days));
        out.push_str("\n[memory]\n");
        out.push_str(&format!("zram = {}\n", self.memory.zram));
        out.push_str(&format!("zram_algorithm = \"{}\"\n", self.memory.zram_algorithm));
        out.push_str(&format!("mglru = {}\n", self.memory.mglru));
        out.push_str(&format!("thp = \"{}\"\n", self.memory.thp));
        out.push_str("\n[desktop]\n");
        out.push_str(&format!("environment = \"{}\"\n", self.desktop.environment));
        out.push_str(&format!("compositor = {}\n", self.desktop.compositor));
        out.push_str(&format!("terminal = \"{}\"\n", self.desktop.terminal));
        out.push_str(&format!("launcher = \"{}\"\n", self.desktop.launcher));
        out.push_str(&format!("bar = \"{}\"\n", self.desktop.bar));
        out.push_str(&format!("notifications = \"{}\"\n", self.desktop.notifications));
        out.push_str(&format!("lock = \"{}\"\n", self.desktop.lock));
        out.push_str(&format!("kb_layout = \"{}\"\n", self.desktop.kb_layout));
        out.push_str(&format!("gap = {}\n", self.desktop.gap));
        out.push_str(&format!("autologin = {}\n", self.desktop.autologin));
        out.push_str(&format!("greeter_user = \"{}\"\n", self.desktop.greeter_user));
        out.push_str("\n[privacy]\n");
        out.push_str(&format!("destructive_tools = {}\n", self.privacy.destructive_tools));
        out.push_str(&format!(
            "machine_id_policy = \"{}\"\n",
            self.privacy.machine_id_policy
        ));
        out.push_str(&format!("hostname_mode = \"{}\"\n", self.privacy.hostname_mode));
        out.push_str("\n[vault]\n");
        out.push_str(&format!("idle_unmount_secs = {}\n", self.vault.idle_unmount_secs));
        out.push_str("\n[live]\n");
        out.push_str(&format!("default_mode = \"{}\"\n", self.live.default_mode));
        out.push_str(&format!("persist_label = \"{}\"\n", self.live.persist_label));
        out.push_str(&format!(
            "max_pass_attempts = {}\n",
            self.live.max_pass_attempts
        ));
        out.push_str(&format!("fallback = \"{}\"\n", self.live.fallback));
        out.push_str(&format!("trim = {}\n", self.live.trim));
        Ok(out)
    }

    /// Cross-field validation. Returns a list of problems (empty = valid).
    pub fn validate(&self) -> Result<()> {
        let mut problems = Vec::new();
        if !matches!(self.storage.mode.as_str(), "persistent" | "live") {
            problems.push(format!("storage.mode invalid: {}", self.storage.mode));
        }
        if !matches!(self.storage.root_fs.as_str(), "ext4" | "f2fs" | "btrfs") {
            problems.push(format!("storage.root_fs invalid: {}", self.storage.root_fs));
        }
        if !matches!(self.storage.boot_tier.as_str(), "A" | "B" | "C") {
            problems.push(format!("storage.boot_tier invalid: {}", self.storage.boot_tier));
        }
        if !matches!(self.anonymity.level.as_str(), "standard" | "hardened" | "maximum") {
            problems.push(format!("anonymity.level invalid: {}", self.anonymity.level));
        }
        if self.desktop.environment != "niri" {
            problems.push(format!(
                "desktop.environment invalid: {} (v3 ships exactly one session: niri)",
                self.desktop.environment
            ));
        }
        if !matches!(self.live.default_mode.as_str(), "persist" | "volatile" | "session") {
            problems.push(format!("live.default_mode invalid: {}", self.live.default_mode));
        }
        if !matches!(self.live.fallback.as_str(), "volatile" | "panic") {
            problems.push(format!("live.fallback invalid: {}", self.live.fallback));
        }
        if self.storage.hibernation && !self.storage.mode.eq("persistent") {
            problems.push("hibernation requires persistent storage".into());
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(Error::Config(problems.join("; ")))
        }
    }

    /// Doctor checks: actionable hints for a running system.
    pub fn doctor(&self) -> Vec<(String, bool, String)> {
        vec![
            (
                "Niri Wayland session is the configured desktop".into(),
                self.desktop.environment == "niri",
                "set [desktop].environment = niri".into(),
            ),
            (
                "zram enabled for anonymous memory".into(),
                self.memory.zram,
                "enable [memory].zram".into(),
            ),
            (
                "transparent Tor routing active".into(),
                self.anonymity.transparent_tor,
                "enable [anonymity].transparent_tor".into(),
            ),
            (
                "non-Tor egress blocked".into(),
                self.anonymity.block_non_tor_egress,
                "enable [anonymity].block_non_tor_egress".into(),
            ),
            (
                "hibernation disabled (RAM image on disk is a leak vector)".into(),
                !self.storage.hibernation,
                "keep [storage].hibernation = false".into(),
            ),
            (
                "destructive tools opt-in only".into(),
                !self.privacy.destructive_tools,
                "keep [privacy].destructive_tools = false unless needed".into(),
            ),
        ]
    }
}

/// Emit the hardening sysctl content for a profile.
pub fn hardening_sysctl(profile: HardenProfile) -> String {
    let mut out = String::from("# Generated by namikaze-config harden\n");
    out.push_str("kernel.kptr_restrict = 2\n");
    out.push_str("kernel.dmesg_restrict = 1\n");
    out.push_str("kernel.unprivileged_bpf_disabled = 1\n");
    out.push_str("kernel.yama.ptrace_scope = 2\n");
    out.push_str("kernel.randomize_va_space = 2\n");
    out.push_str("fs.suid_dumpable = 0\n");
    out.push_str("fs.protected_hardlinks = 1\n");
    out.push_str("fs.protected_fifos = 1\n");
    out.push_str("fs.protected_regular = 2\n");
    out.push_str("fs.protected_symlinks = 1\n");
    out.push_str("vm.mmap_min_addr = 65536\n");
    out.push_str("vm.unprivileged_userfaultfd = 0\n");
    out.push_str("net.core.bpf_jit_harden = 2\n");
    out.push_str("net.ipv4.conf.all.rp_filter = 1\n");
    out.push_str("net.ipv4.conf.all.accept_redirects = 0\n");
    out.push_str("net.ipv4.conf.all.send_redirects = 0\n");
    out.push_str("net.ipv4.conf.all.accept_source_route = 0\n");
    out.push_str("net.ipv4.tcp_syncookies = 1\n");
    if matches!(profile, HardenProfile::CisL2) {
        out.push_str("kernel.kexec_load_disabled = 1\n");
        out.push_str("kernel.sysrq = 0\n");
        out.push_str("kernel.unprivileged_userns_clone = 0\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        assert!(SystemConfig::default().validate().is_ok());
    }

    #[test]
    fn invalid_level_is_rejected() {
        let mut cfg = SystemConfig::default();
        cfg.anonymity.level = "extreme".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn invalid_environment_is_rejected() {
        let mut cfg = SystemConfig::default();
        cfg.desktop.environment = "xfce".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn shipped_system_toml_matches_schema() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../sysroot/etc/namikaze/system.toml");
        let cfg = SystemConfig::load(&path)
            .expect("sysroot/etc/namikaze/system.toml must parse against the schema");
        assert_eq!(cfg.desktop.environment, "niri");
        assert!(cfg.desktop.compositor);
        assert_eq!(cfg.desktop.terminal, "foot");
        assert_eq!(cfg.live.default_mode, "persist");
        assert_eq!(cfg.live.max_pass_attempts, 5);
    }

    #[test]
    fn l2_profile_adds_controls() {
        let l1 = hardening_sysctl(HardenProfile::CisL1);
        let l2 = hardening_sysctl(HardenProfile::CisL2);
        assert!(!l1.contains("kexec_load_disabled"));
        assert!(l2.contains("kexec_load_disabled"));
    }

    #[test]
    fn roundtrip_preserves_values() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../sysroot/etc/namikaze/system.toml");
        let cfg = SystemConfig::load(&path).unwrap();
        let text = cfg.to_toml().unwrap();
        let again = SystemConfig::from_str(&text).unwrap();
        assert_eq!(cfg, again);
    }

    #[test]
    fn unknown_key_fails_loudly() {
        let err = SystemConfig::from_str("[storage]\nmode = \"live\"\nnope = 1\n").unwrap_err();
        assert!(err.to_string().contains("unknown key"));
    }
}
