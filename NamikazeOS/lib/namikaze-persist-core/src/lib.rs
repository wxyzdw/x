// SPDX-License-Identifier: MPL-2.0
//! Pure logic for the NamikazeOS encrypted persist volume.
//!
//! Argon2id profiles scaled to machine resources, integrity modes, the
//! passphrase policy and the exact `cryptsetup` argument construction.
//! No I/O happens here; `namikaze-persist` and `namikaze-init` execute.

#![forbid(unsafe_code)]

/// Argon2id cost profiles. Memory hardness is what makes off-line guessing
/// with GPUs/ASICs uneconomical; caps keep boot time bounded on low-RAM SBCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ArgonProfile {
    LowMem,
    #[default]
    Balanced,
    Paranoid,
}

impl ArgonProfile {
    /// Parse the `argon` configuration value.
    pub fn parse(value: &str) -> ArgonProfile {
        match value {
            "lowmem" | "low" => ArgonProfile::LowMem,
            "paranoid" => ArgonProfile::Paranoid,
            _ => ArgonProfile::Balanced,
        }
    }

    /// Derive concrete parameters from the machine (cpus, RAM in KiB).
    pub fn params(self, cpus: u32, ram_kb: u64) -> ArgonParams {
        let quarter = (ram_kb / 4).min(u32::MAX as u64) as u32;
        let parallel = cpus.clamp(1, 4);
        match self {
            ArgonProfile::LowMem => {
                ArgonParams { time_cost_ms: 500, memory_kb: quarter.min(256 * 1024), parallel }
            }
            ArgonProfile::Balanced => {
                ArgonParams { time_cost_ms: 800, memory_kb: quarter.min(1024 * 1024), parallel }
            }
            ArgonProfile::Paranoid => ArgonParams {
                time_cost_ms: 2000,
                memory_kb: (quarter * 2).min(2048 * 1024),
                parallel,
            },
        }
    }
}

/// Concrete PBKDF parameters handed to cryptsetup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgonParams {
    pub time_cost_ms: u32,
    pub memory_kb: u32,
    pub parallel: u32,
}

/// Optional dm-integrity layer below LUKS2 for bit-rot resistance on
/// cheap flash. HMAC mode intentionally not offered: it adds keys to guard
/// without removing the passphrase the user already has to protect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IntegrityMode {
    #[default]
    None,
    Crc,
}

impl IntegrityMode {
    pub fn parse(value: &str) -> IntegrityMode {
        match value {
            "crc" | "crc32c" => IntegrityMode::Crc,
            _ => IntegrityMode::None,
        }
    }

    /// Extra cryptsetup arguments for `luksFormat`.
    pub fn cryptsetup_args(self) -> &'static [&'static str] {
        match self {
            IntegrityMode::None => &[],
            IntegrityMode::Crc => &["--integrity", "crc32c"],
        }
    }
}

/// Passphrase policy errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassError {
    TooShort,
    Mismatch,
}

impl std::fmt::Display for PassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PassError::TooShort => write!(f, "passphrase must be at least 12 characters"),
            PassError::Mismatch => write!(f, "passphrases do not match"),
        }
    }
}

/// Minimum passphrase length for volume creation. Unlock accepts whatever
/// the user types; the policy guards creation quality only.
pub fn validate_passphrase(pass: &[u8]) -> std::result::Result<(), PassError> {
    if pass.len() < 12 {
        return Err(PassError::TooShort);
    }
    Ok(())
}

/// Reserved LUKS key slot for user-created recovery keys. Never written
/// automatically; only `--recovery` operations may touch it.
pub const RECOVERY_SLOT: u8 = 7;

/// Build the exact `cryptsetup luksFormat` argv for the given profile.
/// The passphrase is fed on stdin (`--key-file=-`), never through argv.
pub fn format_argv(
    device: &str,
    profile: ArgonProfile,
    integrity: IntegrityMode,
    cpus: u32,
    ram_kb: u64,
) -> Vec<String> {
    let p = profile.params(cpus, ram_kb);
    let mut argv = vec![
        "cryptsetup".to_string(),
        "luksFormat".to_string(),
        "--type".to_string(),
        "luks2".to_string(),
        "--pbkdf".to_string(),
        "argon2id".to_string(),
        "--pbkdf-memory".to_string(),
        p.memory_kb.to_string(),
        "--pbkdf-time-cost".to_string(),
        p.time_cost_ms.to_string(),
        "--pbkdf-parallel".to_string(),
        p.parallel.to_string(),
        "--key-slot".to_string(),
        "0".to_string(),
    ];
    for arg in integrity.cryptsetup_args() {
        argv.push(arg.to_string());
    }
    argv.push(device.to_string());
    argv
}

/// Parsed highlights of a `cryptsetup luksDump` document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LuksSummary {
    pub pbkdf: Option<String>,
    pub cipher: Option<String>,
    pub cipher_mode: Option<String>,
    pub keyslots: Vec<u8>,
}

/// Extract PBKDF, cipher and keyslot list from `luksDump` output.
/// Parsing is intentionally tolerant: unknown formats yield empty fields.
pub fn parse_luks_dump(text: &str) -> LuksSummary {
    let mut s = LuksSummary::default();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("PBKDF:") {
            let v = rest.trim();
            if !v.is_empty() && !v.starts_with('(') {
                s.pbkdf = Some(v.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("Cipher name:") {
            s.cipher = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Cipher mode:") {
            s.cipher_mode = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Keyslot ") {
            if let Some(num) = rest.split(':').next() {
                if let Ok(slot) = num.trim().parse::<u8>() {
                    s.keyslots.push(slot);
                }
            }
        } else if line.strip_prefix("Keyslots:").is_some() {
            // modern luksDump header; slot lines are handled below
        } else if let Some(colon) = line.find(": ") {
            // modern format slot lines look like "  0: luks2"
            let head = line[..colon].trim();
            if !head.is_empty() && head.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(slot) = head.parse::<u8>() {
                    s.keyslots.push(slot);
                }
            }
        }
    }
    s
}

/// Doctor checks over a parsed summary. Each tuple is (check, ok, detail).
pub fn doctor_checks(s: &LuksSummary) -> Vec<(String, bool, String)> {
    vec![
        (
            "pbkdf-is-argon2id".to_string(),
            s.pbkdf.as_deref() == Some("argon2id"),
            s.pbkdf.clone().unwrap_or_else(|| "unknown".to_string()),
        ),
        (
            "cipher-is-aes-xts".to_string(),
            s.cipher.as_deref().map(|c| c.contains("aes")).unwrap_or(false)
                && s.cipher_mode.as_deref().map(|m| m.contains("xts")).unwrap_or(false),
            format!(
                "{} / {}",
                s.cipher.clone().unwrap_or_else(|| "unknown".into()),
                s.cipher_mode.clone().unwrap_or_else(|| "unknown".into())
            ),
        ),
        (
            "keyslots-present".to_string(),
            !s.keyslots.is_empty(),
            format!("{} slot(s)", s.keyslots.len()),
        ),
        (
            "recovery-slot-absent".to_string(),
            !s.keyslots.contains(&RECOVERY_SLOT),
            "slot 7 reserved for explicit recovery keys".to_string(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon_scales_with_memory() {
        let low = ArgonProfile::LowMem.params(2, 512 * 1024);
        let high = ArgonProfile::Paranoid.params(4, 8 * 1024 * 1024);
        assert!(high.memory_kb > low.memory_kb);
        assert_eq!(high.parallel, 4);
    }

    #[test]
    fn passphrase_min_length() {
        assert_eq!(validate_passphrase(b"short"), Err(PassError::TooShort));
        assert!(validate_passphrase(b"a long enough phrase").is_ok());
    }

    #[test]
    fn format_argv_is_exact() {
        let argv = format_argv(
            "/dev/sdz4",
            ArgonProfile::Balanced,
            IntegrityMode::Crc,
            4,
            8 * 1024 * 1024,
        );
        assert_eq!(argv[0], "cryptsetup");
        assert!(argv.windows(2).any(|w| w == ["--pbkdf", "argon2id"]));
        assert!(argv.contains(&"/dev/sdz4".to_string()));
        assert!(argv.contains(&"--integrity".to_string()));
    }

    #[test]
    fn luks_dump_parses() {
        let dump = "\
LUKS header information
Version:        2
Cipher name:    aes
Cipher mode:    xts-plain64
PBKDF:          argon2id
Keyslots:
  0: luks2
    Priority:  normal";
        let s = parse_luks_dump(dump);
        assert_eq!(s.pbkdf.as_deref(), Some("argon2id"));
        assert_eq!(s.cipher.as_deref(), Some("aes"));
        assert_eq!(s.keyslots, vec![0]);
        let checks = doctor_checks(&s);
        assert!(checks.iter().all(|(_, ok, _)| *ok));
    }
}
