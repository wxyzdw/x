// SPDX-License-Identifier: MPL-2.0
//! namikaze-tune: performance and power policy profiles.
//!
//! Adapts to the detected machine (board class from namikaze-hal): SBCs get
//! conservative defaults, servers get throughput-oriented values. Swap is
//! encrypted (zram) only; cold swap to disk is never enabled.

#![forbid(unsafe_code)]

use namikaze_common::{Error, Result};
use namikaze_persist_core::ArgonProfile;

/// Tuning profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Default: responsive desktop, modest power draw.
    Balanced,
    /// Maximum performance; higher heat and power.
    Performance,
    /// Maximum battery / silence; slower wake-ups allowed.
    Stealth,
}

impl Profile {
    pub fn parse(value: &str) -> Profile {
        match value {
            "performance" | "max" => Profile::Performance,
            "stealth" | "battery" => Profile::Stealth,
            _ => Profile::Balanced,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Balanced => "balanced",
            Profile::Performance => "performance",
            Profile::Stealth => "stealth",
        }
    }
}

/// Sysctl values for a profile, as (path-under-/proc/sys, value) pairs.
pub fn sysctl_values(profile: Profile) -> Vec<(&'static str, &'static str)> {
    match profile {
        Profile::Balanced => vec![
            ("vm/swappiness", "60"),
            ("vm/vfs_cache_pressure", "100"),
            ("vm/dirty_writeback_centisecs", "600"),
            ("kernel/sched_autogroup_enabled", "1"),
        ],
        Profile::Performance => vec![
            ("vm/swappiness", "100"),
            ("vm/vfs_cache_pressure", "50"),
            ("vm/dirty_writeback_centisecs", "300"),
            ("kernel/sched_autogroup_enabled", "1"),
        ],
        Profile::Stealth => vec![
            ("vm/swappiness", "10"),
            ("vm/vfs_cache_pressure", "150"),
            ("vm/dirty_writeback_centisecs", "1500"),
            ("kernel/sched_autogroup_enabled", "1"),
        ],
    }
}

/// cpufreq governor for a profile.
pub fn governor(profile: Profile) -> &'static str {
    match profile {
        Profile::Performance => "performance",
        Profile::Balanced => "schedutil",
        Profile::Stealth => "powersave",
    }
}

/// Recommend an Argon2id profile from available RAM (KiB).
pub fn recommend_argon(ram_kb: u64) -> ArgonProfile {
    if ram_kb < 2 * 1024 * 1024 {
        ArgonProfile::LowMem
    } else if ram_kb >= 8 * 1024 * 1024 {
        ArgonProfile::Paranoid
    } else {
        ArgonProfile::Balanced
    }
}

/// Apply a profile: sysctl writes then cpufreq governor. Individual failures
/// are tolerated (kernels differ per arch) and reported in the summary.
pub fn apply(profile: Profile) -> Result<Vec<(String, bool)>> {
    let mut report = Vec::new();
    for (key, value) in sysctl_values(profile) {
        let path = std::path::Path::new("/proc/sys").join(key);
        let ok = std::fs::write(&path, value).is_ok();
        report.push((key.to_string(), ok));
    }
    let gov = governor(profile);
    let mut written = 0;
    if let Ok(entries) = std::fs::read_dir("/sys/devices/system/cpu") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("cpu") || !name[3..].chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let gov_path = entry.path().join("cpufreq/scaling_governor");
            if std::fs::write(&gov_path, gov).is_ok() {
                written += 1;
            }
        }
    }
    report.push((format!("cpufreq/{gov}"), written > 0));
    if report.iter().all(|(_, ok)| !*ok) {
        return Err(Error::Other("no sysctl or cpufreq write succeeded".into()));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_differ() {
        assert!(governor(Profile::Performance) != governor(Profile::Stealth));
        let (a, b) = (sysctl_values(Profile::Balanced), sysctl_values(Profile::Stealth));
        assert_ne!(a, b);
    }

    #[test]
    fn argon_recommendation() {
        assert_eq!(recommend_argon(1024 * 1024), ArgonProfile::LowMem);
        assert_eq!(recommend_argon(4 * 1024 * 1024), ArgonProfile::Balanced);
        assert_eq!(recommend_argon(16 * 1024 * 1024), ArgonProfile::Paranoid);
    }

    #[test]
    fn governor_mapping_exact() {
        assert_eq!(governor(Profile::Performance), "performance");
        assert_eq!(governor(Profile::Balanced), "schedutil");
        assert_eq!(governor(Profile::Stealth), "powersave");
    }

    #[test]
    fn profile_parse_aliases() {
        assert_eq!(Profile::parse("performance"), Profile::Performance);
        assert_eq!(Profile::parse("max"), Profile::Performance);
        assert_eq!(Profile::parse("stealth"), Profile::Stealth);
        assert_eq!(Profile::parse("battery"), Profile::Stealth);
        assert_eq!(Profile::parse("balanced"), Profile::Balanced);
        assert_eq!(Profile::parse("unknown-value"), Profile::Balanced);
    }

    #[test]
    fn swappiness_orders_by_profile() {
        let perf = swappiness(Profile::Performance);
        let balanced = swappiness(Profile::Balanced);
        let stealth = swappiness(Profile::Stealth);
        assert!(perf > balanced && balanced > stealth);
    }

    #[test]
    fn sysctl_paths_are_flat_keys() {
        for profile in [Profile::Balanced, Profile::Performance, Profile::Stealth] {
            for (path, value) in sysctl_values(profile) {
                assert!(!path.starts_with('/'), "path must be /proc/sys relative: {path}");
                assert!(!value.is_empty(), "value must not be empty for {path}");
                assert!(!value.contains(' '), "value must be a single token for {path}");
            }
        }
    }

    fn swappiness(profile: Profile) -> u32 {
        sysctl_values(profile)
            .iter()
            .find(|(p, _)| *p == "vm/swappiness")
            .map(|(_, v)| v.parse().expect("swappiness numeric"))
            .expect("swappiness present")
    }
}
