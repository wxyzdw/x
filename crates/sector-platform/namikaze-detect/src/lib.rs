// SPDX-License-Identifier: MPL-2.0
//! CPU, firmware and virtualization detection with tuning profiles.
//!
//! The ISO boots on every machine; this crate decides HOW it should run on
//! this one. Exposed as a library so `namikaze-report` can reuse results.

#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use namikaze_common::{Error, Result};
use namikaze_rt::json::{self, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    X86_64Base,
    X86_64V2,
    X86_64V3,
    X86_64V4,
    ArmV8_0,
    ArmV8_1Plus,
    Other,
}

impl Profile {
    /// snake_case tag used by the JSON report.
    pub fn as_tag(&self) -> &'static str {
        match self {
            Profile::X86_64Base => "x86_64_base",
            Profile::X86_64V2 => "x86_64_v2",
            Profile::X86_64V3 => "x86_64_v3",
            Profile::X86_64V4 => "x86_64_v4",
            Profile::ArmV8_0 => "arm_v8_0",
            Profile::ArmV8_1Plus => "arm_v8_1_plus",
            Profile::Other => "other",
        }
    }

    pub fn as_label(&self) -> &'static str {
        match self {
            Profile::X86_64Base => "x86-64-base",
            Profile::X86_64V2 => "x86-64-v2",
            Profile::X86_64V3 => "x86-64-v3",
            Profile::X86_64V4 => "x86-64-v4",
            Profile::ArmV8_0 => "armv8.0",
            Profile::ArmV8_1Plus => "armv8.1+",
            Profile::Other => "other",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetectionReport {
    pub machine: String,
    pub profile: Profile,
    pub vendor: String,
    pub product: String,
    pub guest: Option<String>,
    pub virtio: bool,
}

fn x86_64_level() -> Profile {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx512f") {
            Profile::X86_64V4
        } else if std::arch::is_x86_feature_detected!("avx2")
            && std::arch::is_x86_feature_detected!("bmi2")
            && std::arch::is_x86_feature_detected!("fma")
        {
            Profile::X86_64V3
        } else if std::arch::is_x86_feature_detected!("sse4.2")
            && std::arch::is_x86_feature_detected!("popcnt")
        {
            Profile::X86_64V2
        } else {
            Profile::X86_64Base
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Profile::X86_64Base
    }
}

fn aarch64_level() -> Profile {
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("lse") {
            Profile::ArmV8_1Plus
        } else {
            Profile::ArmV8_0
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        Profile::Other
    }
}

fn arm_hwcaps_level() -> Profile {
    // Fallback when runtime feature detection is unavailable: parse hwcaps
    // from /proc/cpuinfo on armv7/arm64 hosts.
    let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") else {
        return Profile::Other;
    };
    let Some(features) = cpuinfo
        .lines()
        .find(|l| l.starts_with("Features"))
        .and_then(|l| l.split(':').nth(1))
    else {
        return Profile::Other;
    };
    if features.split_whitespace().any(|f| f == "atomics" || f == "lse") {
        Profile::ArmV8_1Plus
    } else {
        Profile::ArmV8_0
    }
}

/// Detect the microarchitectural profile for the running CPU.
pub fn detect_profile() -> Profile {
    match std::env::consts::ARCH {
        "x86_64" => x86_64_level(),
        "aarch64" => {
            let l = aarch64_level();
            if matches!(l, Profile::Other) {
                arm_hwcaps_level()
            } else {
                l
            }
        }
        "arm" => arm_hwcaps_level(),
        _ => Profile::Other,
    }
}

fn dmi_field(name: &str) -> String {
    namikaze_common::read_first_line(&Path::new("/sys/class/dmi/id").join(name)).unwrap_or_default()
}

fn detect_guest() -> Option<String> {
    let vendor = dmi_field("sys_vendor").to_lowercase();
    let product = dmi_field("product_name").to_lowercase();
    let hay = format!("{vendor} {product}");
    for (needle, label) in [
        ("qemu", "qemu"),
        ("vmware", "vmware"),
        ("virtualbox", "virtualbox"),
        ("innotek", "virtualbox"),
        ("microsoft corporation", "hyper-v"),
        ("xen", "xen"),
    ] {
        if hay.contains(needle) {
            return Some(label.to_string());
        }
    }
    if Path::new("/proc/xen").exists() {
        return Some("xen".into());
    }
    None
}

impl DetectionReport {
    /// Deterministic JSON rendering (sorted keys).
    pub fn to_json(&self) -> Value {
        json::obj(&[
            ("machine", Value::Str(self.machine.clone())),
            ("profile", Value::Str(self.profile.as_tag().to_string())),
            ("vendor", Value::Str(self.vendor.clone())),
            ("product", Value::Str(self.product.clone())),
            (
                "guest",
                self.guest
                    .clone()
                    .map(Value::Str)
                    .unwrap_or(Value::Null),
            ),
            ("virtio", Value::Bool(self.virtio)),
        ])
    }
}

/// Produce a full detection report for the running machine.
pub fn detect() -> DetectionReport {
    DetectionReport {
        machine: std::env::consts::ARCH.to_string(),
        profile: detect_profile(),
        vendor: dmi_field("sys_vendor"),
        product: dmi_field("product_name"),
        guest: detect_guest(),
        virtio: Path::new("/sys/bus/virtio").exists(),
    }
}

/// Apply the tuning profile: CPU governor and IO scheduler.
pub fn apply_tuning() -> Result<()> {
    if Path::new("/sys/devices/system/cpu").exists() {
        for entry in fs::read_dir("/sys/devices/system/cpu")?
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("cpu"))
        {
            let gov = entry.path().join("cpufreq/scaling_governor");
            if gov.exists() {
                let _ = fs::write(&gov, "performance");
            }
        }
    }
    for entry in fs::read_dir("/sys/block")?.flatten() {
        let dev = entry.file_name().to_string_lossy().to_string();
        let sched = entry.path().join("queue/scheduler");
        if !sched.exists() {
            continue;
        }
        let choice = if dev.starts_with("nvme") { "none" } else { "mq-deadline" };
        fs::write(&sched, choice).map_err(Error::Io)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_ascii_and_stable() {
        assert_eq!(Profile::X86_64V3.as_label(), "x86-64-v3");
        assert_eq!(Profile::ArmV8_0.as_label(), "armv8.0");
    }
}
