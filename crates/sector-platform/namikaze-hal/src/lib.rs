// SPDX-License-Identifier: MPL-2.0
//! namikaze-hal: hardware adaptation layer.
//!
//! Matches boot-time detection data against a curated board database and
//! produces a complete hardware plan: DTB selection, firmware set, ordered
//! module list, GPU/WiFi driver choice and seatd-aware udev rules. One ISO,
//! every machine: arch-generic kernels plus per-board glue defined here.

#![forbid(unsafe_code)]

pub mod board_db;
pub mod gpu;
pub mod pci;
pub mod udev_gen;

use std::fs;
use std::path::Path;

use namikaze_common::{Error, Result};
use namikaze_rt::json::{self, Value};

/// CPU architectures shipped on the OneISO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
    Armv7,
    Armv6,
    Riscv64,
    Loongarch64,
    Ppc64le,
    S390x,
}

impl Arch {
    /// snake_case JSON tag.
    pub fn as_tag(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
            Arch::Armv7 => "armv7",
            Arch::Armv6 => "armv6",
            Arch::Riscv64 => "riscv64",
            Arch::Loongarch64 => "loongarch64",
            Arch::Ppc64le => "ppc64le",
            Arch::S390x => "s390x",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
            Arch::Armv7 => "armv7",
            Arch::Armv6 => "armv6",
            Arch::Riscv64 => "riscv64",
            Arch::Loongarch64 => "loongarch64",
            Arch::Ppc64le => "ppc64le",
            Arch::S390x => "s390x",
        }
    }

    pub fn parse(value: &str) -> Option<Arch> {
        Some(match value {
            "x86_64" | "amd64" => Arch::X86_64,
            "aarch64" | "arm64" => Arch::Aarch64,
            "armv7" | "arm" => Arch::Armv7,
            "armv6" => Arch::Armv6,
            "riscv64" => Arch::Riscv64,
            "loongarch64" => Arch::Loongarch64,
            "ppc64le" => Arch::Ppc64le,
            "s390x" => Arch::S390x,
            _ => return None,
        })
    }
}

/// System-on-chip identifiers for the supported board families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Soc {
    Bcm2712,
    Bcm2711,
    Bcm2837,
    Rk3588,
    Rk3588s,
    Rk3568,
    Sun8iH3,
    Sun50iA64,
    Sun50iH6,
    MesonG12b,
    MesonSm1,
    MesonGxl,
    Am625,
    J721e,
    Tegra234,
    Jh7110,
    Th1520,
    Fu740,
    Sg2042,
    Power9,
    Loongson3A,
    AppleT8103,
    AppleT6020,
    X86Intel,
    X86Amd,
    Generic,
}

/// Board-specific behavior flags consumed by init and service scripts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quirk {
    /// Serial console overrides the default tty for early messages.
    SerialConsole(&'static str),
    /// DTB is supplied by the firmware (Petitboot); the kernel ships none.
    FirmwareProvidedDtb,
    /// Stack requires vendor userland (Asahi); treated as experimental.
    RequiresAsahi,
    /// Board is bring-up quality; excluded from the certified build.
    Experimental,
}

/// Detection inputs gathered from namikaze-detect and runtime sysfs scans.
#[derive(Debug, Clone, Default)]
pub struct HardwareReport {
    pub arch: Option<Arch>,
    pub dt_compatibles: Vec<String>,
    pub dmi_board_name: Option<String>,
    pub dmi_board_vendor: Option<String>,
    pub cpu_model: Option<String>,
    pub ram_kb: u64,
    pub pci: Vec<pci::PciDevice>,
    pub usb: Vec<pci::UsbDevice>,
}

impl HardwareReport {
    /// Best matching board profile: DT compatible exact match first, then
    /// DMI glob, then the arch generic row.
    pub fn best_board(&self) -> &'static board_db::BoardProfile {
        board_db::match_board(self)
    }

    /// Load a report written by `namikaze-detect` as KEY=VALUE lines.
    pub fn from_env_file(path: &Path) -> Result<HardwareReport> {
        let text = fs::read_to_string(path)?;
        let mut r = HardwareReport::default();
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            match k {
                "NAMIKAZE_ARCH" => r.arch = Arch::parse(v),
                "NAMIKAZE_DT_COMPATIBLE" => {
                    r.dt_compatibles = v.split_whitespace().map(String::from).collect();
                }
                "NAMIKAZE_DMI_BOARD_NAME" => r.dmi_board_name = Some(v.to_string()),
                "NAMIKAZE_DMI_BOARD_VENDOR" => r.dmi_board_vendor = Some(v.to_string()),
                "NAMIKAZE_CPU_MODEL" => r.cpu_model = Some(v.to_string()),
                "NAMIKAZE_RAM_KB" => r.ram_kb = v.parse().unwrap_or(0),
                _ => {}
            }
        }
        Ok(r)
    }

    /// Re-scan the running system (post-pivot path when no env file exists).
    pub fn from_sysfs() -> Result<HardwareReport> {
        let mut r = HardwareReport::default();
        if let Ok(t) = fs::read_to_string("/proc/device-tree/compatible") {
            r.dt_compatibles = t
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
        }
        let dmi = |f: &str| -> Option<String> {
            fs::read_to_string(format!("/sys/class/dmi/id/{f}"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        r.dmi_board_vendor = dmi("board_vendor");
        r.dmi_board_name = dmi("board_name");
        if let Ok(t) = fs::read_to_string("/proc/meminfo") {
            for line in t.lines() {
                if let Some(rest) = line.strip_prefix("MemTotal:") {
                    r.ram_kb = rest
                        .trim()
                        .trim_end_matches(" kB")
                        .replace(',', "")
                        .parse()
                        .unwrap_or(0);
                }
            }
        }
        r.arch = Arch::parse(std::env::consts::ARCH);
        let _ = pci::scan(&mut r);
        Ok(r)
    }
}

/// The complete plan written to /run/namikaze by `apply`.
#[derive(Debug, Clone)]
pub struct AppliedPlan {
    pub board: String,
    pub arch: String,
    pub dtb: String,
    pub gpu_driver: String,
    pub wifi_driver: String,
    pub firmware_dirs: Vec<String>,
    pub modules: Vec<String>,
    pub env_file: String,
    pub udev_rules: String,
    pub modules_load: String,
}

/// Write the hardware plan for the running machine: environment file for
/// consumers, udev rules, forced module load list and a JSON summary.
pub fn apply(report: &HardwareReport, run_dir: &Path) -> Result<AppliedPlan> {
    let board = report.best_board();
    fs::create_dir_all(run_dir)?;
    fs::create_dir_all(run_dir.join("udev/rules.d"))?;

    let gpu_driver = gpu::select(report);
    let wifi_driver = gpu::wifi_select(report);

    let env = format!(
        "NAMIKAZE_BOARD={}\nNAMIKAZE_ARCH={}\nNAMIKAZE_DTB={}\n\
         NAMIKAZE_GPU_DRIVER={}\nNAMIKAZE_WIFI_DRIVER={}\n\
         NAMIKAZE_DT_COMPATIBLE={}\nNAMIKAZE_DMI_BOARD_NAME={}\n\
         NAMIKAZE_CPU_MODEL={}\nNAMIKAZE_RAM_KB={}\n",
        board.id,
        board.arch.as_str(),
        board.dtb,
        gpu_driver.as_str(),
        wifi_driver.as_str(),
        report.dt_compatibles.join(" "),
        report.dmi_board_name.as_deref().unwrap_or(""),
        report.cpu_model.as_deref().unwrap_or(""),
        report.ram_kb,
    );
    let env_file = run_dir.join("hardware.env");
    fs::write(&env_file, env)?;

    let rules = udev_gen::generate(report);
    let udev_rules = run_dir.join("udev/rules.d/70-namikaze-hw.rules");
    fs::write(&udev_rules, rules)?;

    let mut modules = String::new();
    for m in board.modules {
        modules.push_str(m);
        modules.push('\n');
    }
    let modules_load = run_dir.join("modules.load");
    fs::write(&modules_load, modules)?;

    let plan = AppliedPlan {
        board: board.id.to_string(),
        arch: board.arch.as_str().to_string(),
        dtb: board.dtb.to_string(),
        gpu_driver: gpu_driver.as_str().to_string(),
        wifi_driver: wifi_driver.as_str().to_string(),
        firmware_dirs: board.firmware_dirs.iter().map(|s| s.to_string()).collect(),
        modules: board.modules.iter().map(|s| s.to_string()).collect(),
        env_file: env_file.display().to_string(),
        udev_rules: udev_rules.display().to_string(),
        modules_load: modules_load.display().to_string(),
    };
    fs::write(
        run_dir.join("hardware-plan.json"),
        plan_to_json(&plan).to_pretty(),
    )?;
    Ok(plan)
}

/// Render the applied plan as deterministic JSON.
fn plan_to_json(plan: &AppliedPlan) -> Value {
    json::obj(&[
        ("board", Value::Str(plan.board.clone())),
        ("arch", Value::Str(plan.arch.clone())),
        ("dtb", Value::Str(plan.dtb.clone())),
        ("gpu_driver", Value::Str(plan.gpu_driver.clone())),
        ("wifi_driver", Value::Str(plan.wifi_driver.clone())),
        (
            "firmware_dirs",
            Value::Arr(plan.firmware_dirs.iter().map(|s| Value::Str(s.clone())).collect()),
        ),
        ("modules", Value::Arr(plan.modules.iter().map(|s| Value::Str(s.clone())).collect())),
        ("env_file", Value::Str(plan.env_file.clone())),
        ("udev_rules", Value::Str(plan.udev_rules.clone())),
        ("modules_load", Value::Str(plan.modules_load.clone())),
    ])
}

/// Firmware set needed for a board: linux-firmware subdirectories plus the
/// GPU and WiFi driver families. Used by the firmware squashfs builder.
pub fn firmware_plan(board_id: &str) -> Result<Vec<String>> {
    let board = board_db::BOARDS
        .iter()
        .find(|b| b.id == board_id)
        .ok_or_else(|| Error::Config(format!("unknown board: {board_id}")))?;
    let mut set: Vec<String> = board
        .firmware_dirs
        .iter()
        .map(|s| s.to_string())
        .collect();
    for extra in gpu::firmware_dirs(board.soc, gpu::select_for_soc(board.soc)) {
        if !set.iter().any(|s| s == extra) {
            set.push(extra.to_string());
        }
    }
    Ok(set)
}

/// Validate a hardware environment file parses (used in tests and CI).
pub fn validate_env_file(path: &Path) -> Result<()> {
    HardwareReport::from_env_file(path).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_file_roundtrip() {
        let dir = std::env::temp_dir().join("namikaze-hal-test-env");
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("hardware.env");
        fs::write(
            &p,
            "NAMIKAZE_ARCH=aarch64\nNAMIKAZE_DT_COMPATIBLE=radxa,rock-5b\nNAMIKAZE_RAM_KB=8388608\n",
        )
        .unwrap();
        let r = HardwareReport::from_env_file(&p).unwrap();
        assert_eq!(r.arch, Some(Arch::Aarch64));
        assert_eq!(r.dt_compatibles, vec!["radxa,rock-5b"]);
        assert_eq!(r.best_board().id, "rock-5b");
    }

    #[test]
    fn firmware_plan_unknown_board() {
        assert!(firmware_plan("does-not-exist").is_err());
    }

    #[test]
    fn firmware_plan_known_board() {
        let plan = firmware_plan("rpi4").unwrap();
        assert!(plan.iter().any(|s| s == "brcm"));
    }
}
