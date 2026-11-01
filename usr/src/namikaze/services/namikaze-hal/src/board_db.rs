// SPDX-License-Identifier: MPL-2.0
#![forbid(unsafe_code)]
//! Curated board database. One row per supported device; every field is
//! consumed by a concrete stage (DTB selection, firmware packing, module
//! loading, quirks handling). No codenames, no emoji, pure identifiers.

use crate::{Arch, HardwareReport, Quirk, Soc};

pub struct BoardProfile {
    pub id: &'static str,
    pub arch: Arch,
    pub soc: Soc,
    /// device-tree compatible strings, in match priority order.
    pub compatible: &'static [&'static str],
    /// x86/ppc DMI board-name globs (empty for DT platforms).
    pub dmi_board: &'static [&'static str],
    pub dtb: &'static str,
    pub dtb_overlays: &'static [&'static str],
    /// linux-firmware subdirectories required by this board.
    pub firmware_dirs: &'static [&'static str],
    /// Ordered module load list emitted to /run/namikaze/modules.load.
    pub modules: &'static [&'static str],
    pub quirks: &'static [Quirk],
}

macro_rules! board {
    ($id:literal, $arch:expr, $soc:expr, $compat:expr, $dmi:expr, $dtb:expr,
     $ovl:expr, $fw:expr, $mods:expr, $quirks:expr) => {
        BoardProfile {
            id: $id,
            arch: $arch,
            soc: $soc,
            compatible: $compat,
            dmi_board: $dmi,
            dtb: $dtb,
            dtb_overlays: $ovl,
            firmware_dirs: $fw,
            modules: $mods,
            quirks: $quirks,
        }
    };
}

pub static BOARDS: &[BoardProfile] = &[
    board!(
        "rpi5",
        Arch::Aarch64,
        Soc::Bcm2712,
        &["raspberrypi,5-model-b"],
        &[],
        "broadcom/bcm2712-rpi-5-b.dtb",
        &[],
        &["brcm"],
        &["pcie-brcmstb", "rp1", "sdhci-brcmstb", "stmmac", "stmmac-platform", "vc4"],
        &[Quirk::SerialConsole("ttyS10"), Quirk::Experimental]
    ),
    board!(
        "rpi4",
        Arch::Aarch64,
        Soc::Bcm2711,
        &["raspberrypi,4-model-b", "raspberrypi,4-compute-module"],
        &[],
        "broadcom/bcm2711-rpi-4-b.dtb",
        &["disable-bt"],
        &["brcm"],
        &["pcie-brcmstb", "bcmgenet", "sdhci-iproc", "brcmfmac", "brcmutil", "vc4", "v3d"],
        &[]
    ),
    board!(
        "rpi3",
        Arch::Aarch64,
        Soc::Bcm2837,
        &["raspberrypi,3-model-b", "raspberrypi,3-compute-module"],
        &[],
        "broadcom/bcm2710-rpi-3-b.dtb",
        &["disable-bt"],
        &["brcm"],
        &["brcmfmac", "brcmutil", "vc4", "sdhci-iproc"],
        &[]
    ),
    board!(
        "rpi-zero-2-w",
        Arch::Aarch64,
        Soc::Bcm2837,
        &["raspberrypi,zero-2-w"],
        &[],
        "broadcom/bcm2710-rpi-zero-2-w.dtb",
        &[],
        &["brcm"],
        &["brcmfmac", "brcmutil", "vc4"],
        &[Quirk::SerialConsole("ttyS0")]
    ),
    board!(
        "rock-5b",
        Arch::Aarch64,
        Soc::Rk3588,
        &["radxa,rock-5b"],
        &[],
        "rockchip/rk3588-rock-5b.dtb",
        &[],
        &["rockchip", "rtl_nic", "rtl_bt", "rtw89"],
        &[
            "dwmac-rk",
            "panthor",
            "rk808-regulator",
            "phy-rockchip-usbdp",
            "rtw89pci",
            "rtw89_8852be"
        ],
        &[]
    ),
    board!(
        "orangepi-5",
        Arch::Aarch64,
        Soc::Rk3588s,
        &["xunlong,orangepi-5"],
        &[],
        "rockchip/rk3588s-orangepi-5.dtb",
        &[],
        &["rockchip", "rtl_nic", "rtl_bt"],
        &["dwmac-rk", "panthor", "rk808-regulator", "phy-rockchip-usbdp"],
        &[]
    ),
    board!(
        "rock-5-itx",
        Arch::Aarch64,
        Soc::Rk3588,
        &["radxa,rock-5-itx"],
        &[],
        "rockchip/rk3588-rock-5-itx.dtb",
        &[],
        &["rockchip", "rtl_nic", "rtl_bt", "rtw89"],
        &["dwmac-rk", "panthor", "rk808-regulator", "phy-rockchip-usbdp", "nvme"],
        &[]
    ),
    board!(
        "lubancat-4",
        Arch::Aarch64,
        Soc::Rk3588s,
        &["rockchip,rk3588s-lubancat-4"],
        &[],
        "rockchip/rk3588s-lubancat-4.dtb",
        &[],
        &["rockchip", "rtl_nic", "rtl_bt"],
        &["dwmac-rk", "panthor", "rk808-regulator", "phy-rockchip-usbdp"],
        &[]
    ),
    board!(
        "rock-3a",
        Arch::Aarch64,
        Soc::Rk3568,
        &["radxa,rock-3a"],
        &[],
        "rockchip/rk3568-rock-3a.dtb",
        &[],
        &["rockchip", "rtl_nic", "rtl_bt", "realtek"],
        &["dwmac-rk", "panfrost", "rk808-regulator", "phy-rockchip-naneng-combphy"],
        &[]
    ),
    // Radxa Zero 3 (RK3566) shares the RK3568 driver class.
    board!(
        "radxa-zero-3",
        Arch::Aarch64,
        Soc::Rk3568,
        &["radxa,zero-3", "radxa,zero-3e"],
        &[],
        "rockchip/rk3566-radxa-zero-3.dtb",
        &[],
        &["rockchip"],
        &["dwmac-rk", "panfrost"],
        &[]
    ),
    board!(
        "orangepi-pc",
        Arch::Armv7,
        Soc::Sun8iH3,
        &["xunlong,orangepi-pc"],
        &[],
        "allwinner/sun8i-h3-orangepi-pc.dtb",
        &[],
        &["xradio", "rtl_nic"],
        &["dwmac-sun8i"],
        &[]
    ),
    board!(
        "pine64",
        Arch::Aarch64,
        Soc::Sun50iA64,
        &["allwinner,pine64"],
        &[],
        "allwinner/sun50i-a64-pine64.dtb",
        &[],
        &["rtlwifi", "rtl_bt", "rtl_nic"],
        &["dwmac-sun8i", "r8723bs"],
        &[]
    ),
    board!(
        "pine-h64",
        Arch::Aarch64,
        Soc::Sun50iH6,
        &["pine64,pine-h64"],
        &[],
        "allwinner/sun50i-h6-pine-h64.dtb",
        &[],
        &["rtl_nic", "rtl_bt"],
        &["dwmac-sun8i", "panfrost"],
        &[]
    ),
    board!(
        "odroid-n2",
        Arch::Aarch64,
        Soc::MesonG12b,
        &["hardkernel,odroid-n2", "hardkernel,odroid-n2-plus"],
        &[],
        "amlogic/meson-g12b-odroid-n2.dtb",
        &[],
        &["amlogic", "rtl_nic"],
        &["dwmac-meson8b", "panfrost"],
        &[]
    ),
    board!(
        "bananapi-m5",
        Arch::Aarch64,
        Soc::MesonSm1,
        &["bananapi,bpi-m5"],
        &[],
        "amlogic/meson-sm1-bananapi-m5.dtb",
        &[],
        &["amlogic", "rtl_nic", "rtl_bt"],
        &["dwmac-meson8b", "panfrost"],
        &[]
    ),
    board!(
        "le-potato",
        Arch::Aarch64,
        Soc::MesonGxl,
        &["libretech,aml-s905x-cc"],
        &[],
        "amlogic/meson-gxl-s905x-libretech-cc.dtb",
        &[],
        &["rtl_nic"],
        &["dwmac-meson8b"],
        &[]
    ),
    board!(
        "beagleplay",
        Arch::Aarch64,
        Soc::Am625,
        &["beagle,beagleplay"],
        &[],
        "ti/k3-am625-beagleplay.dtb",
        &[],
        &["ti-connectivity"],
        &["am65-cpsw-nuss", "wl18xx", "wlcore_sdio", "davinci_mdio"],
        &[]
    ),
    board!(
        "visionfive-2",
        Arch::Riscv64,
        Soc::Jh7110,
        &["starfive,visionfive-2-v1.3b", "starfive,visionfive-2-v1.2a"],
        &[],
        "starfive/jh7110-starfive-visionfive-2-v1.3b.dtb",
        &[],
        &["img"],
        &["dwmac-starfive", "powervr"],
        &[Quirk::Experimental]
    ),
    board!(
        "lichee-pi-4a",
        Arch::Riscv64,
        Soc::Th1520,
        &["thead,th1520-lichee-pi-4a"],
        &[],
        "thead/th1520-lichee-pi-4a.dtb",
        &[],
        &["img"],
        &["dwmac-thead", "powervr"],
        &[Quirk::Experimental]
    ),
    board!(
        "hifive-unmatched",
        Arch::Riscv64,
        Soc::Fu740,
        &["sifive,hifive-unmatched-a00"],
        &[],
        "sifive/hifive-unmatched-a00.dtb",
        &[],
        &[],
        &["dwmac-sifive"],
        &[]
    ),
    board!(
        "milkv-pioneer",
        Arch::Riscv64,
        Soc::Sg2042,
        &["sophgo,sg2042-milkv-pioneer"],
        &[],
        "sophgo/sg2042-milkv-pioneer.dtb",
        &[],
        &[],
        &[],
        &[Quirk::Experimental]
    ),
    board!(
        "apple-m1",
        Arch::Aarch64,
        Soc::AppleT8103,
        &["apple,j274", "apple,t8103"],
        &[],
        "apple/t8103-j274.dtb",
        &[],
        &[],
        &[],
        &[Quirk::RequiresAsahi, Quirk::Experimental]
    ),
    board!(
        "apple-m2",
        Arch::Aarch64,
        Soc::AppleT6020,
        &["apple,j473s", "apple,t6020"],
        &[],
        "apple/t6020-j473s.dtb",
        &[],
        &[],
        &[],
        &[Quirk::RequiresAsahi, Quirk::Experimental]
    ),
    board!(
        "jetson-orin-nano",
        Arch::Aarch64,
        Soc::Tegra234,
        &["nvidia,p3768-0000+p3767-0005"],
        &[],
        "nvidia/tegra234-p3767-0005+p3768-0000-nvme.dtb",
        &[],
        &["nvidia"],
        &["tegra-mgbe", "nvme"],
        &[Quirk::Experimental]
    ),
    board!(
        "talos-ii",
        Arch::Ppc64le,
        Soc::Power9,
        &["ibm,power9"],
        &["2S4L", "2S2L"],
        "",
        &[],
        &[],
        &[],
        &[Quirk::FirmwareProvidedDtb]
    ),
    board!(
        "generic-aarch64",
        Arch::Aarch64,
        Soc::Generic,
        &[],
        &[],
        "",
        &[],
        &["brcm", "rockchip", "amlogic", "rtl_nic", "rtl_bt"],
        &[],
        &[]
    ),
    board!(
        "generic-x86-64",
        Arch::X86_64,
        Soc::Generic,
        &[],
        &["*"],
        "",
        &[],
        &["amd", "amd-ucode", "intel", "i915", "xe", "nvidia", "rtl_nic", "rtl_bt", "qca"],
        &[],
        &[]
    ),
    board!(
        "generic-loongarch",
        Arch::Loongarch64,
        Soc::Loongson3A,
        &[],
        &["Loongson*"],
        "",
        &[],
        &[],
        &[],
        &[Quirk::Experimental]
    ),
];

/// Match order: DT compatible (exact) -> DMI glob -> arch generic.
pub fn match_board(report: &HardwareReport) -> &'static BoardProfile {
    for b in BOARDS {
        for compat in &report.dt_compatibles {
            if b.compatible.iter().any(|c| c == compat) {
                return b;
            }
        }
    }
    // Specific DMI globs first; the "*" catch-all on generic-x86-64 must
    // never swallow a specific board match further down the table.
    for catchall in [false, true] {
        for b in BOARDS {
            if let Some(name) = &report.dmi_board_name {
                if b.dmi_board.iter().any(|g| (*g == "*") == catchall && glob_match(g, name)) {
                    return b;
                }
            }
        }
    }
    let arch = report.arch.unwrap_or(Arch::X86_64);
    BOARDS
        .iter()
        .find(|b| b.id.starts_with("generic-") && b.arch == arch)
        .unwrap_or(&BOARDS[BOARDS.len() - 1])
}

/// Minimal glob: a single leading/trailing/embedded '*' wildcard; sufficient
/// for DMI board names.
pub fn glob_match(glob: &str, name: &str) -> bool {
    let (prefix, suffix) = match glob.split_once('*') {
        Some((p, s)) => (p, Some(s)),
        None => (glob, None),
    };
    let rest = match name.strip_prefix(prefix) {
        Some(r) => r,
        None => return false,
    };
    match suffix {
        Some(s) => rest.ends_with(s),
        None => rest.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(compat: &[&str]) -> HardwareReport {
        HardwareReport {
            arch: Some(Arch::Aarch64),
            dt_compatibles: compat.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn matches_by_dt_compatible() {
        assert_eq!(report(&["radxa,rock-5b"]).best_board().id, "rock-5b");
        assert_eq!(report(&["raspberrypi,4-compute-module"]).best_board().id, "rpi4");
    }

    #[test]
    fn falls_back_to_generic() {
        let b = report(&["acme,unknown-board"]).best_board();
        assert!(b.id.starts_with("generic-"));
    }

    #[test]
    fn dmi_glob_matches() {
        let mut r = HardwareReport {
            arch: Some(Arch::X86_64),
            dmi_board_name: Some("Loongson-3A5000-7A1000-PC".to_string()),
            ..Default::default()
        };
        assert_eq!(r.best_board().id, "generic-loongarch");
        r.dmi_board_name = Some("Supermicro X11".to_string());
        assert_eq!(r.best_board().id, "generic-x86-64");
    }

    #[test]
    fn glob_semantics() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("Loongson*", "Loongson-3A5000"));
        assert!(!glob_match("Loongson*", "Intel NUC"));
        assert!(glob_match("exact", "exact"));
    }
}
