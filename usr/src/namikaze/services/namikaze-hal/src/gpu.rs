// SPDX-License-Identifier: MPL-2.0
#![forbid(unsafe_code)]
//! GPU and WiFi driver selection. Deterministic: board first, PCI class
//! fallback for x86 machines. Only free drivers are ever selected.

use crate::board_db::match_board;
use crate::{HardwareReport, Soc};

/// Graphics driver chosen for the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuDriver {
    Panfrost,
    Panthor,
    Lima,
    Vc4V3d,
    MsmFreedreno,
    Powervr,
    TegraDrm,
    AppleAgx,
    Amdgpu,
    I915,
    Xe,
    Nouveau,
    VirtioGpu,
    SimpleFramebuffer,
}

impl GpuDriver {
    pub fn as_str(self) -> &'static str {
        match self {
            GpuDriver::Panfrost => "panfrost",
            GpuDriver::Panthor => "panthor",
            GpuDriver::Lima => "lima",
            GpuDriver::Vc4V3d => "vc4",
            GpuDriver::MsmFreedreno => "msm",
            GpuDriver::Powervr => "powervr",
            GpuDriver::TegraDrm => "tegra",
            GpuDriver::AppleAgx => "agx",
            GpuDriver::Amdgpu => "amdgpu",
            GpuDriver::I915 => "i915",
            GpuDriver::Xe => "xe",
            GpuDriver::Nouveau => "nouveau",
            GpuDriver::VirtioGpu => "virtio_gpu",
            GpuDriver::SimpleFramebuffer => "simpledrm",
        }
    }
}

/// Select the GPU driver for a full report.
pub fn select(report: &HardwareReport) -> GpuDriver {
    let board = match_board(report);
    select_for_soc(board.soc)
}

/// Select by SoC; x86 falls back to the PCI vendor probe.
pub fn select_for_soc(soc: Soc) -> GpuDriver {
    match soc {
        Soc::Rk3588 | Soc::Rk3588s => GpuDriver::Panthor,
        Soc::Rk3568 | Soc::Sun50iH6 | Soc::MesonG12b | Soc::MesonSm1 => GpuDriver::Panfrost,
        // Mali-400/450 Utgard family -> lima.
        Soc::Sun8iH3 | Soc::Sun50iA64 | Soc::MesonGxl => GpuDriver::Lima,
        Soc::Bcm2712 | Soc::Bcm2711 | Soc::Bcm2837 => GpuDriver::Vc4V3d,
        Soc::Jh7110 | Soc::Th1520 => GpuDriver::Powervr,
        Soc::Tegra234 => GpuDriver::TegraDrm,
        Soc::Am625 | Soc::J721e | Soc::Fu740 | Soc::Sg2042 | Soc::Loongson3A => {
            GpuDriver::SimpleFramebuffer
        }
        Soc::AppleT8103 | Soc::AppleT6020 => GpuDriver::AppleAgx,
        Soc::Power9 => GpuDriver::Amdgpu,
        Soc::X86Intel => GpuDriver::I915,
        Soc::X86Amd => GpuDriver::Amdgpu,
        Soc::Generic => GpuDriver::SimpleFramebuffer,
    }
}

/// WiFi driver families, decided from PCI vendor when the board carries a
/// standard card, or fixed by the SoC/SDIO attachment otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiDriver {
    Iwlwifi,
    Ath11k,
    Ath12k,
    Mt76,
    Rtw89,
    Brcmfmac,
    Wl18xx,
    Rtl8xxxu,
    None,
}

impl WifiDriver {
    pub fn as_str(self) -> &'static str {
        match self {
            WifiDriver::Iwlwifi => "iwlwifi",
            WifiDriver::Ath11k => "ath11k",
            WifiDriver::Ath12k => "ath12k",
            WifiDriver::Mt76 => "mt76",
            WifiDriver::Rtw89 => "rtw89",
            WifiDriver::Brcmfmac => "brcmfmac",
            WifiDriver::Wl18xx => "wl18xx",
            WifiDriver::Rtl8xxxu => "rtl8xxxu",
            WifiDriver::None => "none",
        }
    }
}

/// Select the WiFi driver for a full report.
pub fn wifi_select(report: &HardwareReport) -> WifiDriver {
    let board = match_board(report);
    if board.modules.contains(&"brcmfmac") {
        return WifiDriver::Brcmfmac;
    }
    if board.modules.contains(&"wl18xx") {
        return WifiDriver::Wl18xx;
    }
    if board.modules.iter().any(|m| m.starts_with("rtw89")) {
        return WifiDriver::Rtw89;
    }
    if board.modules.contains(&"r8723bs") {
        return WifiDriver::Rtl8xxxu;
    }
    wifi_from_pci(report)
}

/// PCI vendor fallback for add-in and mini-PCIe cards.
pub fn wifi_from_pci(report: &HardwareReport) -> WifiDriver {
    let net = report.pci.iter().find(|d| d.class == 0x02).map(|d| d.vendor).unwrap_or(0);
    match net {
        0x8086 => WifiDriver::Iwlwifi,
        0x14c3 => WifiDriver::Mt76,
        0x17cb => WifiDriver::Ath11k,
        0x10ec => WifiDriver::Rtw89,
        0x02d0 => WifiDriver::Brcmfmac,
        _ => WifiDriver::None,
    }
}

/// linux-firmware subdirectories for GPU+WLAN of a SoC. Consumed by the
/// firmware squashfs builder alongside the board's own set.
pub fn firmware_dirs(_soc: Soc, gpu: GpuDriver) -> &'static [&'static str] {
    match gpu {
        GpuDriver::Amdgpu => &["amdgpu", "radeon"],
        GpuDriver::I915 | GpuDriver::Xe => &["i915"],
        GpuDriver::Nouveau => &["nvidia"],
        GpuDriver::Panthor | GpuDriver::Panfrost | GpuDriver::Lima => &[],
        GpuDriver::Vc4V3d => &[],
        GpuDriver::Powervr => &["img"],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Arch;

    #[test]
    fn soc_selection() {
        assert_eq!(select_for_soc(Soc::Rk3588), GpuDriver::Panthor);
        assert_eq!(select_for_soc(Soc::Bcm2711), GpuDriver::Vc4V3d);
        assert_eq!(select_for_soc(Soc::AppleT6020), GpuDriver::AppleAgx);
    }

    #[test]
    fn pci_wifi_vendor_map() {
        let r = HardwareReport {
            arch: Some(Arch::X86_64),
            pci: vec![crate::pci::PciDevice {
                domain: 0,
                bus: 0,
                slot: 0,
                function: 0,
                vendor: 0x8086,
                device: 0x2725,
                class: 0x02,
            }],
            ..Default::default()
        };
        assert_eq!(wifi_from_pci(&r), WifiDriver::Iwlwifi);
    }

    #[test]
    fn board_wifi_wins_over_pci() {
        let r = HardwareReport {
            arch: Some(Arch::Aarch64),
            dt_compatibles: vec!["raspberrypi,4-model-b".to_string()],
            ..Default::default()
        };
        assert_eq!(wifi_select(&r), WifiDriver::Brcmfmac);
    }
}
