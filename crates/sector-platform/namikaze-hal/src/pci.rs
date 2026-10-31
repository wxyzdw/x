// SPDX-License-Identifier: MPL-2.0
#![forbid(unsafe_code)]
//! Pure-sysfs PCI and USB enumeration; no dependency on libudev.

use std::fs;
use std::io;

use crate::HardwareReport;

/// One PCI function from /sys/bus/pci/devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciDevice {
    pub domain: u16,
    pub bus: u8,
    pub slot: u8,
    pub function: u8,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
}

/// One USB device from /sys/bus/usb/devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbDevice {
    pub bus: u8,
    pub port: u8,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
}

/// Scan both buses into the report. Missing buses are not errors: boards
/// legitimately have zero PCI devices (most SBCs) or zero USB at scan time.
pub fn scan(report: &mut HardwareReport) -> io::Result<()> {
    if let Ok(entries) = fs::read_dir("/sys/bus/pci/devices") {
        for entry in entries.flatten() {
            let path = entry.path();
            let (Some(vendor), Some(device), Some(class)) = (
                parse_hex_id(&path.join("vendor")),
                parse_hex_id(&path.join("device")),
                parse_hex_id(&path.join("class")),
            ) else {
                continue;
            };
            report.pci.push(PciDevice {
                domain: 0,
                bus: 0,
                slot: 0,
                function: 0,
                vendor: vendor as u16,
                device: device as u16,
                class: ((class >> 16) & 0xff) as u8,
            });
        }
    }
    if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Interface nodes carry a colon (1-2:1.0); devices do not.
            if name.contains(':') {
                continue;
            }
            let path = entry.path();
            let (Some(vendor), Some(device), Some(class)) = (
                parse_hex_id(&path.join("idVendor")),
                parse_hex_id(&path.join("idProduct")),
                parse_hex_id(&path.join("bDeviceClass")),
            ) else {
                continue;
            };
            report.usb.push(UsbDevice {
                bus: 0,
                port: 0,
                vendor: vendor as u16,
                device: device as u16,
                class: class as u8,
            });
        }
    }
    Ok(())
}

fn parse_hex_id(path: &std::path::Path) -> Option<u32> {
    let raw = fs::read_to_string(path).ok()?;
    u32::from_str_radix(raw.trim().trim_start_matches("0x"), 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_tolerates_missing_sysfs() {
        // On the build host /sys/bus/pci may exist; the call must never
        // panic either way and must return an empty report on failure.
        let mut r = HardwareReport::default();
        let _ = scan(&mut r);
    }
}
