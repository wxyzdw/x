// SPDX-License-Identifier: MPL-2.0
//! namikaze-usbguard: pure-Rust USB device policy engine.
//!
//! The upstream usbguard project is a C++ daemon; this crate implements the
//! same policy model natively for NamikazeOS by scanning sysfs and writing
//! `authorized` (0/1) per device. Default is deny for unknown devices.
//!
//! Policy file: /etc/namikaze/usbguard/policy.toml
//!
//! ```toml
//! default_action = "deny"   # deny | log
//! [[allow]]
//! vendor  = "046d"
//! product = "c52b"          # optional
//! serial  = "..."           # optional
//! ```

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use namikaze_common::{append_log, init_tracing, var_path, Error, Result};
use namikaze_rt::args::Cli;
use namikaze_rt::log_warn;
use namikaze_rt::toml::{self, Value};

const POLICY_PATH: &str = "/etc/namikaze/usbguard/policy.toml";
const EVENTS: &str = "usbguard/events.log";

const USAGE: &[&str] = &[
    "namikaze-usbguard: default-deny USB device policy for NamikazeOS",
    "",
    "usage:",
    "  namikaze-usbguard list            list USB devices with authorization state",
    "  namikaze-usbguard authorize DEV   authorize a device (sysfs + policy entry)",
    "  namikaze-usbguard deny DEV        unauthorize a device",
    "  namikaze-usbguard watch           enforce policy continuously (2s scan)",
    "  namikaze-usbguard enforce         one-shot enforcement pass",
];

#[derive(Debug, Clone)]
struct Policy {
    default_action: Option<String>,
    allow: Vec<AllowRule>,
}

#[derive(Debug, Clone)]
struct AllowRule {
    vendor: String,
    product: Option<String>,
    serial: Option<String>,
}

fn opt_str(t: &std::collections::BTreeMap<String, Value>, k: &str) -> Option<String> {
    t.get(k).and_then(|v| v.as_str()).map(str::to_string)
}

fn parse_policy(raw: &str) -> Option<Policy> {
    let root = toml::parse(raw).ok()?;
    let default_action = opt_str(&root, "default_action");
    let mut allow = Vec::new();
    if let Some(Value::TableArr(items)) = root.get("allow") {
        for t in items {
            let vendor = opt_str(t, "vendor")?;
            allow.push(AllowRule {
                vendor,
                product: opt_str(t, "product"),
                serial: opt_str(t, "serial"),
            });
        }
    }
    Some(Policy { default_action, allow })
}

#[derive(Debug, Clone)]
pub struct UsbDevice {
    pub syspath: PathBuf,
    pub name: String,
    pub vendor: String,
    pub product: String,
    pub serial: String,
    pub authorized: Option<String>,
    pub mass_storage: bool,
}

fn read_trim(p: &Path) -> String {
    fs::read_to_string(p).map(|s| s.trim().to_string()).unwrap_or_default()
}

fn load_policy() -> Policy {
    fs::read_to_string(POLICY_PATH)
        .ok()
        .and_then(|raw| parse_policy(&raw))
        .unwrap_or(Policy { default_action: Some("deny".into()), allow: vec![] })
}

/// Scan /sys/bus/usb/devices for device entries.
pub fn scan() -> Vec<UsbDevice> {
    let mut devices = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") else {
        return devices;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        // Interface entries contain ':' and are skipped.
        if name.contains(':') || !p.join("idVendor").exists() {
            continue;
        }
        let mass_storage = fs::read_dir(&p)
            .map(|children| {
                children
                    .flatten()
                    .filter(|c| c.file_name().to_string_lossy().contains(':'))
                    .any(|c| read_trim(&c.path().join("bInterfaceClass")) == "08")
            })
            .unwrap_or(false);
        devices.push(UsbDevice {
            syspath: p.clone(),
            name,
            vendor: read_trim(&p.join("idVendor")),
            product: read_trim(&p.join("idProduct")),
            serial: read_trim(&p.join("serial")),
            authorized: fs::read_to_string(p.join("authorized")).ok().map(|s| s.trim().to_string()),
            mass_storage,
        });
    }
    devices.sort_by(|a, b| a.name.cmp(&b.name));
    devices
}

fn rule_matches(rule: &AllowRule, dev: &UsbDevice) -> bool {
    if !dev.vendor.eq_ignore_ascii_case(&rule.vendor) {
        return false;
    }
    if let Some(prod) = &rule.product {
        if !dev.product.eq_ignore_ascii_case(prod) {
            return false;
        }
    }
    if let Some(ser) = &rule.serial {
        if !dev.serial.eq_ignore_ascii_case(ser) {
            return false;
        }
    }
    true
}

fn is_allowed(policy: &Policy, dev: &UsbDevice) -> bool {
    policy.allow.iter().any(|r| rule_matches(r, dev))
}

fn write_authorized(dev: &UsbDevice, value: &str) -> Result<()> {
    fs::write(dev.syspath.join("authorized"), value)
        .map_err(|e| Error::Other(format!("cannot set authorized on {}: {e}", dev.name)))
}

/// Enforce the policy on the current device list; returns actions taken.
pub fn enforce_once() -> Result<usize> {
    let policy = load_policy();
    let default_deny = policy.default_action.as_deref().unwrap_or("deny") == "deny";
    let mut actions = 0;
    for dev in scan() {
        if is_allowed(&policy, &dev) {
            continue;
        }
        match (default_deny, dev.mass_storage) {
            (true, _) | (false, true) => {
                if dev.authorized.as_deref() != Some("0") {
                    write_authorized(&dev, "0")?;
                    let line = format!(
                        "denied device {} (vid {} pid {})",
                        dev.name, dev.vendor, dev.product
                    );
                    log_warn!("{line}");
                    append_log(&var_path(EVENTS), &line)?;
                    actions += 1;
                }
            }
            (false, false) => {
                let line = format!("unknown device {} logged (default=log)", dev.name);
                log_warn!("{line}");
                append_log(&var_path(EVENTS), &line)?;
            }
        }
    }
    Ok(actions)
}

fn main() -> Result<()> {
    init_tracing("info");
    let cli = Cli::capture();
    if cli.wants_help() || cli.sub().is_none() {
        cli.usage_exit(USAGE);
    }
    let free = cli.free(&[]);
    match cli.sub().unwrap_or_default() {
        "list" => {
            let policy = load_policy();
            for dev in scan() {
                let state = if is_allowed(&policy, &dev) { "allowed" } else { "unknown" };
                println!(
                    "{:12} vid={} pid={} serial={:20} storage={:5} auth={:?} [{}]",
                    dev.name,
                    dev.vendor,
                    dev.product,
                    dev.serial,
                    dev.mass_storage,
                    dev.authorized,
                    state
                );
            }
        }
        "authorize" => {
            let device = free.get(1).cloned().unwrap_or_default();
            let target = scan()
                .into_iter()
                .find(|d| d.name == device)
                .ok_or_else(|| Error::Other(format!("device {device} not found")))?;
            write_authorized(&target, "1")?;
            append_log(&var_path(EVENTS), &format!("authorized {device} (manual)"))?;
            println!("authorized {device}");
        }
        "deny" => {
            let device = free.get(1).cloned().unwrap_or_default();
            let target = scan()
                .into_iter()
                .find(|d| d.name == device)
                .ok_or_else(|| Error::Other(format!("device {device} not found")))?;
            write_authorized(&target, "0")?;
            append_log(&var_path(EVENTS), &format!("denied {device} (manual)"))?;
            println!("denied {device}");
        }
        "enforce" => {
            let n = enforce_once()?;
            println!("enforced; {n} action(s)");
        }
        "watch" => {
            println!("watching for USB changes (Ctrl-C to stop)");
            loop {
                enforce_once()?;
                sleep(Duration::from_secs(2));
            }
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            cli.usage_exit(USAGE);
        }
    }
    Ok(())
}
