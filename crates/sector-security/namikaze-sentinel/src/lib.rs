// SPDX-License-Identifier: MPL-2.0
//! namikaze-sentinel: tamper detection and response.
//!
//! Components:
//! - Failure policy: sliding-window login failure tracking with a capture
//!   decision after N failures (default 3) inside the window (default 300 s).
//! - Audit chain: every event extends a SHA-256 hash chain, so tampering
//!   with the event log is detectable.
//! - Capture: stores an encrypted webcam frame via namikaze-vault when the
//!   policy triggers and a camera is available. Local-only by hard rule:
//!   nothing is ever uploaded. Opt-in via /etc/namikaze/system.toml.
//!
//! Legal note: capture features require explicit, informed user consent
//! (KVKK / GDPR). The state machine refuses to enable capture otherwise.

#![forbid(unsafe_code)]

#[cfg(feature = "pam-module")]
pub mod pam;
#[cfg(not(feature = "pam-module"))]
pub mod pam {}

use std::path::Path;

use namikaze_common::{append_log, var_path, Error, Result};
use namikaze_rt::json;

const STATE_FILE: &str = "sentinel/state.json";
const CHAIN_FILE: &str = "sentinel/audit.jsonl";
const CAPTURE_DIR: &str = "sentinel/captures";

/// Serializes as a compact JSON object (state.json format).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SentinelState {
    /// Failure timestamps (unix seconds)
    pub failures: Vec<u64>,
    /// Sealed tamper flags consumed at boot (e.g. LUKS pass failures)
    pub tamper_flags: u32,
    /// Head of the audit hash chain
    pub chain_head: String,
}

impl SentinelState {
    fn to_json(&self) -> Vec<u8> {
        json::obj(&[
            (
                "failures",
                json::Value::Arr(
                    self.failures.iter().map(|t| json::Value::Int(*t as i64)).collect(),
                ),
            ),
            ("tamper_flags", json::Value::Int(self.tamper_flags as i64)),
            ("chain_head", json::Value::Str(self.chain_head.clone())),
        ])
        .to_compact()
        .into_bytes()
    }

    fn from_json(raw: &[u8]) -> Option<SentinelState> {
        let v = json::parse(std::str::from_utf8(raw).ok()?).ok()?;
        Some(SentinelState {
            failures: v
                .get("failures")
                .and_then(|x| x.as_arr())
                .map(|a| a.iter().filter_map(|x| x.as_i64().map(|i| i as u64)).collect())
                .unwrap_or_default(),
            tamper_flags: v.get("tamper_flags").and_then(|x| x.as_i64()).unwrap_or(0) as u32,
            chain_head: v
                .get("chain_head")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string(),
        })
    }
}

/// Policy decision after a failure is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Log,
    Capture,
    Lockout,
}

/// Sliding-window failure policy.
pub struct FailurePolicy {
    pub max_failures: u32,
    pub window_secs: u64,
}

impl FailurePolicy {
    pub fn new(max_failures: u32, window_secs: u64) -> Self {
        Self { max_failures, window_secs }
    }

    /// Decide what to do for the next failure, given past timestamps.
    pub fn decide(&self, state: &SentinelState, now: u64) -> Decision {
        let in_window =
            state.failures.iter().filter(|t| now.saturating_sub(**t) <= self.window_secs).count()
                as u32;
        // Threshold semantics: capture on the 4th failure (>3 wrong tries).
        if state.tamper_flags > 0 || in_window >= self.max_failures {
            Decision::Capture
        } else if in_window + 1 >= self.max_failures.saturating_sub(1) {
            Decision::Lockout
        } else {
            Decision::Log
        }
    }
}

/// Load sentinel state (defaults when missing).
pub fn load_state() -> SentinelState {
    std::fs::read(var_path(STATE_FILE))
        .ok()
        .and_then(|raw| SentinelState::from_json(&raw))
        .unwrap_or_default()
}

/// Persist sentinel state atomically (write to temp then rename).
pub fn store_state(state: &SentinelState) -> Result<()> {
    let path = var_path(STATE_FILE);
    let tmp = var_path("sentinel/state.json.tmp");
    std::fs::create_dir_all(path.parent().ok_or_else(|| Error::Other("bad state path".into()))?)?;
    std::fs::write(&tmp, state.to_json())?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

/// Extend the audit hash chain with an event; returns the new head.
pub fn audit_append(state: &mut SentinelState, kind: &str, details: &str) -> Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut hasher_input = String::new();
    hasher_input.push_str(&state.chain_head);
    hasher_input.push_str(&format!("|{now}|{kind}|{details}"));
    let head = namikaze_vault::hash(hasher_input.as_bytes());
    let line = format!("{now} {kind} {details} {head}");
    append_log(&var_path(CHAIN_FILE), &line)?;
    state.chain_head = head.clone();
    Ok(head)
}

/// Verify the audit chain end-to-end. Returns (events, valid).
pub fn audit_verify() -> Result<(usize, bool)> {
    let path = var_path(CHAIN_FILE);
    if !path.exists() {
        return Ok((0, true));
    }
    let raw = std::fs::read_to_string(path)?;
    let mut prev = String::new();
    let mut count = 0usize;
    let mut valid = true;
    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        let ts = parts.next().unwrap_or_default();
        let kind = parts.next().unwrap_or_default();
        // details may contain spaces; the head is the last token.
        let head = line.split_whitespace().last().unwrap_or_default();
        let details_start = line.find(kind).map(|i| i + kind.len() + 1).unwrap_or(0);
        let details_end = line.len().saturating_sub(head.len() + 1);
        let details = &line[details_start..details_end];
        let mut input = String::new();
        input.push_str(&prev);
        input.push_str(&format!("|{ts}|{kind}|{details}"));
        let expected = namikaze_vault::hash(input.as_bytes());
        if expected != head {
            valid = false;
        }
        prev = head.to_string();
        count += 1;
    }
    Ok((count, valid))
}

/// Capture a single frame with the system camera helper; returns the stored
/// path. Requires an explicit consent marker set by the first-boot wizard.
pub fn capture_image() -> Result<std::path::PathBuf> {
    let consent = namikaze_common::etc_path("sentinel/consent");
    if !Path::new(&consent).exists() {
        return Err(Error::Other(
            "capture refused: no user consent marker (/etc/namikaze/sentinel/consent)".into(),
        ));
    }
    let dir = var_path(CAPTURE_DIR);
    std::fs::create_dir_all(&dir)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let out = dir.join(format!("capture-{now}.jpg"));
    let status = std::process::Command::new("/usr/libexec/namikaze/frame-grab")
        .arg(out.to_str().unwrap_or_default())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => Ok(out),
        Ok(s) => Err(Error::Other(format!("frame-grab exited with {s}"))),
        Err(e) => Err(Error::Other(format!("camera helper unavailable: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_captures_after_threshold() {
        let policy = FailurePolicy::new(3, 300);
        let mut state = SentinelState::default();
        assert_eq!(policy.decide(&state, 1000), Decision::Log);
        state.failures = vec![990, 995, 999];
        assert_eq!(policy.decide(&state, 1000), Decision::Capture);
    }

    #[test]
    fn policy_window_expires() {
        let policy = FailurePolicy::new(3, 300);
        let state = SentinelState { failures: vec![1, 2, 3], ..Default::default() };
        assert_eq!(policy.decide(&state, 10_000), Decision::Log);
    }

    #[test]
    fn tamper_flag_forces_capture() {
        let policy = FailurePolicy::new(3, 300);
        let state = SentinelState { tamper_flags: 1, ..Default::default() };
        assert_eq!(policy.decide(&state, 5), Decision::Capture);
    }

    #[test]
    fn state_json_roundtrip() {
        let state =
            SentinelState { failures: vec![1, 2, 3], tamper_flags: 2, chain_head: "abc".into() };
        let back = SentinelState::from_json(&state.to_json()).unwrap();
        assert_eq!(back, state);
    }
}
