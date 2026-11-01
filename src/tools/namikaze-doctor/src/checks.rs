// SPDX-License-Identifier: MPL-2.0
//! Pure check logic for namikaze-doctor. Filesystem access happens only in
//! the binary; every rule here is a function over already-read data so the
//! verdicts are unit-testable and deterministic.

#![forbid(unsafe_code)]

/// One executed diagnostic with its verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

impl Check {
    fn new(name: &str, passed: bool, detail: String) -> Self {
        Self { name: name.to_string(), passed, detail }
    }
}

/// Ordered collection of checks.
#[derive(Debug, Default)]
pub struct Checker {
    checks: Vec<Check>,
}

impl Checker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, check: Check) {
        self.checks.push(check);
    }

    pub fn checks(&self) -> &[Check] {
        &self.checks
    }
}

/// Mandatory hardening sysctls and the values they must hold. A key that
/// is absent reads as a failure except where noted (values "absent" fail).
pub const MANDATORY_SYSCTLS: &[(&str, &str)] = &[
    ("kernel.yama.ptrace_scope", "2"),
    ("kernel.unprivileged_bpf_disabled", "1"),
    ("kernel.randomize_va_space", "2"),
    ("net.ipv4.conf.all.accept_redirects", "0"),
    ("net.ipv4.conf.all.send_redirects", "0"),
    ("fs.protected_symlinks", "1"),
    ("fs.protected_regular", "2"),
];

/// Evaluate the sysctl snapshot collected by the binary.
pub fn sysctl_verdicts(raw: &[(String, String)]) -> Vec<(String, bool, String)> {
    let mut out = Vec::new();
    for (key, want) in MANDATORY_SYSCTLS {
        let found = raw
            .iter()
            .find(|(k, _)| k.ends_with(&key.replace('.', "/")))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "unreadable".to_string());
        let (passed, detail) = if found == "unreadable" || found == "absent" {
            (false, format!("{key}: not exposed by this kernel"))
        } else if found == *want {
            (true, format!("{key} = {found}"))
        } else {
            (false, format!("{key} = {found} (want {want})"))
        };
        out.push((key.to_string(), passed, detail));
    }
    out
}

impl Check {
    /// Bundle of sysctl verdicts collapsed into one check entry.
    pub fn sysctls(raw: Vec<(String, String)>) -> Check {
        let verdicts = sysctl_verdicts(&raw);
        let failed: Vec<&str> =
            verdicts.iter().filter(|(_, ok, _)| !ok).map(|(k, _, _)| k.as_str()).collect();
        Check::new(
            "hardening-sysctls",
            failed.is_empty(),
            if failed.is_empty() {
                format!("{} mandatory keys correct", verdicts.len())
            } else if failed.len() == verdicts.len() {
                format!("not exposed by this kernel: {}", failed.join(", "))
            } else {
                format!("offending keys: {}", failed.join(", "))
            },
        )
    }

    /// Version fingerprint check (always passes; documents what runs).
    pub fn version(version: &str) -> Check {
        Check::new("version", true, format!("NamikazeOS {version}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn all_hardened_passes() {
        let raw = snap(&[
            ("/proc/sys/kernel/yama/ptrace_scope", "2"),
            ("/proc/sys/kernel/unprivileged_bpf_disabled", "1"),
            ("/proc/sys/kernel/randomize_va_space", "2"),
            ("/proc/sys/net/ipv4/conf/all/accept_redirects", "0"),
            ("/proc/sys/net/ipv4/conf/all/send_redirects", "0"),
            ("/proc/sys/fs/protected_symlinks", "1"),
            ("/proc/sys/fs/protected_regular", "2"),
        ]);
        let c = Check::sysctls(raw);
        assert!(c.passed, "detail: {}", c.detail);
    }

    #[test]
    fn weak_value_fails_naming_the_key() {
        let raw = snap(&[
            ("/proc/sys/kernel/yama/ptrace_scope", "0"),
            ("/proc/sys/kernel/unprivileged_bpf_disabled", "1"),
            ("/proc/sys/kernel/randomize_va_space", "2"),
            ("/proc/sys/net/ipv4/conf/all/accept_redirects", "0"),
            ("/proc/sys/net/ipv4/conf/all/send_redirects", "0"),
            ("/proc/sys/fs/protected_symlinks", "1"),
            ("/proc/sys/fs/protected_regular", "2"),
        ]);
        let c = Check::sysctls(raw);
        assert!(!c.passed);
        assert!(c.detail.contains("ptrace_scope"));
    }

    #[test]
    fn missing_key_fails() {
        let c = Check::sysctls(Vec::new());
        assert!(!c.passed);
        assert!(c.detail.contains("not exposed"));
    }

    #[test]
    fn version_check_documents() {
        let c = Check::version("3.0.0-alpha.2");
        assert!(c.passed);
        assert!(c.detail.contains("3.0.0-alpha.2"));
    }
}
