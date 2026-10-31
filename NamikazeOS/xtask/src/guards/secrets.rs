// SPDX-License-Identifier: MPL-2.0
//! secrets-guard: fail if credential-shaped strings or key material leak
//! into tracked files, or if secret-bearing file names (.env, *.pem, *.key)
//! are tracked at all.
//!
//! The patterns are matched by hand (prefix find + character-class walk)
//! so this stays std-only; the pattern prefixes below are deliberately
//! split from their suffix rules so this file never matches itself.

use std::path::{Path, PathBuf};
use std::process::Command;

use namikaze_common::{Error, Result};

use crate::util::violations_report;

/// A credential shape: a literal prefix, the minimum number of body
/// characters and the character class of the body.
type TokenRule = (&'static str, usize, fn(u8) -> bool);

/// PEM marker halves, kept apart so the guard never matches itself.
const PEM_BEGIN: &str = "-----BEGIN";
const PEM_KEY: &str = "PRIVATE KEY";

const TOKEN_RULES: &[TokenRule] = &[
    ("ghp_", 20, is_token_char),
    ("github_pat_", 20, is_token_char),
    ("sk-ant-", 20, is_token_char),
    ("sk-proj-", 20, is_token_char),
    ("xoxb-", 20, is_token_char),
    ("AKIA", 16, is_access_key_char),
];

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn is_access_key_char(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}

/// File names that must never be tracked, whatever their content.
const FORBIDDEN_NAMES: &[&str] = &[".env", "id_rsa", "id_ed25519"];

fn forbidden_suffix(path: &str) -> bool {
    path.ends_with(".pem") || path.ends_with(".key")
}

/// True when `text` contains a credential-shaped token.
fn contains_token(text: &str) -> bool {
    let bytes = text.as_bytes();
    for (prefix, min_len, class) in TOKEN_RULES {
        let mut from = 0;
        while let Some(pos) = text[from..].find(prefix) {
            let start = from + pos + prefix.len();
            let mut end = start;
            while end < bytes.len() && class(bytes[end]) {
                end += 1;
            }
            if end - start >= *min_len {
                return true;
            }
            from = start;
        }
    }
    // key material: BEGIN and PRIVATE KEY on the same line; the two
    // literals live in separate constants so this file never matches
    // its own rule
    for line in text.lines() {
        if line.contains(PEM_BEGIN) && line.contains(PEM_KEY) {
            return true;
        }
    }
    false
}

/// The repository toplevel, so git paths resolve regardless of the
/// working directory the tasks run from.
fn repo_toplevel() -> Result<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|e| Error::Other(format!("secrets-guard: cannot run git: {e}")))?;
    if !out.status.success() {
        return Err(Error::Other("secrets-guard: not a git repository".into()));
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_owned()))
}

/// All tracked paths in the repository, relative to the toplevel.
fn tracked_files(top: &Path) -> Result<Vec<PathBuf>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(top)
        .args(["ls-files", "-z", ":/"])
        .output()
        .map_err(|e| Error::Other(format!("secrets-guard: cannot run git: {e}")))?;
    if !out.status.success() {
        return Err(Error::Other("secrets-guard: git ls-files failed".into()));
    }
    Ok(out
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| PathBuf::from(String::from_utf8_lossy(p).into_owned()))
        .collect())
}

pub(crate) fn run(_root: &Path) -> Result<()> {
    let top = repo_toplevel()?;
    let mut violations = Vec::new();
    for rel in tracked_files(&top)? {
        let rel_text = rel.to_string_lossy().replace('\\', "/");
        let name = rel.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if FORBIDDEN_NAMES.contains(&name.as_str()) || forbidden_suffix(&rel_text) {
            violations.push(format!("{rel_text}: secret-bearing file name tracked"));
        }
        let Ok(text) = std::fs::read_to_string(top.join(&rel)) else { continue };
        if contains_token(&text) {
            violations.push(format!("{rel_text}: credential-shaped string found"));
        }
    }
    violations_report("secrets-guard (credential leak scan)", &violations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_runtime_built_tokens() {
        let gh = format!("ghp_{}", "a".repeat(20));
        assert!(contains_token(&gh));
        let aws = format!("AKIA{}", "A".repeat(16));
        assert!(contains_token(&aws));
        // built at runtime so this source line never matches the rule
        let pem = format!("{}BEGIN {} {}", "-----", "PRIVATE", "KEY");
        assert!(contains_token(&pem));
    }

    #[test]
    fn passes_benign_text_and_bare_prefixes() {
        assert!(!contains_token("ghp_ and AKIA are just prefixes here"));
        assert!(!contains_token("sha256 ghp_ is not a token"));
        assert!(!contains_token("plain configuration text"));
        assert!(!contains_token("sk-proj- too short body abcdef"));
    }
}
