// SPDX-License-Identifier: MPL-2.0
//! namikaze-i18n: user-facing string localization.
//!
//! Engineering sources are ASCII English only (CI-enforced). Every string a
//! user can see lives in the fluent-style catalogs below; the loader
//! implements the subset the catalogs use (`id = text` with `{ $arg }`
//! placeholders). Adding a language is a matter of adding a directory and
//! registering it in [`catalogs`]. Zero third-party dependencies.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::OnceLock;

use namikaze_common::{Error, Result};

const EN: &str = include_str!("../locales/en/main.ftl");
const TR: &str = include_str!("../locales/tr/main.ftl");

/// One parsed catalog: message id -> raw pattern.
type Bundle = HashMap<&'static str, HashMap<String, String>>;

fn parse_catalog(source: &'static str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((id, value)) = line.split_once('=') {
            map.insert(id.trim().to_string(), value.trim().to_string());
        }
    }
    map
}

fn catalogs() -> &'static Bundle {
    static CATALOGS: OnceLock<Bundle> = OnceLock::new();
    CATALOGS.get_or_init(|| {
        let mut map: Bundle = HashMap::new();
        map.insert("en", parse_catalog(EN));
        map.insert("tr", parse_catalog(TR));
        map
    })
}

/// Languages available in the shipped catalogs.
pub fn available() -> Vec<&'static str> {
    catalogs().keys().copied().collect()
}

/// Translate a message id with optional placeholder arguments. Falls back
/// to en, then to the id itself.
pub fn translate(lang: &str, id: &str, args: &[(&str, String)]) -> String {
    let map = catalogs();
    let pattern =
        map.get(lang).and_then(|b| b.get(id)).or_else(|| map.get("en").and_then(|b| b.get(id)));
    let Some(pattern) = pattern else {
        return id.to_string();
    };
    let mut out = pattern.clone();
    for (k, v) in args {
        out = out.replace(&format!("{{ ${k} }}"), v);
    }
    out
}

/// Convenience wrapper without arguments; errors when the id is unknown.
pub fn tr(lang: &str, id: &str) -> Result<String> {
    let out = translate(lang, id, &[]);
    if out == id && !catalogs().get("en").map(|b| b.contains_key(id)).unwrap_or(false) {
        return Err(Error::Other(format!("missing i18n id: {id}")));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_catalog_resolves() {
        assert!(tr("en", "welcome-title").is_ok());
    }

    #[test]
    fn turkish_catalog_resolves() {
        assert!(tr("tr", "welcome-title").is_ok());
    }

    #[test]
    fn unknown_id_errors() {
        assert!(tr("en", "no-such-id").is_err());
    }

    #[test]
    fn placeholders_substitute() {
        let out = translate("en", "ram-usage", &[("mb", "512".to_string())]);
        assert_eq!(out, "Memory in use: 512 MB");
    }

    #[test]
    fn fallback_to_english() {
        let out = translate("xx", "welcome-title", &[]);
        assert_eq!(out, "Welcome to NamikazeOS");
    }
}
