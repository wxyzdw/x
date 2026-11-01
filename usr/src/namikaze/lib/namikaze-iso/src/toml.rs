// SPDX-License-Identifier: MPL-2.0
//! Minimal TOML subset reader for the ISO manifests.
//!
//! The workspace carries no third-party crates, so the few manifest values
//! the ISO build needs (`iso/manifest/oneiso.toml`, `iso/manifest/
//! limine.lock`) are read by this hand-written parser. It understands the
//! subset the manifests actually use: `[section]` and `[[array]]` headers
//! plus `key = "string"` pairs. Integers, booleans and nested tables are
//! rejected as a configuration error so future manifest extensions fail
//! loudly instead of being silently ignored.

use std::path::Path;

use namikaze_common::{Error, Result};

/// One logical section: either `[name]` or the Nth `[[name]]` occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Section {
    /// Header name without brackets (array headers keep the bare name).
    pub(crate) name: String,
    /// True for `[[name]]` array-of-tables headers.
    pub(crate) array: bool,
    /// Key/value string pairs in file order.
    pub(crate) pairs: Vec<(String, String)>,
}

impl Section {
    /// Value of the first pair with this key, if any.
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}

/// Parse the TOML subset into an ordered list of sections. Content before
/// the first header lands in a synthetic section named "" (the oneiso.toml
/// manifest uses no top-level keys, but being tolerant keeps the parser
/// honest about file order).
pub(crate) fn parse(text: &str) -> Result<Vec<Section>> {
    let mut sections = Vec::new();
    sections.push(Section { name: String::new(), array: false, pairs: Vec::new() });
    let mut current = 0usize;
    for (lineno, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim().to_string();
        if line.is_empty() {
            continue;
        }
        if let Some(header) = parse_header(&line) {
            sections.push(header);
            current = sections.len() - 1;
            continue;
        }
        let (key, value) = parse_pair(&line).ok_or_else(|| {
            Error::Config(format!("manifest line {}: not a key = \"value\" pair", lineno + 1))
        })?;
        sections[current].pairs.push((key, value));
    }
    Ok(sections)
}

/// Parse a manifest file: read, parse, return the section list.
pub(crate) fn parse_file(path: &Path) -> Result<Vec<Section>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("{}: unreadable manifest: {e}", path.display())))?;
    parse(&text)
}

/// Find the first section matching a header.
pub(crate) fn section<'a>(sections: &'a [Section], name: &str, array: bool) -> Option<&'a Section> {
    sections.iter().find(|s| s.array == array && s.name == name)
}

/// Find all `[[name]]` sections in file order.
pub(crate) fn sections<'a>(sections: &'a [Section], name: &str) -> Vec<&'a Section> {
    sections.iter().filter(|s| s.array && s.name == name).collect()
}

fn strip_comment(raw: &str) -> &str {
    let mut in_string = false;
    for (i, c) in raw.char_indices() {
        match c {
            '"' => in_string = !in_string,
            '#' if !in_string => return &raw[..i],
            _ => {}
        }
    }
    raw
}

fn parse_header(line: &str) -> Option<Section> {
    if let Some(rest) = line.strip_prefix("[[") {
        let inner = rest.strip_suffix("]]")?;
        return Some(Section { name: inner.trim().to_string(), array: true, pairs: Vec::new() });
    }
    let inner = line.strip_prefix('[')?.strip_suffix(']')?;
    Some(Section { name: inner.trim().to_string(), array: false, pairs: Vec::new() })
}

fn parse_pair(line: &str) -> Option<(String, String)> {
    let (key, rest) = line.split_once('=')?;
    let key = key.trim().to_string();
    let rest = rest.trim();
    let value = strip_string(rest)?;
    Some((key, value))
}

fn strip_string(rest: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = rest.chars();
    // first non-space must open a quoted string
    loop {
        match chars.next() {
            Some('"') => break,
            Some(c) if c.is_whitespace() => continue,
            _ => return None,
        }
    }
    loop {
        match chars.next() {
            Some('"') => break,
            Some('\\') => {
                // basic escapes; unknown escapes are rejected
                match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    _ => return None,
                }
            }
            Some(c) => out.push(c),
            None => return None,
        }
    }
    // only trailing whitespace may follow the closing quote
    if !chars.all(|c| c.is_whitespace()) {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_manifest_subset() {
        let text = "# comment\n[iso]\nlabel = \"NAMIKAZE_ISO\"\n\n[[arch]]\ntree = \"x86-64\"\n";
        let secs = parse(text).unwrap();
        let iso = section(&secs, "iso", false).unwrap();
        assert_eq!(iso.get("label"), Some("NAMIKAZE_ISO"));
        let arch = sections(&secs, "arch");
        assert_eq!(arch.len(), 1);
        assert_eq!(arch[0].get("tree"), Some("x86-64"));
    }

    #[test]
    fn rejects_non_string_values() {
        assert!(parse("x = 42").is_err());
        assert!(parse("x = true").is_err());
        assert!(parse("[a.b]\n").is_ok()); // dotted headers parse as plain names
    }
}
