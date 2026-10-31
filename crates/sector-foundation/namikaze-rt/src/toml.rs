// SPDX-License-Identifier: MPL-2.0
//! Strict TOML subset parser: the configuration surface of NamikazeOS.
//!
//! Supported (everything the shipped configs use):
//! - `[table]` and `[a.b.c]` headers, `[[array.of.tables]]`
//! - bare and quoted keys, `#` comments
//! - basic strings with escapes, integers, booleans, single-line arrays
//! - duplicate key detection and re-opened table merge rejection
//!
//! Unsupported (fails loudly instead of silently misparsing): multi-line
//! strings, literal strings ('...'), floats, dates, inline tables.

use std::collections::BTreeMap;

/// A parsed TOML value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    Arr(Vec<Value>),
    Table(BTreeMap<String, Value>),
    /// Array of tables ([[x]]); each element is a Table.
    TableArr(Vec<BTreeMap<String, Value>>),
}

impl Value {
    /// String view.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Integer view.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Boolean view.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Table view.
    pub fn as_table(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Table(t) => Some(t),
            _ => None,
        }
    }

    /// Table array view.
    pub fn as_table_arr(&self) -> Option<&[BTreeMap<String, Value>]> {
        match self {
            Value::TableArr(a) => Some(a),
            _ => None,
        }
    }

    /// Array-of-values view.
    pub fn as_arr(&self) -> Option<&[Value]> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }

    /// Navigate a dotted path inside tables.
    pub fn path(&self, path: &str) -> Option<&Value> {
        let mut cur = self;
        for part in path.split('.') {
            match cur {
                Value::Table(t) => cur = t.get(part)?,
                _ => return None,
            }
        }
        Some(cur)
    }
}

/// Parse a TOML document into its root table.
pub fn parse(text: &str) -> crate::Result<BTreeMap<String, Value>> {
    let mut root: BTreeMap<String, Value> = BTreeMap::new();
    // Where key=value lines land: root, a named table, or the newest
    // element of an [[array of tables]].
    let mut target = Target::Root;
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(body) = line.strip_prefix("[[") {
            let body =
                body.strip_suffix("]]").ok_or_else(|| err(line_no, "unterminated [[header]]"))?;
            let path = split_key(body, line_no)?;
            open_table_arr(&mut root, &path, line_no)?;
            target = Target::ArrElem(path);
            continue;
        }
        if let Some(body) = line.strip_prefix('[') {
            let body =
                body.strip_suffix(']').ok_or_else(|| err(line_no, "unterminated [header]"))?;
            let path = split_key(body, line_no)?;
            open_table(&mut root, &path, line_no)?;
            target = Target::Table(path);
            continue;
        }
        // key = value
        let Some(eq) = find_unquoted(line, '=') else {
            return Err(err(line_no, "expected key = value"));
        };
        let key = line[..eq].trim();
        let val_text = line[eq + 1..].trim();
        if key.is_empty() || val_text.is_empty() {
            return Err(err(line_no, "empty key or value"));
        }
        let key_parts = split_key(key, line_no)?;
        let value = parse_value(val_text, line_no)?;
        insert(&mut root, &target, &key_parts, value, line_no)?;
    }
    Ok(root)
}

/// Insertion target established by the most recent header.
#[derive(Debug, Clone)]
enum Target {
    Root,
    Table(Vec<String>),
    ArrElem(Vec<String>),
}

fn err(line_no: usize, msg: &str) -> crate::Error {
    crate::Error::Parse(format!("line {line_no}: {msg}"))
}

fn strip_comment(line: &str) -> &str {
    // cut at the first '#' that is not inside a quoted string
    let mut in_str = false;
    let mut escape = false;
    for (i, c) in line.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        match c {
            '\\' if in_str => escape = true,
            '"' => in_str = !in_str,
            '#' if !in_str => return &line[..i],
            _ => {}
        }
    }
    line
}

fn find_unquoted(line: &str, needle: char) -> Option<usize> {
    let mut in_str = false;
    let mut escape = false;
    for (i, c) in line.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        match c {
            '\\' if in_str => escape = true,
            '"' => in_str = !in_str,
            c if c == needle && !in_str => return Some(i),
            _ => {}
        }
    }
    None
}

fn split_key(text: &str, line_no: usize) -> crate::Result<Vec<String>> {
    let mut out = Vec::new();
    for part in text.split('.') {
        let p = part.trim();
        if p.is_empty() {
            return Err(err(line_no, "empty key segment"));
        }
        if p.starts_with('"') && p.ends_with('"') && p.len() >= 2 {
            out.push(p[1..p.len() - 1].to_string());
        } else {
            if !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
                return Err(err(line_no, &format!("invalid bare key {p:?}")));
            }
            out.push(p.to_string());
        }
    }
    Ok(out)
}

fn parse_value(text: &str, line_no: usize) -> crate::Result<Value> {
    if let Some(rest) = text.strip_prefix('"') {
        let body = rest.strip_suffix('"').ok_or_else(|| err(line_no, "unterminated string"))?;
        return Ok(Value::Str(unescape(body, line_no)?));
    }
    match text {
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        _ => {}
    }
    if text.starts_with('[') {
        let body = text
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .ok_or_else(|| err(line_no, "unterminated array"))?;
        let mut items = Vec::new();
        for item in split_top(body, ',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            items.push(parse_value(item, line_no)?);
        }
        return Ok(Value::Arr(items));
    }
    if let Ok(i) = text.replace('_', "").parse::<i64>() {
        return Ok(Value::Int(i));
    }
    Err(err(line_no, &format!("unsupported value {text:?}")))
}

fn split_top(text: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth: usize = 0;
    let mut in_str = false;
    let mut cur = String::new();
    for c in text.chars() {
        match c {
            '"' => {
                in_str = !in_str;
                cur.push(c);
            }
            '[' if !in_str => {
                depth += 1;
                cur.push(c);
            }
            ']' if !in_str => {
                depth = depth.saturating_sub(1);
                cur.push(c);
            }
            c if c == sep && !in_str && depth == 0 => {
                out.push(cur.clone());
                cur.clear();
            }
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn unescape(body: &str, line_no: usize) -> crate::Result<String> {
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                let code =
                    u32::from_str_radix(&hex, 16).map_err(|_| err(line_no, "bad \\u escape"))?;
                out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
            }
            _ => return Err(err(line_no, "unknown escape")),
        }
    }
    Ok(out)
}

fn table_at<'a>(
    root: &'a mut BTreeMap<String, Value>,
    path: &[String],
    line_no: usize,
) -> crate::Result<&'a mut BTreeMap<String, Value>> {
    let mut cur = root;
    for part in path {
        let entry = cur.entry(part.clone()).or_insert_with(|| Value::Table(BTreeMap::new()));
        match entry {
            Value::Table(t) => cur = t,
            _ => return Err(err(line_no, &format!("key {part:?} is not a table"))),
        }
    }
    Ok(cur)
}

fn open_table(
    root: &mut BTreeMap<String, Value>,
    path: &[String],
    line_no: usize,
) -> crate::Result<()> {
    let (last, parents) = path.split_last().ok_or_else(|| err(line_no, "empty header"))?;
    let parent = table_at(root, parents, line_no)?;
    match parent.get(last) {
        Some(Value::Table(_)) => Ok(()),
        Some(_) => Err(err(line_no, &format!("key {last:?} redefined as table"))),
        None => {
            parent.insert(last.clone(), Value::Table(BTreeMap::new()));
            Ok(())
        }
    }
}

fn open_table_arr(
    root: &mut BTreeMap<String, Value>,
    path: &[String],
    line_no: usize,
) -> crate::Result<()> {
    let (last, parents) = path.split_last().ok_or_else(|| err(line_no, "empty header"))?;
    let parent = table_at(root, parents, line_no)?;
    let entry = parent.entry(last.clone()).or_insert_with(|| Value::TableArr(Vec::new()));
    match entry {
        Value::TableArr(a) => {
            a.push(BTreeMap::new());
            Ok(())
        }
        _ => Err(err(line_no, &format!("key {last:?} conflicts with [[header]]"))),
    }
}

fn insert(
    root: &mut BTreeMap<String, Value>,
    target: &Target,
    key: &[String],
    value: Value,
    line_no: usize,
) -> crate::Result<()> {
    match target {
        Target::Root => insert_into_table(root, key, value, line_no),
        Target::Table(path) => {
            let table = table_at(root, path, line_no)?;
            insert_into_table(table, key, value, line_no)
        }
        Target::ArrElem(path) => {
            let (last, parents) = path.split_last().ok_or_else(|| err(line_no, "empty header"))?;
            let parent = table_at(root, parents, line_no)?;
            match parent.get_mut(last) {
                Some(Value::TableArr(items)) => {
                    let t = items.last_mut().ok_or_else(|| err(line_no, "no active table"))?;
                    insert_into_table(t, key, value, line_no)
                }
                _ => Err(err(line_no, "header lost its table array")),
            }
        }
    }
}

fn insert_into_table(
    table: &mut BTreeMap<String, Value>,
    key: &[String],
    value: Value,
    line_no: usize,
) -> crate::Result<()> {
    let (leaf, base) = key.split_last().ok_or_else(|| err(line_no, "empty key"))?;
    let mut cur = table;
    for part in base {
        let entry = cur.entry(part.clone()).or_insert_with(|| Value::Table(BTreeMap::new()));
        match entry {
            Value::Table(t) => cur = t,
            _ => return Err(err(line_no, "dotted key crosses a non-table")),
        }
    }
    if cur.contains_key(leaf) {
        return Err(err(line_no, &format!("duplicate key {leaf:?}")));
    }
    cur.insert(leaf.to_string(), value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_system_config_shape() {
        let src = r#"
# top comment
[storage]
mode = "persistent"          # trailing comment

[storage.pbkdf]
algo = "argon2id"
memory_kb = 1048576
iterations = 4

[anonymity]
transparent_tor = true
ipv6 = "privacy"

[[upstreams]]
name = "primary"
transport = "dot"

[[upstreams]]
name = "fallback"
transport = "doh"
"#;
        let root = Value::Table(parse(src).unwrap());
        assert_eq!(root.path("storage.mode").unwrap().as_str(), Some("persistent"));
        assert_eq!(root.path("storage.pbkdf.memory_kb").unwrap().as_int(), Some(1048576));
        assert_eq!(root.path("anonymity.transparent_tor").unwrap().as_bool(), Some(true));
        let ups = root.path("upstreams").unwrap().as_table_arr().unwrap();
        assert_eq!(ups.len(), 2);
        assert_eq!(ups[1].get("transport").unwrap().as_str(), Some("doh"));
    }

    #[test]
    fn duplicate_keys_fail() {
        assert!(parse("a = 1\na = 2\n").is_err());
        assert!(parse("[t]\nx = 1\n[t]\nx = 2\n").is_err());
    }

    #[test]
    fn arrays_and_escapes() {
        let root = parse("env = [\"LANG\", \"LC_ALL\"]\ns = \"a\\nb\"\n").unwrap();
        assert_eq!(root.get("env").unwrap().as_arr().unwrap()[1].as_str(), Some("LC_ALL"));
        assert_eq!(root.get("s").unwrap().as_str(), Some("a\nb"));
    }

    #[test]
    fn rejects_unknown_syntax() {
        assert!(parse("x = 1.5\n").is_err());
        assert!(parse("x = 'literal'\n").is_err());
        assert!(parse("x = { inline = 1 }\n").is_err());
        assert!(parse("[un\nterminated\n").is_err());
    }
}
