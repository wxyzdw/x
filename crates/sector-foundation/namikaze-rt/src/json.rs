// SPDX-License-Identifier: MPL-2.0
//! JSON value tree, recursive-descent parser and deterministic writers.
//!
//! Objects keep sorted key order (BTreeMap) so every serialized document is
//! byte-stable: SBOMs, manifests and audit chains diff cleanly.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// A parsed JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Num(f64),
    Str(String),
    Arr(Vec<Value>),
    Obj(BTreeMap<String, Value>),
}

impl Value {
    /// Object field accessor.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(m) => m.get(key),
            _ => None,
        }
    }

    /// String view.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Integer view (accepts integral floats too).
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Num(f) if f.fract() == 0.0 && f.abs() < 9.0e18 => Some(*f as i64),
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

    /// Array view.
    pub fn as_arr(&self) -> Option<&[Value]> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }

    /// Compact serialization (no whitespace).
    pub fn to_compact(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, None, 0);
        out
    }

    /// Pretty serialization (two-space indent, trailing newline omitted).
    pub fn to_pretty(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, Some(2), 0);
        out
    }

    fn write(&self, out: &mut String, indent: Option<usize>, depth: usize) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Int(i) => {
                let _ = write!(out, "{i}");
            }
            Value::Num(f) => {
                if f.is_finite() {
                    let _ = write!(out, "{f}");
                } else {
                    out.push_str("null");
                }
            }
            Value::Str(s) => write_string(out, s),
            Value::Arr(a) => {
                if a.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    newline_indent(out, indent, depth + 1);
                    v.write(out, indent, depth + 1);
                }
                newline_indent(out, indent, depth);
                out.push(']');
            }
            Value::Obj(m) => {
                if m.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    newline_indent(out, indent, depth + 1);
                    write_string(out, k);
                    out.push(':');
                    if indent.is_some() {
                        out.push(' ');
                    }
                    v.write(out, indent, depth + 1);
                }
                newline_indent(out, indent, depth);
                out.push('}');
            }
        }
    }
}

fn newline_indent(out: &mut String, indent: Option<usize>, depth: usize) {
    if let Some(n) = indent {
        out.push('\n');
        for _ in 0..n * depth {
            out.push(' ');
        }
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Parse a JSON document.
pub fn parse(text: &str) -> crate::Result<Value> {
    let bytes: Vec<char> = text.chars().collect();
    let mut p = Parser { src: &bytes, pos: 0 };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.pos != p.src.len() {
        return Err(crate::Error::Parse("trailing characters after JSON".into()));
    }
    Ok(v)
}

struct Parser<'a> {
    src: &'a [char],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<char> {
        self.src.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ') | Some('\t') | Some('\n') | Some('\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, c: char) -> crate::Result<()> {
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(crate::Error::Parse(format!(
                "expected {c:?} at byte offset {}",
                self.pos
            )))
        }
    }

    fn literal(&mut self, word: &str) -> crate::Result<()> {
        for c in word.chars() {
            self.expect(c)?;
        }
        Ok(())
    }

    fn value(&mut self) -> crate::Result<Value> {
        self.skip_ws();
        match self.peek() {
            Some('{') => self.object(),
            Some('[') => self.array(),
            Some('"') => Ok(Value::Str(self.string()?)),
            Some('t') => {
                self.literal("true")?;
                Ok(Value::Bool(true))
            }
            Some('f') => {
                self.literal("false")?;
                Ok(Value::Bool(false))
            }
            Some('n') => {
                self.literal("null")?;
                Ok(Value::Null)
            }
            Some(c) if c == '-' || c.is_ascii_digit() => self.number(),
            Some(c) => Err(crate::Error::Parse(format!(
                "unexpected character {c:?} at offset {}",
                self.pos
            ))),
            None => Err(crate::Error::Parse("unexpected end of input".into())),
        }
    }

    fn object(&mut self) -> crate::Result<Value> {
        self.expect('{')?;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.pos += 1;
            return Ok(Value::Obj(map));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.expect(':')?;
            let val = self.value()?;
            map.insert(key, val);
            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.pos += 1;
                }
                Some('}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(crate::Error::Parse("expected ',' or '}'".into())),
            }
        }
        Ok(Value::Obj(map))
    }

    fn array(&mut self) -> crate::Result<Value> {
        self.expect('[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.pos += 1;
            return Ok(Value::Arr(items));
        }
        loop {
            items.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.pos += 1;
                }
                Some(']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(crate::Error::Parse("expected ',' or ']'".into())),
            }
        }
        Ok(Value::Arr(items))
    }

    fn string(&mut self) -> crate::Result<String> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(crate::Error::Parse("unterminated string".into())),
                Some('"') => {
                    self.pos += 1;
                    break;
                }
                Some('\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some('"') => out.push('"'),
                        Some('\\') => out.push('\\'),
                        Some('/') => out.push('/'),
                        Some('b') => out.push('\u{8}'),
                        Some('f') => out.push('\u{c}'),
                        Some('n') => out.push('\n'),
                        Some('r') => out.push('\r'),
                        Some('t') => out.push('\t'),
                        Some('u') => {
                            self.pos += 1;
                            let mut code = 0u32;
                            for _ in 0..4 {
                                let c = self.peek()
                                    .ok_or_else(|| crate::Error::Parse("bad \\u escape".into()))?;
                                code = code * 16
                                    + c.to_digit(16)
                                        .ok_or_else(|| crate::Error::Parse("bad hex digit".into()))?;
                                self.pos += 1;
                            }
                            // surrogate pair handling
                            if (0xd800..0xdc00).contains(&code) {
                                if self.peek() == Some('\\') {
                                    self.pos += 1;
                                    self.expect('u')?;
                                    let mut low = 0u32;
                                    for _ in 0..4 {
                                        let c = self.peek().ok_or_else(|| {
                                            crate::Error::Parse("bad \\u escape".into())
                                        })?;
                                        low = low * 16 + c
                                            .to_digit(16)
                                            .ok_or_else(|| crate::Error::Parse("bad hex".into()))?;
                                        self.pos += 1;
                                    }
                                    code = 0x10000
                                        + ((code - 0xd800) << 10)
                                        + (low - 0xdc00);
                                }
                            }
                            out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                            continue;
                        }
                        _ => return Err(crate::Error::Parse("bad escape".into())),
                    }
                    self.pos += 1;
                }
                Some(c) => {
                    out.push(c);
                    self.pos += 1;
                }
            }
        }
        Ok(out)
    }

    fn number(&mut self) -> crate::Result<Value> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.pos += 1;
        }
        let mut float = false;
        if self.peek() == Some('.') {
            float = true;
            self.pos += 1;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some('e') | Some('E')) {
            float = true;
            self.pos += 1;
            if matches!(self.peek(), Some('+') | Some('-')) {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let text: String = self.src[start..self.pos].iter().collect();
        if float {
            text.parse::<f64>()
                .map(Value::Num)
                .map_err(|_| crate::Error::Parse(format!("bad number {text:?}")))
        } else {
            text.parse::<i64>()
                .map(Value::Int)
                .map_err(|_| crate::Error::Parse(format!("bad integer {text:?}")))
        }
    }
}

/// Build an object conveniently: `obj(&[("k", v)])`.
pub fn obj(pairs: &[(&str, Value)]) -> Value {
    Value::Obj(pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_shapes() {
        let src = r#"{"a":1,"b":[true,null,"x\ny"],"c":{"d":-2.5}}"#;
        let v = parse(src).unwrap();
        assert_eq!(v.get("a").unwrap().as_i64(), Some(1));
        assert_eq!(v.get("b").unwrap().as_arr().unwrap().len(), 3);
        assert_eq!(v.to_compact(), src);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("{").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("nul").is_err());
        assert!(parse("{}x").is_err());
    }

    #[test]
    fn pretty_is_stable() {
        let v = parse(r#"{"z":1,"a":[1,2]}"#).unwrap();
        let pretty = v.to_pretty();
        assert_eq!(parse(&pretty).unwrap(), v);
        assert!(pretty.starts_with("{\n  \"a\": ["));
    }

    #[test]
    fn escapes_and_unicode() {
        let v = parse("\"\\u00e9\"").unwrap();
        assert_eq!(v.as_str(), Some("\u{e9}"));
        let v = parse("\"\\ud83d\\ude00\"").unwrap();
        assert_eq!(v.as_str(), Some("\u{1f600}"));
    }
}
