// SPDX-License-Identifier: MPL-2.0
//! The plumb message and its wire format, transcribed from
//! `src/libplumb/mesg.c` and `plumb(6)`.
//!
//! A message is six newline-terminated header lines followed by the
//! raw data:
//!
//! ```text
//! src\n
//! dst\n
//! wdir\n
//! type\n
//! attrs\n          - space separated name=value pairs, value quoted
//! ndata\n          - decimal byte count of the data that follows
//! <ndata bytes>
//! ```
//!
//! A nil C field packs as an empty line; the Rust port represents
//! those fields as empty strings, which round-trips identically.
//! `unpack_partial` reproduces `plumbunpackpartial`'s three outcomes:
//! complete, incomplete (the plumber buffers and waits), or malformed
//! (the plumber answers `bad plumb message format`).

#![forbid(unsafe_code)]

/// One `name=value` message attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr {
    pub name: String,
    pub value: String,
}

/// A plumb message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plumbmsg {
    pub src: String,
    pub dst: String,
    pub wdir: String,
    pub typ: String,
    pub attr: Vec<Attr>,
    pub data: Vec<u8>,
}

/// Why a buffer is not (yet) a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnpackError {
    /// The declared length needs `need` more bytes than the buffer
    /// carries; `plumbunpackpartial` reports this through `morep` and
    /// the plumber keeps accumulating the write.
    NeedMore(usize),
    /// Malformed: unterminated header, length mismatch, junk after
    /// the data. The plumber answers `bad plumb message format`.
    Bad,
}

impl Plumbmsg {
    pub fn new() -> Plumbmsg {
        Plumbmsg {
            src: String::new(),
            dst: String::new(),
            wdir: String::new(),
            typ: String::new(),
            attr: Vec::new(),
            data: Vec::new(),
        }
    }

    /// Serialize exactly as libplumb's `plumbpack` does: five field
    /// lines, the attribute line, the decimal data length, the data.
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for field in [&self.src, &self.dst, &self.wdir, &self.typ] {
            out.extend_from_slice(field.as_bytes());
            out.push(b'\n');
        }
        out.extend_from_slice(pack_attr(&self.attr).as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.data.len().to_string().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(&self.data);
        out
    }

    /// The attribute value for `name`, first match wins
    /// (`plumblookup`).
    pub fn attr(&self, name: &str) -> Option<&str> {
        attr_lookup(&self.attr, name)
    }

    /// Append an attribute (`plumbaddattr` appends at the tail).
    pub fn add_attr(&mut self, name: &str, value: &str) {
        self.attr.push(Attr { name: name.to_string(), value: value.to_string() });
    }

    /// Remove the first attribute named `name`; true when it existed
    /// (`plumbdelattr`, called only after a successful lookup by the
    /// `attr delete` verb).
    pub fn del_attr(&mut self, name: &str) -> bool {
        if let Some(i) = self.attr.iter().position(|a| a.name == name) {
            self.attr.remove(i);
            true
        } else {
            false
        }
    }
}

impl Default for Plumbmsg {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a buffer that may be a truncated or malformed message
/// (`plumbunpackpartial`).
pub fn unpack_partial(buf: &[u8]) -> Result<Plumbmsg, UnpackError> {
    let mut cursor = 0usize;
    let mut lines: Vec<String> = Vec::with_capacity(6);
    for _ in 0..6 {
        let start = cursor;
        let nl = buf[start..].iter().position(|&b| b == b'\n');
        match nl {
            None => return Err(UnpackError::Bad),
            Some(rel) => {
                let end = start + rel;
                lines.push(String::from_utf8_lossy(&buf[start..end]).into_owned());
                cursor = end + 1;
            }
        }
    }
    let ndata = atoi(&lines[5]);
    let remaining = buf.len() - cursor;
    if ndata < 0 || ndata != remaining as i64 {
        if ndata > remaining as i64 {
            return Err(UnpackError::NeedMore(ndata as usize - remaining));
        }
        return Err(UnpackError::Bad);
    }
    Ok(Plumbmsg {
        src: std::mem::take(&mut lines[0]),
        dst: std::mem::take(&mut lines[1]),
        wdir: std::mem::take(&mut lines[2]),
        typ: std::mem::take(&mut lines[3]),
        attr: unpack_attr(&lines[4]),
        data: buf[cursor..].to_vec(),
    })
}

/// C `atoi`: skip blanks, optional sign, decimal digits; anything
/// else is 0. The plumber reads the length line through `atoi`, so
/// `xyz` declares zero bytes of data.
fn atoi(s: &str) -> i64 {
    let mut it = s.chars().peekable();
    while matches!(it.peek(), Some(' ' | '\t')) {
        it.next();
    }
    let mut sign = 1i64;
    if matches!(it.peek(), Some('+')) {
        it.next();
    } else if matches!(it.peek(), Some('-')) {
        sign = -1;
        it.next();
    }
    let mut acc: i64 = 0;
    let mut any = false;
    for c in it {
        if let Some(d) = c.to_digit(10) {
            any = true;
            acc = acc.saturating_mul(10).saturating_add(d as i64);
        } else {
            break;
        }
    }
    if any {
        sign * acc
    } else {
        0
    }
}

/// Parse an attribute line: whitespace-separated `name=value` tokens
/// with single-quoted values (`plumbunpackattr`). A token without `=`
/// stops the parse - the C code returns the attributes collected so
/// far rather than failing outright.
pub fn unpack_attr(s: &str) -> Vec<Attr> {
    let mut out = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut p = 0usize;
    while p < chars.len() && chars[p] != '\n' {
        while p < chars.len() && (chars[p] == ' ' || chars[p] == '\t') {
            p += 1;
        }
        if p >= chars.len() || chars[p] == '\n' {
            break;
        }
        let mut q = p;
        while q < chars.len()
            && chars[q] != '\n'
            && chars[q] != ' '
            && chars[q] != '\t'
            && chars[q] != '='
        {
            q += 1;
        }
        if q >= chars.len() || chars[q] != '=' {
            break; // malformed attribute: stop
        }
        let name: String = chars[p..q].iter().collect();
        q += 1; // skip '='
        let mut value = String::new();
        let mut quoting = false;
        while q < chars.len() && chars[q] != '\n' {
            let c = chars[q];
            q += 1;
            if quoting {
                if c == '\'' {
                    if q < chars.len() && chars[q] == '\'' {
                        q += 1;
                        value.push('\'');
                    } else {
                        quoting = false;
                    }
                } else {
                    value.push(c);
                }
            } else if c == ' ' || c == '\t' {
                break;
            } else if c == '\'' {
                quoting = true;
            } else {
                value.push(c);
            }
        }
        out.push(Attr { name, value });
        p = q;
    }
    out
}

/// Serialize attributes as `name='value'` pairs separated by blanks
/// (`plumbpackattr`; every value is quoted). No attributes at all
/// packs as the empty string, exactly like the C nil return.
pub fn pack_attr(attrs: &[Attr]) -> String {
    let mut out = String::new();
    for (i, a) in attrs.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&a.name);
        out.push('=');
        out.push_str(&crate::regex::quote(&a.value));
    }
    out
}

/// First attribute named `name` (`plumblookup`).
pub fn attr_lookup<'a>(attrs: &'a [Attr], name: &str) -> Option<&'a str> {
    attrs.iter().find(|a| a.name == name).map(|a| a.value.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(src: &str, dst: &str, wdir: &str, typ: &str, attr: &[Attr], data: &[u8]) -> Plumbmsg {
        Plumbmsg {
            src: src.into(),
            dst: dst.into(),
            wdir: wdir.into(),
            typ: typ.into(),
            attr: attr.to_vec(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn pack_unpack_roundtrip() {
        let m = msg(
            "plumb",
            "edit",
            "/usr/src",
            "text",
            &[Attr { name: "action".into(), value: "showdata".into() }],
            b"/etc/hosts",
        );
        let wire = m.pack();
        assert_eq!(wire, b"plumb\nedit\n/usr/src\ntext\naction='showdata'\n10\n/etc/hosts");
        let back = unpack_partial(&wire).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn nil_fields_pack_as_empty_lines() {
        let m = msg("", "", "", "", &[], b"x");
        let wire = m.pack();
        assert_eq!(wire, b"\n\n\n\n\n1\nx");
        assert_eq!(unpack_partial(&wire).unwrap(), m);
    }

    #[test]
    fn incomplete_data_reports_needed_bytes() {
        let full = msg("s", "d", "w", "t", &[], b"0123456789").pack();
        let cut = full.len() - 4;
        match unpack_partial(&full[..cut]) {
            Err(UnpackError::NeedMore(4)) => {}
            other => panic!("expected NeedMore(4), got {other:?}"),
        }
        // and the complete buffer parses
        assert!(unpack_partial(&full).is_ok());
    }

    #[test]
    fn length_mismatch_is_bad() {
        let mut wire = msg("s", "d", "w", "t", &[], b"abc").pack();
        // claim 3 bytes, carry 4
        let n = wire.len() - 4;
        wire[n - 3] = b'4';
        assert_eq!(unpack_partial(&wire), Err(UnpackError::Bad));
    }

    #[test]
    fn unterminated_header_is_bad() {
        assert_eq!(unpack_partial(b"src\ndst"), Err(UnpackError::Bad));
    }

    #[test]
    fn atoi_is_c_semantics() {
        assert_eq!(atoi("42"), 42);
        assert_eq!(atoi("  7x"), 7);
        assert_eq!(atoi("xyz"), 0);
        assert_eq!(atoi(""), 0);
        assert_eq!(atoi("-3"), -3);
    }

    #[test]
    fn attr_quoting_roundtrip() {
        let attrs = vec![
            Attr { name: "a".into(), value: "has space".into() },
            Attr { name: "b".into(), value: "it's".into() },
        ];
        let packed = pack_attr(&attrs);
        assert_eq!(packed, "a='has space' b='it''s'");
        assert_eq!(unpack_attr(&packed), attrs);
    }

    #[test]
    fn unquoted_values_and_malformed_tokens() {
        let attrs = unpack_attr("k=v other=2");
        assert_eq!(attrs.len(), 2);
        assert_eq!(attr_lookup(&attrs, "other"), Some("2"));
        // a token without '=' stops the parse, keeping earlier attrs
        let bad = unpack_attr("k=v oops name=last");
        assert_eq!(bad.len(), 1);
    }

    #[test]
    fn attr_lookup_add_del() {
        let mut m = Plumbmsg::new();
        m.add_attr("click", "12");
        m.add_attr("click", "13");
        assert_eq!(m.attr("click"), Some("12"));
        assert!(m.del_attr("click"));
        assert_eq!(m.attr("click"), Some("13"));
        assert!(!m.del_attr("nope"));
    }
}
