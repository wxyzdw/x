// SPDX-License-Identifier: MPL-2.0
//! The plumbing rules language: parser, variable expansion and the
//! rules-file machinery. Transcribed from
//! `src/cmd/plumb/rules.c` (plan9port, Bell Labs lineage) against
//! `plumber(4)`.
//!
//! A rules file is a sequence of rulesets separated by blank lines.
//! Each line is a comment (`#`), an include, an assignment
//! (`name = value`), or a rule `object verb argument...`. The objects
//! are `arg attr data dst plumb src type wdir` (plus `kind`, the
//! accepted pre-9.5 spelling of `type`); the verbs are
//! `add client delete is isdir isfile matches set start to`. Every
//! combination that makes no sense is a parse error with the C
//! original's exact message. Pattern rules accumulate into a ruleset;
//! `plumb to` actions name the port, `plumb start` / `plumb client`
//! name commands; a ruleset may carry at most one command action.
//! A ruleset with only `plumb to` lines declares ports without
//! matching anything.

#![forbid(unsafe_code)]

use crate::matcher::{cleanname, Exec};
use crate::msg::pack_attr;
use crate::regex::Regex;

/// Maximum capture references, `$0`..`$99` (the C `NMATCHSUBEXP`).
pub use crate::regex::NMATCHSUBEXP;

/// Ports a ruleset may not name (`badports` in rules.c).
pub const BAD_PORTS: [&str; 3] = [".", "..", "send"];

/// The rule objects, in table order (`objects[]`); the index is the
/// C enum value.
pub const OBJECTS: [&str; 8] = ["arg", "attr", "data", "dst", "plumb", "src", "type", "wdir"];

/// The rule verbs, in table order (`verbs[]`).
pub const VERBS: [&str; 10] =
    ["add", "client", "delete", "is", "isdir", "isfile", "matches", "set", "start", "to"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    Arg,
    Attr,
    Data,
    Dst,
    Plumb,
    Src,
    Type,
    Wdir,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Add,
    Client,
    Delete,
    Is,
    Isdir,
    Isfile,
    Matches,
    Set,
    Start,
    To,
}

impl Object {
    fn from_table(word: &str) -> Option<Object> {
        Some(match word {
            "arg" => Object::Arg,
            "attr" => Object::Attr,
            "data" => Object::Data,
            "dst" => Object::Dst,
            "plumb" => Object::Plumb,
            "src" => Object::Src,
            "type" => Object::Type,
            "wdir" => Object::Wdir,
            _ => return None,
        })
    }

    pub fn name(&self) -> &'static str {
        OBJECTS[self.table_index()]
    }

    fn table_index(&self) -> usize {
        match self {
            Object::Arg => 0,
            Object::Attr => 1,
            Object::Data => 2,
            Object::Dst => 3,
            Object::Plumb => 4,
            Object::Src => 5,
            Object::Type => 6,
            Object::Wdir => 7,
        }
    }
}

impl Verb {
    fn from_table(word: &str) -> Option<Verb> {
        Some(match word {
            "add" => Verb::Add,
            "client" => Verb::Client,
            "delete" => Verb::Delete,
            "is" => Verb::Is,
            "isdir" => Verb::Isdir,
            "isfile" => Verb::Isfile,
            "matches" => Verb::Matches,
            "set" => Verb::Set,
            "start" => Verb::Start,
            "to" => Verb::To,
            _ => return None,
        })
    }

    pub fn name(&self) -> &'static str {
        VERBS[self.table_index()]
    }

    fn table_index(&self) -> usize {
        match self {
            Verb::Add => 0,
            Verb::Client => 1,
            Verb::Delete => 2,
            Verb::Is => 3,
            Verb::Isdir => 4,
            Verb::Isfile => 5,
            Verb::Matches => 6,
            Verb::Set => 7,
            Verb::Start => 8,
            Verb::To => 9,
        }
    }
}

/// One rule line: `object verb argument`, with the argument kept
/// both raw (`arg`, what `printrules` prints and the runtime commands
/// re-expand) and parse-time expanded (`qarg`, what `is` compares and
/// `matches` compiles).
#[derive(Debug, Clone)]
pub struct Rule {
    pub obj: Object,
    pub verb: Verb,
    pub arg: String,
    pub qarg: String,
    pub regex: Option<Regex>,
}

/// A ruleset: pattern rules, action rules, and the port named by the
/// (single) `plumb to` action.
#[derive(Debug, Clone)]
pub struct Ruleset {
    pub pat: Vec<Rule>,
    pub act: Vec<Rule>,
    pub port: Option<String>,
}

/// A rules-file variable: raw value plus quote-processed value; `$name`
/// expands to the quote-processed one (`Var.value` / `Var.qvalue`).
#[derive(Debug, Clone)]
pub struct Var {
    pub name: String,
    pub value: String,
    pub qvalue: String,
}

#[derive(Debug)]
struct InputFrame {
    name: String,
    text: Vec<char>,
    pos: usize,
    lineno: usize,
    /// File-backed frames pop when exhausted; string frames (the
    /// incremental `<rules input>`) end the parse instead, like the
    /// C `input->end` convention.
    file_backed: bool,
}

/// The rules parser: variables, ports and rulesets accumulated across
/// every source fed through it (initial file, includes, incremental
/// writes) - the C globals `vars`, `ports` and `rules`.
#[derive(Debug, Default)]
pub struct RulesParser {
    pub vars: Vec<Var>,
    pub rulesets: Vec<Ruleset>,
    pub ports: Vec<String>,
    inputs: Vec<InputFrame>,
    /// Text written to `plumb/rules` that has not parsed into a
    /// complete ruleset yet (the C `writerules` text buffer).
    pending: String,
}

/// `plumb to` lines whose ruleset has no patterns declare ports.
/// The C dirtab allows 50 entries: `.`, `rules`, `send` and 47 ports.
const MAX_PORTS: usize = 47;

impl RulesParser {
    pub fn new() -> RulesParser {
        RulesParser::default()
    }

    /// Parse a rules file from disk (supports `include`).
    pub fn parse_file(&mut self, path: &str) -> Result<(), String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        self.push_input(path, &text, true)?;
        self.run()
    }

    /// Parse a string of rules (the initial load reads a file; the
    /// `rules` file interface feeds strings).
    pub fn parse_text(&mut self, name: &str, text: &str) -> Result<(), String> {
        self.push_input(name, text, false)?;
        self.run()
    }

    fn push_input(&mut self, name: &str, text: &str, file_backed: bool) -> Result<(), String> {
        if self.inputs.len() >= 10 {
            // the C guard exists to protect the stack; the message is
            // kept verbatim because users will have memorized it
            return Err(self.parse_error("include stack too deep; max 10"));
        }
        self.inputs.push(InputFrame {
            name: name.to_string(),
            text: text.chars().collect(),
            pos: 0,
            lineno: 0,
            file_backed,
        });
        Ok(())
    }

    fn run(&mut self) -> Result<(), String> {
        while let Some(rs) = self.read_ruleset()? {
            self.rulesets.push(rs);
        }
        self.make_ports();
        Ok(())
    }

    fn getline(&mut self) -> Option<String> {
        loop {
            let top = self.inputs.last_mut()?;
            if top.pos >= top.text.len() {
                if top.file_backed {
                    self.inputs.pop();
                    continue;
                }
                return None;
            }
            let mut line = String::new();
            while top.pos < top.text.len() {
                let c = top.text[top.pos];
                top.pos += 1;
                if c == '\n' || c == '\0' {
                    break;
                }
                line.push(c);
            }
            top.lineno += 1;
            return Some(line);
        }
    }

    fn parse_error(&self, msg: &str) -> String {
        let mut where_ = String::new();
        for frame in &self.inputs {
            let _ = std::fmt::Write::write_fmt(
                &mut where_,
                format_args!("{}:{}: ", frame.name, frame.lineno),
            );
        }
        format!("{where_}{msg}")
    }

    /// One line of input: end of input, a boundary (blank, comment or
    /// assignment - the C `readrule` returns nil for all three, and
    /// any of them terminates an in-progress ruleset), or a rule.
    fn read_rule(&mut self) -> Result<Read, String> {
        loop {
            let line = match self.getline() {
                None => return Ok(Read::Eof),
                Some(l) => l,
            };
            let trimmed = line.trim_start_matches([' ', '\t']);
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return Ok(Read::Boundary);
            }
            if self.try_include(trimmed)? {
                continue;
            }
            if self.try_assignment(trimmed)? {
                return Ok(Read::Boundary);
            }
            return Ok(Read::Rule(self.parse_rule_line(trimmed)?));
        }
    }

    /// `include file` - push the file onto the input stack. Returns
    /// false when the line does not begin with `include`; any line
    /// that does but is malformed is a parse error, exactly like C.
    fn try_include(&mut self, line: &str) -> Result<bool, String> {
        if !line.starts_with("include") {
            return Ok(false);
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        let malformed = || self.parse_error("malformed include statement");
        if words.len() < 2 || words[0] != "include" || words[1].starts_with('#') {
            return Err(malformed());
        }
        if words.len() > 2 && !words[2].starts_with('#') {
            return Err(malformed());
        }
        let target = words[1];
        let resolved = if std::path::Path::new(target).is_file() {
            target.to_string()
        } else if !target.starts_with('/')
            && !target.starts_with("./")
            && !target.starts_with("../")
        {
            // the C fallback opens #9/plumb/name; this tree keeps the
            // plumbing include library under etc/plumb (or
            // $NAMIKAZE_PLUMB, set per deployment)
            let dir = std::env::var("NAMIKAZE_PLUMB").unwrap_or_else(|_| "etc/plumb".to_string());
            format!("{dir}/{target}")
        } else {
            target.to_string()
        };
        match std::fs::read_to_string(&resolved) {
            Ok(text) => {
                self.push_input(&resolved, &text, true)?;
                Ok(true)
            }
            Err(_) => Err(self.parse_error(&format!("can't open {resolved} for inclusion"))),
        }
    }

    /// `name = value` - a variable assignment. False when the line is
    /// not an assignment (then it must be a rule).
    fn try_assignment(&mut self, line: &str) -> Result<bool, String> {
        let chars: Vec<char> = line.chars().collect();
        let mut p = 0usize;
        while p < chars.len() && (chars[p].is_ascii_alphanumeric() || chars[p] == '_') {
            p += 1;
        }
        // scanvarname requires a letter or underscore to start
        if p == 0 || !(chars[0].is_ascii_alphabetic() || chars[0] == '_') {
            return Ok(false);
        }
        let name: String = chars[..p].iter().collect();
        while p < chars.len() && (chars[p] == ' ' || chars[p] == '\t') {
            p += 1;
        }
        if p >= chars.len() || chars[p] != '=' {
            return Ok(false);
        }
        p += 1;
        while p < chars.len() && (chars[p] == ' ' || chars[p] == '\t') {
            p += 1;
        }
        let raw: String = chars[p..].iter().collect();
        let (qval, _) = expand(None, &raw, &self.vars)?;
        self.set_variable(name, raw, qval);
        Ok(true)
    }

    fn set_variable(&mut self, name: String, raw: String, qvalue: String) {
        if let Some(v) = self.vars.iter_mut().find(|v| v.name == name) {
            v.value = raw;
            v.qvalue = qvalue;
        } else {
            self.vars.push(Var { name, value: raw, qvalue });
        }
    }

    pub fn variable(&self, name: &str) -> Option<&str> {
        self.vars.iter().find(|v| v.name == name).map(|v| v.qvalue.as_str())
    }

    fn parse_rule_line(&mut self, line: &str) -> Result<Rule, String> {
        let (obj_word, rest) = match line.split_once([' ', '\t']) {
            None => (line, ""),
            Some((o, r)) => (o, r.trim_start_matches([' ', '\t'])),
        };
        let (verb_word, arg) = match rest.split_once([' ', '\t']) {
            None => (rest, ""),
            Some((v, a)) => (v, a.trim_start_matches([' ', '\t'])),
        };
        if obj_word.is_empty() || verb_word.is_empty() || arg.is_empty() {
            return Err(self.parse_error("malformed rule"));
        }
        let obj = match Object::from_table(obj_word) {
            Some(o) => o,
            None if obj_word == "kind" => Object::Type, // backwards compatibility
            None => return Err(self.parse_error(&format!("unknown object {obj_word}"))),
        };
        let verb = match Verb::from_table(verb_word) {
            Some(v) => v,
            None => return Err(self.parse_error(&format!("unknown verb {verb_word}"))),
        };
        let (qarg, _) = expand(None, arg, &self.vars)?;
        let mut rule = Rule { obj, verb, arg: arg.to_string(), qarg, regex: None };
        self.validate_rule(&mut rule)?;
        Ok(rule)
    }

    /// `parserule`: reject verb/object combinations that make no
    /// sense, with the C messages, and compile `matches` arguments.
    fn validate_rule(&self, rule: &mut Rule) -> Result<(), String> {
        let bad = |v: &Verb, o: &Object| {
            self.parse_error(&format!("{} not valid verb for object {}", v.name(), o.name()))
        };
        match rule.obj {
            Object::Plumb => {
                if !matches!(rule.verb, Verb::Client | Verb::Start | Verb::To) {
                    return Err(bad(&rule.verb, &rule.obj));
                }
            }
            _ => {
                if matches!(rule.verb, Verb::Client | Verb::Start | Verb::To) {
                    return Err(bad(&rule.verb, &rule.obj));
                }
                if rule.obj != Object::Attr && matches!(rule.verb, Verb::Add | Verb::Delete) {
                    return Err(bad(&rule.verb, &rule.obj));
                }
                if rule.verb == Verb::Matches {
                    rule.regex =
                        Some(Regex::compile(&rule.qarg).map_err(|e| self.parse_error(&e))?);
                }
            }
        }
        Ok(())
    }

    /// Assemble one ruleset. `Ok(None)` means end of input; a chunk
    /// of only `plumb to` lines declares ports and keeps reading.
    fn read_ruleset(&mut self) -> Result<Option<Ruleset>, String> {
        loop {
            let mut pat: Vec<Rule> = Vec::new();
            let mut act: Vec<Rule> = Vec::new();
            let mut port: Option<String> = None;
            let mut ncmd = 0usize;
            let mut inrule = false;
            let mut eof = false;
            loop {
                match self.read_rule()? {
                    Read::Eof => {
                        eof = true;
                        break;
                    }
                    Read::Boundary => {
                        if inrule {
                            break;
                        }
                    }
                    Read::Rule(rule) => {
                        inrule = true;
                        match rule.obj {
                            Object::Plumb => {
                                if rule.verb == Verb::To {
                                    if !pat.is_empty() && port.is_some() {
                                        return Err(self.parse_error("too many ports"));
                                    }
                                    if BAD_PORTS.contains(&rule.qarg.as_str()) {
                                        return Err(self.parse_error(&format!(
                                            "illegal port name {}",
                                            rule.qarg
                                        )));
                                    }
                                    port = Some(rule.qarg.clone());
                                } else {
                                    ncmd += 1;
                                }
                                act.push(rule);
                            }
                            _ => pat.push(rule),
                        }
                    }
                }
            }
            if ncmd > 1 {
                return Err(self.parse_error("ruleset has more than one client or start action"));
            }
            if !pat.is_empty() && !act.is_empty() {
                return Ok(Some(Ruleset { pat, act, port }));
            }
            if pat.is_empty() && act.is_empty() {
                if eof {
                    return Ok(None);
                }
                continue;
            }
            if act.is_empty() || port.is_none() {
                return Err(self.parse_error("ruleset must have patterns and actions"));
            }
            // a bare port declaration: every action must be `plumb to`
            for a in &act {
                if a.verb != Verb::To {
                    return Err(self.parse_error("ruleset must have actions"));
                }
            }
            for a in &act {
                self.add_port(&a.qarg);
            }
        }
    }

    /// Register a port; a no-op when it exists or exceeds the dirtab
    /// capacity (`addport`).
    pub fn add_port(&mut self, port: &str) {
        if port.is_empty() || self.ports.iter().any(|p| p == port) {
            return;
        }
        if self.ports.len() >= MAX_PORTS {
            eprintln!("plumber: too many ports; max {MAX_PORTS}");
            return;
        }
        self.ports.push(port.to_string());
    }

    /// Add a port for every ruleset destination (`makeports`).
    pub fn make_ports(&mut self) {
        let names: Vec<String> = self.rulesets.iter().filter_map(|r| r.port.clone()).collect();
        for p in names {
            self.add_port(&p);
        }
    }

    /// The `plumb/rules` view: variables, ports, then every ruleset
    /// with its raw arguments (`printrules` / `printpat` / `printvar`).
    pub fn print_rules(&self) -> String {
        let mut out = String::new();
        for v in &self.vars {
            let _ =
                std::fmt::Write::write_fmt(&mut out, format_args!("{}={}\n\n", v.name, v.value));
        }
        for p in &self.ports {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("plumb to {p}\n"));
        }
        out.push('\n');
        for rs in &self.rulesets {
            for r in rs.pat.iter().chain(rs.act.iter()) {
                let _ = std::fmt::Write::write_fmt(
                    &mut out,
                    format_args!("{}\t{}\t{}\n", r.obj.name(), r.verb.name(), r.arg),
                );
            }
            out.push('\n');
        }
        out
    }

    /// Append text to the `plumb/rules` write side (`writerules`):
    /// accumulate, parse every complete ruleset (the C heuristic: a
    /// blank line ends a ruleset), keep the remainder pending. A
    /// parse error is returned and the failing ruleset stays pending
    /// so later writes can complete it; rules parsed before the
    /// error remain in effect. (The C original could re-append
    /// earlier rulesets after an error because its buffer rolled
    /// back wholesale; keeping the parsed prefix avoids duplicates.)
    pub fn write_rules(&mut self, text: &str) -> Result<(), String> {
        self.pending.push_str(text);
        self.parse_pending(false)
    }

    /// Parse whatever is still pending - the flush a close of the
    /// rules file performs (`writerules(nil, 0)`).
    pub fn flush_rules(&mut self) -> Result<(), String> {
        let r = self.parse_pending(true);
        self.pending.clear();
        r
    }

    /// Wipe the rule set (opening `plumb/rules` with OTRUNC). Ports
    /// are never deleted, per `plumber(4)`.
    pub fn clear_rules(&mut self) {
        self.rulesets.clear();
        self.pending.clear();
    }

    fn parse_pending(&mut self, all: bool) -> Result<(), String> {
        let chars: Vec<char> = self.pending.chars().collect();
        let limit = if all {
            chars.len()
        } else {
            let mut last = None;
            for i in 0..chars.len().saturating_sub(1) {
                if chars[i] == '\n' && chars[i + 1] == '\n' {
                    last = Some(i + 2);
                }
            }
            match last {
                Some(end) => end,
                None => return Ok(()),
            }
        };
        let head: String = chars[..limit].iter().collect();
        self.push_input("<rules input>", &head, false)?;
        let mut failed_at: Option<usize> = None;
        let mut err: Option<String> = None;
        loop {
            let start = self.inputs.last().map(|f| f.pos).unwrap_or(0);
            match self.read_ruleset() {
                Ok(Some(rs)) => self.rulesets.push(rs),
                Ok(None) => break,
                Err(e) => {
                    failed_at = Some(start);
                    err = Some(e);
                    break;
                }
            }
        }
        self.inputs.pop();
        let tail_at = failed_at.unwrap_or(limit);
        self.pending = chars[tail_at..].iter().collect();
        self.make_ports();
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

enum Read {
    Eof,
    Boundary,
    Rule(Rule),
}

/// The `$` machinery of rules.c: expand one blank-terminated token,
/// processing single quotes and `$` references.
///
/// Returns the expansion and the number of characters consumed (the
/// C `ends` pointer). Expansion is capped at 4096 bytes like the C
/// `ebuf`; a longer result is the parse error `expanded string too
/// long`, and an unterminated quote is `runaway quoted string
/// literal`.
///
/// With no `Exec` (parse time) only user variables expand - `$data`
/// and `$1` stay literal in `qarg` until a message arrives. With an
/// `Exec` the message fields shadow user variables: `$src $dst $dir
/// $attr $data $file $type $wdir` and the captures `$0..$99`.
pub fn expand(exec: Option<&Exec>, s: &str, vars: &[Var]) -> Result<(String, usize), String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut quoting = false;
    let mut i = 0usize;
    loop {
        let input_left = i < chars.len() && (quoting || (chars[i] != ' ' && chars[i] != '\t'));
        if !input_left || out.len() > 4095 {
            if input_left {
                return Err("expanded string too long".to_string());
            }
            if quoting {
                return Err("runaway quoted string literal".to_string());
            }
            return Ok((out, i));
        }
        let c = chars[i];
        if c == '\'' {
            i += 1;
            if !quoting {
                quoting = true;
            } else if chars.get(i) == Some(&'\'') {
                out.push('\'');
                i += 1;
            } else {
                quoting = false;
            }
            continue;
        }
        if !quoting && c == '$' {
            i += 1;
            match dollar(exec, &chars, i, vars) {
                Some((val, namelen)) => {
                    if out.len() + val.len() > 4095 {
                        return Err("expanded string too long".to_string());
                    }
                    out.push_str(&val);
                    i += namelen;
                }
                None => out.push('$'),
            }
            continue;
        }
        out.push(c);
        i += 1;
    }
}

/// Resolve one `$` reference; `None` means "emit a literal `$` and
/// copy the name as ordinary text" - the C behavior for unknown
/// variables. The `wdir` lookup reproduces the historic
/// `memcmp(s, "wdir", 3)` against a 4-character name: any name
/// starting `wdi` of length 4 resolves to the working directory.
fn dollar(
    exec: Option<&Exec>,
    chars: &[char],
    pos: usize,
    vars: &[Var],
) -> Option<(String, usize)> {
    let rest = &chars[pos..];
    if let Some(e) = exec {
        if let Some(&d) = rest.first() {
            if d.is_ascii_digit() {
                let mut n = 0usize;
                while n < rest.len() && rest[n].is_ascii_digit() {
                    n += 1;
                }
                let m: usize = rest[..n].iter().collect::<String>().parse().unwrap_or(NMATCHSUBEXP);
                if m >= NMATCHSUBEXP {
                    return Some((String::new(), n));
                }
                let val = e.matches.get(m).cloned().flatten().unwrap_or_default();
                return Some((val, n));
            }
        }
        let mut n = 0usize;
        if rest.first().is_some_and(|&c| c.is_ascii_alphabetic() || c == '_') {
            while n < rest.len() && (rest[n].is_ascii_alphanumeric() || rest[n] == '_') {
                n += 1;
            }
        }
        if n == 0 {
            return None;
        }
        let name: String = rest[..n].iter().collect();
        if n == 3 {
            if name == "src" {
                return Some((e.msg.src.clone(), n));
            }
            if name == "dst" {
                return Some((e.msg.dst.clone(), n));
            }
            if name == "dir" {
                return Some((filename(e), n));
            }
        }
        if n == 4 {
            if name == "attr" {
                return Some((pack_attr(&e.msg.attr), n));
            }
            if name == "data" {
                return Some((e.msg.data_str(), n));
            }
            if name == "file" {
                return Some((filename_for(e, e.file.clone()), n));
            }
            if name == "type" {
                return Some((e.msg.typ.clone(), n));
            }
            if name.starts_with("wdi") {
                return Some((e.msg.wdir.clone(), n));
            }
        }
    } else {
        // parse time: no message, no captures - digits and field
        // names stay literal
        if rest.first().is_some_and(|c| c.is_ascii_digit()) {
            return None;
        }
    }
    let mut n = 0usize;
    if rest.first().is_some_and(|&c| c.is_ascii_alphabetic() || c == '_') {
        while n < rest.len() && (rest[n].is_ascii_alphanumeric() || rest[n] == '_') {
            n += 1;
        }
    }
    if n == 0 {
        return None;
    }
    let name: String = rest[..n].iter().collect();
    let v = vars.iter().find(|v| v.name == name)?;
    Some((v.qvalue.clone(), n))
}

/// `$dir` / `$file` resolution (`filename` in rules.c): an explicitly
/// matched file wins, otherwise the data if absolute or no working
/// directory is known, otherwise wdir/data.
fn filename(e: &Exec) -> String {
    filename_for(e, e.dir.clone())
}

fn filename_for(e: &Exec, name: Option<String>) -> String {
    if let Some(n) = name.filter(|n| !n.is_empty()) {
        return cleanname(&n);
    }
    let data = e.msg.data_str();
    if data.starts_with('/') || e.msg.wdir.is_empty() {
        cleanname(&data)
    } else {
        cleanname(&format!("{}/{}", e.msg.wdir, data))
    }
}

/// Split a command argument into `$`-expanded words (`buildargv`).
pub fn buildargv(arg: &str, exec: &Exec, vars: &[Var]) -> Result<Vec<String>, String> {
    let chars: Vec<char> = arg.chars().collect();
    let mut argv = Vec::new();
    let mut i = 0usize;
    loop {
        while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
            i += 1;
        }
        if i >= chars.len() {
            return Ok(argv);
        }
        let (word, used) = expand(Some(exec), &chars[i..].iter().collect::<String>(), vars)?;
        argv.push(word);
        i += used;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> (Vec<Ruleset>, Vec<String>) {
        let mut p = RulesParser::new();
        p.parse_text("test", text).unwrap();
        (p.rulesets.clone(), p.ports.clone())
    }

    fn parse_err(text: &str) -> String {
        let mut p = RulesParser::new();
        p.parse_text("test", text).unwrap_err()
    }

    #[test]
    fn basic_ruleset() {
        let (sets, ports) = parse("data matches '[a-zA-Z0-9_./]+'\nplumb to edit\n");
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].pat.len(), 1);
        assert_eq!(sets[0].act.len(), 1);
        assert_eq!(sets[0].port.as_deref(), Some("edit"));
        assert_eq!(ports, vec!["edit"]);
    }

    #[test]
    fn kind_is_type_backwards_compatible() {
        let (sets, _) = parse("kind is text\nplumb to show\n");
        assert_eq!(sets[0].pat[0].obj, Object::Type);
    }

    #[test]
    fn assignments_and_parse_time_expansion() {
        let mut p = RulesParser::new();
        p.parse_text("t", "editor = acme\nfoo=$editor/e\nplumb to edit\n").unwrap();
        assert_eq!(p.variable("editor"), Some("acme"));
        assert_eq!(p.variable("foo"), Some("acme/e"));
        // the raw value keeps the whole line
        assert_eq!(p.vars.iter().find(|v| v.name == "editor").unwrap().value, "acme");
    }

    #[test]
    fn unknown_variable_stays_literal_at_parse_time() {
        let (q, _) = expand(None, "$nosuch/x", &[]).unwrap();
        assert_eq!(q, "$nosuch/x");
        // captures and fields too
        let (q1, _) = expand(None, "$1", &[]).unwrap();
        assert_eq!(q1, "$1");
        let (qd, _) = expand(None, "$data", &[]).unwrap();
        assert_eq!(qd, "$data");
    }

    #[test]
    fn quoting_machines() {
        let (q, used) = expand(None, "'a b' c", &[]).unwrap();
        assert_eq!(q, "a b");
        // the consumed count stops AT the terminating blank, like the
        // C `ends` pointer
        assert_eq!(used, "'a b'".chars().count());
        let (q2, _) = expand(None, "'it''s'", &[]).unwrap();
        assert_eq!(q2, "it's");
        assert_eq!(expand(None, "'oops", &[]), Err("runaway quoted string literal".to_string()));
    }

    #[test]
    fn validation_errors_are_verbatim() {
        assert!(parse_err("data start x\n").contains("start not valid verb for object data"));
        assert!(parse_err("data add x\n").contains("add not valid verb for object data"));
        // `attr is` is not a parse error in the C original either: the
        // verb simply never matches (verbis has no attr case)
        assert!(parse_err("plumb is x\n").contains("is not valid verb for object plumb"));
        assert!(parse_err("nosuch is x\n").contains("unknown object nosuch"));
        assert!(parse_err("data nosuchverb x\n").contains("unknown verb nosuchverb"));
        assert!(parse_err("data is\n").contains("malformed rule"));
    }

    #[test]
    fn port_rules() {
        assert!(parse_err("plumb to send\n").contains("illegal port name send"));
        assert!(parse_err("plumb to .\n").contains("illegal port name ."));
        let (_, ports) = parse("plumb to a\nplumb to b\n");
        assert_eq!(ports, vec!["a", "b"]);
        assert!(parse_err("data is x\nplumb to a\nplumb to b\n").contains("too many ports"));
        let (sets, _) = parse("data is x\nplumb to one\n");
        assert_eq!(sets[0].port.as_deref(), Some("one"));
    }

    #[test]
    fn at_most_one_command_action() {
        assert!(parse_err("data is x\nplumb start a\nplumb client b\nplumb to p\n")
            .contains("more than one client or start action"));
        let (sets, _) = parse("data is x\nplumb start a\nplumb to p\n");
        assert_eq!(sets[0].act.len(), 2);
    }

    #[test]
    fn ruleset_must_have_both_sides() {
        assert!(parse_err("data is x\n").contains("ruleset must have patterns and actions"));
        // a command action without a port has nowhere to route
        assert!(parse_err("plumb client c\n").contains("ruleset must have patterns and actions"));
    }

    #[test]
    fn blank_lines_separate_rulesets() {
        let (sets, _) = parse("data is a\nplumb to p1\n\ndata is b\nplumb to p2\n");
        assert_eq!(sets.len(), 2);
        assert_eq!(sets[1].port.as_deref(), Some("p2"));
    }

    #[test]
    fn print_rules_shape() {
        let mut p = RulesParser::new();
        p.parse_text("t", "src=plumb\ndata matches 'x'\nplumb to edit\n").unwrap();
        p.make_ports();
        let out = p.print_rules();
        assert!(out.contains("src=plumb\n\n"));
        assert!(out.contains("plumb to edit\n"));
        assert!(out.contains("data\tmatches\t'x'\n"));
        assert!(out.contains("plumb\tto\tedit\n"));
    }

    #[test]
    fn dollar_fields_with_message() {
        use crate::msg::Plumbmsg;
        let mut m = Plumbmsg::new();
        m.src = "plumb".into();
        m.dst = "edit".into();
        m.wdir = "/w".into();
        m.typ = "text".into();
        m.data = b"/w/a b.txt".to_vec();
        let e = Exec::new(&m);
        let vars: Vec<Var> =
            vec![Var { name: "home".into(), value: "/root".into(), qvalue: "/root".into() }];
        let (q, _) = expand(Some(&e), "$dst:$type:$src:$home", &vars).unwrap();
        assert_eq!(q, "edit:text:plumb:/root");
        let (qd, _) = expand(Some(&e), "$data", &vars).unwrap();
        assert_eq!(qd, "/w/a b.txt");
        // $dir resolves wdir-relative data
        let (qdir, _) = expand(Some(&e), "$dir", &vars).unwrap();
        assert_eq!(qdir, "/w/a b.txt");
    }

    #[test]
    fn wdir_quirk_is_reproduced() {
        use crate::msg::Plumbmsg;
        let m = Plumbmsg::new();
        let e = Exec::new(&m);
        let (q, _) = expand(Some(&e), "$wdix", &[]).unwrap();
        // the C memcmp(s, "wdir", 3) accepts any 4-char name from "wdi"
        assert_eq!(q, "");
        assert!(e.msg.wdir.is_empty());
    }

    #[test]
    fn captures_expand_at_runtime() {
        use crate::msg::Plumbmsg;
        let mut m = Plumbmsg::new();
        m.data = b"/usr/src/x.rs".to_vec();
        let mut e = Exec::new(&m);
        e.matches[1] = Some("/usr/src/x.rs".into());
        let vars: Vec<Var> =
            vec![Var { name: "editor".into(), value: "acme".into(), qvalue: "acme".into() }];
        // expand is a one-token expander: the blank ends the token
        let (tok, _) = expand(Some(&e), "acme $1", &vars).unwrap();
        assert_eq!(tok, "acme");
        let (q, _) = expand(Some(&e), "$1", &vars).unwrap();
        assert_eq!(q, "/usr/src/x.rs");
        // out of range capture is the empty string
        let (q100, _) = expand(Some(&e), "[$100]", &vars).unwrap();
        assert_eq!(q100, "[]");
    }

    #[test]
    fn buildargv_splits_and_expands() {
        use crate::msg::Plumbmsg;
        let mut m = Plumbmsg::new();
        m.data = b"hello".to_vec();
        let mut e = Exec::new(&m);
        e.matches[1] = Some("hello".into());
        let argv = buildargv("run $1 --flag 'two words'", &e, &[]).unwrap();
        assert_eq!(argv, vec!["run", "hello", "--flag", "two words"]);
    }

    #[test]
    fn include_is_recursive() {
        // include of a missing file is an error naming the file
        let mut p = RulesParser::new();
        let err = p.parse_text("t", "include nosuchfile-xyz\n").unwrap_err();
        assert!(err.contains("can't open"), "got: {err}");
        // a malformed include line is rejected outright
        let mut p2 = RulesParser::new();
        let err2 = p2.parse_text("t", "include\n").unwrap_err();
        assert!(err2.contains("malformed include statement"));
    }

    #[test]
    fn include_depth_is_bounded() {
        // self-include through the depth guard: build a file that
        // includes itself
        let dir = std::env::temp_dir().join("plumber-selfinc");
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("self");
        std::fs::write(&f, "include self\n").unwrap();
        std::env::set_var("NAMIKAZE_PLUMB", &dir);
        let mut p = RulesParser::new();
        let err = p.parse_text("t", "include self\n").unwrap_err();
        std::env::remove_var("NAMIKAZE_PLUMB");
        assert!(err.contains("include stack too deep; max 10"), "got: {err}");
    }
}
