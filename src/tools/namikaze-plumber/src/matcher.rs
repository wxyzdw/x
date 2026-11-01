// SPDX-License-Identifier: MPL-2.0
//! Matching a plumb message against a ruleset: the Rust transcription
//! of `src/cmd/plumb/match.c`.
//!
//! The order is the whole story: a ruleset matches when every pattern
//! rule, applied in file order, holds - and pattern rules may rewrite
//! the message as they go (`set` mutates, `attr add` extends, a
//! `data matches` with a click captures the clicked region). The
//! first ruleset that matches wins; the plumber never tries the rest.
//!
//! One documented departure: a runtime expansion failure (a runaway
//! quote in a command argument, an over-long expansion) answers the
//! sender with an `Rerror`; the C original killed the whole plumber.

#![forbid(unsafe_code)]

use std::process::{Command, Stdio};

use crate::msg::{attr_lookup, Plumbmsg};
use crate::regex::{Caps, Regex, NMATCHSUBEXP};
use crate::rules::{buildargv, Object, Ruleset, Verb};

/// The state carried across the pattern rules of one matching
/// attempt (`Exec` in plumber.h).
#[derive(Debug, Clone)]
pub struct Exec {
    pub msg: Plumbmsg,
    /// `$0..$99`, the string value of each capture.
    pub matches: Vec<Option<String>>,
    /// Span of the click match, once taken.
    pub p0: i64,
    pub p1: i64,
    /// A click match happened: the `click` attribute must go.
    pub clearclick: bool,
    /// ...and the data must be rewritten to `$0`.
    pub setdata: bool,
    /// A `plumb client` matched: hold the message for the port.
    pub holdforclient: bool,
    /// `$file` / `$dir` - resolved by `isfile` / `isdir`.
    pub file: Option<String>,
    pub dir: Option<String>,
}

impl Exec {
    pub fn new(msg: &Plumbmsg) -> Exec {
        Exec {
            msg: msg.clone(),
            matches: vec![None; NMATCHSUBEXP],
            p0: -1,
            p1: -1,
            clearclick: false,
            setdata: false,
            holdforclient: false,
            file: None,
            dir: None,
        }
    }
}

impl Plumbmsg {
    /// The data as text for matching and `$data` expansion. Plumb
    /// messages are text in practice; arbitrary bytes are rendered
    /// lossily, exactly the data a rules author would see.
    pub fn data_str(&self) -> String {
        String::from_utf8_lossy(&self.data).into_owned()
    }
}

/// Plan 9 `cleanname`: lexical path cleaning - collapse `//`, remove
/// `.`, resolve `..` against what precedes, drop trailing slashes,
/// and return `.` for an empty relative result.
pub fn cleanname(path: &str) -> String {
    let abs = path.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for el in path.split('/') {
        match el {
            "" | "." => {}
            ".." => {
                if stack.last().is_some_and(|top| *top != "..") {
                    stack.pop();
                } else if !abs {
                    stack.push("..");
                }
            }
            f => stack.push(f),
        }
    }
    let joined = stack.join("/");
    match (abs, joined.is_empty()) {
        (true, true) => "/".to_string(),
        (true, false) => format!("/{joined}"),
        (false, true) => ".".to_string(),
        (false, false) => joined,
    }
}

/// `absolute(dir, file)`: join unless already absolute, then clean.
fn absolute(dir: &str, file: &str) -> String {
    if file.starts_with('/') {
        file.to_string()
    } else {
        cleanname(&format!("{dir}/{file}"))
    }
}

/// Match the message against the ruleset. `Ok(None)` is "no match";
/// `Some(exec)` carries the (possibly rewritten) message.
///
/// The message is mutated in place and every mutation survives a
/// failed ruleset: the C original rewrites `m` through the `Exec`
/// pointer and only frees the `Exec` on failure, so a later ruleset
/// matches against whatever earlier pattern rules did to it.
pub fn match_ruleset(
    msg: &mut Plumbmsg,
    rs: &Ruleset,
    vars: &[crate::rules::Var],
) -> Result<Option<Exec>, String> {
    if !msg.dst.is_empty() && rs.port.as_ref().is_some_and(|p| *p != msg.dst) {
        return Ok(None);
    }
    let mut e = Exec::new(msg);
    let mut matched = true;
    for rule in &rs.pat {
        if !match_pat(&mut e, rule, vars)? {
            matched = false;
            break;
        }
    }
    if matched {
        if let Some(port) = &rs.port {
            if e.msg.dst.is_empty() {
                e.msg.dst = port.clone();
            }
        }
        rewrite(&mut e);
    }
    *msg = e.msg.clone();
    Ok(if matched { Some(e) } else { None })
}

/// One pattern rule; true keeps the ruleset alive.
fn match_pat(
    e: &mut Exec,
    r: &crate::rules::Rule,
    vars: &[crate::rules::Var],
) -> Result<bool, String> {
    match r.verb {
        Verb::Add => verb_add(e, r, vars),
        Verb::Delete => verb_delete(e, r, vars),
        Verb::Is => Ok(verb_is(e, r)),
        Verb::Isdir => verb_isfile(e, r, vars, true),
        Verb::Isfile => verb_isfile(e, r, vars, false),
        Verb::Matches => Ok(verb_matches(e, r)),
        Verb::Set => verb_set(e, r, vars),
        _ => Ok(false),
    }
}

/// `obj is text` - string equality against the parse-time expanded
/// argument. Only the five text fields are implemented, as in C.
fn verb_is(e: &Exec, r: &crate::rules::Rule) -> bool {
    match r.obj {
        Object::Data => e.msg.data_str() == r.qarg,
        Object::Dst => e.msg.dst == r.qarg,
        Object::Type => e.msg.typ == r.qarg,
        Object::Wdir => e.msg.wdir == r.qarg,
        Object::Src => e.msg.src == r.qarg,
        _ => false,
    }
}

/// `obj matches pattern`. Every field but `data` must match the whole
/// field text; `data` matches the whole data unless the message
/// carries a `click` attribute, in which case the match must cover
/// the click position (and fixes it, as `p0`/`p1`).
fn verb_matches(e: &mut Exec, r: &crate::rules::Rule) -> bool {
    let re = match &r.regex {
        Some(re) => re.clone(),
        None => return false,
    };
    match r.obj {
        Object::Data => {
            let chars: Vec<char> = e.msg.data_str().chars().collect();
            match attr_lookup(&e.msg.attr, "click") {
                Some(click) => {
                    let click = click.parse::<usize>().unwrap_or(0);
                    let caps = match clickmatch(&re, &chars, click) {
                        Some(caps) => caps,
                        None => return false,
                    };
                    let (p0, p1) = caps.spans[0].unwrap();
                    let (p0, p1) = (p0 as i64, p1 as i64);
                    if e.p0 >= 0 && !(p0 == e.p0 && p1 == e.p1) {
                        return false;
                    }
                    e.clearclick = true;
                    e.setdata = true;
                    e.p0 = p0;
                    e.p1 = p1;
                    set_matches(&mut e.matches, &caps, &chars);
                    true
                }
                None => {
                    let text = e.msg.data_str();
                    full_match(&re, &text, e)
                }
            }
        }
        Object::Dst => {
            let text = e.msg.dst.clone();
            full_match(&re, &text, e)
        }
        Object::Type => {
            let text = e.msg.typ.clone();
            full_match(&re, &text, e)
        }
        Object::Wdir => {
            let text = e.msg.wdir.clone();
            full_match(&re, &text, e)
        }
        Object::Src => {
            let text = e.msg.src.clone();
            full_match(&re, &text, e)
        }
        _ => false,
    }
}

/// Whole-field match: a match exists and covers the entire text
/// (`rs[0].s.sp==alltext && rs[0].e.ep==alltext+ntext`).
fn full_match(re: &Regex, text: &str, e: &mut Exec) -> bool {
    match re.match_full(text) {
        Some(caps) => {
            let chars: Vec<char> = text.chars().collect();
            set_matches(&mut e.matches, &caps, &chars);
            true
        }
        None => false,
    }
}

fn set_matches(matches: &mut [Option<String>], caps: &Caps, chars: &[char]) {
    for i in 0..NMATCHSUBEXP {
        *matches.get_mut(i).unwrap() = match caps.spans.get(i).copied().flatten() {
            Some((a, b)) if a <= b => Some(chars[a..b].iter().collect()),
            _ => None,
        };
    }
}

/// The click matcher. The click names a character position; the match
/// must begin at or before it and end at or after it. The C loop
/// tries every start offset up to the click count inclusive - here in
/// consistent character space, which agrees with the C for ASCII and
/// with the manual for UTF-8.
fn clickmatch(re: &Regex, chars: &[char], click: usize) -> Option<Caps> {
    let clickp = click.min(chars.len());
    for start in 0..=click.min(chars.len()) {
        if let Some(caps) = re.find_at(chars, start) {
            if let Some((sp, ep)) = caps.spans[0] {
                if sp <= clickp && clickp <= ep {
                    return Some(caps);
                }
            }
        }
    }
    None
}

/// `arg isdir path` / `arg isfile path`, and the data/wdir spellings.
/// `isdir` requires a directory; `isfile` requires an existing
/// non-directory. The resolved path becomes `$dir` / `$file`.
fn verb_isfile(
    e: &mut Exec,
    r: &crate::rules::Rule,
    vars: &[crate::rules::Var],
    want_dir: bool,
) -> Result<bool, String> {
    let (obj, raw) = match r.obj {
        Object::Arg => (Object::Arg, r.arg.clone()),
        Object::Data => (Object::Data, e.msg.data_str()),
        Object::Wdir => (Object::Wdir, e.msg.wdir.clone()),
        _ => return Ok(false),
    };
    let text = match obj {
        Object::Arg => expand_runtime(r, e, vars)?,
        _ => raw,
    };
    let file = absolute(&e.msg.wdir, &text);
    let meta = match std::fs::metadata(&file) {
        Ok(m) => m,
        Err(_) => return Ok(false),
    };
    let is_dir = meta.is_dir();
    if is_dir != want_dir {
        return Ok(false);
    }
    if want_dir {
        e.dir = Some(file);
    } else {
        e.file = Some(file);
    }
    Ok(true)
}

/// `obj set text` - rewrite the field with the runtime-expanded
/// argument; always "matches" (it is a condition with side effects,
/// exactly as in C).
fn verb_set(
    e: &mut Exec,
    r: &crate::rules::Rule,
    vars: &[crate::rules::Var],
) -> Result<bool, String> {
    let new = expand_runtime(r, e, vars)?;
    match r.obj {
        Object::Data => {
            e.msg.data = new.into_bytes();
            e.p0 = -1;
            e.p1 = -1;
            e.setdata = false;
        }
        Object::Dst => e.msg.dst = new,
        Object::Type => e.msg.typ = new,
        Object::Wdir => e.msg.wdir = new,
        Object::Src => e.msg.src = new,
        _ => return Ok(false),
    }
    Ok(true)
}

/// `attr add name=value...` - append attributes; always matches.
fn verb_add(
    e: &mut Exec,
    r: &crate::rules::Rule,
    vars: &[crate::rules::Var],
) -> Result<bool, String> {
    if r.obj != Object::Attr {
        return Ok(false);
    }
    let text = expand_runtime(r, e, vars)?;
    for a in crate::msg::unpack_attr(&text) {
        e.msg.attr.push(a);
    }
    Ok(true)
}

/// `attr delete name` - true when the attribute existed and went.
fn verb_delete(
    e: &mut Exec,
    r: &crate::rules::Rule,
    vars: &[crate::rules::Var],
) -> Result<bool, String> {
    if r.obj != Object::Attr {
        return Ok(false);
    }
    let name = expand_runtime(r, e, vars)?;
    if attr_lookup(&e.msg.attr, &name).is_none() {
        return Ok(false);
    }
    e.msg.del_attr(&name);
    Ok(true)
}

/// Runtime `$` expansion of a rule argument. The C plumber dies on a
/// failure here; this port answers the sender with an error instead
/// (documented departure).
fn expand_runtime(
    r: &crate::rules::Rule,
    e: &Exec,
    vars: &[crate::rules::Var],
) -> Result<String, String> {
    let (expanded, _) = crate::rules::expand(Some(e), &r.arg, vars)?;
    Ok(expanded)
}

/// Post-match message fixup (`rewrite`): when a click was consumed,
/// drop the `click` attribute and, if the rule asked for it, rewrite
/// the data to `$0` (the clicked region).
fn rewrite(e: &mut Exec) {
    if !e.clearclick {
        return;
    }
    e.msg.del_attr("click");
    if e.setdata {
        let vars: Vec<crate::rules::Var> = Vec::new();
        if let Ok((data, _)) = crate::rules::expand(Some(e), "$0", &vars) {
            e.msg.data = data.into_bytes();
        }
    }
}

/// What to do when no client listens on the destination port
/// (`startup`): run the `plumb start` command, or hold the message
/// for a `plumb client` rule until the port opens.
#[derive(Debug)]
pub enum Action {
    /// argv, ready to spawn.
    Start(Vec<String>),
    /// hold the message for the port.
    Client,
}

/// Decide the action for a matched message whose port has no
/// listeners. `rs == nil` in C falls straight through to
/// "no start action for plumb message".
pub fn find_action(
    rs: Option<&Ruleset>,
    e: &mut Exec,
    vars: &[crate::rules::Var],
) -> Result<Action, String> {
    let rs = match rs {
        Some(rs) => rs,
        None => return Err("no start action for plumb message".to_string()),
    };
    for act in &rs.act {
        match act.verb {
            Verb::Start => {
                let argv = buildargv(&act.arg, e, vars)?;
                if argv.first().map_or(true, String::is_empty) {
                    return Err("empty argument list".to_string());
                }
                return Ok(Action::Start(argv));
            }
            Verb::Client => {
                if e.msg.dst.is_empty() {
                    return Err("no port for \"client rule\"".to_string());
                }
                e.holdforclient = true;
                return Ok(Action::Client);
            }
            _ => {}
        }
    }
    Err("no start action for plumb message".to_string())
}

/// Run a start command the way `execproc` wires the fds: stdin from
/// /dev/null, stdout and stderr inherited. A failed exec exits the C
/// helper thread silently; a failed spawn is ignored the same way.
pub fn perform(action: Action) {
    if let Action::Start(argv) = action {
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
        let _ = cmd.spawn();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::Attr;
    use crate::rules::RulesParser;

    fn parse(text: &str) -> Vec<Ruleset> {
        let mut p = RulesParser::new();
        p.parse_text("t", text).unwrap();
        p.rulesets.clone()
    }

    fn m(dst: &str, data: &str) -> Plumbmsg {
        let mut msg = Plumbmsg::new();
        msg.src = "plumb".into();
        msg.dst = dst.into();
        msg.wdir = "/tmp".into();
        msg.typ = "text".into();
        msg.data = data.as_bytes().to_vec();
        msg
    }

    fn vars() -> Vec<crate::rules::Var> {
        Vec::new()
    }

    #[test]
    fn matches_routes_by_data_pattern() {
        let rs = &parse("data matches '[a-zA-Z0-9_./]+'\nplumb to edit\n")[0];
        let e = match_ruleset(&mut m("", "/usr/src/x.rs"), rs, &vars()).unwrap().unwrap();
        assert_eq!(e.msg.dst, "edit");
        assert_eq!(e.matches[0].as_deref(), Some("/usr/src/x.rs"));
    }

    #[test]
    fn matches_must_cover_the_whole_field() {
        let rs = &parse("dst matches 'ed'\nplumb to x\n")[0];
        assert!(match_ruleset(&mut m("edit", "d"), rs, &vars()).unwrap().is_none());
        let rs2 = &parse("dst matches 'ed.*'\nplumb to edit\n")[0];
        assert!(match_ruleset(&mut m("edit", "d"), rs2, &vars()).unwrap().is_some());
    }

    #[test]
    fn explicit_dst_scopes_the_ruleset() {
        let rs = &parse("data matches '.*'\nplumb to edit\n")[0];
        assert!(match_ruleset(&mut m("other", "d"), rs, &vars()).unwrap().is_none());
        assert!(match_ruleset(&mut m("edit", "d"), rs, &vars()).unwrap().is_some());
        // and a ruleset match fills in an empty destination
        let e = match_ruleset(&mut m("", "d"), rs, &vars()).unwrap().unwrap();
        assert_eq!(e.msg.dst, "edit");
    }

    #[test]
    fn click_match_captures_region_and_rewrites_data() {
        let rs = &parse("data matches '[a-zA-Z0-9_]+'\nplumb to edit\n")[0];
        let mut msg = m("", "word one WORD2 three");
        msg.add_attr("click", "11");
        let e = match_ruleset(&mut msg, rs, &vars()).unwrap().unwrap();
        assert!(e.clearclick && e.setdata);
        assert_eq!(e.p0, 9);
        assert_eq!(e.p1, 14);
        assert_eq!(e.msg.data_str(), "WORD2");
        assert!(e.msg.attr("click").is_none());
    }

    #[test]
    fn click_must_lie_inside_the_match() {
        let rs = &parse("data matches 'one'\nplumb to edit\n")[0];
        let mut msg = m("", "one two");
        msg.add_attr("click", "5");
        assert!(match_ruleset(&mut msg, rs, &vars()).unwrap().is_none());
    }

    #[test]
    fn is_compares_parse_time_expanded_arg() {
        let rs = &parse("data is 'a b'\nplumb to x\n")[0];
        assert!(match_ruleset(&mut m("", "a b"), rs, &vars()).unwrap().is_some());
        assert!(match_ruleset(&mut m("", "ab"), rs, &vars()).unwrap().is_none());
    }

    #[test]
    fn set_rewrites_fields_and_always_matches() {
        let rs = &parse("data matches '(.*)'\ndata set [x]\ndst set other\nplumb to other\n")[0];
        let e = match_ruleset(&mut m("", "orig"), rs, &vars()).unwrap().unwrap();
        assert_eq!(e.msg.data_str(), "[x]");
        assert_eq!(e.msg.dst, "other");
    }

    #[test]
    fn attr_add_delete() {
        let rs = &parse("data matches '.*'\nattr add flag=yes\nattr delete stale\nplumb to p\n")[0];
        let mut msg = m("", "d");
        msg.add_attr("stale", "old");
        let e = match_ruleset(&mut msg, rs, &vars()).unwrap().unwrap();
        assert_eq!(e.msg.attr("flag"), Some("yes"));
        assert_eq!(e.msg.attr("stale"), None);
        // deleting a missing attribute fails the rule
        let rs2 = &parse("data matches '.*'\nattr delete nope\nplumb to p\n")[0];
        assert!(match_ruleset(&mut m("", "d"), rs2, &vars()).unwrap().is_none());
    }

    #[test]
    fn isfile_resolves_against_wdir() {
        let dir = std::env::temp_dir().join("plumber-isfile");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("somefile.txt");
        std::fs::write(&file, b"x").unwrap();
        let ds = dir.to_str().unwrap().to_string();
        let rs = &parse("data isfile 'plumber-isfile/somefile.txt'\nplumb to open\n")[0];
        let mut msg = m("", "somefile.txt");
        msg.wdir = ds.clone();
        let e = match_ruleset(&mut msg, rs, &vars()).unwrap().unwrap();
        assert_eq!(e.file, Some(file.to_str().unwrap().to_string()));
        // isdir against the directory itself
        let rs2 = &parse("data isdir '.'\nplumb to open\n")[0];
        let mut msg2 = m("", "plumber-isfile");
        msg2.wdir = std::env::temp_dir().to_str().unwrap().to_string();
        let e2 = match_ruleset(&mut msg2, rs2, &vars()).unwrap().unwrap();
        assert!(e2.dir.is_some());
    }

    #[test]
    fn first_matching_ruleset_wins() {
        let sets = parse("data is a\nplumb to first\n\ndata matches '.*'\nplumb to second\n");
        let e1 = match_ruleset(&mut m("", "a"), &sets[0], &vars()).unwrap().unwrap();
        assert_eq!(e1.msg.dst, "first");
        let e2 = match_ruleset(&mut m("", "a"), &sets[1], &vars()).unwrap().unwrap();
        assert_eq!(e2.msg.dst, "second");
    }

    #[test]
    fn cleanname_plan9_semantics() {
        assert_eq!(cleanname("/a/b/../c"), "/a/c");
        assert_eq!(cleanname("a/./b//"), "a/b");
        assert_eq!(cleanname("/../x"), "/x");
        assert_eq!(cleanname("a/b/../.."), ".");
        assert_eq!(cleanname(""), ".");
        assert_eq!(cleanname("/"), "/");
        assert_eq!(cleanname("../../../x"), "../../../x");
    }

    #[test]
    fn find_action_strings() {
        let mut e = Exec::new(&m("", "f.txt"));
        let p = RulesParser::new();
        let err = find_action(None, &mut e, &p.vars).unwrap_err();
        assert_eq!(err, "no start action for plumb message");
        let sets2 = parse("data matches '.*'\nplumb to p\n");
        let err2 = find_action(Some(&sets2[0]), &mut e, &p.vars).unwrap_err();
        assert_eq!(err2, "no start action for plumb message");
        // client without a destination has no port to hold on
        let sets3 = parse("data matches '.*'\nplumb client viewer\nplumb to p\n");
        let mut e3 = Exec::new(&m("", "f.txt"));
        let err3 = find_action(Some(&sets3[0]), &mut e3, &p.vars).unwrap_err();
        assert_eq!(err3, "no port for \"client rule\"");
        let mut e4 = Exec::new(&m("viewer", "f.txt"));
        match find_action(Some(&sets3[0]), &mut e4, &p.vars).unwrap() {
            Action::Client => assert!(e4.holdforclient),
            _ => panic!("expected client"),
        }
    }

    #[test]
    fn empty_start_argument_list_is_rejected() {
        let sets = parse("data matches '.*'\nplumb start ''\nplumb to p\n");
        let mut e = Exec::new(&m("", "x"));
        let p = RulesParser::new();
        let err = find_action(Some(&sets[0]), &mut e, &p.vars).unwrap_err();
        assert_eq!(err, "empty argument list");
    }

    #[test]
    fn runtime_expansion_error_is_reported() {
        // $data is literal at parse time and expands at runtime; three
        // copies of a 2000-byte data blow the 4096-byte expansion cap,
        // which answers the sender instead of killing the plumber
        let sets = parse("data matches '.*'\nattr add $data$data$data\nplumb to p\n");
        let big = "x".repeat(2000);
        let err = match_ruleset(&mut m("", &big), &sets[0], &vars()).unwrap_err();
        assert_eq!(err, "expanded string too long");
    }

    #[test]
    fn attrs_survive_matching() {
        let rs = &parse("data matches '.*'\nplumb to p\n")[0];
        let mut msg = m("", "d");
        msg.attr.push(Attr { name: "flag".into(), value: "1".into() });
        let e = match_ruleset(&mut msg, rs, &vars()).unwrap().unwrap();
        assert_eq!(e.msg.attr("flag"), Some("1"));
    }
}
