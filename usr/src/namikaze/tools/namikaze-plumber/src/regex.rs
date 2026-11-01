// SPDX-License-Identifier: MPL-2.0
//! A Plan 9 style regular expression engine, the piece the plumber's
//! rules language is built on (`regexp(2)` semantics, as used by
//! `sys/src/cmd/plumber/match.c` through libregexp).
//!
//! Supported syntax is the Plan 9 set: literals, `.`, character
//! classes `[...]` with ranges and `^` negation, the anchors `^` and
//! `$`, greedy postfix operators `* + ?`, alternation `|` and
//! capturing groups `(...)`. There are no lazy quantifiers, no `\b`
//! and no backreferences - Plan 9 has none either.
//!
//! Matching is leftmost, and at a fixed start the overall match is
//! the longest one (the Thompson / Plan 9 tradition); subexpressions
//! follow the greedy derivation that produced it. `$0` is the whole
//! match, `$1..$99` the subexpressions, bounded by
//! [`NMATCHSUBEXP`] exactly like the plumber's own header (`plumber.h`
//! sets the bound to 100).
//!
//! Two deliberate departures from the C original, both documented in
//! the crate root: the engine works in characters (the C code mixed
//! byte offsets and character counts, which only agrees with the
//! manual for ASCII), and a step budget replaces the C stack-overflow
//! failure mode for pathological patterns.

#![forbid(unsafe_code)]

use std::fmt::Write as _;

/// Maximum number of capturing groups, `$0` through `$99`. The
/// plumber's `plumber.h` carries the same bound (`NMATCHSUBEXP = 100`).
pub const NMATCHSUBEXP: usize = 100;

/// Backtracking step budget. The C engine could smash its stack on a
/// pathological pattern; here a runaway search aborts with a parse
/// error instead of hanging the plumber.
const STEP_BUDGET: u64 = 2_000_000;

#[derive(Debug, Clone)]
enum Node {
    Empty,
    Char(char),
    Any,
    Class { negated: bool, ranges: Vec<(char, char)> },
    BeginText,
    EndText,
    Group { idx: usize, sub: Box<Node> },
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Repeat { sub: Box<Node>, min: u32, max: u32 },
}

const INF: u32 = u32::MAX;

/// Capture spans in character indices: entry `i` is the span of `$i`.
pub type Spans = Vec<Option<(usize, usize)>>;

/// The continuation of the backtracking matcher at one position.
type Cont<'c> = &'c mut dyn FnMut(usize, &mut Spans) -> bool;

/// A compiled regular expression.
#[derive(Debug, Clone)]
pub struct Regex {
    root: Node,
    ngroups: usize,
}

/// The capture spans of one match, in character indices.
/// `spans[0]` is the whole match, `spans[1..]` the groups.
#[derive(Debug, Clone)]
pub struct Caps {
    pub spans: Vec<Option<(usize, usize)>>,
}

impl Caps {
    /// The matched substring for capture `i`, or `""` when the group
    /// did not participate. This is what the rules language's `$n`
    /// expands to (the C `dollar()` returns the empty string for a
    /// missing group, never a nil pointer).
    pub fn group(&self, text: &[char], i: usize) -> String {
        match self.spans.get(i).copied().flatten() {
            Some((a, b)) if a <= b => text[a..b].iter().collect(),
            _ => String::new(),
        }
    }
}

struct Parser<'p> {
    src: &'p [char],
    pos: usize,
    ngroups: usize,
}

impl<'p> Parser<'p> {
    fn peek(&self) -> Option<char> {
        self.src.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn parse_alt(&mut self) -> Result<Node, String> {
        let mut branches = vec![self.parse_concat()?];
        while self.peek() == Some('|') {
            self.pos += 1;
            branches.push(self.parse_concat()?);
        }
        if branches.len() == 1 {
            Ok(branches.pop().unwrap_or(Node::Empty))
        } else {
            Ok(Node::Alt(branches))
        }
    }

    fn parse_concat(&mut self) -> Result<Node, String> {
        let mut items: Vec<Node> = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.parse_atom()?;
            let atom = self.parse_postfix(atom)?;
            items.push(atom);
        }
        match items.len() {
            0 => Ok(Node::Empty),
            1 => Ok(items.pop().unwrap_or(Node::Empty)),
            _ => Ok(Node::Concat(items)),
        }
    }

    fn parse_postfix(&mut self, atom: Node) -> Result<Node, String> {
        let (min, max) = match self.peek() {
            Some('*') => {
                self.pos += 1;
                (0, INF)
            }
            Some('+') => {
                self.pos += 1;
                (1, INF)
            }
            Some('?') => {
                self.pos += 1;
                (0, 1)
            }
            _ => return Ok(atom),
        };
        // Plan 9 has no chained quantifiers: a** is malformed.
        if matches!(self.peek(), Some('*' | '+' | '?')) {
            return Err("malformed repetition operator".to_string());
        }
        Ok(Node::Repeat { sub: Box::new(atom), min, max })
    }

    fn parse_atom(&mut self) -> Result<Node, String> {
        match self.bump() {
            None => Ok(Node::Empty),
            Some('(') => {
                self.ngroups += 1;
                if self.ngroups >= NMATCHSUBEXP {
                    return Err(format!("too many subexpressions; max {}", NMATCHSUBEXP - 1));
                }
                let idx = self.ngroups;
                let sub = self.parse_alt()?;
                if self.bump() != Some(')') {
                    return Err("unclosed group".to_string());
                }
                Ok(Node::Group { idx, sub: Box::new(sub) })
            }
            Some(')') => Err("unexpected )".to_string()),
            Some('[') => self.parse_class(),
            Some('.') => Ok(Node::Any),
            Some('^') => Ok(Node::BeginText),
            Some('$') => Ok(Node::EndText),
            Some('*' | '+' | '?') => Err("malformed repetition operator".to_string()),
            Some('\\') => self.parse_escape(),
            Some(c) => Ok(Node::Char(c)),
        }
    }

    fn parse_escape(&mut self) -> Result<Node, String> {
        match self.bump() {
            None => Err("trailing backslash".to_string()),
            Some('n') => Ok(Node::Char('\n')),
            Some('t') => Ok(Node::Char('\t')),
            Some('r') => Ok(Node::Char('\r')),
            // a backslash before any other character makes it literal;
            // Plan 9's regexp has no other escape sequences
            Some(c) => Ok(Node::Char(c)),
        }
    }

    fn parse_class(&mut self) -> Result<Node, String> {
        let negated = if self.peek() == Some('^') {
            self.pos += 1;
            true
        } else {
            false
        };
        let mut ranges: Vec<(char, char)> = Vec::new();
        let mut first = true;
        loop {
            let c = self.bump().ok_or("malformed character class")?;
            if c == ']' && !first {
                break;
            }
            first = false;
            let lo = if c == '\\' {
                match self.bump() {
                    None => return Err("malformed character class".to_string()),
                    Some('n') => '\n',
                    Some('t') => '\t',
                    Some('r') => '\r',
                    Some(e) => e,
                }
            } else {
                c
            };
            // range unless '-' is last or literal at the start
            if self.peek() == Some('-') && self.src.get(self.pos + 1) != Some(&']') {
                self.pos += 1; // consume '-'
                let hi_c = self.bump().ok_or("malformed character class")?;
                let hi = if hi_c == '\\' {
                    match self.bump() {
                        None => return Err("malformed character class".to_string()),
                        Some('n') => '\n',
                        Some('t') => '\t',
                        Some('r') => '\r',
                        Some(e) => e,
                    }
                } else {
                    hi_c
                };
                if hi < lo {
                    return Err(format!("bad character range {lo}-{hi}"));
                }
                ranges.push((lo, hi));
            } else {
                ranges.push((lo, lo));
            }
        }
        Ok(Node::Class { negated, ranges })
    }
}

impl Regex {
    /// Compile a Plan 9 regular expression.
    pub fn compile(pattern: &str) -> Result<Regex, String> {
        let src: Vec<char> = pattern.chars().collect();
        let mut p = Parser { src: &src, pos: 0, ngroups: 0 };
        let root = p.parse_alt()?;
        if p.pos != src.len() {
            return Err("unexpected )".to_string());
        }
        Ok(Regex { root, ngroups: p.ngroups })
    }

    /// Number of capturing groups (excluding the whole match).
    pub fn ngroups(&self) -> usize {
        self.ngroups
    }

    /// Search for the leftmost match starting at or after character
    /// offset `from`. Returns the longest match at that position.
    pub fn find_at(&self, text: &[char], from: usize) -> Option<Caps> {
        for start in from..=text.len() {
            let mut caps: Spans = vec![None; NMATCHSUBEXP];
            let steps = Steps::default();
            let mut best: Option<(usize, Spans)> = None;
            self.m(
                &self.root,
                text,
                start,
                &mut caps,
                &mut |end, caps_out| {
                    if best.as_ref().map_or(true, |(e, _)| end > *e) {
                        best = Some((end, caps_out.clone()));
                    }
                    false // never satisfied: keep exploring for a longer match
                },
                &steps,
            );
            if steps.exhausted() {
                return None;
            }
            if let Some((end, spans)) = best {
                let mut spans = spans;
                spans[0] = Some((start, end));
                return Some(Caps { spans });
            }
        }
        None
    }

    /// Leftmost-longest search anywhere in `text`.
    pub fn find(&self, text: &str) -> Option<Caps> {
        let chars: Vec<char> = text.chars().collect();
        self.find_at(&chars, 0)
    }

    /// A match that must cover the entire text, both ends anchored -
    /// the shape every non-`data` `matches` verb uses
    /// (`rs[0].s.sp==alltext && rs[0].e.ep==alltext+ntext` in match.c).
    pub fn match_full(&self, text: &str) -> Option<Caps> {
        let chars: Vec<char> = text.chars().collect();
        let caps = self.find_at(&chars, 0)?;
        if caps.spans[0] == Some((0, chars.len())) {
            Some(caps)
        } else {
            None
        }
    }

    fn m(
        &self,
        node: &Node,
        text: &[char],
        pos: usize,
        caps: &mut Spans,
        cont: Cont<'_>,
        steps: &Steps,
    ) -> bool {
        steps.tick();
        if steps.exhausted() {
            return false;
        }
        match node {
            Node::Empty => cont(pos, caps),
            Node::Char(c) => text.get(pos) == Some(c) && cont(pos + 1, caps),
            Node::Any => matches!(text.get(pos), Some(&ch) if ch != '\n') && cont(pos + 1, caps),
            Node::Class { negated, ranges } => {
                let hit = match text.get(pos) {
                    Some(&ch) => ranges.iter().any(|&(a, b)| ch >= a && ch <= b),
                    None => false,
                };
                let ok = match text.get(pos) {
                    Some(_) => hit != *negated,
                    None => false,
                };
                ok && cont(pos + 1, caps)
            }
            Node::BeginText => pos == 0 && cont(pos, caps),
            Node::EndText => pos == text.len() && cont(pos, caps),
            Node::Group { idx, sub } => {
                let idx = *idx;
                let saved = caps[idx];
                let matched = self.m(
                    sub,
                    text,
                    pos,
                    caps,
                    &mut |end, caps_inner| {
                        let prev = caps_inner[idx];
                        caps_inner[idx] = Some((pos, end));
                        if cont(end, caps_inner) {
                            true
                        } else {
                            caps_inner[idx] = prev;
                            false
                        }
                    },
                    steps,
                );
                if !matched {
                    caps[idx] = saved;
                }
                matched
            }
            Node::Concat(items) => self.m_concat(items, text, pos, caps, cont, steps),
            Node::Alt(branches) => {
                for b in branches {
                    if self.m(b, text, pos, caps, cont, steps) {
                        return true;
                    }
                }
                false
            }
            Node::Repeat { sub, min, max } => {
                self.m_repeat(sub, *min, *max, text, pos, 0, caps, cont, steps)
            }
        }
    }

    fn m_concat(
        &self,
        items: &[Node],
        text: &[char],
        pos: usize,
        caps: &mut Spans,
        cont: Cont<'_>,
        steps: &Steps,
    ) -> bool {
        match items.split_first() {
            None => cont(pos, caps),
            Some((head, rest)) => self.m(
                head,
                text,
                pos,
                caps,
                &mut |p2, caps_inner| self.m_concat(rest, text, p2, caps_inner, cont, steps),
                steps,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn m_repeat(
        &self,
        sub: &Node,
        min: u32,
        max: u32,
        text: &[char],
        pos: usize,
        count: u32,
        caps: &mut Spans,
        cont: Cont<'_>,
        steps: &Steps,
    ) -> bool {
        // greedy: explore taking one more repetition first; a
        // zero-width submatch would loop forever, so it ends the loop
        if count < max
            && self.m(
                sub,
                text,
                pos,
                caps,
                &mut |p2, caps_inner| {
                    p2 != pos
                        && self.m_repeat(
                            sub,
                            min,
                            max,
                            text,
                            p2,
                            count + 1,
                            caps_inner,
                            cont,
                            steps,
                        )
                },
                steps,
            )
        {
            return true;
        }
        // ...then fall back to the continuation at this position
        count >= min && cont(pos, caps)
    }
}

#[derive(Default)]
struct Steps {
    n: std::cell::Cell<u64>,
}

impl Steps {
    fn tick(&self) {
        self.n.set(self.n.get().saturating_add(1));
    }
    fn exhausted(&self) -> bool {
        self.n.get() > STEP_BUDGET
    }
}

/// Escape `value` the way the plumber quotes attribute values and
/// rule arguments: wrapped in single quotes, inner quotes doubled.
/// libplumb's `quote()` always quotes, even the empty string.
pub fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for c in value.chars() {
        if c == '\'' {
            out.push('\'');
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// Render a character class for error messages and tests.
pub fn show_spans(caps: &Caps, text: &[char]) -> String {
    let mut out = String::new();
    for (i, span) in caps.spans.iter().enumerate() {
        if let Some((a, b)) = span {
            let _ = write!(out, "${i}='{}' ", text[*a..*b].iter().collect::<String>());
        }
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans_of(pat: &str, text: &str) -> Vec<String> {
        let re = Regex::compile(pat).unwrap();
        let caps = re.find(text).unwrap();
        let chars: Vec<char> = text.chars().collect();
        (0..=re.ngroups()).map(|i| caps.group(&chars, i)).collect()
    }

    #[test]
    fn literals_and_any() {
        assert_eq!(spans_of("abc", "xxabcxx")[0], "abc");
        assert_eq!(spans_of("a.c", "abc")[0], "abc");
        assert!(Regex::compile("a.c").unwrap().find("a\nc").is_none());
    }

    #[test]
    fn classes() {
        assert_eq!(spans_of("[a-c]+", "zzabbazz")[0], "abba");
        assert_eq!(spans_of("[^a-z]+", "ab--cd")[0], "--");
        assert!(Regex::compile("[b-a]").is_err());
        assert_eq!(spans_of("[]]+", "a]]b")[0], "]]");
        assert_eq!(spans_of("[a-]+", "-a-")[0], "-a-");
    }

    #[test]
    fn alternation_and_groups() {
        assert_eq!(spans_of("(cat|dog)s?", "hotdogs")[0], "dogs");
        assert_eq!(spans_of("(cat|dog)s?", "hotdogs")[1], "dog");
        assert_eq!(spans_of("((a)(b))", "ab")[2], "a");
        assert_eq!(spans_of("((a)(b))", "ab")[3], "b");
    }

    #[test]
    fn greedy_quantifiers() {
        assert_eq!(spans_of("a*", "aaa")[0], "aaa");
        assert_eq!(spans_of("a?", "aaa")[0], "a");
        assert_eq!(spans_of("<.*>", "<a><b>")[0], "<a><b>");
        assert_eq!(spans_of("<[^>]*>", "<a><b>")[0], "<a>");
    }

    #[test]
    fn leftmost_longest() {
        // leftmost position wins over a longer later match
        assert_eq!(spans_of("x|yy", "xyy")[0], "x");
        // at a fixed position the overall match is the longest
        assert_eq!(spans_of("a|ab", "ab")[0], "ab");
    }

    #[test]
    fn anchors() {
        let re = Regex::compile("^ab$").unwrap();
        assert!(re.match_full("ab").is_some());
        assert!(re.match_full("xab").is_none());
        assert!(re.match_full("abc").is_none());
        let re2 = Regex::compile("^/usr").unwrap();
        assert!(re2.find("/usr/bin").is_some());
        assert!(re2.find("x/usr").is_none());
    }

    #[test]
    fn escaped_metacharacters() {
        assert_eq!(spans_of(r"\(a\)", "(a)")[0], "(a)");
        assert_eq!(spans_of(r"a\.b", "a.b")[0], "a.b");
        assert!(Regex::compile(r"a\.b").unwrap().find("axb").is_none());
    }

    #[test]
    fn plumber_file_pattern() {
        // the shape of the default plumbing rules
        let re = Regex::compile("[a-zA-Z0-9_\\-./]+").unwrap();
        let text = "= /usr/src/namikaze/README.md now";
        let caps = re.find(text).unwrap();
        let chars: Vec<char> = text.chars().collect();
        assert_eq!(caps.group(&chars, 0), "/usr/src/namikaze/README.md");
    }

    #[test]
    fn subexpression_bound() {
        // NMATCHSUBEXP = 100: the 100th group overflows
        let ninety_nine = "(a)".repeat(99);
        let hundred = "(a)".repeat(100);
        assert!(Regex::compile(&ninety_nine).is_ok());
        assert!(Regex::compile(&hundred).is_err());
    }

    #[test]
    fn malformed_patterns() {
        assert!(Regex::compile("(ab").is_err());
        assert!(Regex::compile("ab)").is_err());
        assert!(Regex::compile("a**").is_err());
        assert!(Regex::compile("[ab").is_err());
        assert!(Regex::compile("ab\\").is_err());
    }

    #[test]
    fn empty_repetition_guards() {
        // (a*)* must terminate
        assert_eq!(spans_of("(a*)*b", "aab")[0], "aab");
        assert_eq!(spans_of("(a?)*b", "ab")[0], "ab");
    }

    #[test]
    fn quote_doubles_inner_quotes() {
        assert_eq!(quote("a'b"), "'a''b'");
        assert_eq!(quote(""), "''");
    }
}
