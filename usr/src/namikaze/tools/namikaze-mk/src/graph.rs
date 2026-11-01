// SPDX-License-Identifier: MPL-2.0
//! The build engine: dependency walk, meta-rule stem matching,
//! out-of-date decisions and recipe execution - the semantics of
//! Plan 9's mk(1), with every failure carrying the rule, the file and
//! the reason.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::SystemTime;

use crate::parse::Item;

/// A rule from the mkfile: targets, optional attributes, prereqs and
/// the tab-indented recipe.
#[derive(Debug, Clone)]
pub struct Rule {
    pub targets: Vec<String>,
    pub attrs: Vec<char>,
    pub prereqs: Vec<String>,
    pub recipe: Vec<String>,
    pub line: usize,
}

impl Rule {
    fn attr(&self, c: char) -> bool {
        self.attrs.contains(&c)
    }

    /// Is this a meta-rule (target contains % or &)?
    pub fn is_meta(&self) -> bool {
        self.targets.iter().any(|t| t.contains('%') || t.contains('&'))
    }
}

/// Every failure mode of a build, with full context.
#[derive(Debug, Clone)]
pub enum MkError {
    /// A mkfile line could not be understood.
    Parse { file: String, line: usize, msg: String },
    /// The dependency graph has a cycle; `chain` shows the whole loop.
    Cycle { chain: Vec<String> },
    /// Something must be built but no rule or file provides it.
    NoRule { target: String, needed_by: Option<String> },
    /// A recipe line failed; `line` is the rule line in its mkfile.
    Recipe { target: String, cmd: String, code: i32, line: usize },
    /// Filesystem trouble outside recipes.
    Io { what: String },
    /// A `$` reference that mk cannot interpret.
    Expansion(String),
}

impl fmt::Display for MkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MkError::Parse { file, line, msg } => write!(f, "{file}:{line}: {msg}"),
            MkError::Cycle { chain } => {
                write!(f, "dependency cycle: {}", chain.join(" -> "))
            }
            MkError::NoRule { target, needed_by } => match needed_by {
                Some(by) => write!(f, "no rule to make {target}, needed by {by}"),
                None => write!(f, "no rule to make {target}"),
            },
            MkError::Recipe { target, cmd, code, line } if *line > 0 => {
                write!(f, "mkfile line {line}: recipe for {target} failed with status {code}: {cmd}")
            }
            MkError::Recipe { target, cmd, code, .. } => {
                write!(f, "recipe for {target} failed with status {code}: {cmd}")
            }
            MkError::Io { what } => write!(f, "{what}"),
            MkError::Expansion(msg) => write!(f, "expansion error: {msg}"),
        }
    }
}

impl std::error::Error for MkError {}

/// The mk interpreter state.
pub struct Engine {
    pub vars: HashMap<String, Vec<String>>,
    rules: HashMap<String, Rule>,
    /// exact-rule targets in mkfile order; the first is the default goal
    order: Vec<String>,
    meta_rules: Vec<Rule>,
    pub dry_run: bool,
    pub force: bool,
    made: HashSet<String>,
    times: HashMap<String, SystemTime>,
}

fn file_time(path: &str) -> Option<SystemTime> {
    fs::metadata(path).ok()?.modified().ok()
}

impl Engine {
    /// An engine with the process environment imported, as mk does.
    pub fn new() -> Engine {
        let vars: HashMap<String, Vec<String>> = std::env::vars()
            .map(|(k, v)| (k, vec![v]))
            .collect();
        Engine {
            vars,
            rules: HashMap::new(),
            order: Vec::new(),
            meta_rules: Vec::new(),
            dry_run: false,
            force: false,
            made: HashSet::new(),
            times: HashMap::new(),
        }
    }

    /// Load parsed items: assignments become variables (values stay
    /// raw; expansion happens at use time), rules split into exact and
    /// meta rules.
    pub fn load(&mut self, items: &[Item]) -> Result<(), MkError> {
        for item in items {
            match item {
                Item::Assign { var, values } => {
                    self.vars.insert(var.clone(), values.clone());
                }
                Item::Rule { targets, attrs, prereqs, recipe, line } => {
                    let rule = Rule {
                        targets: targets.clone(),
                        attrs: attrs.clone(),
                        prereqs: prereqs.clone(),
                        recipe: recipe.clone(),
                        line: *line,
                    };
                    if rule.is_meta() {
                        self.meta_rules.push(rule);
                    } else {
                        for target in targets {
                            if !self.order.contains(target) {
                                self.order.push(target.clone());
                            }
                            if self.rules.contains_key(target) {
                                return Err(MkError::Parse {
                                    file: String::new(),
                                    line: *line,
                                    msg: format!("duplicate rule for target \"{target}\""),
                                });
                            }
                            self.rules.insert(target.clone(), rule.clone());
                        }
                    }
                }
                Item::Include { .. } => unreachable!("includes are resolved by the parser"),
            }
        }
        Ok(())
    }

    /// The first non-meta rule target in file order: mk's default goal.
    pub fn default_target(&self) -> Option<String> {
        self.order.first().cloned()
    }

    /// Expand `$name` sequences. Unknown variables are empty, as in
    /// mk; `context` holds the recipe-time variables ($target, $stem
    /// and friends) which shadow file variables.
    pub fn expand(&self, text: &str, context: &HashMap<String, String>) -> Result<String, MkError> {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::new();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] != '$' {
                out.push(chars[i]);
                i += 1;
                continue;
            }
            i += 1;
            if i >= chars.len() {
                return Err(MkError::Expansion("a bare '$' at the end of input".into()));
            }
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let name: String = chars[start..i].iter().collect();
            if name.is_empty() {
                return Err(MkError::Expansion(format!(
                    "a '$' not followed by a name in \"{text}\""
                )));
            }
            match context.get(&name) {
                Some(v) => out.push_str(v),
                None => match self.vars.get(&name) {
                    Some(values) => {
                        // one level of expansion for stored values
                        let joined = values.join(" ");
                        if joined.contains('$') {
                            let expanded = self.expand(&joined, context)?;
                            out.push_str(&expanded);
                        } else {
                            out.push_str(&joined);
                        }
                    }
                    None => {}
                },
            }
        }
        Ok(out)
    }

    /// Build a target (or verify it is up to date).
    pub fn build(
        &mut self,
        target: &str,
        needed_by: Option<&str>,
        chain: &mut Vec<String>,
    ) -> Result<(), MkError> {
        if chain.iter().any(|t| t == target) {
            let mut loop_chain = chain.clone();
            loop_chain.push(target.to_string());
            return Err(MkError::Cycle { chain: loop_chain });
        }
        if self.made.contains(target) {
            return Ok(());
        }
        chain.push(target.to_string());
        let outcome = self.build_inner(target, needed_by, chain);
        chain.pop();
        if outcome.is_ok() {
            self.made.insert(target.to_string());
        }
        outcome
    }

    fn build_inner(
        &mut self,
        target: &str,
        needed_by: Option<&str>,
        chain: &mut Vec<String>,
    ) -> Result<(), MkError> {
        // find the exact rule or a matching meta-rule
        let (rule, stem) = match self.rules.get(target) {
            Some(r) => (r.clone(), String::new()),
            None => match self.match_meta(target) {
                Some((r, stem)) => (r, stem),
                None => {
                    if file_time(target).is_some() {
                        // a plain file with no rule: a leaf
                        if let Some(t) = file_time(target) {
                            self.times.insert(target.to_string(), t);
                        }
                        return Ok(());
                    }
                    return Err(MkError::NoRule {
                        target: target.to_string(),
                        needed_by: needed_by.map(String::from),
                    });
                }
            },
        };

        // substitute % with the stem in the prereq names of meta-rules
        let prereqs: Vec<String> = if stem.is_empty() {
            rule.prereqs.clone()
        } else {
            rule.prereqs.iter().map(|p| p.replace('%', &stem)).collect()
        };

        // build the prereqs first, remembering who came out new
        let target_time = file_time(target);
        let mut newprereq: Vec<String> = Vec::new();
        for prereq in &prereqs {
            self.build(prereq, Some(target), chain)?;
            let pt = self
                .times
                .get(prereq)
                .copied()
                .or_else(|| file_time(prereq));
            match (pt, target_time) {
                (Some(pt), Some(tt)) if pt > tt => newprereq.push(prereq.clone()),
                (Some(_), None) => newprereq.push(prereq.clone()),
                _ => {}
            }
        }

        let virtual_rule = rule.attr('V');
        let out_of_date = virtual_rule
            || self.force
            || target_time.is_none()
            || !newprereq.is_empty();
        if !out_of_date {
            if let Some(t) = target_time {
                self.times.insert(target.to_string(), t);
            }
            return Ok(());
        }

        // recipe-time variables, shadowing file variables (mk(1))
        let mut context: HashMap<String, String> = HashMap::new();
        context.insert("target".into(), target.to_string());
        context.insert("prereq".into(), prereqs.join(" "));
        context.insert("newprereq".into(), newprereq.join(" "));
        context.insert("stem".into(), stem.clone());
        context.insert("nproc".into(), "0".into());
        let pid = std::process::id().to_string();
        context.insert("pid".into(), pid);

        if rule.recipe.is_empty() {
            // no recipe: the rule is a pure grouping; with N the file
            // time is updated, otherwise the target behaves virtually
            if rule.attr('N') {
                self.touch(target)?;
            }
            self.times.insert(target.to_string(), SystemTime::now());
            return Ok(());
        }

        for line in &rule.recipe {
            let expanded = self.expand(line, &context)?;
            if !rule.attr('Q') || self.dry_run {
                println!("{expanded}");
            }
            if self.dry_run {
                continue;
            }
            let shell = self
                .vars
                .get("MKSHELL")
                .and_then(|v| v.first().cloned())
                .unwrap_or_else(|| "/bin/sh".to_string());
            let status = Command::new(&shell)
                .arg("-c")
                .arg(&expanded)
                .status()
                .map_err(|e| MkError::Io {
                    what: format!("cannot run {shell} for {target}: {e}"),
                })?;
            let code = status.code().unwrap_or(if status.success() { 0 } else { 1 });
            if code != 0 && !rule.attr('E') {
                if rule.attr('D') {
                    let _ = fs::remove_file(target);
                }
                return Err(MkError::Recipe {
                    target: target.to_string(),
                    cmd: expanded,
                    code,
                    line: rule.line,
                });
            }
        }

        // record the new time: the file if the recipe made one, the
        // clock otherwise (virtual target)
        let time = file_time(target).unwrap_or_else(SystemTime::now);
        self.times.insert(target.to_string(), time);
        Ok(())
    }

    fn touch(&mut self, target: &str) -> Result<(), MkError> {
        if self.dry_run {
            return Ok(());
        }
        let path = Path::new(target);
        if path.exists() {
            let now = filetime_set_now(target);
            self.mark_time(target, now);
        } else {
            fs::write(target, b"").map_err(|e| {
                MkError::Io { what: format!("cannot create {target}: {e}") }
            })?;
        }
        Ok(())
    }

    fn mark_time(&mut self, target: &str, t: SystemTime) {
        self.times.insert(target.to_string(), t);
    }

    /// Match a target against the meta-rules in file order. `%` takes
    /// any stem, `&` takes a stem without '.' or '/'; the first match
    /// in file order wins.
    fn match_meta(&self, target: &str) -> Option<(Rule, String)> {
        for rule in &self.meta_rules {
            for pattern in &rule.targets {
                if let Some(stem) = meta_stem(pattern, target) {
                    return Some((rule.clone(), stem));
                }
            }
        }
        None
    }
}

/// The stem when `pattern` (A%B or A&B) matches `name`, else None.
fn meta_stem(pattern: &str, name: &str) -> Option<String> {
    let sep = if pattern.contains('%') {
        '%'
    } else if pattern.contains('&') {
        '&'
    } else {
        return None;
    };
    let pos = pattern.find(sep)?;
    let prefix = &pattern[..pos];
    let suffix = &pattern[pos + 1..];
    if name.len() < prefix.len() + suffix.len() || !name.starts_with(prefix) || !name.ends_with(suffix)
    {
        return None;
    }
    let stem = &name[prefix.len()..name.len() - suffix.len()];
    if stem.is_empty() {
        return None;
    }
    if sep == '&' && (stem.contains('.') || stem.contains('/')) {
        return None;
    }
    Some(stem.to_string())
}

/// Set the modified time of an existing file to now, portably: rewrite
/// one byte if the file is empty-safe (mk's N attr needs any change).
fn filetime_set_now(target: &str) -> SystemTime {
    // std has no set_mtime; append nothing but open+write a byte is
    // destructive. The honest portable trick: read and rewrite.
    if let Ok(meta) = fs::metadata(target) {
        if meta.is_file() {
            if let Ok(bytes) = fs::read(target) {
                if fs::write(target, &bytes).is_ok() {
                    if let Some(t) = file_time(target) {
                        return t;
                    }
                }
            }
        }
    }
    SystemTime::now()
}

impl Default for Engine {
    fn default() -> Engine {
        Engine::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_stem_matching_rules() {
        assert_eq!(meta_stem("%", "prog"), Some("prog".into()));
        assert_eq!(meta_stem("%.c", "hello.c"), Some("hello".into()));
        assert_eq!(meta_stem("%.c", ".c"), None, "an empty stem matches nothing");
        assert_eq!(meta_stem("%.c", "hello.o"), None);
        // & refuses dots and slashes
        assert_eq!(meta_stem("&.c", "hello.c"), Some("hello".into()));
        assert_eq!(meta_stem("&", "a.b"), None);
        assert_eq!(meta_stem("&", "a/b"), None);
        // % refuses nothing
        assert_eq!(meta_stem("%", "a.b/c"), Some("a.b/c".into()));
    }

    #[test]
    fn expansion_of_known_and_unknown_variables() {
        let mut e = Engine::new();
        e.vars.insert("CC".into(), vec!["8c".into()]);
        e.vars.insert("FLAGS".into(), vec!["-w".into(), "-F".into()]);
        let mut ctx = HashMap::new();
        ctx.insert("target".to_string(), "prog".to_string());
        assert_eq!(e.expand("$CC $FLAGS -o $target", &ctx).expect("expand"), "8c -w -F -o prog");
        assert_eq!(e.expand("$NOSUCH", &ctx).expect("expand"), "");
        let err = e.expand("$ name!", &ctx).expect_err("invalid name");
        assert!(err.to_string().contains("not followed by a name"), "got: {err}");
        // single level indirection
        e.vars.insert("WRAP".into(), vec!["via $CC".into()]);
        assert_eq!(e.expand("$WRAP", &ctx).expect("expand"), "via 8c");
    }
}
