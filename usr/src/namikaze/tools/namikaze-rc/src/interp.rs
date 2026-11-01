// SPDX-License-Identifier: MPL-2.0
//! The rc interpreter: term expansion (with the rc rules for lists,
//! concatenation and globbing), builtins, external commands through
//! PATH, pipelines, redirections and control flow.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::glob;
use crate::lex::{Part, RcError, Word};
use crate::parse::{Cond, Node, Redir, Term};

/// A runtime failure, separate from syntax errors.
#[derive(Debug)]
pub enum RunError {
    /// The child process or a file operation failed; the io detail is
    /// already folded into the message with Plan 9 wording.
    Io { what: String },
    /// A semantic problem with a message already fit for stderr.
    Msg(String),
    /// `exit [code]`
    Exit(i32),
}

impl RunError {
    /// A redirection or semantic problem, prefixed for clarity.
    fn msg(m: impl Into<String>) -> RunError {
        RunError::Msg(format!("redirection: {}", m.into()))
    }

    /// Plan 9 wording for the common io failure kinds.
    fn io(what: impl Into<String>, e: std::io::Error) -> RunError {
        let what = what.into();
        let text = match e.kind() {
            std::io::ErrorKind::NotFound => format!("{what}: file does not exist"),
            std::io::ErrorKind::PermissionDenied => format!("{what}: permission denied"),
            _ => format!("{what}: {e}"),
        };
        RunError::Io { what: text }
    }
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Io { what } => write!(f, "{what}"),
            RunError::Msg(m) => write!(f, "{m}"),
            RunError::Exit(code) => write!(f, "exit {code}"),
        }
    }
}

/// One character of an expanded word, with its quoting origin - only
/// unquoted-origin characters take part in filename matching.
#[derive(Clone)]
struct Ch {
    c: char,
    quoted: bool,
}

/// The interpreter state: variables, $ifs, $* and the status.
pub struct Interp {
    pub vars: HashMap<String, Vec<String>>,
    pub ifs: String,
    pub status: String,
    pub script_args: Vec<String>,
    /// Outcome of the most recent if condition, for `if not`.
    pub last_if_taken: Option<bool>,
    /// Cap on expansion products so `a*b ^ c*d` cannot explode memory.
    pub max_expansion: usize,
}

impl Interp {
    /// A fresh interpreter importing the process environment.
    pub fn new() -> Interp {
        let mut vars: HashMap<String, Vec<String>> = HashMap::new();
        for (k, v) in std::env::vars() {
            vars.insert(k, vec![v]);
        }
        vars.insert("ifs".into(), vec![" \t\n".into()]);
        vars.insert("status".into(), vec!["0".into()]);
        Interp {
            vars,
            ifs: " \t\n".into(),
            status: "0".into(),
            script_args: Vec::new(),
            last_if_taken: None,
            max_expansion: 100_000,
        }
    }

    /// Run one command tree; returns the exit status and updates
    /// `$status`.
    pub fn run(&mut self, node: &Node) -> Result<i32, RunError> {
        let code = self.run_inner(node)?;
        self.status = code.to_string();
        Ok(code)
    }

    fn run_inner(&mut self, node: &Node) -> Result<i32, RunError> {
        match node {
            Node::Simple { argv, redirs } => {
                let code = self.simple(argv, redirs)?;
                self.status = code.to_string();
                Ok(code)
            }
            Node::Seq(items) => {
                let mut last = 0;
                for item in items {
                    last = self.run_inner(item)?;
                }
                Ok(last)
            }
            Node::And(a, b) => {
                let left = self.run_inner(a)?;
                if left == 0 {
                    self.run_inner(b)
                } else {
                    Ok(left)
                }
            }
            Node::Or(a, b) => {
                let left = self.run_inner(a)?;
                if left != 0 {
                    self.run_inner(b)
                } else {
                    Ok(left)
                }
            }
            Node::Pipe(stages) => self.pipeline(stages),
            Node::Bg(inner) => self.background(inner),
            Node::Block(inner) => self.run_inner(inner),
            Node::If { cond, then, els } => {
                let taken = self.eval_cond(cond)?;
                self.last_if_taken = Some(taken);
                if taken {
                    self.run_inner(then)
                } else if let Some(els) = els {
                    self.run_inner(els)
                } else {
                    Ok(0)
                }
            }
            Node::IfNot(body) => {
                let run = self.last_if_taken == Some(false);
                self.last_if_taken = None;
                if run {
                    self.run_inner(body)
                } else {
                    Ok(0)
                }
            }
            Node::While { cond, body } => {
                let mut last = 0;
                while self.eval_cond(cond)? {
                    last = self.run_inner(body)?;
                }
                Ok(last)
            }
            Node::For { var, list, body } => {
                let values = self.expand_terms(list)?;
                let mut last = 0;
                for v in values {
                    self.vars.insert(var.clone(), vec![v]);
                    last = self.run_inner(body)?;
                }
                Ok(last)
            }
        }
    }

    fn eval_cond(&mut self, cond: &Cond) -> Result<bool, RunError> {
        match cond {
            Cond::Not(inner) => Ok(!self.eval_cond(inner)?),
            Cond::Match(subject, patterns) => {
                let subj = self.expand_terms(subject)?;
                let pats = self.expand_terms(patterns)?;
                Ok(subj.iter().any(|s| pats.iter().any(|p| glob::match_glob(p, s))))
            }
            Cond::Cmd(node) => Ok(self.run_inner(node)? == 0),
        }
    }

    // ---------------- expansion ----------------

    fn expand_terms(&mut self, terms: &[Term]) -> Result<Vec<String>, RunError> {
        let mut out = Vec::new();
        for t in terms {
            out.extend(self.expand_term(t)?);
        }
        Ok(out)
    }

    fn expand_term(&mut self, term: &Term) -> Result<Vec<String>, RunError> {
        let raw = self.expand_term_raw(term)?;
        // glob pass: only candidates with unquoted-origin metacharacters
        let mut out: Vec<String> = Vec::new();
        for chars in raw {
            let text: String = chars.iter().map(|c| c.c).collect();
            let globbable = chars.iter().any(|c| !c.quoted && matches!(c.c, '*' | '?' | '['));
            if globbable {
                out.extend(glob::expand(&text));
            } else {
                out.push(text);
            }
        }
        Ok(out)
    }

    fn expand_term_raw(&mut self, term: &Term) -> Result<Vec<Vec<Ch>>, RunError> {
        let raw: Vec<Vec<Ch>> = match term {
            Term::Lit(w) => vec![self.word_chars(w)],
            Term::Var(name) => self
                .lookup(name)
                .into_iter()
                .map(|s| s.chars().map(|c| Ch { c, quoted: false }).collect())
                .collect(),
            Term::VarSub(name, idx) => {
                let list = self.lookup(name);
                idx.iter()
                    .filter_map(|i| list.get(i - 1).cloned())
                    .map(|s| s.chars().map(|c| Ch { c, quoted: false }).collect())
                    .collect()
            }
            Term::Bq(node) => {
                let src = crate::unparse::node(node);
                let out = self.capture_block(&src)?;
                out.into_iter()
                    .map(|s| s.chars().map(|c| Ch { c, quoted: false }).collect())
                    .collect()
            }
            Term::List(items) => {
                // a list literal keeps its elements whole; only `*`
                // style globbing of the joined text would be wrong here
                let mut out: Vec<Vec<Ch>> = Vec::new();
                for item in items {
                    out.extend(self.expand_term_raw(item)?);
                }
                return Ok(out);
            }
            Term::VarCount(name) => {
                let n = self.lookup(name).len();
                vec![vec![Ch { c: std::char::from_digit(n as u32, 10).unwrap_or('0'), quoted: false }]]
            }
            Term::Concat(parts) => {
                let mut lists: Vec<Vec<Vec<Ch>>> = Vec::new();
                for p in parts {
                    lists.push(self.expand_term_raw(p)?);
                }
                // rc: concatenation with an empty list yields nothing
                if lists.iter().any(|l| l.is_empty()) {
                    return Ok(Vec::new());
                }
                let mut product: Vec<Vec<Ch>> = vec![Vec::new()];
                for list in lists {
                    let mut next = Vec::new();
                    for prefix in &product {
                        for elem in &list {
                            let mut joined = prefix.clone();
                            joined.extend(elem.iter().cloned());
                            next.push(joined);
                            if next.len() > self.max_expansion {
                                return Err(RunError::Msg(format!(
                                    "expansion exceeds {} elements; refusing to build it",
                                    self.max_expansion
                                )));
                            }
                        }
                    }
                    product = next;
                }
                product
            }
        };
        Ok(raw)
    }

    fn word_chars(&self, w: &Word) -> Vec<Ch> {
        w.0.iter()
            .flat_map(|p| match p {
                Part::Quoted(s) => s.chars().map(|c| Ch { c, quoted: true }).collect::<Vec<Ch>>(),
                Part::Unquoted(s) => {
                    s.chars().map(|c| Ch { c, quoted: false }).collect::<Vec<Ch>>()
                }
            })
            .collect()
    }

    fn lookup(&self, name: &str) -> Vec<String> {
        match name {
            "*" => self.script_args.clone(),
            "status" => vec![self.status.clone()],
            // $1 .. $9 are the elements of $* (rc(1))
            digit if digit.len() == 1 && digit.chars().all(|c| c.is_ascii_digit()) => {
                let idx: usize = digit.parse().unwrap_or(0);
                self.script_args.get(idx.wrapping_sub(1)).cloned().into_iter().collect()
            }
            _ => self.vars.get(name).cloned().unwrap_or_default(),
        }
    }

    /// Run a block in a child copy of this binary, capture stdout and
    /// split it on $ifs - the rc command substitution.
    fn capture_block(&mut self, src: &str) -> Result<Vec<String>, RunError> {
        let exe =
            std::env::current_exe().map_err(|e| RunError::io("cannot locate the rc binary", e))?;
        let mut cmd = Command::new(exe);
        cmd.arg("-c").arg(src).stdin(Stdio::null());
        // rc exports every variable; lists are space-joined for env
        for (k, v) in &self.vars {
            cmd.env(k, v.join(" "));
        }
        let out = cmd
            .output()
            .map_err(|e| RunError::io(format!("command substitution `{src}"), e))?;
        if !out.stderr.is_empty() {
            let mut err = std::io::stderr();
            let _ = err.write_all(&out.stderr);
            let _ = err.flush();
        }
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        Ok(text
            .split(|c: char| self.ifs.contains(c))
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect())
    }

    // ---------------- commands ----------------

    fn simple(&mut self, argv: &[Term], redirs: &[Redir]) -> Result<i32, RunError> {
        // rc(1): "any command may be preceded by a sequence of
        // assignments interspersed with redirections. The assignments
        // remain in effect until the end of the command, unless the
        // command is empty, in which case they are effective until
        // rescinded by later assignments."
        let mut k = 0;
        let mut assigned: Vec<(String, Option<Vec<String>>)> = Vec::new();
        while k < argv.len() {
            match &argv[k] {
                Term::Lit(w) => match assignment_name(w) {
                    Some(name) => {
                        k += 1;
                        let mut value = Vec::new();
                        if let Some((_, rest)) = w.text().split_once('=') {
                            if !rest.is_empty() {
                                value.push(rest.to_string());
                            }
                        }
                        // a parenthesized list is the whole value
                        if matches!(argv.get(k), Some(Term::List(_))) {
                            if let Some(Term::List(items)) = argv.get(k) {
                                value = self.expand_terms(items)?;
                            }
                            k += 1;
                        }
                        assigned.push((name, None));
                        self.set_var(&assigned.last().expect("just pushed").0, value);
                    }
                    None => break,
                },
                _ => break,
            }
        }
        if k == argv.len() {
            // stand-alone assignments persist
            return Ok(0);
        }
        // assignments before a command are scoped to that command
        let saved: Vec<(String, Option<Vec<String>>)> = assigned
            .iter()
            .map(|(name, _)| (name.clone(), self.vars.get(name).cloned()))
            .collect();
        // the values assigned above are the "new" ones; the saved ones
        // captured them already, so re-apply is unnecessary
        let result = {
            let words = self.expand_terms(&argv[k..])?;
            if words.is_empty() {
                Ok(0)
            } else {
                let code = self.dispatch(&words, redirs)?;
                self.status = code.to_string();
                Ok(code)
            }
        };
        for (name, old) in saved {
            match old {
                Some(v) => {
                    self.vars.insert(name, v);
                }
                None => {
                    self.vars.remove(&name);
                }
            }
        }
        let code = result?;
        self.status = code.to_string();
        Ok(code)
    }

    fn set_var(&mut self, name: &str, value: Vec<String>) {
        self.vars.insert(name.to_string(), value);
    }

    /// Route an expanded command line to a builtin or the PATH.
    fn dispatch(&mut self, words: &[String], redirs: &[Redir]) -> Result<i32, RunError> {
        let name = words[0].clone();
        match name.as_str() {
            "cd" => self.builtin_cd(words, redirs),
            "pwd" => self.builtin_pwd(redirs),
            "shift" => self.builtin_shift(words),
            "true" => Ok(0),
            "false" => Ok(1),
            "exit" => {
                let code = words.get(1).and_then(|c| c.parse::<i32>().ok()).unwrap_or(0);
                Err(RunError::Exit(code))
            }
            "." => self.builtin_dot(words),
            "eval" => self.builtin_eval(words),
            _ => {
                if redirs.is_empty() {
                    self.external(words)
                } else {
                    self.external_with_redirs(words, redirs)
                }
            }
        }
    }

    /// The file path a redirection targets (validates the term is a
    /// single plain word).
    fn redirect_target(&mut self, redir: &Redir) -> Result<String, RunError> {
        let term = match redir {
            Redir::In(t) | Redir::Out(t) | Redir::Append(t) | Redir::Both(t) => t,
        };
        let expanded = self.expand_term(term)?;
        match expanded.len() {
            1 => Ok(expanded.into_iter().next().expect("len checked")),
            0 => Err(RunError::msg("expands to nothing")),
            n => Err(RunError::msg(format!("expands to {n} words, expected one"))),
        }
    }

    fn builtin_cd(&mut self, words: &[String], redirs: &[Redir]) -> Result<i32, RunError> {
        if !redirs.is_empty() {
            return Err(RunError::msg("on the cd builtin is not supported"));
        }
        let target = match words.get(1) {
            Some(d) => d.clone(),
            None => self
                .lookup("home")
                .into_iter()
                .next()
                .ok_or_else(|| RunError::Msg("cd: no argument and no $home".into()))?,
        };
        let path = PathBuf::from(&target);
        std::env::set_current_dir(&path).map_err(|e| RunError::io(format!("cd {target}"), e))?;
        if let Ok(now) = std::env::current_dir() {
            self.vars.insert("PWD".into(), vec![now.to_string_lossy().into_owned()]);
        }
        Ok(0)
    }

    fn builtin_pwd(&mut self, redirs: &[Redir]) -> Result<i32, RunError> {
        if !redirs.is_empty() {
            return Err(RunError::msg("on the pwd builtin is not supported"));
        }
        let cwd = std::env::current_dir().map_err(|e| RunError::io("pwd", e))?;
        println!("{}", cwd.display());
        Ok(0)
    }

    fn builtin_shift(&mut self, words: &[String]) -> Result<i32, RunError> {
        if words.len() > 1 {
            return Err(RunError::Msg("shift takes no arguments".into()));
        }
        if self.script_args.is_empty() {
            return Err(RunError::Msg("shift: the argument list is already empty".into()));
        }
        self.script_args.remove(0);
        Ok(0)
    }

    fn builtin_dot(&mut self, words: &[String]) -> Result<i32, RunError> {
        let file = words.get(1).ok_or_else(|| RunError::Msg(". needs a file name".into()))?;
        let src = fs::read_to_string(file).map_err(|e| RunError::io(format!(". {file}"), e))?;
        let node = crate::parse::parse(&src)
            .map_err(|e: RcError| RunError::Msg(format!(". {file}: {e}")))?;
        self.run(&node)
    }

    fn builtin_eval(&mut self, words: &[String]) -> Result<i32, RunError> {
        let joined = words[1..].join(" ");
        let node = crate::parse::parse(&joined)
            .map_err(|e: RcError| RunError::Msg(format!("eval: {e}")))?;
        self.run(&node)
    }

    fn child_env(&self, cmd: &mut Command) {
        for (k, v) in &self.vars {
            if k != "*" && k != "status" {
                cmd.env(k, v.join(" "));
            }
        }
    }

    fn external(&mut self, words: &[String]) -> Result<i32, RunError> {
        let mut cmd = Command::new(&words[0]);
        cmd.args(&words[1..]);
        self.child_env(&mut cmd);
        self.spawn_and_wait(&mut cmd, &words[0])
    }

    fn apply_redirs(&mut self, cmd: &mut Command, redirs: &[Redir]) -> Result<(), RunError> {
        for r in redirs {
            let path = self.redirect_target(r)?;
            match r {
                Redir::In(_) => {
                    let f = fs::File::open(&path).map_err(|e| RunError::io(format!("< {path}"), e))?;
                    cmd.stdin(Stdio::from(f));
                }
                Redir::Out(_) => {
                    let f = fs::File::create(&path).map_err(|e| RunError::io(format!("> {path}"), e))?;
                    cmd.stdout(Stdio::from(f));
                }
                Redir::Append(_) => {
                    let f = fs::OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(&path)
                        .map_err(|e| RunError::io(format!(">> {path}"), e))?;
                    cmd.stdout(Stdio::from(f));
                }
                Redir::Both(_) => {
                    let f = fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(false)
                        .open(&path)
                        .map_err(|e| RunError::io(format!("<> {path}"), e))?;
                    cmd.stdin(Stdio::from(f.try_clone().map_err(|e| RunError::io("<>", e))?));
                    cmd.stdout(Stdio::from(f));
                }
            }
        }
        Ok(())
    }

    fn external_with_redirs(&mut self, words: &[String], redirs: &[Redir]) -> Result<i32, RunError> {
        let mut cmd = Command::new(&words[0]);
        cmd.args(&words[1..]);
        self.child_env(&mut cmd);
        self.apply_redirs(&mut cmd, redirs)?;
        self.spawn_and_wait(&mut cmd, &words[0])
    }

    fn spawn_and_wait(&self, cmd: &mut Command, name: &str) -> Result<i32, RunError> {
        match cmd.status() {
            Ok(st) => Ok(st.code().unwrap_or(if st.success() { 0 } else { 1 })),
            Err(e) => match e.kind() {
                std::io::ErrorKind::NotFound => {
                    Err(RunError::Io { what: format!("{name}: file does not exist") })
                }
                std::io::ErrorKind::PermissionDenied => {
                    Err(RunError::Io { what: format!("{name}: permission denied") })
                }
                _ => Err(RunError::Io { what: format!("{name}: {e}") }),
            },
        }
    }

    fn pipeline(&mut self, stages: &[Node]) -> Result<i32, RunError> {
        if stages.len() > 64 {
            return Err(RunError::Msg("pipelines are limited to 64 stages".into()));
        }
        // expand every stage first: problems surface before any child
        // is spawned
        let mut commands: Vec<(Vec<String>, Vec<Redir>)> = Vec::new();
        for stage in stages {
            match stage {
                Node::Simple { argv, redirs } => {
                    let words = self.expand_terms(argv)?;
                    if words.is_empty() {
                        return Err(RunError::Msg("empty command in a pipeline".into()));
                    }
                    let name = words[0].clone();
                    if is_builtin(&name) {
                        return Err(RunError::Msg(format!(
                            "the {name} builtin cannot run in a pipeline"
                        )));
                    }
                    commands.push((words, redirs.clone()));
                }
                _ => {
                    return Err(RunError::Msg(
                        "only simple commands can appear in a pipeline".into(),
                    ));
                }
            }
        }
        let n = commands.len();
        let mut children = Vec::new();
        for (i, (words, redirs)) in commands.iter().enumerate() {
            let mut cmd = Command::new(&words[0]);
            cmd.args(&words[1..]);
            self.child_env(&mut cmd);
            if i > 0 {
                cmd.stdin(Stdio::piped());
            }
            if i + 1 < n {
                cmd.stdout(Stdio::piped());
            }
            self.apply_redirs(&mut cmd, redirs)?;
            let child = cmd.spawn().map_err(|e| {
                let what = match e.kind() {
                    std::io::ErrorKind::NotFound => format!("{}: file does not exist", words[0]),
                    std::io::ErrorKind::PermissionDenied => {
                        format!("{}: permission denied", words[0])
                    }
                    _ => words[0].clone(),
                };
                RunError::Io { what }
            })?;
            children.push(child);
        }
        // wire the pipes between consecutive children
        for i in 0..children.len().saturating_sub(1) {
            let stdout = children[i].stdout.take();
            let stdin = children[i + 1].stdin.take();
            if let (Some(read), Some(write)) = (stdout, stdin) {
                std::thread::spawn(move || {
                    let mut r = read;
                    let mut w = write;
                    let _ = std::io::copy(&mut r, &mut w);
                });
            }
        }
        let mut last = 0;
        for child in &mut children {
            match child.wait() {
                Ok(st) => last = st.code().unwrap_or(if st.success() { 0 } else { 1 }),
                Err(e) => return Err(RunError::io("waiting for a pipeline stage", e)),
            }
        }
        Ok(last)
    }

    fn background(&mut self, inner: &Node) -> Result<i32, RunError> {
        // any node backgrounds cleanly by re-execing a child copy
        let exe =
            std::env::current_exe().map_err(|e| RunError::io("cannot locate the rc binary", e))?;
        let src = crate::unparse::node(inner);
        let mut cmd = Command::new(exe);
        cmd.arg("-c").arg(src).stdin(Stdio::null());
        self.child_env(&mut cmd);
        cmd.spawn().map_err(|e| RunError::io("backgrounding a command", e))?;
        Ok(0)
    }
}

/// The variable name when a word is an rc assignment (`name=...`):
/// the '=' must actually appear in unquoted text and the prefix must
/// be a plain identifier.
pub fn assignment_name(w: &Word) -> Option<String> {
    let mut prefix = String::new();
    for part in &w.0 {
        match part {
            Part::Quoted(_) => return None,
            Part::Unquoted(text) => match text.find('=') {
                None => prefix.push_str(text),
                Some(0) => return None,
                Some(eq) => {
                    prefix.push_str(&text[..eq]);
                    if prefix.is_empty()
                        || !prefix.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    {
                        return None;
                    }
                    return Some(prefix);
                }
            },
        }
    }
    // the word never contained '=': it is an ordinary command word
    None
}

fn is_builtin(name: &str) -> bool {
    matches!(name, "cd" | "pwd" | "shift" | "true" | "false" | "exit" | "." | "eval")
}

impl Default for Interp {
    fn default() -> Interp {
        Interp::new()
    }
}
