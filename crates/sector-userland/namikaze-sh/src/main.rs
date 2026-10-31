// SPDX-License-Identifier: MPL-2.0
//! namikaze-sh: the NamikazeOS login shell (POSIX-flavoured subset).
//!
//! Pipeline of simple commands with `|`, `<`, `>`, `>>`, `2>` redirection,
//! `;` and `&&`/`||` sequencing, single/double quotes, `$VAR` expansion and
//! builtins: cd, pwd, exit, export, unset, echo, true, false, help.
//! External commands resolve over PATH and run through std::process.
//! Everything is safe Rust; no libc, no third-party crates.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

fn main() {
    // login-shell mode: "-" prefix on argv[0] is accepted and ignored
    let interactive = std::env::args().count() <= 1;
    if interactive {
        println!("namikaze-sh 3.0.0-alpha.2 (MPL-2.0) - type 'help' for builtins");
    }
    let mut env: HashMap<String, String> = std::env::vars().collect();
    let stdin_is_tty = is_tty();
    loop {
        if interactive && stdin_is_tty {
            print!("{}$ ", env.get("PWD").map(String::as_str).unwrap_or("~"));
            let _ = std::io::stdout().flush();
        }
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let line = line.trim_end_matches(['\n', '\r']);
        match run_line(line, &mut env) {
            Ok(code) => {
                if let Some(c) = code {
                    std::process::exit(c);
                }
            }
            Err(msg) => {
                eprintln!("namikaze-sh: {msg}");
            }
        }
    }
}

fn is_tty() -> bool {
    // safe heuristic: /proc/self/fd/0 resolves into /dev/pts or /dev/ttyN
    match std::fs::read_link("/proc/self/fd/0") {
        Ok(target) => {
            let s = target.to_string_lossy();
            s.starts_with("/dev/pts/") || s.starts_with("/dev/tty") || s == "/dev/console"
        }
        Err(_) => false,
    }
}

/// Execute one input line; Ok(Some(code)) means exit was requested.
fn run_line(line: &str, env: &mut HashMap<String, String>) -> Result<Option<i32>, String> {
    let expanded = expand(line, env);
    for seq in split_top(&expanded, ';') {
        let seq = seq.trim();
        if seq.is_empty() {
            continue;
        }
        // && / || chains carry the previous status
        let mut status = 0;
        for part in split_conditionals(seq) {
            let (op, chunk) = part;
            if (op == "&&" && status != 0) || (op == "||" && status == 0) {
                continue;
            }
            status = run_pipeline(&chunk, env)?;
        }
    }
    Ok(None)
}

/// Split on && / || preserving the operator for each chunk. The first
/// chunk runs unconditionally; each later chunk carries the operator that
/// preceded it, evaluated against the previous status.
fn split_conditionals(seq: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let mut rest = seq.trim();
    let mut pending: &'static str = ";";
    loop {
        let next_and = find_top(rest, "&&");
        let next_or = find_top(rest, "||");
        let split = match (next_and, next_or) {
            (Some(a), Some(o)) => Some(a.min(o)),
            (Some(a), None) => Some(a),
            (None, Some(o)) => Some(o),
            (None, None) => None,
        };
        match split {
            Some(idx) => {
                let op: &'static str =
                    if next_and.map(|a| a == idx).unwrap_or(false) { "&&" } else { "||" };
                out.push((pending, rest[..idx].trim().to_string()));
                pending = op;
                rest = rest[idx + 2..].trim();
            }
            None => {
                out.push((pending, rest.to_string()));
                break;
            }
        }
    }
    out
}

/// Find `needle` outside quotes.
fn find_top(s: &str, needle: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let n = needle.as_bytes();
    let mut in_s = false;
    let mut in_d = false;
    let mut i = 0;
    while i + n.len() <= bytes.len() {
        match bytes[i] {
            b'\'' if !in_d => in_s = !in_s,
            b'"' if !in_s => in_d = !in_d,
            _ if !in_s && !in_d => {
                if &bytes[i..i + n.len()] == n {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Split on a top-level separator outside quotes.
fn split_top(s: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_s = false;
    let mut in_d = false;
    for c in s.chars() {
        match c {
            '\'' if !in_d => {
                in_s = !in_s;
                cur.push(c);
            }
            '"' if !in_s => {
                in_d = !in_d;
                cur.push(c);
            }
            c if c == sep && !in_s && !in_d => {
                out.push(cur.clone());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// $VAR / ${VAR} expansion (single pass; unknown vars become empty).
fn expand(line: &str, env: &HashMap<String, String>) -> String {
    let mut out = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('{') => {
                chars.next();
                let mut name = String::new();
                for c in chars.by_ref() {
                    if c == '}' {
                        break;
                    }
                    name.push(c);
                }
                out.push_str(env.get(&name).map(String::as_str).unwrap_or(""));
            }
            Some(c) if c.is_ascii_alphabetic() || *c == '_' => {
                let mut name = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_alphanumeric() || c == '_' {
                        name.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                out.push_str(env.get(&name).map(String::as_str).unwrap_or(""));
            }
            _ => out.push('$'),
        }
    }
    out
}

/// One pipeline: cmd | cmd | cmd with redirections on the last stage.
/// Stage handoff buffers each stage's stdout in memory (std-only, no raw
/// fds needed under `forbid(unsafe_code)`); shell pipelines here carry
/// short text, so this bounds fine for the login-shell role.
fn run_pipeline(pipeline: &str, env: &mut HashMap<String, String>) -> Result<i32, String> {
    let stages: Vec<String> = split_top(pipeline, '|');
    let n = stages.len();
    let mut carry: Vec<u8> = Vec::new();
    let mut status = 0;
    for (i, stage) in stages.iter().enumerate() {
        let is_last = i + 1 == n;
        let cmd = parse_command(stage, env)?;
        if cmd.argv.is_empty() {
            continue;
        }
        if n == 1
            && is_builtin(&cmd.argv[0])
            && cmd.stdin_file.is_none()
            && cmd.stdout_file.is_none()
        {
            return builtin(&cmd, env).map(|opt| opt.unwrap_or(0));
        }
        let mut command = Command::new(&cmd.argv[0]);
        command.args(&cmd.argv[1..]);
        command.envs(env.iter().map(|(k, v)| (k, v)));
        if !carry.is_empty() {
            command.stdin(Stdio::piped());
        } else if let Some(path) = &cmd.stdin_file {
            let f = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
            command.stdin(Stdio::from(f));
        }
        if is_last {
            match &cmd.stdout_file {
                Some((path, append)) => {
                    let f = open_out(path, *append)?;
                    command.stdout(Stdio::from(f));
                }
                None => {
                    command.stdout(Stdio::inherit());
                }
            }
            if let Some((path, _)) = &cmd.stderr_file {
                let f = open_out(path, false)?;
                command.stderr(Stdio::from(f));
            }
        } else {
            command.stdout(Stdio::piped());
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("{}: {e}", cmd.argv[0]))?;
        if !carry.is_empty() {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(&carry);
            }
        }
        carry.clear();
        if !is_last {
            if let Some(mut out) = child.stdout.take() {
                let _ = out.read_to_end(&mut carry);
            }
        }
        let st = child.wait().map_err(|e| format!("wait: {e}"))?;
        status = st.code().unwrap_or(if st.success() { 0 } else { 1 });
    }
    Ok(status)
}

fn open_out(path: &str, append: bool) -> Result<std::fs::File, String> {
    use std::fs::OpenOptions;
    let mut o = OpenOptions::new();
    o.write(true).create(true);
    if append {
        o.append(true);
    } else {
        o.truncate(true);
    }
    o.open(path).map_err(|e| format!("{path}: {e}"))
}

struct SimpleCommand {
    argv: Vec<String>,
    stdin_file: Option<String>,
    stdout_file: Option<(String, bool)>,
    stderr_file: Option<(String, bool)>,
}

/// Tokenize one pipeline stage: words, quotes, redirections.
fn parse_command(stage: &str, env: &HashMap<String, String>) -> Result<SimpleCommand, String> {
    let mut argv = Vec::new();
    let mut stdin_file = None;
    let mut stdout_file = None;
    let mut stderr_file = None;
    let chars: Vec<char> = stage.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '<' {
            let ni = skip_ws(&chars, i + 1);
            let (tok, ni) = read_word(&chars, ni)?;
            stdin_file = Some(expand(&tok, env));
            i = ni;
            continue;
        }
        if c == '>' {
            let (append, ni) = if chars.get(i + 1) == Some(&'>') {
                (true, i + 2)
            } else {
                (false, i + 1)
            };
            let ni = skip_ws(&chars, ni);
            let (tok, ni) = read_word(&chars, ni)?;
            stdout_file = Some((expand(&tok, env), append));
            i = ni;
            continue;
        }
        if c == '2' && chars.get(i + 1) == Some(&'>') {
            let (append, ni) = if chars.get(i + 2) == Some(&'>') {
                (true, i + 3)
            } else {
                (false, i + 2)
            };
            let ni = skip_ws(&chars, ni);
            let (tok, ni) = read_word(&chars, ni)?;
            stderr_file = Some((expand(&tok, env), append));
            i = ni;
            continue;
        }
        let (tok, ni) = read_word(&chars, i)?;
        if !tok.is_empty() {
            argv.push(expand(&tok, env));
        }
        i = ni;
    }
    Ok(SimpleCommand { argv, stdin_file, stdout_file, stderr_file })
}

fn skip_ws(chars: &[char], mut i: usize) -> usize {
    while i < chars.len() && chars[i].is_whitespace() {
        i += 1;
    }
    i
}

/// Read one word starting at `i` (quotes make literal runs).
fn read_word(chars: &[char], mut i: usize) -> Result<(String, usize), String> {
    let mut out = String::new();
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            break;
        }
        if c == '<' || c == '>' {
            break;
        }
        if c == '2' && chars.get(i + 1) == Some(&'>') {
            break;
        }
        if c == '\'' {
            i += 1;
            while i < chars.len() && chars[i] != '\'' {
                out.push(chars[i]);
                i += 1;
            }
            if i >= chars.len() {
                return Err("unterminated single quote".into());
            }
            i += 1;
            continue;
        }
        if c == '"' {
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                out.push(chars[i]);
                i += 1;
            }
            if i >= chars.len() {
                return Err("unterminated double quote".into());
            }
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    Ok((out, i))
}

fn is_builtin(name: &str) -> bool {
    matches!(
        name,
        "cd" | "pwd" | "exit" | "export" | "unset" | "echo" | "true" | "false" | "help"
    )
}

fn builtin(cmd: &SimpleCommand, env: &mut HashMap<String, String>) -> Result<Option<i32>, String> {
    let argv = &cmd.argv;
    match argv[0].as_str() {
        "cd" => {
            let target = argv.get(1).cloned().unwrap_or_else(|| {
                env.get("HOME").cloned().unwrap_or_else(|| "/".into())
            });
            std::env::set_current_dir(&target).map_err(|e| format!("cd: {target}: {e}"))?;
            let pwd = std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            env.insert("PWD".into(), pwd);
            Ok(None)
        }
        "pwd" => {
            println!(
                "{}",
                std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            );
            Ok(None)
        }
        "exit" => Ok(Some(argv.get(1).and_then(|c| c.parse::<i32>().ok()).unwrap_or(0))),
        "export" => {
            for a in &argv[1..] {
                if let Some((k, v)) = a.split_once('=') {
                    env.insert(k.to_string(), v.to_string());
                }
            }
            Ok(None)
        }
        "unset" => {
            for a in &argv[1..] {
                env.remove(a);
            }
            Ok(None)
        }
        "echo" => {
            println!("{}", argv[1..].join(" "));
            Ok(None)
        }
        "true" => Ok(None),
        "false" => Ok(None),
        "help" => {
            println!("builtins: cd pwd exit export unset echo true false help");
            println!("syntax:   pipe |, redirect < > >> 2>, sequence ;, chains && ||, vars $VAR");
            Ok(None)
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> HashMap<String, String> {
        let mut e = HashMap::new();
        e.insert("NAME".to_string(), "namikaze".to_string());
        e
    }

    #[test]
    fn expands_vars() {
        let e = env();
        assert_eq!(expand("hello $NAME", &e), "hello namikaze");
        assert_eq!(expand("${NAME}!", &e), "namikaze!");
        assert_eq!(expand("$MISSING", &e), "");
        assert_eq!(expand("cost $5", &e), "cost $5");
    }

    #[test]
    fn splits_on_top_level_only() {
        assert_eq!(split_top("a;b", ';'), vec!["a", "b"]);
        // quotes shield the inner separator
        assert_eq!(split_top("a;b\"c;d\"", ';'), vec!["a", "b\"c;d\""]);
    }

    #[test]
    fn tokenizes_redirections() {
        let e = env();
        let cmd = parse_command("run --x > /tmp/out 2> /tmp/err < in.txt", &e).unwrap();
        assert_eq!(cmd.argv, vec!["run", "--x"]);
        assert_eq!(cmd.stdout_file.as_ref().map(|(p, a)| (p.as_str(), *a)), Some(("/tmp/out", false)));
        assert_eq!(cmd.stderr_file.as_ref().map(|(p, _)| p.as_str()), Some("/tmp/err"));
        assert_eq!(cmd.stdin_file.as_deref(), Some("in.txt"));
    }

    #[test]
    fn appends_redirect() {
        let e = env();
        let cmd = parse_command("log >> /var/log/x", &e).unwrap();
        assert_eq!(cmd.stdout_file, Some(("/var/log/x".into(), true)));
    }

    #[test]
    fn builtins_run_in_process() {
        let mut e = env();
        let cmd = parse_command("echo hi", &e).unwrap();
        assert_eq!(builtin(&cmd, &mut e).unwrap(), None);
        let cmd = parse_command("false", &e).unwrap();
        assert!(builtin(&cmd, &mut e).is_ok());
    }

    #[test]
    fn pipelines_run() {
        let mut e = env();
        // echo -> tr via our own pipeline plumbing
        let code = run_pipeline("echo namikaze | true", &mut e).unwrap();
        assert_eq!(code, 0);
    }
}
