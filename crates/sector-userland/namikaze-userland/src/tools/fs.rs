// SPDX-License-Identifier: MPL-2.0
#![forbid(unsafe_code)]
//! File and directory tools: cat, echo, ls, cp, mv, rm, mkdir, rmdir, ln,
//! touch, chmod, readlink, basename, dirname, pwd, stat.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use crate::{fail, usage, EXIT_OK};

// ------------------------------------------------------------------ cat ----

/// cat: concatenate files (or stdin for "-") to stdout, byte-exact.
pub fn cat(argv: &[String]) -> i32 {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let dash = String::from("-");
    let mut sources: Vec<&String> = argv.iter().filter(|a| a.as_str() != "--").collect();
    if sources.is_empty() {
        sources.push(&dash);
    }
    let mut code = EXIT_OK;
    for src in sources {
        let copied = if src == "-" {
            let mut stdin = io::stdin();
            io::copy(&mut stdin, &mut out)
        } else {
            match fs::File::open(src.as_str()) {
                Ok(mut f) => io::copy(&mut f, &mut out),
                Err(e) => {
                    code = fail("cat", &format!("cannot open {src}: {e}"));
                    continue;
                }
            }
        };
        if let Err(e) = copied {
            code = fail("cat", &format!("read error on {src}: {e}"));
        }
    }
    let _ = out.flush();
    code
}

// ---------------------------------------------------------------- echo ----

/// Render the echo output bytes; factored out for testing.
fn render_echo(argv: &[String]) -> Vec<u8> {
    let mut newline = true;
    let mut escapes = false;
    let mut words: Vec<&str> = Vec::new();
    for arg in argv {
        if words.is_empty() && arg == "-n" {
            newline = false;
            continue;
        }
        if words.is_empty() && arg == "-e" {
            escapes = true;
            continue;
        }
        if words.is_empty() && arg == "-E" {
            escapes = false;
            continue;
        }
        words.push(arg.as_str());
    }
    let mut line = words.join(" ");
    if escapes {
        line = unescape(&line);
    }
    if newline {
        line.push('\n');
    }
    line.into_bytes()
}

fn unescape(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c != '\\' || i + 1 >= chars.len() {
            out.push(c);
            i += 1;
            continue;
        }
        let n = chars[i + 1];
        i += 2;
        match n {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'a' => out.push('\u{7}'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'v' => out.push('\u{b}'),
            '\\' => out.push('\\'),
            '0' => {
                let mut val: u32 = 0;
                let mut cnt = 0;
                while cnt < 3 && i < chars.len() && ('0'..='7').contains(&chars[i]) {
                    val = val * 8 + chars[i].to_digit(8).unwrap_or(0);
                    i += 1;
                    cnt += 1;
                }
                out.push(char::from_u32(val).unwrap_or('\u{0}'));
            }
            'x' => {
                let mut val: u32 = 0;
                let mut cnt = 0;
                while cnt < 2 && i < chars.len() && chars[i].is_ascii_hexdigit() {
                    val = val * 16 + chars[i].to_digit(16).unwrap_or(0);
                    i += 1;
                    cnt += 1;
                }
                out.push(char::from_u32(val).unwrap_or('\u{0}'));
            }
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}

/// echo: write words separated by spaces, newline unless -n.
pub fn echo(argv: &[String]) -> i32 {
    let bytes = render_echo(argv);
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let _ = out.write_all(&bytes);
    let _ = out.flush();
    EXIT_OK
}

// ------------------------------------------------------------------- ls ----

fn mode_string(mode: u32) -> String {
    let mut s = String::with_capacity(10);
    s.push(match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        0o100000 => '-',
        0o020000 => 'c',
        0o060000 => 'b',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '?',
    });
    for (shift, special) in [(6u32, 0o4000u32), (3, 0o2000), (0, 0o1000)] {
        let bits = (mode >> shift) & 7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        let x = bits & 1 != 0;
        if mode & special != 0 {
            s.push(match (shift, x) {
                (0, true) => 't',
                (0, false) => 'T',
                (_, true) => 's',
                (_, false) => 'S',
            });
        } else {
            s.push(if x { 'x' } else { '-' });
        }
    }
    s
}

fn print_long(path: &str, display: &str) {
    let md = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => {
            println!("{display}");
            return;
        }
    };
    let mode = md.mode();
    let ts = crate::tools::sys::fmt_mtime(md.mtime());
    println!(
        "{} {:>3} {:>5} {:>5} {:>12} {} {}",
        mode_string(mode),
        md.nlink(),
        md.uid(),
        md.gid(),
        md.size(),
        ts,
        display
    );
}

/// ls: list directory contents; -a -A -l -1, combined short flags allowed.
pub fn ls(argv: &[String]) -> i32 {
    let mut all = false;
    let mut almost = false;
    let mut long = false;
    let mut paths: Vec<String> = Vec::new();
    for a in argv {
        let short_flags = a.starts_with('-') && a.len() > 1 && a[1..].chars().all(|c| "aAl1".contains(c));
        if a == "--" {
            continue;
        } else if short_flags {
            for c in a[1..].chars() {
                match c {
                    'a' => all = true,
                    'A' => almost = true,
                    'l' => long = true,
                    _ => {}
                }
            }
        } else if a.starts_with('-') && a.len() > 1 {
            return usage("ls", &format!("unsupported option: {a}"));
        } else {
            paths.push(a.clone());
        }
    }
    if paths.is_empty() {
        paths.push(String::from("."));
    }
    let mut code = EXIT_OK;
    for (i, p) in paths.iter().enumerate() {
        if paths.len() > 1 {
            if i > 0 {
                println!();
            }
            println!("{p}:");
        }
        match fs::metadata(p) {
            Err(e) => {
                code = fail("ls", &format!("cannot access {p}: {e}"));
            }
            Ok(m) if m.is_dir() => {
                let mut names: Vec<String> = Vec::new();
                match fs::read_dir(p) {
                    Ok(rd) => {
                        for entry in rd.flatten() {
                            let name = entry.file_name().to_string_lossy().into_owned();
                            if !all && !almost && name.starts_with('.') {
                                continue;
                            }
                            if almost && (name == "." || name == "..") {
                                continue;
                            }
                            names.push(name);
                        }
                    }
                    Err(e) => {
                        code = fail("ls", &format!("cannot read {p}: {e}"));
                        continue;
                    }
                }
                names.sort_by(|x, y| x.as_bytes().cmp(y.as_bytes()));
                for n in &names {
                    let full = format!("{}/{}", p.trim_end_matches('/'), n);
                    if long {
                        print_long(&full, n);
                    } else {
                        println!("{n}");
                    }
                }
            }
            Ok(_) => {
                if long {
                    print_long(p, p);
                } else {
                    println!("{p}");
                }
            }
        }
    }
    code
}

// ------------------------------------------------------------------- cp ----

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn copy_file(src: &Path, dst: &Path) -> io::Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(src, dst)?;
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    let mut stack: Vec<(PathBuf, PathBuf)> = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((s, d)) = stack.pop() {
        for entry in fs::read_dir(&s)? {
            let entry = entry?;
            let sp = entry.path();
            let dp = d.join(entry.file_name());
            let md = fs::symlink_metadata(&sp)?;
            if md.is_dir() {
                fs::create_dir_all(&dp)?;
                stack.push((sp, dp));
            } else if md.is_symlink() {
                let target = fs::read_link(&sp)?;
                let _ = fs::remove_file(&dp);
                std::os::unix::fs::symlink(&target, &dp)?;
            } else {
                fs::copy(&sp, &dp)?;
            }
        }
    }
    Ok(())
}

/// cp: copy files; -r for trees; a directory destination receives each
/// source under its own name.
pub fn cp(argv: &[String]) -> i32 {
    let mut recursive = false;
    let mut paths: Vec<String> = Vec::new();
    for a in argv {
        match a.as_str() {
            "-r" | "-R" | "--recursive" => recursive = true,
            "--" => {}
            other if other.starts_with('-') && other.len() > 1 => {
                return usage("cp", &format!("unsupported option: {other}"));
            }
            other => paths.push(other.to_string()),
        }
    }
    if paths.len() < 2 {
        return usage("cp", "need SOURCE... DEST");
    }
    let dest = paths.pop().unwrap_or_default();
    let dest_is_dir = fs::metadata(&dest).map(|m| m.is_dir()).unwrap_or(false);
    let mut code = EXIT_OK;
    for src in &paths {
        if same_file(Path::new(src), Path::new(&dest)) {
            code = fail("cp", &format!("'{src}' and '{dest}' are the same file"));
            continue;
        }
        let is_dir = matches!(fs::symlink_metadata(src), Ok(ref md) if md.is_dir());
        if is_dir && !recursive {
            code = fail("cp", &format!("omitting directory '{src}' (need -r)"));
            continue;
        }
        let target = if dest_is_dir {
            Path::new(&dest).join(crate::basename_of(src))
        } else {
            PathBuf::from(dest.as_str())
        };
        let r = if is_dir {
            copy_tree(Path::new(src), &target)
        } else {
            copy_file(Path::new(src), &target)
        };
        if let Err(e) = r {
            code = fail("cp", &format!("{src} -> {}: {e}", target.display()));
        }
    }
    code
}

// ------------------------------------------------------------------- mv ----

/// mv: rename files; falls back to copy+remove across filesystems.
pub fn mv(argv: &[String]) -> i32 {
    let mut paths: Vec<String> = Vec::new();
    for a in argv {
        match a.as_str() {
            "-f" | "--" => {}
            other if other.starts_with('-') && other.len() > 1 => {
                return usage("mv", &format!("unsupported option: {other}"));
            }
            other => paths.push(other.to_string()),
        }
    }
    if paths.len() < 2 {
        return usage("mv", "need SOURCE... DEST");
    }
    let dest = paths.pop().unwrap_or_default();
    let dest_is_dir = fs::metadata(&dest).map(|m| m.is_dir()).unwrap_or(false);
    let mut code = EXIT_OK;
    for src in &paths {
        let destp = if dest_is_dir {
            Path::new(&dest).join(crate::basename_of(src))
        } else {
            PathBuf::from(dest.as_str())
        };
        if fs::rename(src, &destp).is_ok() {
            continue;
        }
        let is_dir = matches!(fs::symlink_metadata(src), Ok(ref md) if md.is_dir());
        let r = if is_dir {
            copy_tree(Path::new(src), &destp).and_then(|_| fs::remove_dir_all(src))
        } else {
            copy_file(Path::new(src), &destp).and_then(|_| fs::remove_file(src))
        };
        if let Err(e) = r {
            code = fail("mv", &format!("{src} -> {}: {e}", destp.display()));
        }
    }
    code
}

// ------------------------------------------------------------------- rm ----

fn is_protected(p: &str) -> bool {
    let norm = p.trim_end_matches('/');
    if matches!(norm, "" | "/" | "." | "..") {
        return true;
    }
    if norm.ends_with("/.") || norm.ends_with("/..") {
        return true;
    }
    fs::canonicalize(norm).map(|c| c == Path::new("/")).unwrap_or(false)
}

/// rm: remove files; -r trees, -f ignore missing; refuses "/" and friends.
pub fn rm(argv: &[String]) -> i32 {
    let mut recursive = false;
    let mut force = false;
    let mut paths: Vec<String> = Vec::new();
    for a in argv {
        let short_flags = a.starts_with('-') && a.len() > 1 && a[1..].chars().all(|c| "rf".contains(c));
        if a == "--" {
            continue;
        } else if short_flags {
            for c in a[1..].chars() {
                if c == 'r' {
                    recursive = true;
                }
                if c == 'f' {
                    force = true;
                }
            }
        } else if a.starts_with('-') && a.len() > 1 {
            return usage("rm", &format!("unsupported option: {a}"));
        } else {
            paths.push(a.clone());
        }
    }
    if paths.is_empty() {
        return usage("rm", "missing operand");
    }
    let mut code = EXIT_OK;
    for p in &paths {
        if is_protected(p) {
            code = fail("rm", &format!("refusing to remove '{p}' (protected path)"));
            continue;
        }
        let outcome = match fs::symlink_metadata(p) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if force {
                    Ok(())
                } else {
                    Err(String::from("no such file or directory"))
                }
            }
            Err(e) => Err(e.to_string()),
            Ok(md) if md.is_dir() => {
                if recursive {
                    fs::remove_dir_all(p).map_err(|e| e.to_string())
                } else {
                    Err(String::from("is a directory (need -r)"))
                }
            }
            Ok(_) => fs::remove_file(p).map_err(|e| e.to_string()),
        };
        if let Err(msg) = outcome {
            code = fail("rm", &format!("cannot remove '{p}': {msg}"));
        }
    }
    code
}

// ---------------------------------------------------------------- mkdir ----

/// mkdir: create directories; -p full chains, -m initial octal mode.
pub fn mkdir(argv: &[String]) -> i32 {
    let mut parents = false;
    let mut mode: Option<u32> = None;
    let mut paths: Vec<String> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "-p" {
            parents = true;
        } else if a == "-m" {
            i += 1;
            match argv.get(i).and_then(|m| u32::from_str_radix(m, 8).ok()) {
                Some(v) => mode = Some(v),
                None => return usage("mkdir", "-m needs an octal mode"),
            }
        } else if a.starts_with("-m") && a.len() > 2 {
            match u32::from_str_radix(&a[2..], 8) {
                Ok(v) => mode = Some(v),
                Err(_) => return usage("mkdir", "-m needs an octal mode"),
            }
        } else if a == "--" {
        } else if a.starts_with('-') && a.len() > 1 {
            return usage("mkdir", &format!("unsupported option: {a}"));
        } else {
            paths.push(a.to_string());
        }
        i += 1;
    }
    if paths.is_empty() {
        return usage("mkdir", "missing operand");
    }
    let mut code = EXIT_OK;
    for p in &paths {
        let r = if parents {
            fs::create_dir_all(p)
        } else {
            fs::create_dir(p)
        };
        if let Err(e) = r {
            code = fail("mkdir", &format!("cannot create '{p}': {e}"));
            continue;
        }
        if let Some(m) = mode {
            let _ = fs::set_permissions(p, fs::Permissions::from_mode(m));
        }
    }
    code
}

// ---------------------------------------------------------------- rmdir ----

/// rmdir: remove empty directories; -p also removes emptied parents.
pub fn rmdir(argv: &[String]) -> i32 {
    let mut parents = false;
    let mut paths: Vec<String> = Vec::new();
    for a in argv {
        match a.as_str() {
            "-p" => parents = true,
            "--" => {}
            other if other.starts_with('-') && other.len() > 1 => {
                return usage("rmdir", &format!("unsupported option: {other}"));
            }
            other => paths.push(other.to_string()),
        }
    }
    if paths.is_empty() {
        return usage("rmdir", "missing operand");
    }
    let mut code = EXIT_OK;
    for p in &paths {
        let mut cur = PathBuf::from(p.as_str());
        loop {
            match fs::remove_dir(&cur) {
                Err(e) => {
                    code = fail("rmdir", &format!("cannot remove '{}': {e}", cur.display()));
                    break;
                }
                Ok(()) => {
                    if !parents || !cur.pop() || cur == Path::new("/") {
                        break;
                    }
                }
            }
        }
    }
    code
}

// ------------------------------------------------------------------- ln ----

/// ln: hard link by default, -s symbolic, -f replace the link name.
pub fn ln(argv: &[String]) -> i32 {
    let mut symlink = false;
    let mut force = false;
    let mut paths: Vec<String> = Vec::new();
    for a in argv {
        let short_flags = a.starts_with('-') && a.len() > 1 && a[1..].chars().all(|c| "sf".contains(c));
        if a == "--" {
            continue;
        } else if short_flags {
            for c in a[1..].chars() {
                if c == 's' {
                    symlink = true;
                }
                if c == 'f' {
                    force = true;
                }
            }
        } else if a.starts_with('-') && a.len() > 1 {
            return usage("ln", &format!("unsupported option: {a}"));
        } else {
            paths.push(a.clone());
        }
    }
    if paths.len() != 2 {
        return usage("ln", "need TARGET LINK_NAME");
    }
    let target = &paths[0];
    let link = &paths[1];
    if force {
        let _ = fs::remove_file(link);
    }
    let r = if symlink {
        std::os::unix::fs::symlink(target, link)
    } else {
        fs::hard_link(target, link)
    };
    match r {
        Ok(()) => EXIT_OK,
        Err(e) => fail("ln", &format!("{target} -> {link}: {e}")),
    }
}

// ---------------------------------------------------------------- touch ----

/// touch: create missing files (unless -c) and refresh modification time.
pub fn touch(argv: &[String]) -> i32 {
    let mut nocreate = false;
    let mut paths: Vec<String> = Vec::new();
    for a in argv {
        match a.as_str() {
            "-c" => nocreate = true,
            "--" => {}
            other if other.starts_with('-') && other.len() > 1 => {
                return usage("touch", &format!("unsupported option: {other}"));
            }
            other => paths.push(other.to_string()),
        }
    }
    if paths.is_empty() {
        return usage("touch", "missing operand");
    }
    let now = std::time::SystemTime::now();
    let mut code = EXIT_OK;
    for p in &paths {
        let exists = fs::symlink_metadata(p).is_ok();
        if !exists {
            if nocreate {
                continue;
            }
            if let Err(e) = fs::OpenOptions::new().create(true).append(true).open(p) {
                code = fail("touch", &format!("cannot create '{p}': {e}"));
                continue;
            }
        }
        let r = fs::OpenOptions::new()
            .write(true)
            .open(p)
            .and_then(|f| f.set_modified(now));
        if let Err(e) = r {
            code = fail("touch", &format!("cannot update times for '{p}': {e}"));
        }
    }
    code
}

// ---------------------------------------------------------------- chmod ----

/// One parsed symbolic clause: (who mask, op, rwx bits, X present).
type Clause = (u32, char, u32, bool);

fn parse_symbolic(spec: &str) -> Result<Vec<Clause>, String> {
    let mut out = Vec::new();
    for clause in spec.split(',') {
        if clause.is_empty() {
            return Err(format!("empty mode clause in '{spec}'"));
        }
        let mut who = 0u32;
        let mut seen_who = false;
        let mut chars = clause.chars().peekable();
        while let Some(&c) = chars.peek() {
            match c {
                'u' => {
                    who |= 0b100;
                    seen_who = true;
                    chars.next();
                }
                'g' => {
                    who |= 0b010;
                    seen_who = true;
                    chars.next();
                }
                'o' => {
                    who |= 0b001;
                    seen_who = true;
                    chars.next();
                }
                'a' => {
                    who |= 0b111;
                    seen_who = true;
                    chars.next();
                }
                _ => break,
            }
        }
        if !seen_who {
            who = 0b111;
        }
        let how = match chars.next() {
            Some(c @ ('+' | '=' | '-')) => c,
            _ => return Err(format!("bad mode clause: {clause}")),
        };
        let mut perms = 0u32;
        let mut has_x = false;
        for c in chars {
            match c {
                'r' => perms |= 4,
                'w' => perms |= 2,
                'x' => perms |= 1,
                'X' => has_x = true,
                's' => perms |= 8,
                't' => perms |= 16,
                _ => return Err(format!("bad permission letter '{c}' in '{clause}'")),
            }
        }
        out.push((who, how, perms, has_x));
    }
    Ok(out)
}

fn special_bits(who: u32, perms: u32) -> u32 {
    let mut bits = 0u32;
    if perms & 8 != 0 {
        if who & 0b100 != 0 {
            bits |= 0o4000;
        }
        if who & 0b010 != 0 {
            bits |= 0o2000;
        }
    }
    if perms & 16 != 0 && who & 0b001 != 0 {
        bits |= 0o1000;
    }
    bits
}

fn apply_symbolic(cur: u32, spec: &str, is_dir: bool) -> Result<u32, String> {
    let mut mode = cur;
    for (who, how, perms, has_x) in parse_symbolic(spec)? {
        let any_exec = is_dir || (mode & 0o111) != 0;
        for (cls_bit, shift) in [(0b100u32, 6u32), (0b010u32, 3u32), (0b001u32, 0u32)] {
            if who & cls_bit == 0 {
                continue;
            }
            let mut bits = (mode >> shift) & 7;
            match how {
                '+' => bits |= perms & 7,
                '-' => bits &= !(perms & 7),
                _ => bits = perms & 7,
            }
            if has_x && how != '-' && any_exec {
                bits |= 1;
            }
            mode = (mode & !(7u32 << shift)) | (bits << shift);
        }
        let sb = special_bits(who, perms);
        mode = match how {
            '+' => mode | sb,
            '-' => mode & !sb,
            _ => (mode & !0o7000) | sb,
        };
    }
    Ok(mode & 0o7777)
}

/// chmod: change permissions; MODE is octal ("644", "4755") or symbolic
/// ("u+x", "go-w", "a=r", comma-separated clauses).
pub fn chmod(argv: &[String]) -> i32 {
    let mut mode_arg: Option<String> = None;
    let mut files: Vec<String> = Vec::new();
    for a in argv {
        if a == "--" {
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            return usage("chmod", &format!("unsupported option: {a}"));
        }
        if mode_arg.is_none() {
            mode_arg = Some(a.clone());
        } else {
            files.push(a.clone());
        }
    }
    let Some(spec) = mode_arg else {
        return usage("chmod", "missing MODE");
    };
    if files.is_empty() {
        return usage("chmod", "missing operand");
    }
    let is_octal = !spec.is_empty() && spec.chars().all(|c| c.is_ascii_digit());
    if !is_octal && parse_symbolic(&spec).is_err() {
        return fail("chmod", &format!("invalid MODE '{spec}'"));
    }
    let mut code = EXIT_OK;
    for f in &files {
        let md = match fs::symlink_metadata(f) {
            Ok(m) => m,
            Err(e) => {
                code = fail("chmod", &format!("cannot access '{f}': {e}"));
                continue;
            }
        };
        let cur = md.permissions().mode() & 0o7777;
        let new = if is_octal {
            match u32::from_str_radix(&spec, 8) {
                Ok(v) => v & 0o7777,
                Err(_) => {
                    code = fail("chmod", &format!("invalid octal MODE '{spec}'"));
                    continue;
                }
            }
        } else {
            match apply_symbolic(cur, &spec, md.is_dir()) {
                Ok(v) => v,
                Err(e) => {
                    code = fail("chmod", &e);
                    continue;
                }
            }
        };
        if let Err(e) = fs::set_permissions(f, fs::Permissions::from_mode(new)) {
            code = fail("chmod", &format!("cannot change '{f}': {e}"));
        }
    }
    code
}

// -------------------------------------------------------------- readlink ----

/// One resolved-walk step, fully owned so symlink targets can be queued
/// without lifetime ties to the link source.
#[derive(Clone)]
enum Step {
    Root,
    Up,
    Name(std::ffi::OsString),
}

fn steps_of(path: &Path) -> Vec<Step> {
    path.components()
        .filter_map(|c| match c {
            Component::RootDir => Some(Step::Root),
            Component::ParentDir => Some(Step::Up),
            Component::Normal(s) => Some(Step::Name(s.to_os_string())),
            _ => None,
        })
        .collect()
}

/// Resolve `p` fully, following at most `budget` symlinks. The final
/// component may be missing (readlink -f semantics).
fn realpath_max(p: &Path, budget: u32) -> io::Result<PathBuf> {
    let mut cur = if p.is_absolute() {
        PathBuf::from("/")
    } else {
        std::env::current_dir()?
    };
    let mut pending: Vec<Vec<Step>> = vec![steps_of(p)];
    let mut budget = budget;
    while let Some(steps) = pending.pop() {
        for (idx, step) in steps.iter().enumerate() {
            match step {
                Step::Root => cur = PathBuf::from("/"),
                Step::Up => {
                    cur.pop();
                }
                Step::Name(name) => {
                    cur.push(name);
                    if budget == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "too many symlink levels",
                        ));
                    }
                    match fs::symlink_metadata(&cur) {
                        Ok(md) if md.is_symlink() => {
                            budget -= 1;
                            let link = fs::read_link(&cur)?;
                            if link.is_absolute() {
                                // an absolute target replaces the whole prefix
                                cur = PathBuf::from("/");
                            } else {
                                // a relative target resolves inside the dir
                                cur.pop();
                            }
                            // the link target resolves before the remaining
                            // steps of the interrupted fragment
                            let tail: Vec<Step> = steps[idx + 1..].to_vec();
                            if !tail.is_empty() {
                                pending.push(tail);
                            }
                            pending.push(steps_of(&link));
                            break;
                        }
                        Ok(_) => {}
                        // -f allows exactly one missing component: the last
                        // step of the last fragment
                        Err(e)
                            if e.kind() == io::ErrorKind::NotFound
                                && idx + 1 == steps.len()
                                && pending.is_empty() => {}
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }
    Ok(cur)
}

/// readlink: print the link target, or the fully resolved path with -f.
pub fn readlink(argv: &[String]) -> i32 {
    let mut fpath = false;
    let mut target: Option<String> = None;
    for a in argv {
        match a.as_str() {
            "-f" => fpath = true,
            "--" => {}
            other if other.starts_with('-') && other.len() > 1 => {
                return usage("readlink", &format!("unsupported option: {other}"));
            }
            other => {
                if target.is_some() {
                    return usage("readlink", "exactly one operand expected");
                }
                target = Some(other.to_string());
            }
        }
    }
    let Some(t) = target else {
        return usage("readlink", "missing operand");
    };
    let p = Path::new(t.as_str());
    let out = if fpath {
        match realpath_max(p, 40) {
            Ok(r) => r,
            Err(e) => return fail("readlink", &format!("{t}: {e}")),
        }
    } else {
        match fs::read_link(p) {
            Ok(l) => l,
            Err(e) => return fail("readlink", &format!("{t}: {e}")),
        }
    };
    println!("{}", out.display());
    EXIT_OK
}

// ------------------------------------------------------------- basename ----

/// basename: strip directory and optional suffix from a path.
pub fn basename(argv: &[String]) -> i32 {
    let args: Vec<&String> = argv.iter().filter(|a| a.as_str() != "--").collect();
    if args.is_empty() || args.len() > 2 {
        return usage("basename", "expected PATH [SUFFIX]");
    }
    let mut base = crate::basename_of(args[0]).to_string();
    if args.len() == 2 {
        let suf = args[1].as_str();
        if !suf.is_empty() && base.ends_with(suf) && base.len() > suf.len() {
            base.truncate(base.len() - suf.len());
        }
    }
    println!("{base}");
    EXIT_OK
}

// -------------------------------------------------------------- dirname ----

fn dirname_of(path: &str) -> &str {
    let t = path.trim_end_matches('/');
    if t.is_empty() {
        return "/";
    }
    match t.rfind('/') {
        Some(0) => "/",
        Some(pos) => &t[..pos],
        None => ".",
    }
}

/// dirname: strip the last component from a path.
pub fn dirname(argv: &[String]) -> i32 {
    let args: Vec<&String> = argv.iter().filter(|a| a.as_str() != "--").collect();
    if args.len() != 1 {
        return usage("dirname", "expected exactly one PATH");
    }
    println!("{}", dirname_of(args[0]));
    EXIT_OK
}

// ------------------------------------------------------------------ pwd ----

/// pwd: print the working directory (always the physical path).
pub fn pwd(argv: &[String]) -> i32 {
    for a in argv {
        if a.starts_with('-') && a.len() > 1 && a != "-L" && a != "-P" {
            return usage("pwd", &format!("unsupported option: {a}"));
        }
    }
    match std::env::current_dir() {
        Ok(d) => {
            println!("{}", d.display());
            EXIT_OK
        }
        Err(e) => fail("pwd", &format!("cannot determine working directory: {e}")),
    }
}

// ----------------------------------------------------------------- stat ----

fn type_name(mode: u32) -> &'static str {
    match mode & 0o170000 {
        0o040000 => "directory",
        0o120000 => "symbolic link",
        0o100000 => "regular file",
        0o020000 => "character device",
        0o060000 => "block device",
        0o010000 => "fifo",
        0o140000 => "socket",
        _ => "unknown",
    }
}

/// stat: report file metadata in a fixed, deterministic format.
pub fn stat(argv: &[String]) -> i32 {
    let files: Vec<&String> = argv.iter().filter(|a| a.as_str() != "--").collect();
    if files.is_empty() {
        return usage("stat", "missing operand");
    }
    let mut code = EXIT_OK;
    for f in files {
        let md = match fs::symlink_metadata(f) {
            Ok(m) => m,
            Err(e) => {
                code = fail("stat", &format!("cannot stat '{f}': {e}"));
                continue;
            }
        };
        let mode = md.mode();
        println!("  File: {f}");
        println!("  Size: {}\tType: {}", md.size(), type_name(mode));
        println!(
            "Mode: ({:04o}/{})  Uid: {}  Gid: {}  Links: {}",
            mode & 0o7777,
            mode_string(mode),
            md.uid(),
            md.gid(),
            md.nlink()
        );
        println!("Modify: {}", crate::tools::sys::fmt_mtime(md.mtime()));
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn echo_render() {
        assert_eq!(render_echo(&args(&["hello", "world"])), b"hello world\n");
        assert_eq!(render_echo(&args(&["-n", "a", "b"])), b"a b");
        assert_eq!(render_echo(&args(&["-e", "a\\tb"])), b"a\tb\n");
        assert_eq!(render_echo(&args(&["-e", "x\\x41"])), b"xA\n");
        assert_eq!(render_echo(&args(&["-e", "q\\0101"])), b"qA\n");
    }

    #[test]
    fn mode_strings() {
        assert_eq!(mode_string(0o100644), "-rw-r--r--");
        assert_eq!(mode_string(0o040755), "drwxr-xr-x");
        assert_eq!(mode_string(0o120777), "lrwxrwxrwx");
        assert_eq!(mode_string(0o104755), "-rwsr-xr-x");
        assert_eq!(mode_string(0o041777), "drwxrwxrwt");
    }

    #[test]
    fn symbolic_modes() {
        assert_eq!(apply_symbolic(0o644, "u+x", false), Ok(0o744));
        assert_eq!(apply_symbolic(0o644, "+x", false), Ok(0o755));
        assert_eq!(apply_symbolic(0o646, "go-w", false), Ok(0o644));
        assert_eq!(apply_symbolic(0o755, "a=r", false), Ok(0o444));
        assert_eq!(apply_symbolic(0o644, "u+x,go-r", false), Ok(0o700));
        // X sets execute only when a directory or already executable
        assert_eq!(apply_symbolic(0o644, "a+X", true), Ok(0o755));
        assert_eq!(apply_symbolic(0o644, "a+X", false), Ok(0o644));
        assert_eq!(apply_symbolic(0o755, "a+X", false), Ok(0o755));
        assert_eq!(apply_symbolic(0o644, "u+s", false), Ok(0o4644));
        assert_eq!(apply_symbolic(0o644, "+t", false), Ok(0o1644));
    }

    #[test]
    fn dirname_cases() {
        assert_eq!(dirname_of("a"), ".");
        assert_eq!(dirname_of("a/b"), "a");
        assert_eq!(dirname_of("/a"), "/");
        assert_eq!(dirname_of("/"), "/");
        assert_eq!(dirname_of("a/b/"), "a");
    }

    #[test]
    fn protected_paths() {
        assert!(is_protected("/"));
        assert!(is_protected("."));
        assert!(is_protected(".."));
        assert!(is_protected("a/.."));
        assert!(!is_protected("some/file"));
        assert!(!is_protected("normal-dir"));
    }

    #[test]
    fn symlink_resolution() {
        let root = std::env::temp_dir().join(format!("nk-ls-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("real")).unwrap();
        fs::write(root.join("real/file"), b"x").unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let r = realpath_max(&root.join("link/file"), 40).unwrap();
        assert_eq!(r, root.join("real/file"));
        let _ = fs::remove_dir_all(&root);
    }
}
