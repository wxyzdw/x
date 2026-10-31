// SPDX-License-Identifier: MPL-2.0
#![forbid(unsafe_code)]
//! Text tools: head, tail, wc, tr, sort, uniq, tee, seq, cut, paste,
//! expand, fold.
//!
//! All tools are byte-exact on input (read_until, never lossy), sort in
//! plain byte order (C locale) and stream wherever practical.

use std::collections::VecDeque;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Seek, Write};

use crate::{fail, usage, EXIT_FAILURE, EXIT_OK};

/// Collect input lines as raw byte vectors from files (or stdin for "-").
/// Returns the collected lines plus false on the first read error.
struct LineSource {
    lines: Vec<Vec<u8>>,
    error: Option<String>,
}

fn read_lines(source: &str) -> LineSource {
    let mut lines = Vec::new();
    let mut error = None;
    let mut feed: Box<dyn BufRead> = if source == "-" {
        Box::new(BufReader::new(io::stdin()))
    } else {
        match fs::File::open(source) {
            Ok(f) => Box::new(BufReader::new(f)),
            Err(e) => {
                return LineSource { lines, error: Some(format!("cannot open {source}: {e}")) }
            }
        }
    };
    let mut buf: Vec<u8> = Vec::new();
    loop {
        buf.clear();
        match feed.read_until(b'\n', &mut buf) {
            Ok(0) => break,
            Ok(_) => {
                if buf.last() == Some(&b'\n') {
                    buf.pop();
                }
                lines.push(buf.clone());
            }
            Err(e) => {
                error = Some(format!("read error on {source}: {e}"));
                break;
            }
        }
    }
    LineSource { lines, error }
}

fn write_lines(lines: &[Vec<u8>]) -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for l in lines {
        out.write_all(l)?;
        out.write_all(b"\n")?;
    }
    out.flush()
}

// ----------------------------------------------------------------- head ----

/// Parsed head/tail invocation: (line limit, byte limit, file list).
type HeadTailOpts = (Option<u64>, Option<u64>, Vec<String>);

fn parse_head_tail(argv: &[String], tool: &str) -> Result<HeadTailOpts, i32> {
    let mut lines: Option<u64> = None;
    let mut bytes: Option<u64> = None;
    let mut files: Vec<String> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--" {
            for rest in &argv[i + 1..] {
                files.push(rest.clone());
            }
            break;
        }
        let parse_value = |txt: &str| -> Result<u64, i32> {
            match txt.parse::<u64>() {
                Ok(v) => Ok(v),
                Err(_) => Err(usage(tool, &format!("bad count: {txt}"))),
            }
        };
        if a == "-n" {
            i += 1;
            let Some(v) = argv.get(i) else { return Err(usage(tool, "-n needs a count")) };
            lines = Some(parse_value(v)?);
        } else if let Some(v) = a.strip_prefix("-n") {
            lines = Some(parse_value(v)?);
        } else if a == "-c" {
            i += 1;
            let Some(v) = argv.get(i) else { return Err(usage(tool, "-c needs a count")) };
            bytes = Some(parse_value(v)?);
        } else if let Some(v) = a.strip_prefix("-c") {
            bytes = Some(parse_value(v)?);
        } else if a.starts_with('-') && a.len() > 1 {
            return Err(usage(tool, &format!("unsupported option: {a}")));
        } else {
            files.push(a.to_string());
        }
        i += 1;
    }
    Ok((lines, bytes, files))
}

/// head: print the first lines (-n) or bytes (-c) of each input.
pub fn head(argv: &[String]) -> i32 {
    let (lines, bytes, files) = match parse_head_tail(argv, "head") {
        Ok(v) => v,
        Err(c) => return c,
    };
    let names: Vec<String> = if files.is_empty() { vec![String::from("-")] } else { files };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut code = EXIT_OK;
    for (idx, name) in names.iter().enumerate() {
        if names.len() > 1 {
            if idx > 0 {
                let _ = out.write_all(b"\n");
            }
            let _ = writeln!(out, "==> {name} <==");
        }
        let limit_bytes = bytes.map(|n| n as usize);
        let emitted: io::Result<()> = if name == "-" {
            emit_head(&mut io::stdin().lock(), &mut out, lines, limit_bytes)
        } else {
            match fs::File::open(name) {
                Ok(f) => emit_head(&mut BufReader::new(f), &mut out, lines, limit_bytes),
                Err(e) => {
                    let _ = writeln!(out, "namikaze-userland: head: cannot open {name}: {e}");
                    Err(io::Error::other("open failed"))
                }
            }
        };
        if emitted.is_err() {
            code = EXIT_FAILURE;
        }
    }
    let _ = out.flush();
    code
}

fn emit_head<R: Read>(
    r: &mut R,
    out: &mut dyn Write,
    lines: Option<u64>,
    bytes: Option<usize>,
) -> io::Result<()> {
    if let Some(n) = bytes {
        let mut taken = r.take(n as u64);
        io::copy(&mut taken, out)?;
        return Ok(());
    }
    let want = lines.unwrap_or(10);
    let mut buf: Vec<u8> = Vec::new();
    let mut shown = 0u64;
    let mut br = BufReader::new(r);
    while shown < want {
        buf.clear();
        let n = br.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        out.write_all(&buf)?;
        shown += 1;
    }
    Ok(())
}

// ----------------------------------------------------------------- tail ----

/// tail: print the last lines (-n) or bytes (-c) of each input.
pub fn tail(argv: &[String]) -> i32 {
    let (lines, bytes, files) = match parse_head_tail(argv, "tail") {
        Ok(v) => v,
        Err(c) => return c,
    };
    let names: Vec<String> = if files.is_empty() { vec![String::from("-")] } else { files };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut code = EXIT_OK;
    for (idx, name) in names.iter().enumerate() {
        if names.len() > 1 {
            if idx > 0 {
                let _ = out.write_all(b"\n");
            }
            let _ = writeln!(out, "==> {name} <==");
        }
        let r = (|| -> io::Result<()> {
            if let Some(n) = bytes {
                return emit_tail_bytes(name, n, &mut out);
            }
            let want = lines.unwrap_or(10);
            emit_tail_lines(name, want, &mut out)
        })();
        if let Err(e) = r {
            let _ = writeln!(out, "namikaze-userland: tail: {name}: {e}");
            code = EXIT_FAILURE;
        }
    }
    let _ = out.flush();
    code
}

fn emit_tail_lines(name: &str, want: u64, out: &mut dyn Write) -> io::Result<()> {
    let cap = want as usize;
    let mut ring: VecDeque<Vec<u8>> = VecDeque::new();
    if name == "-" {
        let stdin = io::stdin();
        let mut br = BufReader::new(stdin.lock());
        let mut buf: Vec<u8> = Vec::new();
        loop {
            buf.clear();
            if br.read_until(b'\n', &mut buf)? == 0 {
                break;
            }
            if ring.len() == cap {
                ring.pop_front();
            }
            ring.push_back(buf.clone());
        }
    } else {
        let f = fs::File::open(name)?;
        let mut br = BufReader::new(f);
        let mut buf: Vec<u8> = Vec::new();
        loop {
            buf.clear();
            if br.read_until(b'\n', &mut buf)? == 0 {
                break;
            }
            if ring.len() == cap {
                ring.pop_front();
            }
            ring.push_back(buf.clone());
        }
    }
    for line in &ring {
        out.write_all(line)?;
    }
    Ok(())
}

fn emit_tail_bytes(name: &str, n: u64, out: &mut dyn Write) -> io::Result<()> {
    if name == "-" {
        let mut data = Vec::new();
        io::stdin().lock().read_to_end(&mut data)?;
        let start = data.len().saturating_sub(n as usize);
        out.write_all(&data[start..])?;
        return Ok(());
    }
    let mut f = fs::File::open(name)?;
    let len = f.metadata()?.len();
    if len > n {
        f.seek(io::SeekFrom::Start(len - n))?;
    }
    io::copy(&mut f, out)?;
    Ok(())
}

// ------------------------------------------------------------------- wc ----

struct Wc {
    lines: u64,
    words: u64,
    bytes: u64,
}

fn count_wc(data: &[u8]) -> Wc {
    let mut w = Wc { lines: 0, words: 0, bytes: data.len() as u64 };
    let mut in_word = false;
    for &b in data {
        if b == b'\n' {
            w.lines += 1;
        }
        let is_space = matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
        if is_space {
            in_word = false;
        } else if !in_word {
            in_word = true;
            w.words += 1;
        }
    }
    w
}

/// wc: count lines, words and bytes per input; a total row for many files.
pub fn wc(argv: &[String]) -> i32 {
    let mut want_lines = false;
    let mut want_words = false;
    let mut want_bytes = false;
    let mut files: Vec<String> = Vec::new();
    for a in argv {
        let short = a.starts_with('-') && a.len() > 1 && a[1..].chars().all(|c| "lwc".contains(c));
        if a == "--" {
            continue;
        } else if short {
            for c in a[1..].chars() {
                match c {
                    'l' => want_lines = true,
                    'w' => want_words = true,
                    _ => want_bytes = true,
                }
            }
        } else if a.starts_with('-') && a.len() > 1 {
            return usage("wc", &format!("unsupported option: {a}"));
        } else {
            files.push(a.clone());
        }
    }
    if !want_lines && !want_words && !want_bytes {
        want_lines = true;
        want_words = true;
        want_bytes = true;
    }
    let names: Vec<String> = if files.is_empty() { vec![String::from("-")] } else { files };
    let mut code = EXIT_OK;
    let mut total = Wc { lines: 0, words: 0, bytes: 0 };
    for name in &names {
        let data_res: Result<Vec<u8>, String> = if name == "-" {
            let mut data = Vec::new();
            match io::stdin().lock().read_to_end(&mut data) {
                Ok(_) => Ok(data),
                Err(e) => Err(e.to_string()),
            }
        } else {
            fs::read(name).map_err(|e| format!("cannot open {name}: {e}"))
        };
        match data_res {
            Err(msg) => {
                code = fail("wc", &msg);
                continue;
            }
            Ok(data) => {
                let w = count_wc(&data);
                total.lines += w.lines;
                total.words += w.words;
                total.bytes += w.bytes;
                print_wc(&w, name, want_lines, want_words, want_bytes);
            }
        }
    }
    if names.len() > 1 {
        print_wc(&total, "total", want_lines, want_words, want_bytes);
    }
    code
}

fn print_wc(w: &Wc, name: &str, l: bool, wr: bool, b: bool) {
    let mut fields: Vec<String> = Vec::new();
    if l {
        fields.push(format!("{:>8}", w.lines));
    }
    if wr {
        fields.push(format!("{:>8}", w.words));
    }
    if b {
        fields.push(format!("{:>8}", w.bytes));
    }
    println!("{} {name}", fields.join(" "));
}

// ------------------------------------------------------------------- tr ----

fn parse_escape(bytes: &[u8], i: &mut usize) -> Result<u8, String> {
    let c = bytes[*i];
    *i += 1;
    if c != b'\\' {
        return Ok(c);
    }
    if *i >= bytes.len() {
        return Err(String::from("trailing backslash in set"));
    }
    let e = bytes[*i];
    *i += 1;
    Ok(match e {
        b'n' => b'\n',
        b't' => b'\t',
        b'r' => b'\r',
        b'a' => 0x07,
        b'b' => 0x08,
        b'f' => 0x0c,
        b'v' => 0x0b,
        b'\\' => b'\\',
        b'0' => 0,
        b'x' => {
            let mut val: u32 = 0;
            let mut cnt = 0;
            while cnt < 2 && *i < bytes.len() && bytes[*i].is_ascii_hexdigit() {
                val = val * 16 + (bytes[*i] as char).to_digit(16).unwrap_or(0);
                *i += 1;
                cnt += 1;
            }
            if cnt == 0 {
                return Err(String::from("\\x needs hex digits"));
            }
            (val & 0xff) as u8
        }
        other => other,
    })
}

fn expand_set(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c1 = parse_escape(bytes, &mut i)?;
        if i + 1 < bytes.len() && bytes[i] == b'-' {
            i += 1;
            let c2 = parse_escape(bytes, &mut i)?;
            if c2 < c1 {
                return Err(format!("bad range {c1}-{c2}"));
            }
            for b in c1..=c2 {
                out.push(b);
            }
        } else {
            out.push(c1);
        }
    }
    Ok(out)
}

/// tr: translate, squeeze (-s) or delete (-d) bytes from stdin.
pub fn tr(argv: &[String]) -> i32 {
    let mut delete = false;
    let mut squeeze = false;
    let mut sets: Vec<String> = Vec::new();
    for a in argv {
        match a.as_str() {
            "-d" => delete = true,
            "-s" => squeeze = true,
            "--" => {}
            other if other.starts_with('-') && other.len() > 1 => {
                return usage("tr", &format!("unsupported option: {other}"));
            }
            other => sets.push(other.to_string()),
        }
    }
    if sets.is_empty() || (!delete && sets.len() < 2) {
        return usage("tr", "need one or two SETs");
    }
    let set1 = match expand_set(&sets[0]) {
        Ok(v) => v,
        Err(e) => return fail("tr", &e),
    };
    let set2: Vec<u8> = if delete {
        Vec::new()
    } else {
        match expand_set(&sets[1]) {
            Ok(v) => v,
            Err(e) => return fail("tr", &e),
        }
    };

    // translation map: for each input byte, the replacement or deletion
    let mut map: [Option<u8>; 256] = [None; 256];
    for (i, slot) in map.iter_mut().enumerate() {
        *slot = Some(i as u8);
    }
    if delete {
        for b in &set1 {
            map[*b as usize] = None;
        }
    } else {
        for (idx, b) in set1.iter().enumerate() {
            let replacement = set2.get(idx).or_else(|| set2.last()).copied().unwrap_or(*b);
            map[*b as usize] = Some(replacement);
        }
    }
    let squeeze_set: Vec<u8> = if squeeze && delete {
        set1.clone()
    } else if squeeze {
        set2.clone()
    } else {
        Vec::new()
    };

    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut code = EXIT_OK;
    let mut pending: Option<u8> = None;
    let mut chunk = [0u8; 65536];
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                for &b in &chunk[..n] {
                    let nb = match map[b as usize] {
                        Some(x) => x,
                        None => continue,
                    };
                    if !squeeze_set.is_empty() && squeeze_set.contains(&nb) {
                        if pending == Some(nb) {
                            continue;
                        }
                        pending = Some(nb);
                    } else {
                        pending = None;
                    }
                    if out.write_all(&[nb]).is_err() {
                        code = fail("tr", "stdout write failed");
                        return code;
                    }
                }
            }
            Err(e) => {
                code = fail("tr", &format!("stdin: {e}"));
                break;
            }
        }
    }
    let _ = out.flush();
    code
}

// ----------------------------------------------------------------- sort ----

fn leading_number(line: &[u8]) -> f64 {
    let mut idx = 0;
    while idx < line.len() && (line[idx] as char).is_whitespace() {
        idx += 1;
    }
    let mut end = idx;
    if end < line.len() && (line[end] == b'+' || line[end] == b'-') {
        end += 1;
    }
    while end < line.len() && line[end].is_ascii_digit() {
        end += 1;
    }
    let txt = std::str::from_utf8(&line[idx..end]).unwrap_or("");
    txt.parse::<f64>().unwrap_or(0.0)
}

/// sort: order lines in plain byte order; -r reverse, -u unique, -n numeric.
pub fn sort(argv: &[String]) -> i32 {
    let mut reverse = false;
    let mut unique = false;
    let mut numeric = false;
    let mut files: Vec<String> = Vec::new();
    for a in argv {
        let short = a.starts_with('-') && a.len() > 1 && a[1..].chars().all(|c| "run".contains(c));
        if a == "--" {
            continue;
        } else if short {
            for c in a[1..].chars() {
                match c {
                    'r' => reverse = true,
                    'u' => unique = true,
                    _ => numeric = true,
                }
            }
        } else if a.starts_with('-') && a.len() > 1 {
            return usage("sort", &format!("unsupported option: {a}"));
        } else {
            files.push(a.clone());
        }
    }
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let names: Vec<String> = if files.is_empty() { vec![String::from("-")] } else { files };
    let mut code = EXIT_OK;
    for name in &names {
        let src = read_lines(name);
        if let Some(e) = src.error {
            code = fail("sort", &e);
            continue;
        }
        lines.extend(src.lines);
    }
    if numeric {
        lines.sort_by(|a, b| {
            let ka = leading_number(a);
            let kb = leading_number(b);
            ka.partial_cmp(&kb).unwrap_or(std::cmp::Ordering::Equal).then(a.cmp(b))
        });
    } else {
        lines.sort();
    }
    if reverse {
        lines.reverse();
    }
    if unique {
        lines.dedup();
    }
    if write_lines(&lines).is_err() {
        code = fail("sort", "stdout write failed");
    }
    code
}

// ----------------------------------------------------------------- uniq ----

/// uniq: collapse repeated adjacent lines; -c counts, -d repeats only,
/// -u uniques only.
pub fn uniq(argv: &[String]) -> i32 {
    let mut counts = false;
    let mut dups = false;
    let mut singles = false;
    let mut files: Vec<String> = Vec::new();
    for a in argv {
        let short = a.starts_with('-') && a.len() > 1 && a[1..].chars().all(|c| "cdu".contains(c));
        if a == "--" {
            continue;
        } else if short {
            for c in a[1..].chars() {
                match c {
                    'c' => counts = true,
                    'd' => dups = true,
                    _ => singles = true,
                }
            }
        } else if a.starts_with('-') && a.len() > 1 {
            return usage("uniq", &format!("unsupported option: {a}"));
        } else {
            files.push(a.clone());
        }
    }
    if files.len() > 2 {
        return usage("uniq", "at most INPUT and OUTPUT expected");
    }
    let input = files.first().cloned().unwrap_or_else(|| String::from("-"));
    let src = read_lines(&input);
    if let Some(e) = src.error {
        return fail("uniq", &e);
    }
    let mut out_lines: Vec<Vec<u8>> = Vec::new();
    let mut i = 0;
    while i < src.lines.len() {
        let mut n = 1u64;
        while i + (n as usize) < src.lines.len() && src.lines[i + n as usize] == src.lines[i] {
            n += 1;
        }
        let is_dup = n > 1;
        let keep = (!dups && !singles) || (dups && is_dup) || (singles && !is_dup);
        if keep {
            let prefix = if counts { format!("{n:>7} ") } else { String::new() };
            let mut line = prefix.into_bytes();
            line.extend_from_slice(&src.lines[i]);
            out_lines.push(line);
        }
        i += n as usize;
    }
    if write_lines(&out_lines).is_err() {
        return fail("uniq", "stdout write failed");
    }
    EXIT_OK
}

// ------------------------------------------------------------------ tee ----

/// tee: copy stdin to stdout and every named file; -a appends.
pub fn tee(argv: &[String]) -> i32 {
    let mut append = false;
    let mut files: Vec<String> = Vec::new();
    for a in argv {
        match a.as_str() {
            "-a" => append = true,
            "--" => {}
            other if other.starts_with('-') && other.len() > 1 => {
                return usage("tee", &format!("unsupported option: {other}"));
            }
            other => files.push(other.to_string()),
        }
    }
    let stdout = io::stdout();
    let mut sinks: Vec<Box<dyn Write>> = vec![Box::new(stdout.lock())];
    for f in &files {
        match fs::OpenOptions::new().write(true).create(true).append(append).open(f) {
            Ok(h) => sinks.push(Box::new(h)),
            Err(e) => return fail("tee", &format!("cannot open {f}: {e}")),
        }
    }
    let mut code = EXIT_OK;
    let mut stdin = io::stdin();
    let mut chunk = [0u8; 65536];
    loop {
        match stdin.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                for s in sinks.iter_mut() {
                    if let Err(e) = s.write_all(&chunk[..n]) {
                        code = fail("tee", &format!("write failed: {e}"));
                    }
                }
            }
            Err(e) => {
                code = fail("tee", &format!("stdin: {e}"));
                break;
            }
        }
    }
    for s in sinks.iter_mut() {
        let _ = s.flush();
    }
    code
}

// ------------------------------------------------------------------ seq ----

fn fmt_seq(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/// seq: print a number sequence; seq LAST, seq FIRST LAST or
/// seq FIRST INCR LAST (integers or decimals).
pub fn seq(argv: &[String]) -> i32 {
    let mut nums: Vec<f64> = Vec::new();
    for a in argv.iter().filter(|a| a.as_str() != "--") {
        match a.parse::<f64>() {
            Ok(v) if v.is_finite() => nums.push(v),
            _ => return usage("seq", &format!("not a number: {a}")),
        }
    }
    let (first, incr, last) = match nums.len() {
        1 => (1.0, 1.0, nums[0]),
        2 => (nums[0], 1.0, nums[1]),
        3 => (nums[0], nums[1], nums[2]),
        _ => return usage("seq", "expected up to three numbers"),
    };
    if incr == 0.0 {
        return fail("seq", "zero increment");
    }
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut code = EXIT_OK;
    let mut i = 0u64;
    loop {
        let v = first + i as f64 * incr;
        let done = (incr > 0.0 && v > last) || (incr < 0.0 && v < last);
        if done {
            break;
        }
        if i > 10_000_000 {
            code = fail("seq", "sequence too long");
            break;
        }
        if writeln!(out, "{}", fmt_seq(v)).is_err() {
            code = fail("seq", "stdout write failed");
            break;
        }
        i += 1;
    }
    let _ = out.flush();
    code
}

// ------------------------------------------------------------------ cut ----

type RangeList = Vec<(u32, Option<u32>)>;

fn parse_ranges(spec: &str) -> Result<RangeList, String> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        if part.is_empty() {
            return Err(String::from("empty range"));
        }
        if let Some(rest) = part.strip_prefix('-') {
            let end: u32 = rest.parse().map_err(|_| format!("bad range: {part}"))?;
            out.push((1, Some(end)));
            continue;
        }
        match part.split_once('-') {
            None => {
                let v: u32 = part.parse().map_err(|_| format!("bad range: {part}"))?;
                out.push((v, Some(v)));
            }
            Some((a, b)) => {
                let start: u32 = a.parse().map_err(|_| format!("bad range: {part}"))?;
                let end: Option<u32> = if b.is_empty() {
                    None
                } else {
                    Some(b.parse().map_err(|_| format!("bad range: {part}"))?)
                };
                out.push((start, end));
            }
        }
    }
    Ok(out)
}

fn in_ranges(ranges: &RangeList, idx: u32) -> bool {
    for (start, end) in ranges {
        if idx >= *start && end.map(|e| idx <= e).unwrap_or(true) {
            return true;
        }
    }
    false
}

/// cut: select byte ranges (-c) or delimiter fields (-f, -d, -s).
pub fn cut(argv: &[String]) -> i32 {
    let mut delim: u8 = b'\t';
    let mut fields: Option<RangeList> = None;
    let mut chars: Option<RangeList> = None;
    let mut only_delim = false;
    let mut files: Vec<String> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--" {
            for rest in &argv[i + 1..] {
                files.push(rest.clone());
            }
            break;
        }
        if a == "-d" {
            i += 1;
            match argv.get(i).and_then(|s| s.as_bytes().first().copied()) {
                Some(b) => delim = b,
                None => return usage("cut", "-d needs a one-byte delimiter"),
            }
        } else if let Some(spec) = a.strip_prefix("-d") {
            match spec.as_bytes().first().copied() {
                Some(b) => delim = b,
                None => return usage("cut", "-d needs a one-byte delimiter"),
            }
        } else if a == "-f" {
            i += 1;
            let Some(spec) = argv.get(i) else { return usage("cut", "-f needs a list") };
            match parse_ranges(spec) {
                Ok(r) => fields = Some(r),
                Err(e) => return fail("cut", &e),
            }
        } else if let Some(spec) = a.strip_prefix("-f") {
            match parse_ranges(spec) {
                Ok(r) => fields = Some(r),
                Err(e) => return fail("cut", &e),
            }
        } else if a == "-c" {
            i += 1;
            let Some(spec) = argv.get(i) else { return usage("cut", "-c needs a list") };
            match parse_ranges(spec) {
                Ok(r) => chars = Some(r),
                Err(e) => return fail("cut", &e),
            }
        } else if let Some(spec) = a.strip_prefix("-c") {
            match parse_ranges(spec) {
                Ok(r) => chars = Some(r),
                Err(e) => return fail("cut", &e),
            }
        } else if a == "-s" {
            only_delim = true;
        } else if a.starts_with('-') && a.len() > 1 {
            return usage("cut", &format!("unsupported option: {a}"));
        } else {
            files.push(a.to_string());
        }
        i += 1;
    }
    if fields.is_none() && chars.is_none() {
        return usage("cut", "need -f LIST or -c LIST");
    }
    if fields.is_some() && chars.is_some() {
        return usage("cut", "-f and -c are exclusive");
    }
    let names: Vec<String> = if files.is_empty() { vec![String::from("-")] } else { files };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut code = EXIT_OK;
    for name in &names {
        let src = read_lines(name);
        if let Some(e) = src.error {
            code = fail("cut", &e);
            continue;
        }
        for line in &src.lines {
            if let Some(ranges) = &chars {
                let mut piece: Vec<u8> = Vec::new();
                for (idx, &b) in line.iter().enumerate() {
                    if in_ranges(ranges, idx as u32 + 1) {
                        piece.push(b);
                    }
                }
                piece.push(b'\n');
                let _ = out.write_all(&piece);
                continue;
            }
            let empty: RangeList = Vec::new();
            let ranges = fields.as_ref().unwrap_or(&empty);
            let parts: Vec<&[u8]> = line.split(|&b| b == delim).collect();
            if parts.len() == 1 {
                if !only_delim {
                    let _ = out.write_all(line);
                    let _ = out.write_all(b"\n");
                }
                continue;
            }
            let mut piece: Vec<u8> = Vec::new();
            for (idx, part) in parts.iter().enumerate() {
                if in_ranges(ranges, idx as u32 + 1) {
                    if !piece.is_empty() {
                        piece.push(delim);
                    }
                    piece.extend_from_slice(part);
                }
            }
            piece.push(b'\n');
            let _ = out.write_all(&piece);
        }
    }
    let _ = out.flush();
    code
}

// ---------------------------------------------------------------- paste ----

/// paste: merge lines of inputs in parallel; -s serializes per file,
/// -d picks the delimiter list (cycled).
pub fn paste(argv: &[String]) -> i32 {
    let mut delims: Vec<u8> = vec![b'\t'];
    let mut serial = false;
    let mut files: Vec<String> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--" {
            for rest in &argv[i + 1..] {
                files.push(rest.clone());
            }
            break;
        }
        if a == "-d" {
            i += 1;
            let Some(spec) = argv.get(i) else { return usage("paste", "-d needs a list") };
            let list: Vec<u8> = spec.bytes().collect();
            if list.is_empty() {
                return usage("paste", "-d needs a list");
            }
            delims = list;
        } else if let Some(spec) = a.strip_prefix("-d") {
            let list: Vec<u8> = spec.bytes().collect();
            if list.is_empty() {
                return usage("paste", "-d needs a list");
            }
            delims = list;
        } else if a == "-s" {
            serial = true;
        } else if a.starts_with('-') && a.len() > 1 {
            return usage("paste", &format!("unsupported option: {a}"));
        } else {
            files.push(a.to_string());
        }
        i += 1;
    }
    let names: Vec<String> = if files.is_empty() { vec![String::from("-")] } else { files };
    let mut sources: Vec<Vec<Vec<u8>>> = Vec::new();
    for name in &names {
        let src = read_lines(name);
        if let Some(e) = src.error {
            return fail("paste", &e);
        }
        sources.push(src.lines);
    }
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let code = EXIT_OK;
    if serial {
        for lines in &sources {
            let mut piece: Vec<u8> = Vec::new();
            for (idx, l) in lines.iter().enumerate() {
                if idx > 0 {
                    piece.push(delims[(idx - 1) % delims.len()]);
                }
                piece.extend_from_slice(l);
            }
            piece.push(b'\n');
            let _ = out.write_all(&piece);
        }
    } else {
        let rows = sources.iter().map(Vec::len).max().unwrap_or(0);
        for r in 0..rows {
            let mut piece: Vec<u8> = Vec::new();
            for (used, lines) in sources.iter().enumerate() {
                if used > 0 {
                    piece.push(delims[(used - 1) % delims.len()]);
                }
                if let Some(l) = lines.get(r) {
                    piece.extend_from_slice(l);
                }
            }
            piece.push(b'\n');
            let _ = out.write_all(&piece);
        }
    }
    let _ = out.flush();
    code
}

// -------------------------------------------------------------- expand ----

/// expand: replace tabs with spaces on every tab stop (-t N, default 8).
/// Byte-exact: only 0x09 bytes are rewritten, everything else passes through.
pub fn expand(argv: &[String]) -> i32 {
    let mut width = 8usize;
    let mut files: Vec<String> = Vec::new();
    let mut iter = argv.iter().peekable();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-t" => match iter.peek().and_then(|n| n.parse::<usize>().ok()) {
                Some(w) if w > 0 => {
                    width = w;
                    let _ = iter.next();
                }
                _ => return usage("expand", "-t needs a positive number"),
            },
            s if s.starts_with("-t") && s.len() > 2 => match s[2..].parse::<usize>() {
                Ok(w) if w > 0 => width = w,
                _ => return usage("expand", &format!("bad tab stop: {s}")),
            },
            "--" => {}
            s if s.starts_with('-') && s.len() > 1 => {
                return usage("expand", &format!("unknown option: {s}"))
            }
            s => files.push(s.to_string()),
        }
    }
    let names: Vec<String> = if files.is_empty() { vec![String::from("-")] } else { files };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut code = EXIT_OK;
    for name in &names {
        let src = read_lines(name);
        if let Some(e) = src.error {
            code = fail("expand", &e);
            continue;
        }
        for line in &src.lines {
            let mut col = 0usize;
            for c in line {
                match *c {
                    b'\t' => {
                        let step = width - (col % width);
                        for _ in 0..step {
                            let _ = out.write_all(b" ");
                        }
                        col += step;
                    }
                    _ => {
                        let _ = out.write_all(&[*c]);
                        col += 1;
                    }
                }
            }
            let _ = out.write_all(b"\n");
        }
    }
    let _ = out.flush();
    code
}

// ---------------------------------------------------------------- fold ----

/// fold: wrap input lines at a column (-w N, default 80). "-s" prefers to
/// break after the last space before the limit; hard breaks win when a
/// single word exceeds the width.
pub fn fold(argv: &[String]) -> i32 {
    let mut width = 80usize;
    let mut break_spaces = false;
    let mut files: Vec<String> = Vec::new();
    let mut iter = argv.iter().peekable();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-w" => match iter.peek().and_then(|n| n.parse::<usize>().ok()) {
                Some(w) if w > 0 => {
                    width = w;
                    let _ = iter.next();
                }
                _ => return usage("fold", "-w needs a positive number"),
            },
            s if s.starts_with("-w") && s.len() > 2 => match s[2..].parse::<usize>() {
                Ok(w) if w > 0 => width = w,
                _ => return usage("fold", &format!("bad width: {s}")),
            },
            "-s" => break_spaces = true,
            "--" => {}
            s if s.starts_with('-') && s.len() > 1 => {
                return usage("fold", &format!("unknown option: {s}"))
            }
            s => files.push(s.to_string()),
        }
    }
    let names: Vec<String> = if files.is_empty() { vec![String::from("-")] } else { files };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut code = EXIT_OK;
    for name in &names {
        let src = read_lines(name);
        if let Some(e) = src.error {
            code = fail("fold", &e);
            continue;
        }
        for line in &src.lines {
            if line.len() <= width {
                let _ = out.write_all(line);
                let _ = out.write_all(b"\n");
                continue;
            }
            let mut start = 0usize;
            while start < line.len() {
                let mut end = (start + width).min(line.len());
                if end < line.len() && break_spaces {
                    if let Some(space) =
                        line[start..end].iter().rposition(|c| *c == b' ' || *c == b'\t')
                    {
                        if space > 0 {
                            end = start + space + 1;
                        }
                    }
                }
                let _ = out.write_all(&line[start..end]);
                let _ = out.write_all(b"\n");
                start = end;
            }
        }
    }
    let _ = out.flush();
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_expand() {
        assert_eq!(expand_set("ab").unwrap(), b"ab");
        assert_eq!(expand_set("a-c").unwrap(), b"abc");
        assert_eq!(expand_set("\\t").unwrap(), b"\t");
        assert_eq!(expand_set("\\x41").unwrap(), b"A");
        assert!(expand_set("c-a").is_err());
    }

    #[test]
    fn wc_counts() {
        let w = count_wc(b"hello world\nsecond line here\n");
        assert_eq!(w.lines, 2);
        assert_eq!(w.words, 5);
        assert_eq!(w.bytes, 29);
    }

    #[test]
    fn numeric_keys() {
        assert_eq!(leading_number(b"  42 apples"), 42.0);
        assert_eq!(leading_number(b"-7 x"), -7.0);
        assert_eq!(leading_number(b"no number"), 0.0);
    }

    #[test]
    fn ranges_parse() {
        let r = parse_ranges("1,3-5,-2,8-").unwrap();
        assert!(in_ranges(&r, 1));
        assert!(in_ranges(&r, 2)); // -2 means 1 through 2
        assert!(in_ranges(&r, 4));
        assert!(!in_ranges(&r, 6));
        assert!(!in_ranges(&r, 7));
        assert!(in_ranges(&r, 8));
        assert!(in_ranges(&r, 100));
        assert!(parse_ranges("bad,").is_err());
    }

    #[test]
    fn seq_format() {
        assert_eq!(fmt_seq(5.0), "5");
        assert_eq!(fmt_seq(-3.0), "-3");
        assert_eq!(fmt_seq(0.5), "0.5");
    }
}
