// SPDX-License-Identifier: MPL-2.0
#![forbid(unsafe_code)]
//! Hashing and comparison tools: sha256sum, comm, mktemp, clear, cmp.

use std::fs;
use std::io::{self, Read, Write};

use crate::{fail, usage, EXIT_OK};
use namikaze_rt::sha256::Sha256;

// ------------------------------------------------------------- sha256sum ----

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// sha256sum: FIPS 180-4 digests of each input (or stdin for "-").
pub fn sha256sum(argv: &[String]) -> i32 {
    let names: Vec<String> = if argv.is_empty() {
        vec![String::from("-")]
    } else {
        argv.iter().filter(|a| a.as_str() != "--").cloned().collect()
    };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut code = EXIT_OK;
    for name in &names {
        let data_res: Result<Vec<u8>, String> = if name == "-" {
            let mut data = Vec::new();
            io::stdin()
                .lock()
                .read_to_end(&mut data)
                .map(|_| data)
                .map_err(|e| e.to_string())
        } else {
            fs::read(name).map_err(|e| format!("cannot open {name}: {e}"))
        };
        match data_res {
            Ok(data) => {
                let _ = writeln!(out, "{}  {name}", sha256_hex(&data));
            }
            Err(msg) => {
                code = fail("sha256sum", &msg);
            }
        }
    }
    let _ = out.flush();
    code
}

// ---------------------------------------------------------------- clear ----

/// clear: reset cursor and erase the visible screen plus scrollback.
pub fn clear(_argv: &[String]) -> i32 {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    // CSI H (home), CSI 2J (erase screen), CSI 3J (erase scrollback).
    let _ = out.write_all(b"\x1b[H\x1b[2J\x1b[3J");
    let _ = out.flush();
    EXIT_OK
}

// ------------------------------------------------------------------ cmp ----

/// cmp: byte-exact comparison of two inputs. "-s" stays silent; exit 0
/// when equal, 1 when different, 2 on trouble. "-" reads stdin once.
pub fn cmp(argv: &[String]) -> i32 {
    let mut silent = false;
    let mut files: Vec<String> = Vec::new();
    for a in argv {
        match a.as_str() {
            "-s" | "--silent" | "--quiet" => silent = true,
            "--" => {}
            s if s.starts_with('-') && s.len() > 1 => {
                return usage("cmp", &format!("unknown option: {s}"));
            }
            s => files.push(s.to_string()),
        }
    }
    if files.len() != 2 {
        return usage("cmp", "need exactly two inputs");
    }
    let read_one = |name: &str| -> Result<Vec<u8>, String> {
        if name == "-" {
            let mut data = Vec::new();
            io::stdin()
                .lock()
                .read_to_end(&mut data)
                .map(|_| data)
                .map_err(|e| e.to_string())
        } else {
            fs::read(name).map_err(|e| format!("cannot open {name}: {e}"))
        }
    };
    let a = match read_one(&files[0]) {
        Ok(d) => d,
        Err(e) => return fail("cmp", &e),
    };
    let b = match read_one(&files[1]) {
        Ok(d) => d,
        Err(e) => return fail("cmp", &e),
    };
    if a == b {
        return EXIT_OK;
    }
    if !silent {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        let common = a.len().min(b.len());
        match a.iter().zip(b.iter()).position(|(x, y)| x != y) {
            Some(pos) => {
                let line = 1 + a[..pos].iter().filter(|c| **c == b'\n').count();
                let _ = writeln!(
                    out,
                    "{0} {1} differ: byte {2}, line {3}",
                    files[0],
                    files[1],
                    pos + 1,
                    line
                );
            }
            None => {
                // one input is a strict prefix of the other
                let (shorter, longer) = if a.len() < b.len() {
                    (&files[0], &files[1])
                } else {
                    (&files[1], &files[0])
                };
                let _ = writeln!(
                    out,
                    "cmp: EOF on {shorter} which is shorter than {longer} after byte {common}"
                );
            }
        }
        let _ = out.flush();
    }
    crate::EXIT_FAILURE
}

// ----------------------------------------------------------------- comm ----

/// comm: compare two sorted files line by line; -1 -2 -3 suppress columns.
pub fn comm(argv: &[String]) -> i32 {
    let mut suppress = [false; 3];
    let mut files: Vec<String> = Vec::new();
    for a in argv {
        match a.as_str() {
            "-1" => suppress[0] = true,
            "-2" => suppress[1] = true,
            "-3" => suppress[2] = true,
            "--" => {}
            other if other.starts_with('-') && other.len() > 1 => {
                return usage("comm", &format!("unsupported option: {other}"));
            }
            other => files.push(other.to_string()),
        }
    }
    if files.len() != 2 {
        return usage("comm", "need exactly two files");
    }
    let mut contents: Vec<Vec<Vec<u8>>> = Vec::new();
    for f in &files {
        if f == "-" {
            let mut data = Vec::new();
            if let Err(e) = io::stdin().lock().read_to_end(&mut data) {
                return fail("comm", &format!("stdin: {e}"));
            }
            contents.push(split_lines(&data));
        } else {
            match fs::read(f) {
                Ok(data) => contents.push(split_lines(&data)),
                Err(e) => return fail("comm", &format!("cannot open {f}: {e}")),
            }
        }
    }
    let a = contents.remove(0);
    let b = contents.remove(0);
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut code = EXIT_OK;
    let emit = |out: &mut dyn Write, col: usize, line: &[u8]| -> io::Result<()> {
        if col == 2 {
            out.write_all(b"\t")?;
        } else if col == 3 {
            out.write_all(b"\t\t")?;
        }
        out.write_all(line)?;
        out.write_all(b"\n")
    };
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => {
                if !suppress[0] {
                    if emit(&mut out, 1, &a[i]).is_err() {
                        code = fail("comm", "stdout write failed");
                    }
                }
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                if !suppress[1] {
                    if emit(&mut out, 2, &b[j]).is_err() {
                        code = fail("comm", "stdout write failed");
                    }
                }
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                if !suppress[2] {
                    if emit(&mut out, 3, &a[i]).is_err() {
                        code = fail("comm", "stdout write failed");
                    }
                }
                i += 1;
                j += 1;
            }
        }
    }
    for line in &a[i..] {
        if !suppress[0] {
            let _ = emit(&mut out, 1, line);
        }
    }
    for line in &b[j..] {
        if !suppress[1] {
            let _ = emit(&mut out, 2, line);
        }
    }
    let _ = out.flush();
    code
}

fn split_lines(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    for &b in data {
        if b == b'\n' {
            out.push(cur.clone());
            cur.clear();
        } else {
            cur.push(b);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

// ---------------------------------------------------------------- mktemp ----

const MKTEMP_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn random_suffix(seed: &[u8], len: usize) -> String {
    seed.iter()
        .take(len)
        .map(|&b| MKTEMP_CHARS[(b % (MKTEMP_CHARS.len() as u8)) as usize] as char)
        .collect()
}

fn read_urandom(n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf)
}

/// mktemp: create a uniquely named file (or directory with -d) from a
/// TEMPLATE with a trailing run of at least three X's.
pub fn mktemp(argv: &[String]) -> i32 {
    let mut make_dir = false;
    let mut template: Option<String> = None;
    for a in argv {
        match a.as_str() {
            "-d" => make_dir = true,
            "--" => {}
            other if other.starts_with('-') && other.len() > 1 => {
                return usage("mktemp", &format!("unsupported option: {other}"));
            }
            other => {
                if template.is_some() {
                    return usage("mktemp", "at most one TEMPLATE expected");
                }
                template = Some(other.to_string());
            }
        }
    }
    let (dir_of, tpl) = match template {
        Some(t) => {
            let p = std::path::Path::new(&t);
            let parent = p.parent().filter(|c| !c.as_os_str().is_empty()).map(|c| c.to_path_buf());
            (parent, t)
        }
        None => (Some(std::path::PathBuf::from("/tmp")), String::from("tmp.XXXXXXXXXX")),
    };
    let xs = tpl.bytes().rev().take_while(|&b| b == b'X').count();
    if xs < 3 {
        return fail("mktemp", "template must end in at least three X's");
    }
    let base = &tpl[..tpl.len() - xs];
    let dir = match dir_of {
        Some(d) => d,
        None => std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
    };
    for _ in 0..100 {
        let seed = match read_urandom(xs) {
            Ok(s) => s,
            Err(e) => return fail("mktemp", &format!("cannot read /dev/urandom: {e}")),
        };
        let candidate = dir.join(format!("{base}{}", random_suffix(&seed, xs)));
        let created = if make_dir {
            fs::create_dir(&candidate).map(|_| ())
        } else {
            fs::OpenOptions::new().write(true).create_new(true).open(&candidate).map(|_| ())
        };
        match created {
            Ok(()) => {
                println!("{}", candidate.display());
                return EXIT_OK;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return fail("mktemp", &format!("{}: {e}", candidate.display())),
        }
    }
    fail("mktemp", "too many collisions")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn line_splitting() {
        assert_eq!(split_lines(b"a\nb\n"), vec![b"a".to_vec(), b"b".to_vec()]);
        assert_eq!(split_lines(b"a\nb"), vec![b"a".to_vec(), b"b".to_vec()]);
        assert_eq!(split_lines(b""), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn mktemp_suffixes() {
        let s = random_suffix(&[0, 1, 2, 3], 4);
        assert_eq!(s.len(), 4);
        assert!(s.chars().all(|c| MKTEMP_CHARS.contains(&(c as u8))));
    }

    #[test]
    fn mktemp_creates_unique_files() {
        let root = std::env::temp_dir().join(format!("nk-mktemp-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let tpl = root.join("t.XXXXXX").to_string_lossy().into_owned();
        let args = vec![tpl.clone()];
        assert_eq!(mktemp(&args), EXIT_OK);
        assert_eq!(mktemp(&args), EXIT_OK);
        let mut count = 0;
        for entry in fs::read_dir(&root).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            if name.starts_with("t.") {
                count += 1;
            }
        }
        assert_eq!(count, 2);
        let _ = fs::remove_dir_all(&root);
    }
}
