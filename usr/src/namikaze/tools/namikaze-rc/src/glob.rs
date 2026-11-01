// SPDX-License-Identifier: MPL-2.0
//! Filename matching for rc: the `*`, `?` and `[class]` patterns of
//! rc(1), with a recursive matcher and directory expansion against an
//! explicit base (the tool passes the cwd, tests pass temp dirs).

use std::fs;
use std::path::Path;

/// Does `text` match the glob `pattern`? `*` spans any run (including
/// empty), `?` exactly one character, `[abc]`/`[a-c]`/`[!abc]` one
/// character from (or not from) a class. A class never matches `/`.
pub fn match_glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    match_from(&p, 0, &t, 0)
}

fn match_from(p: &[char], mut pi: usize, t: &[char], mut ti: usize) -> bool {
    loop {
        match p.get(pi) {
            None => return ti == t.len(),
            Some('*') => {
                // collapse consecutive stars, try every suffix
                let mut np = pi;
                while np < p.len() && p[np] == '*' {
                    np += 1;
                }
                for skip in ti..=t.len() {
                    if match_from(p, np, t, skip) {
                        return true;
                    }
                }
                return false;
            }
            Some('?') => {
                if ti >= t.len() {
                    return false;
                }
                pi += 1;
                ti += 1;
            }
            Some('[') => {
                let close = match p[pi + 1..].iter().position(|c| *c == ']') {
                    Some(off) => pi + 1 + off,
                    None => {
                        // literal '[' when unterminated
                        if ti < t.len() && t[ti] == '[' {
                            pi += 1;
                            ti += 1;
                            continue;
                        }
                        return false;
                    }
                };
                if ti >= t.len() || t[ti] == '/' || !class_matches(&p[pi + 1..close], t[ti]) {
                    return false;
                }
                pi = close + 1;
                ti += 1;
            }
            Some(c) => {
                if ti >= t.len() || t[ti] != *c {
                    return false;
                }
                pi += 1;
                ti += 1;
            }
        }
    }
}

fn class_matches(class: &[char], c: char) -> bool {
    let (negate, class) = match class.first() {
        Some('!') | Some('^') => (true, &class[1..]),
        _ => (false, class),
    };
    let mut hit = false;
    let mut i = 0;
    while i < class.len() {
        if i + 2 < class.len() && class[i + 1] == '-' {
            if c >= class[i] && c <= class[i + 2] {
                hit = true;
            }
            i += 3;
        } else {
            if c == class[i] {
                hit = true;
            }
            i += 1;
        }
    }
    hit != negate
}

/// Expand one pattern against `base`. The pattern may carry a
/// directory prefix; only the leaf is matched. No match yields the
/// pattern unchanged, as rc does. Results are sorted.
pub fn expand_in(base: &Path, pattern: &str) -> Vec<String> {
    let has_meta = pattern.contains('*') || pattern.contains('?') || pattern.contains('[');
    if !has_meta {
        return vec![pattern.to_string()];
    }
    let (dir_part, leaf) = match pattern.rfind('/') {
        Some(idx) => (&pattern[..idx], &pattern[idx + 1..]),
        None => ("", pattern),
    };
    let dir = if dir_part.is_empty() {
        base.to_path_buf()
    } else if Path::new(dir_part).is_absolute() {
        std::path::PathBuf::from(dir_part)
    } else {
        base.join(dir_part)
    };
    let mut out = Vec::new();
    match fs::read_dir(&dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') && !leaf.starts_with('.') {
                    continue; // dotfiles need an explicit dot, sh-style
                }
                if match_glob(leaf, &name) {
                    let joined = if dir_part.is_empty() {
                        name.clone()
                    } else {
                        format!("{dir_part}/{name}")
                    };
                    // a directory match keeps globbing open: `src/*`
                    // matches dirs, callers re-glob if needed; keep the
                    // plain path here, like rc
                    out.push(joined);
                }
            }
        }
        // an unreadable directory yields no matches; the caller then
        // keeps the literal pattern
        Err(_) => {}
    }
    out.sort();
    if out.is_empty() {
        vec![pattern.to_string()]
    } else {
        out
    }
}

/// Expand against the process working directory.
pub fn expand(pattern: &str) -> Vec<String> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    expand_in(&cwd, pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_spans_anything() {
        assert!(match_glob("*", ""));
        assert!(match_glob("*", "anything at all"));
        assert!(match_glob("a*", "apple"));
        assert!(!match_glob("a*", "banana"));
        assert!(match_glob("*x", "box"));
        assert!(!match_glob("*x", "boxy"));
        assert!(match_glob("a*b*c", "a-x-b-y-c"));
    }

    #[test]
    fn question_matches_exactly_one() {
        assert!(match_glob("a?c", "abc"));
        assert!(!match_glob("a?c", "ac"));
        assert!(!match_glob("a?c", "abbc"));
    }

    #[test]
    fn classes_and_negation() {
        assert!(match_glob("[abc]at", "bat"));
        assert!(!match_glob("[abc]at", "dat"));
        assert!(match_glob("[a-c]at", "cat"));
        assert!(match_glob("[!a-c]at", "dat"));
        assert!(!match_glob("[!a-c]at", "bat"));
        // classes do not match the path separator
        assert!(!match_glob("[a-z]*", "/etc/passwd"));
    }

    #[test]
    fn unterminated_class_is_literal() {
        assert!(match_glob("a[bc", "a[bc"));
    }

    #[test]
    fn expansion_sorts_and_keeps_literal_on_miss() {
        let base = std::env::temp_dir().join(format!("rc-glob-{}", std::process::id()));
        fs::create_dir_all(&base).expect("mkdir");
        for name in ["bravo", "alpha", "charlie"] {
            fs::write(base.join(name), b"x").expect("touch");
        }
        fs::create_dir_all(base.join(".hidden")).expect("mkdir dot");
        let hits = expand_in(&base, "*");
        assert_eq!(hits, vec!["alpha", "bravo", "charlie"], "sorted, dotfiles hidden");
        assert_eq!(expand_in(&base, "zz*"), vec!["zz*"], "no match keeps the pattern");
        assert_eq!(expand_in(&base, ".h*"), vec![".hidden"], "explicit dot matches dotfiles");
        fs::remove_dir_all(&base).expect("cleanup");
    }
}
