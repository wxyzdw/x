// SPDX-License-Identifier: MPL-2.0
//! The mkfile parser, following Plan 9's mk(1): assignments, rules
//! with attributes and tab-indented recipes, meta-rules with % and &,
//! `<file` includes and `<|file` execution includes.

use std::fmt;

/// A parsed mkfile element.
#[derive(Debug, Clone)]
pub enum Item {
    /// var=value value ... (a list; empty when nothing follows)
    Assign { var: String, values: Vec<String> },
    /// targets [attrs]: prereqs with the recipe lines that follow
    Rule {
        targets: Vec<String>,
        attrs: Vec<char>,
        prereqs: Vec<String>,
        recipe: Vec<String>,
        line: usize,
    },
    /// `<file` - the file include directive
    Include { file: String },
}

/// A parse failure with file and line.
#[derive(Debug, Clone)]
pub struct ParseError {
    pub file: String,
    pub line: usize,
    pub msg: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.file, self.line, self.msg)
    }
}

impl std::error::Error for ParseError {}

/// Parse a mkfile, expanding `<file` includes relative to the file's
/// directory. `$var` references in target/prereq/assignment words are
/// NOT expanded here - the engine expands at use time, as mk does.
pub fn parse_file(path: &str, depth: usize) -> Result<Vec<Item>, ParseError> {
    if depth > 16 {
        return Err(ParseError {
            file: path.to_string(),
            line: 0,
            msg: "includes nested more than 16 deep".into(),
        });
    }
    let text = std::fs::read_to_string(path).map_err(|e| {
        let msg = match e.kind() {
            std::io::ErrorKind::NotFound => format!("{path}: file does not exist"),
            std::io::ErrorKind::PermissionDenied => format!("{path}: permission denied"),
            _ => format!("{path}: {e}"),
        };
        ParseError { file: path.to_string(), line: 0, msg }
    })?;
    let dir = match path.rfind('/') {
        Some(idx) => path[..idx].to_string(),
        None => ".".to_string(),
    };
    let mut items = Vec::new();
    let mut lines = text.split('\n').peekable();
    let mut line_no = 0usize;
    while let Some(raw) = lines.next() {
        line_no += 1;
        let mut line = raw.to_string();
        // backslash continuation: the next line is glued, newline dropped
        while line.ends_with('\\') {
            line.pop();
            match lines.next() {
                Some(next) => {
                    line_no += 1;
                    line.push_str(next);
                }
                None => {
                    return Err(ParseError {
                        file: path.to_string(),
                        line: line_no,
                        msg: "continued past the last line of the file".into(),
                    });
                }
            }
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // include directives: `^<` followed by a file name
        if let Some(rest) = line.strip_prefix('<') {
            let file = rest.trim().to_string();
            if let Some(cmd) = file.strip_prefix('|') {
                return Err(ParseError {
                    file: path.to_string(),
                    line: line_no,
                    msg: format!("<|{cmd} execution includes are not supported by this port"),
                });
            }
            let joined = if file.starts_with('/') { file } else { format!("{dir}/{file}") };
            items.push(Item::Include { file: joined });
            continue;
        }
        // rule or assignment: a rule has a ':' at top level after the
        // targets; an assignment's first word ends with '='
        let first_word_end = line.find([' ', '\t']).unwrap_or(line.len());
        let first_word = &line[..first_word_end];
        if let Some(eq) = first_word.find('=') {
            if eq > 0 {
                let var = first_word[..eq].to_string();
                // the value may start inside the first word (CC=8c)
                let value_text = format!("{} {}", &first_word[eq + 1..], &line[first_word_end..]);
                let values = split_words(&value_text);
                items.push(Item::Assign { var, values });
                continue;
            }
        }
        // rule line: split targets [attrs]: prereqs
        let colon = match find_rule_colon(&line) {
            Some(idx) => idx,
            None => {
                return Err(ParseError {
                    file: path.to_string(),
                    line: line_no,
                    msg: format!(
                        "neither an assignment nor a rule: \"{line}\""
                    ),
                });
            }
        };
        let targets = split_words(&line[..colon]);
        if targets.is_empty() {
            return Err(ParseError {
                file: path.to_string(),
                line: line_no,
                msg: "rule with an empty target list".into(),
            });
        }
        let (attrs, rest) = match line[colon + 1..].find(':') {
            Some(inner) => {
                let attr_text = &line[colon + 1..colon + 1 + inner];
                // an attribute section is a short run of known letters
                let is_attrs = !attr_text.is_empty()
                    && attr_text
                        .chars()
                        .all(|c| matches!(c, 'D' | 'E' | 'N' | 'Q' | 'U' | 'V' | 'n'));
                if is_attrs && !attr_text.trim().is_empty() {
                    (attr_text.chars().filter(|c| *c != ' ').collect(), &line[colon + 2 + inner..])
                } else {
                    (Vec::new(), &line[colon + 1..])
                }
            }
            None => (Vec::new(), &line[colon + 1..]),
        };
        let prereqs = split_words(rest);
        // recipe: every following line that starts with a tab
        let mut recipe = Vec::new();
        while let Some(next) = lines.peek() {
            if !next.starts_with('\t') {
                break;
            }
            let mut recipe_line = lines.next().expect("peeked").to_string();
            line_no += 1;
            while recipe_line.ends_with('\\') {
                recipe_line.pop();
                match lines.next() {
                    Some(cont) => {
                        line_no += 1;
                        recipe_line.push_str(cont.trim_start());
                    }
                    None => {
                        return Err(ParseError {
                            file: path.to_string(),
                            line: line_no,
                            msg: "recipe continued past the last line of the file".into(),
                        });
                    }
                }
            }
            recipe.push(recipe_line[1..].to_string()); // elide the tab
        }
        items.push(Item::Rule { targets, attrs, prereqs, recipe, line: line_no });
    }
    Ok(items)
}

/// The colon that separates targets from attributes/prereqs: the first
/// ':' outside quotes and not part of a `::`? mk has no `::`; the
/// first colon after the target words is it - but a target word never
/// contains ':', so the first ':' wins unless it sits inside a rule
/// like `a:b:` where it still is the first.
fn find_rule_colon(line: &str) -> Option<usize> {
    line.find(':')
}

/// Split a word list on whitespace. mk words are plain here; `$` stays
/// verbatim for later expansion.
pub fn split_words(s: &str) -> Vec<String> {
    s.split_whitespace().map(String::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_text(text: &str, name: &str) -> String {
        let path = std::env::temp_dir().join(format!("mk-parse-{}-{}", std::process::id(), name));
        std::fs::write(&path, text).expect("write mkfile");
        path.to_str().expect("utf8").to_string()
    }

    fn parse_text(text: &str, name: &str) -> Vec<Item> {
        let path = write_text(text, name);
        let items = parse_file(&path, 0).expect("parse ok");
        std::fs::remove_file(&path).expect("cleanup");
        items
    }

    #[test]
    fn assignments_and_rules() {
        let items = parse_text(
            "CC=8c\nCFLAGS=-w\nprog: a.8 b.8\n\t$CC -o $target a.8 b.8\n",
            "basic",
        );
        assert_eq!(items.len(), 3);
        match &items[0] {
            Item::Assign { var, values, .. } => {
                assert_eq!(var, "CC");
                assert_eq!(values, &["8c"]);
            }
            other => panic!("unexpected {other:?}"),
        }
        match &items[2] {
            Item::Rule { targets, attrs, prereqs, recipe, .. } => {
                assert_eq!(targets, &["prog"]);
                assert!(attrs.is_empty());
                assert_eq!(prereqs, &["a.8", "b.8"]);
                assert_eq!(recipe, &["$CC -o $target a.8 b.8"]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn attributes_section_is_recognized() {
        let items = parse_text("install:VQ: all\n\tcp bin /usr/bin\n", "attrs");
        match &items[0] {
            Item::Rule { attrs, prereqs, .. } => {
                assert_eq!(attrs, &['V', 'Q']);
                assert_eq!(prereqs, &["all"]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn meta_rules_with_percent() {
        let items = parse_text("%: %.c\n\t8c $stem.c\n", "meta");
        match &items[0] {
            Item::Rule { targets, prereqs, recipe, .. } => {
                assert_eq!(targets, &["%"]);
                assert_eq!(prereqs, &["%.c"]);
                assert_eq!(recipe, &["8c $stem.c"]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn empty_assignment_means_empty_list() {
        let items = parse_text("var=\nall: \n\techo done\n", "empty");
        match &items[0] {
            Item::Assign { var, values, .. } => {
                assert_eq!(var, "var");
                assert!(values.is_empty());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn continuations_glue_lines() {
        let items = parse_text("long=a b \\\n c d\n", "cont");
        match &items[0] {
            Item::Assign { values, .. } => assert_eq!(values, &["a", "b", "c", "d"]),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn errors_carry_line_numbers() {
        let path = write_text("this line is neither\n", "bad");
        let err = parse_file(&path, 0).expect_err("bad line");
        assert_eq!(err.line, 1);
        assert!(err.msg.contains("neither an assignment nor a rule"), "got: {err}");
        let path = write_text("a: b\n\trecipe \\", "cont-err");
        let err = parse_file(&path, 0).expect_err("dangling continuation");
        assert!(err.msg.contains("continued past"), "got: {err}");
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let items = parse_text("# a comment\n\nall:\n\techo hi\n", "comments");
        assert_eq!(items.len(), 1);
    }
}
