// SPDX-License-Identifier: MPL-2.0
//! Turning the AST back into rc source. Needed wherever a subtree runs
//! in a child copy of the shell: command substitution and `&`.

use crate::lex::{Part, Word};
use crate::parse::{Cond, Node, Redir, Term};

/// Quote a string the rc way: everything literal inside '...', with
/// '' escaping one quote.
pub fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn word(w: &Word) -> String {
    w.0.iter()
        .map(|p| match p {
            Part::Quoted(s) => quote(s),
            Part::Unquoted(s) => {
                if s.is_empty() {
                    quote(s)
                } else if s.chars().any(|c| {
                    matches!(c, ' ' | '\t' | '\n' | ';' | '&' | '|' | '^' | '$' | '`' | '~'
                        | '{' | '}' | '(' | ')' | '<' | '>' | '#' | '\'' | '*' | '?' | '[')
                }) {
                    quote(s)
                } else {
                    s.clone()
                }
            }
        })
        .collect()
}

fn term(t: &Term) -> String {
    match t {
        Term::Lit(w) => word(w),
        Term::Var(name) => {
            if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !name.is_empty() {
                format!("${name}")
            } else {
                format!("${}", quote(name))
            }
        }
        Term::VarSub(name, idx) => {
            let list = idx.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(" ");
            format!("${name}({list})")
        }
        Term::Bq(node) => format!("`{}", block(node)),
        Term::Concat(parts) => parts.iter().map(term).collect::<Vec<_>>().join(""),
        Term::List(items) => format!("({})", terms(items)),
        Term::VarCount(name) => format!("$#{name}"),
    }
}

fn terms(list: &[Term]) -> String {
    list.iter().map(term).collect::<Vec<_>>().join(" ")
}

fn redir(r: &Redir) -> String {
    match r {
        Redir::In(t) => format!("< {}", term(t)),
        Redir::Out(t) => format!("> {}", term(t)),
        Redir::Append(t) => format!(">> {}", term(t)),
        Redir::Both(t) => format!("<> {}", term(t)),
    }
}

fn block(n: &Node) -> String {
    match n {
        // a body that is already a block renders as-is: `if(c) { ... }`
        // must not grow braces on every round trip
        Node::Block(_) => node(n),
        _ => format!("{{ {} }}", node(n)),
    }
}

fn cond(c: &Cond) -> String {
    match c {
        Cond::Match(subject, patterns) => {
            let mut all = subject.clone();
            all.extend(patterns.clone());
            format!("~ {}", terms(&all))
        }
        Cond::Not(inner) => format!("not {}", cond(inner)),
        Cond::Cmd(inner) => node(inner),
    }
}

/// Render one node back to source text.
pub fn node(n: &Node) -> String {
    match n {
        Node::Simple { argv, redirs } => {
            let mut parts: Vec<String> = argv.iter().map(term).collect();
            parts.extend(redirs.iter().map(redir));
            parts.join(" ")
        }
        Node::Pipe(stages) => stages.iter().map(node).collect::<Vec<_>>().join(" | "),
        Node::And(a, b) => format!("{} && {}", node(a), node(b)),
        Node::Or(a, b) => format!("{} || {}", node(a), node(b)),
        Node::Bg(inner) => format!("{} &", node(inner)),
        Node::Seq(items) => {
            let mut out = String::new();
            for (i, item) in items.iter().enumerate() {
                if i > 0 && !matches!(items[i - 1], Node::Bg(_)) {
                    out.push_str("; ");
                } else if i > 0 {
                    out.push(' ');
                }
                out.push_str(&node(item));
            }
            out
        }
        Node::Block(inner) => block(inner),
        Node::IfNot(inner) => format!("if not {}", block(inner)),
        Node::If { cond: c, then, els } => {
            let head = format!("if({}) {}", cond(c), block(then));
            match els {
                Some(e) => format!("{head} else {}", block(e)),
                None => head,
            }
        }
        Node::While { cond: c, body } => format!("while({}) {}", cond(c), block(body)),
        Node::For { var, list, body } => {
            format!("for({var} in {}) {}", terms(list), block(body))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse;

    fn roundtrip(src: &str) {
        let parsed = parse(src).unwrap_or_else(|e| panic!("parse \"{src}\": {e}"));
        let unparsed = node(&parsed);
        let reparsed = parse(&unparsed).unwrap_or_else(|e| panic!("reparse \"{unparsed}\": {e}"));
        assert_eq!(node(&reparsed), unparsed, "unparse of \"{src}\" is stable");
    }

    #[test]
    fn unparse_is_reparseable() {
        roundtrip("echo hello world");
        roundtrip("echo a$b ^ c");
        roundtrip("ls > out | wc >> counts");
        roundtrip("if(~ $x a b) { echo yes } else { echo no }");
        roundtrip("while(test -f x) { sleep 1 }");
        roundtrip("for(i in a b c) { echo $i }");
        roundtrip("sleep 1 & echo done");
        roundtrip("echo `{seq 1 3}");
        roundtrip("a; b; c");
        roundtrip("if(not test -f x) { echo gone }");
    }

    #[test]
    fn quoting_survives_the_round_trip() {
        let parsed = parse("echo 'two words'").expect("parse");
        let unparsed = node(&parsed);
        assert!(unparsed.contains("'two words'"), "got: {unparsed}");
        // quotes with quotes inside
        let parsed = parse("echo 'it''s'").expect("parse");
        assert!(node(&parsed).contains("'it''s'"), "got: {}", node(&parsed));
    }
}
