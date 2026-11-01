// SPDX-License-Identifier: MPL-2.0
//! The parser of the rc shell: token stream -> AST, following the
//! grammar of Plan 9's rc(1) for the subset this port implements.
//! Every error names the position and what the parser expected.

use crate::lex::{Pos, RcError, Token, Tok, Word};

/// A word ingredient: a literal, a variable, a subscripted variable or
/// a command substitution. Adjacent ingredients concatenate (`a$b`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Lit(Word),
    Var(String),
    /// $x(1 3 5): 1-based indices, out-of-range dropped
    VarSub(String, Vec<usize>),
    /// ` {block}: stdout of the block, split on $ifs
    Bq(Box<Node>),
    /// explicit or juxtaposed concatenation of terms
    Concat(Vec<Term>),
    /// (a b c): a list literal, the value side of an assignment
    List(Vec<Term>),
    /// $#name: the element count, as a single string
    VarCount(String),
}

/// An I/O redirection attached to a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redir {
    In(Term),
    Out(Term),
    Append(Term),
    Both(Term),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedirKind {
    In,
    Out,
    Append,
    Both,
}

/// The condition of if/while.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cond {
    /// `~ subject patterns...`
    Match(Vec<Term>, Vec<Term>),
    /// `not` inverts the inner condition
    Not(Box<Cond>),
    /// a command: true when its status is success
    Cmd(Box<Node>),
}

/// The command tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Simple { argv: Vec<Term>, redirs: Vec<Redir> },
    /// a | b | c - one or more stages
    Pipe(Vec<Node>),
    /// a && b
    And(Box<Node>, Box<Node>),
    /// a || b
    Or(Box<Node>, Box<Node>),
    /// cmd &
    Bg(Box<Node>),
    /// a; b; c (newlines fold in)
    Seq(Vec<Node>),
    /// { ... } as a command
    Block(Box<Node>),
    If { cond: Cond, then: Box<Node>, els: Option<Box<Node>> },
    /// rc's `if not cmd`: the body runs when the immediately preceding
    /// if condition was false
    IfNot(Box<Node>),
    While { cond: Cond, body: Box<Node> },
    For { var: String, list: Vec<Term>, body: Box<Node> },
}

struct Parser {
    toks: Vec<Token>,
    pos: usize,
}

/// True when a word can head an rc assignment (`name=...`).
fn assignment_like(w: &Word) -> bool {
    crate::interp::assignment_name(w).is_some()
}

/// Parse a whole input (one line, one file).
pub fn parse(src: &str) -> Result<Node, RcError> {
    let toks = crate::lex::lex(src)?;
    let mut p = Parser { toks, pos: 0 };
    let node = p.seq_until_eof()?;
    // everything must be consumed
    if let Some(t) = p.peek() {
        return Err(RcError::new(
            t.pos,
            format!("unexpected {n} after end of input", n = tok_name(&t.tok)),
        ));
    }
    Ok(node)
}

fn tok_name(t: &Tok) -> &'static str {
    match t {
        Tok::Word(_) => "word",
        Tok::Caret => "'^'",
        Tok::Dollar => "'$'",
        Tok::Backquote => "'`'",
        Tok::Tilde => "'~'",
        Tok::Semi => "';'",
        Tok::Newline => "newline",
        Tok::Amp => "'&'",
        Tok::Pipe => "'|'",
        Tok::AndAnd => "'&&'",
        Tok::OrOr => "'||'",
        Tok::LBrace => "'{'",
        Tok::RBrace => "'}'",
        Tok::LParen => "'('",
        Tok::RParen => "')'",
        Tok::Lt => "'<'",
        Tok::Gt => "'>'",
        Tok::Append => "'>>'",
        Tok::Both => "'<>'",
        Tok::If => "'if'",
        Tok::While => "'while'",
        Tok::For => "'for'",
        Tok::In => "'in'",
        Tok::Not => "'not'",
        Tok::Else => "'else'",
    }
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let out = self.toks.get(self.pos).cloned();
        if out.is_some() {
            self.pos += 1;
        }
        out
    }

    fn expect(&mut self, want: &Tok, what: &str) -> Result<Pos, RcError> {
        match self.peek() {
            Some(Token { pos, tok, .. }) if tok == want => {
                let pos = *pos;
                self.pos += 1;
                Ok(pos)
            }
            Some(Token { pos, tok, .. }) => Err(RcError::new(
                *pos,
                format!("expected {what}, found {got_name}", got_name = tok_name(tok)),
            )),
            None => Err(RcError::new(
                Pos { line: u32::MAX, col: 0 },
                format!("unexpected end of input, expected {what}"),
            )),
        }
    }

    fn skip_newlines(&mut self) {
        while matches!(self.peek(), Some(t) if t.tok == Tok::Newline) {
            self.pos += 1;
        }
    }

    /// seq: andor separated by ; newline or & (the last wraps in Bg)
    fn seq_until_eof(&mut self) -> Result<Node, RcError> {
        let mut items: Vec<Node> = Vec::new();
        self.skip_newlines();
        loop {
            match self.peek() {
                None => break,
                Some(t) if t.tok == Tok::RBrace => break,
                _ => {}
            }
            let mut node = self.andor()?;
            // & separates like ; but backgrounds the command before it
            let backgrounded = matches!(self.peek(), Some(t) if t.tok == Tok::Amp);
            if backgrounded {
                self.pos += 1;
                node = Node::Bg(Box::new(node));
            }
            items.push(node);
            if backgrounded {
                // & is its own separator: the next command follows at once
                self.skip_newlines();
                continue;
            }
            match self.peek() {
                Some(t) if t.tok == Tok::Semi || t.tok == Tok::Newline => {
                    self.pos += 1;
                    self.skip_newlines();
                }
                Some(t) if t.tok == Tok::RBrace => break,
                None => break,
                Some(t) => {
                    return Err(RcError::new(
                        t.pos,
                        format!("unexpected {n} - expected ';' or newline", n = tok_name(&t.tok)),
                    ));
                }
            }
        }
        match items.len() {
            0 => Err(RcError::new(Pos { line: 1, col: 1 }, "empty command")),
            1 => Ok(items.pop().expect("len checked")),
            _ => Ok(Node::Seq(items)),
        }
    }

    fn andor(&mut self) -> Result<Node, RcError> {
        let mut left = self.pipeline()?;
        loop {
            match self.peek().map(|t| t.tok.clone()) {
                Some(Tok::AndAnd) => {
                    self.pos += 1;
                    let right = self.pipeline()?;
                    left = Node::And(Box::new(left), Box::new(right));
                }
                Some(Tok::OrOr) => {
                    self.pos += 1;
                    let right = self.pipeline()?;
                    left = Node::Or(Box::new(left), Box::new(right));
                }
                _ => return Ok(left),
            }
        }
    }

    fn pipeline(&mut self) -> Result<Node, RcError> {
        let first = self.command()?;
        let mut stages = vec![first];
        while matches!(self.peek(), Some(t) if t.tok == Tok::Pipe) {
            self.pos += 1;
            stages.push(self.command()?);
        }
        if stages.len() == 1 {
            Ok(stages.pop().expect("len checked"))
        } else {
            Ok(Node::Pipe(stages))
        }
    }

    /// One command: leading redirections, the unit, trailing
    /// redirections. A unit that is not a simple command gets the
    /// redirections applied through a wrapping simple command.
    fn command(&mut self) -> Result<Node, RcError> {
        let mut redirs: Vec<Redir> = Vec::new();
        loop {
            let kind = match self.peek().map(|t| t.tok.clone()) {
                Some(Tok::Lt) => Some(RedirKind::In),
                Some(Tok::Gt) => Some(RedirKind::Out),
                Some(Tok::Append) => Some(RedirKind::Append),
                Some(Tok::Both) => Some(RedirKind::Both),
                _ => None,
            };
            match kind {
                Some(kind) => {
                    self.pos += 1;
                    let target = self.term()?;
                    redirs.push(match kind {
                        RedirKind::In => Redir::In(target),
                        RedirKind::Out => Redir::Out(target),
                        RedirKind::Append => Redir::Append(target),
                        RedirKind::Both => Redir::Both(target),
                    });
                }
                None => break,
            }
        }
        let node = self.unit()?;
        // trailing redirections apply to the command too
        loop {
            let kind = match self.peek().map(|t| t.tok.clone()) {
                Some(Tok::Lt) => Some(RedirKind::In),
                Some(Tok::Gt) => Some(RedirKind::Out),
                Some(Tok::Append) => Some(RedirKind::Append),
                Some(Tok::Both) => Some(RedirKind::Both),
                _ => None,
            };
            match kind {
                Some(kind) => {
                    self.pos += 1;
                    let target = self.term()?;
                    redirs.push(match kind {
                        RedirKind::In => Redir::In(target),
                        RedirKind::Out => Redir::Out(target),
                        RedirKind::Append => Redir::Append(target),
                        RedirKind::Both => Redir::Both(target),
                    });
                }
                None => break,
            }
        }
        if redirs.is_empty() {
            return Ok(node);
        }
        match node {
            Node::Simple { argv, redirs: mut old } => {
                old.extend(redirs);
                Ok(Node::Simple { argv, redirs: old })
            }
            _ => Err(RcError::new(
                Pos { line: 1, col: 1 },
                "redirections on a compound command are not supported by this port",
            )),
        }
    }

    fn unit(&mut self) -> Result<Node, RcError> {
        match self.peek() {
            Some(t) if t.tok == Tok::LBrace => {
                self.pos += 1;
                let inner = self.seq_until_eof()?;
                self.expect(&Tok::RBrace, "'}' to close the block")?;
                Ok(Node::Block(Box::new(inner)))
            }
            Some(t) if t.tok == Tok::If => self.if_node(),
            Some(t) if t.tok == Tok::While => self.while_node(),
            Some(t) if t.tok == Tok::For => self.for_node(),
            Some(t) if t.tok == Tok::Tilde => Err(RcError::new(
                t.pos,
                "'~' is only valid inside an if or while condition",
            )),
            Some(t) if self.starts_term(&t.tok) => self.simple(),
            Some(t) => Err(RcError::new(t.pos, format!("unexpected {n}", n = tok_name(&t.tok)))),
            None => Err(RcError::new(Pos { line: u32::MAX, col: 0 }, "unexpected end of input")),
        }
    }

    fn starts_term(&self, t: &Tok) -> bool {
        matches!(t, Tok::Word(_) | Tok::Dollar | Tok::Backquote)
    }

    fn if_node(&mut self) -> Result<Node, RcError> {
        self.next(); // if
        if matches!(self.peek(), Some(t) if t.tok == Tok::Not) {
            self.pos += 1;
            let body = self.unit()?;
            return Ok(Node::IfNot(Box::new(body)));
        }
        self.expect(&Tok::LParen, "'(' after 'if'")?;
        let cond = self.cond()?;
        self.expect(&Tok::RParen, "')' to close the if condition")?;
        let then = self.unit()?;
        let els = if matches!(self.peek(), Some(t) if t.tok == Tok::Else) {
            self.pos += 1;
            Some(Box::new(self.unit()?))
        } else {
            None
        };
        Ok(Node::If { cond, then: Box::new(then), els })
    }

    fn while_node(&mut self) -> Result<Node, RcError> {
        self.next(); // while
        self.expect(&Tok::LParen, "'(' after 'while'")?;
        let cond = self.cond()?;
        self.expect(&Tok::RParen, "')' to close the while condition")?;
        let body = self.unit()?;
        Ok(Node::While { cond, body: Box::new(body) })
    }

    fn for_node(&mut self) -> Result<Node, RcError> {
        self.next(); // for
        self.expect(&Tok::LParen, "'(' after 'for'")?;
        let var = match self.next() {
            Some(Token { tok: Tok::Word(w), .. }) => w.text(),
            Some(Token { pos, tok, .. }) => {
                return Err(RcError::new(
                    pos,
                    format!("expected a loop variable name, found {n}", n = tok_name(&tok)),
                ));
            }
            None => {
                return Err(RcError::new(
                    Pos { line: u32::MAX, col: 0 },
                    "unexpected end of input in 'for'",
                ));
            }
        };
        self.expect(&Tok::In, "'in' after the loop variable")?;
        let list = self.terms_until_rparen()?;
        self.expect(&Tok::RParen, "')' to close the for list")?;
        let body = self.unit()?;
        Ok(Node::For { var, list, body: Box::new(body) })
    }

    /// Terms up to a ')' , with glued terms concatenated (`a$b`).
    fn terms_until_rparen(&mut self) -> Result<Vec<Term>, RcError> {
        let mut out = Vec::new();
        loop {
            match self.peek() {
                Some(t) if t.tok == Tok::RParen => return Ok(out),
                Some(t) if self.starts_term(&t.tok) => {
                    let glued = t.glued && !out.is_empty();
                    let term = self.term()?;
                    if glued {
                        let last = out.last_mut().expect("non-empty");
                        let merged = match std::mem::replace(last, Term::Lit(Word(vec![]))) {
                            Term::Concat(mut parts) => {
                                parts.push(term);
                                Term::Concat(parts)
                            }
                            one => Term::Concat(vec![one, term]),
                        };
                        *last = merged;
                    } else {
                        out.push(term);
                    }
                }
                Some(t) => {
                    return Err(RcError::new(
                        t.pos,
                        format!("unexpected {n} in the term list", n = tok_name(&t.tok)),
                    ));
                }
                None => {
                    return Err(RcError::new(
                        Pos { line: u32::MAX, col: 0 },
                        "unexpected end of input, expected ')'",
                    ));
                }
            }
        }
    }

    fn cond(&mut self) -> Result<Cond, RcError> {
        if matches!(self.peek(), Some(t) if t.tok == Tok::Not) {
            self.pos += 1;
            return Ok(Cond::Not(Box::new(self.cond()?)));
        }
        if matches!(self.peek(), Some(t) if t.tok == Tok::Tilde) {
            let tilde_pos = self.peek().map(|t| t.pos).unwrap_or(Pos { line: 1, col: 1 });
            self.pos += 1;
            let subject = vec![self.term().map_err(|e| {
                RcError::new(tilde_pos, format!("'~' needs a subject: {e}"))
            })?];
            let patterns = self.terms_until_rparen_pattern()?;
            if patterns.is_empty() {
                return Err(RcError::new(
                    tilde_pos,
                    "'~' needs at least one pattern",
                ));
            }
            return Ok(Cond::Match(subject, patterns));
        }
        Ok(Cond::Cmd(Box::new(self.pipeline()?)))
    }

    /// Terms stopped by the next non-term token (used inside '~').
    fn terms_until_rparen_pattern(&mut self) -> Result<Vec<Term>, RcError> {
        let mut out = Vec::new();
        loop {
            match self.peek() {
                Some(t) if self.starts_term(&t.tok) => {
                    let glued = t.glued && !out.is_empty();
                    let term = self.term()?;
                    if glued {
                        let last = out.last_mut().expect("non-empty");
                        let merged = match std::mem::replace(last, Term::Lit(Word(vec![]))) {
                            Term::Concat(mut parts) => {
                                parts.push(term);
                                Term::Concat(parts)
                            }
                            one => Term::Concat(vec![one, term]),
                        };
                        *last = merged;
                    } else {
                        out.push(term);
                    }
                }
                _ => return Ok(out),
            }
        }
    }

    /// A simple command: one or more terms; a term glued to the
    /// previous one (`a$b`) concatenates, a spaced one starts a new
    /// argument.
    fn simple(&mut self) -> Result<Node, RcError> {
        let mut argv: Vec<Term> = Vec::new();
        argv.push(self.term()?);
        // an assignment word may take a parenthesized list as its value
        if let Some(Term::Lit(w)) = argv.first() {
            if assignment_like(w) && matches!(self.peek(), Some(t) if t.tok == Tok::LParen) {
                self.pos += 1;
                let items = self.terms_until_rparen()?;
                self.expect(&Tok::RParen, "')' to close the list")?;
                argv.push(Term::List(items));
            }
        }
        loop {
            let glued = match self.peek() {
                Some(t) if self.starts_term(&t.tok) => t.glued,
                _ => break,
            };
            let term = self.term()?;
            if glued {
                let last = argv.last_mut().expect("non-empty");
                let merged = match std::mem::replace(last, Term::Lit(Word(vec![]))) {
                    Term::Concat(mut parts) => {
                        parts.push(term);
                        Term::Concat(parts)
                    }
                    one => Term::Concat(vec![one, term]),
                };
                *argv.last_mut().expect("non-empty") = merged;
            } else {
                argv.push(term);
            }
        }
        Ok(Node::Simple { argv, redirs: Vec::new() })
    }

    /// One term, including explicit ^ concatenation chains.
    fn term(&mut self) -> Result<Term, RcError> {
        let first = self.one_term()?;
        if matches!(self.peek(), Some(t) if t.tok == Tok::Caret) {
            let mut parts = vec![first];
            while matches!(self.peek(), Some(t) if t.tok == Tok::Caret) {
                self.pos += 1;
                parts.push(self.one_term()?);
            }
            return Ok(Term::Concat(parts));
        }
        Ok(first)
    }

    fn one_term(&mut self) -> Result<Term, RcError> {
        match self.next() {
            Some(Token { tok: Tok::Word(w), .. }) => Ok(Term::Lit(w)),
            Some(Token { tok: Tok::Dollar, .. }) => {
                let name = match self.next() {
                    Some(Token { tok: Tok::Word(w), .. }) => w.text(),
                    Some(Token { pos, tok, .. }) => {
                        return Err(RcError::new(
                            pos,
                            format!("expected a variable name after '$', found {n}", n = tok_name(&tok)),
                        ));
                    }
                    None => {
                        return Err(RcError::new(
                            Pos { line: u32::MAX, col: 0 },
                            "unexpected end of input after '$'",
                        ));
                    }
                };
                // $#name: element count (the lexer may deliver '#' and
                // the name as one word, glued after '$')
                if let Some(rest) = name.strip_prefix('#') {
                    if rest.is_empty() {
                        // separate "#" token: the name is the next word
                        match self.next() {
                            Some(Token { tok: Tok::Word(w), .. }) => {
                                return Ok(Term::VarCount(w.text()));
                            }
                            Some(Token { pos, tok, .. }) => {
                                return Err(RcError::new(
                                    pos,
                                    format!("expected a variable name after '$#', found {n}", n = tok_name(&tok)),
                                ));
                            }
                            None => {
                                return Err(RcError::new(
                                    Pos { line: u32::MAX, col: 0 },
                                    "unexpected end of input after '$#'",
                                ));
                            }
                        }
                    }
                    return Ok(Term::VarCount(rest.to_string()));
                }
                if name == "#" {
                    let count_name = match self.next() {
                        Some(Token { tok: Tok::Word(w), .. }) => w.text(),
                        Some(Token { pos, tok, .. }) => {
                            return Err(RcError::new(
                                pos,
                                format!("expected a variable name after '$#', found {n}", n = tok_name(&tok)),
                            ));
                        }
                        None => {
                            return Err(RcError::new(
                                Pos { line: u32::MAX, col: 0 },
                                "unexpected end of input after '$#'",
                            ));
                        }
                    };
                    return Ok(Term::VarCount(count_name));
                }
                // $x(1 2): subscript list
                let sub_pos = self.peek().map(|t| t.pos).unwrap_or(Pos { line: 1, col: 1 });
                if matches!(self.peek(), Some(t) if t.tok == Tok::LParen) {
                    self.pos += 1;
                    let mut idx = Vec::new();
                    while let Some(Token { tok: Tok::Word(w), .. }) = self.peek() {
                        let text = w.text();
                        match text.parse::<usize>() {
                            Ok(n) if n >= 1 => {
                                idx.push(n);
                                self.pos += 1;
                            }
                            _ => {
                                return Err(RcError::new(
                                    sub_pos,
                                    format!("subscript \"{text}\" is not a positive integer"),
                                ));
                            }
                        }
                    }
                    self.expect(&Tok::RParen, "')' to close the subscript")?;
                    if idx.is_empty() {
                        return Err(RcError::new(sub_pos, "empty subscript after variable name"));
                    }
                    return Ok(Term::VarSub(name, idx));
                }
                Ok(Term::Var(name))
            }
            Some(Token { tok: Tok::Backquote, .. }) => {
                self.expect(&Tok::LBrace, "'{' after '`'")?;
                let inner = self.seq_until_eof()?;
                self.expect(&Tok::RBrace, "'}' to close the ` block")?;
                Ok(Term::Bq(Box::new(inner)))
            }
            Some(Token { pos, tok, .. }) => {
                Err(RcError::new(pos, format!("unexpected {n}", n = tok_name(&tok))))
            }
            None => Err(RcError::new(
                Pos { line: u32::MAX, col: 0 },
                "unexpected end of input, expected a term",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lex::Part;

    fn word(s: &str) -> Term {
        Term::Lit(Word(vec![Part::Unquoted(s.into())]))
    }

    fn parse_ok(src: &str) -> Node {
        parse(src).unwrap_or_else(|e| panic!("parse \"{src}\" failed: {e}"))
    }

    #[test]
    fn simple_command() {
        let n = parse_ok("echo hello world");
        match n {
            Node::Simple { argv, redirs } => {
                assert_eq!(argv, vec![word("echo"), word("hello"), word("world")]);
                assert!(redirs.is_empty());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn glue_binds_words_together() {
        let n = parse_ok("echo a$b");
        match n {
            Node::Simple { argv, .. } => assert_eq!(argv.len(), 2, "a$b is one argument"),
            other => panic!("unexpected {other:?}"),
        }
        // with a space they are separate
        let n = parse_ok("echo a $b");
        match n {
            Node::Simple { argv, .. } => assert_eq!(argv.len(), 3),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn explicit_caret_allows_spaces() {
        let n = parse_ok("echo a ^ b");
        match n {
            Node::Simple { argv, .. } => assert_eq!(argv.len(), 2, "a ^ b is one argument"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn redirections_and_pipes() {
        let n = parse_ok("ls > out.txt");
        match n {
            Node::Simple { argv, redirs } => {
                assert_eq!(argv.len(), 1);
                assert_eq!(redirs, vec![Redir::Out(word("out.txt"))]);
            }
            other => panic!("unexpected {other:?}"),
        }
        let n = parse_ok("a | b | c");
        match n {
            Node::Pipe(stages) => assert_eq!(stages.len(), 3),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn if_with_tilde_and_else() {
        let n = parse_ok("if(~ $x a* b) { echo yes } else { echo no }");
        match n {
            Node::If { cond: Cond::Match(subj, pats), els: Some(_), .. } => {
                assert_eq!(subj, vec![Term::Var("x".into())]);
                assert_eq!(pats, vec![word("a*"), word("b")]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn if_with_command_condition() {
        let n = parse_ok("if(test -f /tmp/x) echo yes");
        match n {
            Node::If { cond: Cond::Cmd(_), .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn not_negates_the_condition() {
        let n = parse_ok("if(not ~ $x a) echo no");
        match n {
            Node::If { cond: Cond::Not(_), .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn while_and_for() {
        let n = parse_ok("while(true) { echo tick }");
        match n {
            Node::While { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
        let n = parse_ok("for(i in a b c) { echo $i }");
        match n {
            Node::For { var, list, .. } => {
                assert_eq!(var, "i");
                assert_eq!(list, vec![word("a"), word("b"), word("c")]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn backgrounding_and_sequencing() {
        let n = parse_ok("sleep 10 & echo done");
        match n {
            Node::Seq(items) => {
                assert!(matches!(items[0], Node::Bg(_)));
                assert!(matches!(items[1], Node::Simple { .. }));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn backquote_substitution_is_a_term() {
        let n = parse_ok("echo `{seq 1 3}");
        match n {
            Node::Simple { argv, .. } => {
                assert_eq!(argv.len(), 2);
                assert!(matches!(argv[1], Term::Bq(_)));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn subscripts_parse() {
        let n = parse_ok("echo $x(1 3)");
        match n {
            Node::Simple { argv, .. } => {
                assert_eq!(argv[1], Term::VarSub("x".into(), vec![1, 3]));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn errors_carry_positions() {
        let err = parse("if $x) echo").expect_err("missing parens");
        assert!(err.msg.contains("expected '(' after 'if'"), "got: {err}");
        let err = parse("echo 'unterminated").expect_err("lexer error propagates");
        assert!(err.msg.contains("unterminated quote"), "got: {err}");
        let err = parse("echo a b; )").expect_err("stray paren");
        assert!(err.msg.contains("unexpected ')'"), "got: {err}");
    }

    #[test]
    fn semicolons_and_newlines_fold() {
        let n = parse_ok("echo a\necho b\necho c");
        match n {
            Node::Seq(items) => assert_eq!(items.len(), 3),
            other => panic!("unexpected {other:?}"),
        }
    }
}
