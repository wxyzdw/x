// SPDX-License-Identifier: MPL-2.0
//! The lexer of the rc shell, adapted from Plan 9's rc(1) grammar.
//!
//! rc has exactly one quoting mechanism - single quotes, doubled
//! inside themselves ('it''s' -> it's) - and a small set of metacharacters.
//! Every failure carries the line and column it happened at.

/// One source position, 1-based line and byte column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pos {
    pub line: u32,
    pub col: u32,
}

/// A lexer/parser error with its source position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcError {
    pub pos: Pos,
    pub msg: String,
}

impl std::fmt::Display for RcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}, column {}: {}", self.pos.line, self.pos.col, self.pos_msg())
    }
}

impl RcError {
    fn pos_msg(&self) -> &str {
        &self.msg
    }

    pub fn new(pos: Pos, msg: impl Into<String>) -> RcError {
        RcError { pos, msg: msg.into() }
    }
}

impl std::error::Error for RcError {}

/// A piece of a word: quoted text is literal, unquoted text takes part
/// in variable splitting and globbing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    Quoted(String),
    Unquoted(String),
}

/// One word: a sequence of quoted and unquoted segments. `$` var
/// references are emitted as separate tokens, so a Word here is pure
/// literal text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word(pub Vec<Part>);

impl Word {
    /// The fully quoted form of the word (used for diagnostics).
    pub fn text(&self) -> String {
        self.0.iter().map(|p| match p {
            Part::Quoted(s) | Part::Unquoted(s) => s.clone(),
        }).collect()
    }
}

/// One token with its positions and whether it is glued to the
/// previous token (no whitespace between them) - rc distinguishes
/// `a$b` from `a $b`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub pos: Pos,
    /// position just past the token's last character
    pub end: Pos,
    pub tok: Tok,
    /// true when this token starts exactly where the previous one ended
    pub glued: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    Word(Word),
    /// ^ explicit concatenation
    Caret,
    /// $ followed by the variable word
    Dollar,
    /// ` command substitution
    Backquote,
    /// ~ pattern match operator
    Tilde,
    Semi,
    Newline,
    Amp,
    Pipe,
    AndAnd,
    OrOr,
    LBrace,
    RBrace,
    LParen,
    RParen,
    Lt,
    Gt,
    Append, // >>
    Both,   // <>
    If,
    While,
    For,
    In,
    Not,
    Else,
}

/// Tokenize one input string. Newlines separate commands; comments run
/// from `#` to end of line.
pub fn lex(src: &str) -> Result<Vec<Token>, RcError> {
    let mut out: Vec<Token> = Vec::new();
    macro_rules! push_tok {
        ($start:expr, $end:expr, $tok:expr) => {{
            let glued = match out.last() {
                Some(prev) => prev.end == $start,
                None => false,
            };
            out.push(Token { pos: $start, end: $end, tok: $tok, glued });
        }};
    }
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0usize;
    let mut line = 1u32;
    let mut col = 1u32;
    let mut word: Vec<Part> = Vec::new();
    let mut word_start = Pos { line, col };

    macro_rules! flush_word {
        () => {
            if !word.is_empty() {
                let parts = std::mem::take(&mut word);
                let end = Pos { line, col };
                push_tok!(word_start, end, Tok::Word(Word(parts)));
            }
        };
    }

    while i < chars.len() {
        let c = chars[i];
        let pos = Pos { line, col };
        match c {
            '\'' => {
                // the only quoting in rc; '' escapes one quote
                let start = pos;
                i += 1;
                col += 1;
                let mut quoted = String::new();
                loop {
                    if i >= chars.len() {
                        return Err(RcError::new(start, "unterminated quote"));
                    }
                    if chars[i] == '\'' {
                        if i + 1 < chars.len() && chars[i + 1] == '\'' {
                            quoted.push('\'');
                            i += 2;
                            col += 2;
                            continue;
                        }
                        i += 1;
                        col += 1;
                        break;
                    }
                    quoted.push(chars[i]);
                    if chars[i] == '\n' {
                        line += 1;
                        col = 1;
                    } else {
                        col += 1;
                    }
                    i += 1;
                }
                if word.is_empty() {
                    word_start = start;
                }
                word.push(Part::Quoted(quoted));
            }
            ' ' | '\t' => {
                flush_word!();
                i += 1;
                col += 1;
            }
            '\n' => {
                flush_word!();
                let end = Pos { line, col };
                push_tok!(pos, end, Tok::Newline);
                i += 1;
                line += 1;
                col = 1;
            }
            '#' => {
                // `$#name` is the element count; a glued '#' after '$'
                // is that syntax, any other '#' starts a comment
                let after_dollar = matches!(
                    out.last().map(|t| &t.tok),
                    Some(Tok::Dollar)
                );
                if after_dollar {
                    let start = Pos { line, col };
                    if word.is_empty() {
                        word_start = start;
                    }
                    word.push(Part::Unquoted("#".into()));
                    i += 1;
                    col += 1;
                } else {
                    while i < chars.len() && chars[i] != '\n' {
                        i += 1;
                        col += 1;
                    }
                }
            }
            ';' => {
                flush_word!();
                // advance before pushing so `end` is correct
                i += 1;
                col += 1;
                let end = Pos { line, col };
                push_tok!(pos, end, Tok::Semi);
            }
            '&' => {
                flush_word!();
                i += 1;
                col += 1;
                if i < chars.len() && chars[i] == '&' {
                    i += 1;
                    col += 1;
                    let end = Pos { line, col };
                    push_tok!(pos, end, Tok::AndAnd);
                } else {
                    let end = Pos { line, col };
                    push_tok!(pos, end, Tok::Amp);
                }
            }
            '|' => {
                flush_word!();
                i += 1;
                col += 1;
                if i < chars.len() && chars[i] == '|' {
                    i += 1;
                    col += 1;
                    let end = Pos { line, col };
                    push_tok!(pos, end, Tok::OrOr);
                } else {
                    let end = Pos { line, col };
                    push_tok!(pos, end, Tok::Pipe);
                }
            }
            '^' => {
                flush_word!();
                // advance before pushing so `end` is correct
                i += 1;
                col += 1;
                let end = Pos { line, col };
                push_tok!(pos, end, Tok::Caret);
            }
            '$' => {
                flush_word!();
                // advance before pushing so `end` is correct
                i += 1;
                col += 1;
                let end = Pos { line, col };
                push_tok!(pos, end, Tok::Dollar);
            }
            '`' => {
                flush_word!();
                // advance before pushing so `end` is correct
                i += 1;
                col += 1;
                let end = Pos { line, col };
                push_tok!(pos, end, Tok::Backquote);
            }
            '~' => {
                flush_word!();
                // advance before pushing so `end` is correct
                i += 1;
                col += 1;
                let end = Pos { line, col };
                push_tok!(pos, end, Tok::Tilde);
            }
            '{' => {
                flush_word!();
                // advance before pushing so `end` is correct
                i += 1;
                col += 1;
                let end = Pos { line, col };
                push_tok!(pos, end, Tok::LBrace);
            }
            '}' => {
                flush_word!();
                // advance before pushing so `end` is correct
                i += 1;
                col += 1;
                let end = Pos { line, col };
                push_tok!(pos, end, Tok::RBrace);
            }
            '(' => {
                flush_word!();
                // advance before pushing so `end` is correct
                i += 1;
                col += 1;
                let end = Pos { line, col };
                push_tok!(pos, end, Tok::LParen);
            }
            ')' => {
                flush_word!();
                // advance before pushing so `end` is correct
                i += 1;
                col += 1;
                let end = Pos { line, col };
                push_tok!(pos, end, Tok::RParen);
            }
            '<' => {
                flush_word!();
                i += 1;
                col += 1;
                if i < chars.len() && chars[i] == '>' {
                    i += 1;
                    col += 1;
                    let end = Pos { line, col };
                    push_tok!(pos, end, Tok::Both);
                } else {
                    let end = Pos { line, col };
                    push_tok!(pos, end, Tok::Lt);
                }
            }
            '>' => {
                flush_word!();
                i += 1;
                col += 1;
                if i < chars.len() && chars[i] == '>' {
                    i += 1;
                    col += 1;
                    let end = Pos { line, col };
                    push_tok!(pos, end, Tok::Append);
                } else {
                    let end = Pos { line, col };
                    push_tok!(pos, end, Tok::Gt);
                }
            }
            _ if is_word_char(c) => {
                let start = pos;
                let mut text = String::new();
                while i < chars.len() && is_word_char(chars[i]) {
                    text.push(chars[i]);
                    i += 1;
                    col += 1;
                }
                // keywords are recognized as standalone unquoted words
                let keyword = match text.as_str() {
                    "if" => Some(Tok::If),
                    "while" => Some(Tok::While),
                    "for" => Some(Tok::For),
                    "in" => Some(Tok::In),
                    "not" => Some(Tok::Not),
                    "else" => Some(Tok::Else),
                    _ => None,
                };
                if let Some(kw) = keyword {
                    flush_word!();
                    let end = Pos { line, col };
                    push_tok!(start, end, kw);
                } else {
                    if word.is_empty() {
                        word_start = start;
                    }
                    word.push(Part::Unquoted(text));
                }
            }
            _ => {
                flush_word!();
                return Err(RcError::new(pos, format!("unexpected character '{c}'")));
            }
        }
    }
    flush_word!();
    Ok(out)
}

fn is_word_char(c: char) -> bool {
    !matches!(
        c,
        ' ' | '\t'
            | '\n'
            | '\r'
            | ';'
            | '&'
            | '|'
            | '^'
            | '$'
            | '`'
            | '~'
            | '{'
            | '}'
            | '('
            | ')'
            | '<'
            | '>'
            | '#'
            | '\''
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(src: &str) -> Vec<Tok> {
        lex(src).expect("lex ok").into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn quoting_is_the_only_escape() {
        assert_eq!(toks("'hello world'"), vec![Tok::Word(Word(vec![Part::Quoted("hello world".into())]))]);
        // doubled quote inside quotes
        assert_eq!(toks("'it''s'"), vec![Tok::Word(Word(vec![Part::Quoted("it's".into())]))]);
        // mixed
        assert_eq!(
            toks("a'b'c"),
            vec![Tok::Word(Word(vec![
                Part::Unquoted("a".into()),
                Part::Quoted("b".into()),
                Part::Unquoted("c".into()),
            ]))]
        );
    }

    #[test]
    fn metacharacters_split_words() {
        assert_eq!(toks("a|b").len(), 3);
        assert_eq!(toks("a;b;c").len(), 5);
        assert_eq!(toks("x>y"), vec![
            Tok::Word(Word(vec![Part::Unquoted("x".into())])),
            Tok::Gt,
            Tok::Word(Word(vec![Part::Unquoted("y".into())])),
        ]);
    }

    #[test]
    fn comments_run_to_newline() {
        let t = toks("a # rest of line\nb");
        assert_eq!(t, vec![
            Tok::Word(Word(vec![Part::Unquoted("a".into())])),
            Tok::Newline,
            Tok::Word(Word(vec![Part::Unquoted("b".into())])),
        ]);
    }

    #[test]
    fn keywords_are_recognized_but_concatenation_wins() {
        assert!(toks("if").contains(&Tok::If));
        // "iffy" is one word, not the keyword
        assert_eq!(toks("iffy"), vec![Tok::Word(Word(vec![Part::Unquoted("iffy".into())]))]);
        // quoted keywords are words
        assert_eq!(toks("'if'"), vec![Tok::Word(Word(vec![Part::Quoted("if".into())]))]);
    }

    #[test]
    fn unterminated_quote_is_positioned() {
        let err = lex("echo 'oops").expect_err("unterminated");
        assert!(err.msg.contains("unterminated quote"), "got: {err}");
        assert_eq!(err.pos, Pos { line: 1, col: 6 });
    }

    #[test]
    fn line_numbers_track_newlines() {
        let err = lex("a\nb\n'never ends").expect_err("unterminated");
        assert_eq!(err.pos.line, 3, "the quote starts on line 3");
    }

    #[test]
    fn redirection_and_logic_operators() {
        let t = toks("a >> b <> c && d || e");
        assert_eq!(t, vec![
            Tok::Word(Word(vec![Part::Unquoted("a".into())])),
            Tok::Append,
            Tok::Word(Word(vec![Part::Unquoted("b".into())])),
            Tok::Both,
            Tok::Word(Word(vec![Part::Unquoted("c".into())])),
            Tok::AndAnd,
            Tok::Word(Word(vec![Part::Unquoted("d".into())])),
            Tok::OrOr,
            Tok::Word(Word(vec![Part::Unquoted("e".into())])),
        ]);
    }
}
