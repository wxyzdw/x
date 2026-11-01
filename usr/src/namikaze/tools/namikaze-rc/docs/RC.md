# namikaze-rc

Plan 9's rc shell, adapted to Rust from the surveyed `rc(1)` manual.
Its defining bet is that every value is a list of words: one quoting
mechanism, no word-splitting after expansion, and a grammar small
enough to hold in your head.

## Modules

| module  | provides |
| ------- | -------- |
| lex     | the tokenizer: one quoting mechanism (single quotes, `''` doubling), metacharacters, line continuation |
| parse   | the grammar to an AST with positioned errors (`line 3, column 7: unexpected ...`): commands, pipelines, `if`/`while`/`for`, `if not`, subshells, assignments |
| interp  | the evaluator: list values, `^` concatenation with the pairwise/singleton/cross rules, `$x(1 2)` subscripts, `$#x`, `~` pattern matching, backquote command substitution, assignments scoped to a command |
| glob    | file name pattern matching applied to the result of substitution; dotfiles need an explicit dot, an unreadable directory yields no matches |
| unparse | AST back to canonical text: empty words and metacharacters are re-quoted, lists are spaced |

## Design rules

- std-only, `#![forbid(unsafe_code)]`; the child process runs through
  `std::process::Command` with argv assembled from list values, so
  there is no shell injection surface by construction.
- Syntax errors are positioned and quiet: the message names the line
  and column, never prints the whole script.
- Runtime failures carry the plan9 wording (`/bin/sh: does not exist`
  becomes `does not exist` against the command name) and exit status
  1; rc's own syntax errors exit 2, like the original.
- Assignment scoping follows the manual's exact rule: `a=1 cmd` binds
  `a` for the duration of `cmd` only.

## When to extend

The grammar grows only when a surveyed `rc(1)` feature is missing -
the current gaps are deliberate (no `switch`, no `<>`, no builtin
functions yet). Every new rule gets a positioned parse test and an
end-to-end test through the real binary.
