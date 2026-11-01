# namikaze-mk

Plan 9's mk, adapted to Rust from the surveyed `mk(1)` manual: a
dependency-driven build tool that shells out to rc for recipes and
keeps its own language to a minimum - rules, prerequisites, variables
and attributes.

## Modules

| module | provides |
| ------ | -------- |
| parse  | the mkfile grammar: rules with the D, E, N, Q, U, V attributes, assignments, `<file` includes, `%` (any stem) and `&` (no dot or slash) meta-rules, positioned errors that name the mkfile line |
| graph  | the evaluator: variable expansion (one level for stored values, recipe variables `$target $prereq $newprereq $stem $pid`), target selection with the attribute matrix, cycle detection that prints the loop |
| main   | the CLI: `mk [-n] [-a] [-f mkfile] [target...]`, command-line variable overrides in any argument position, job execution through rc |

## Design rules

- std-only, `#![forbid(unsafe_code)]`; recipes run through
  `namikaze-rc` semantics via `std::process::Command` with `/bin/sh`
  only when `SHELLS` is overridden - the default shell is rc.
- Command-line assignments win over mkfile assignments no matter
  which argument position they appear in, per `mk(1)`.
- `-n` prints the commands without running them; `-a` forces
  out-of-date targets; out-of-dateness compares modification times of
  prerequisites against the target.
- Failures name the mkfile line and the recipe line that failed, and
  a cycle reports the full loop (`a -> b -> c -> a`), not just a
  boolean.

## When to extend

The attribute set is closed: the six letters of the surveyed manual.
Anything new (parallelism, pools) lands as a flag, never as a new
attribute, so existing mkfiles keep their meaning.
