# Plan 9 from Bell Labs: the full source survey and the NamikazeOS adaptation map

*Survey date: 2026-11-01. Source: `http://9p.io/sources/plan9/` - the official
Bell Labs mirror of the Plan 9 4th edition tree. License: MIT (Plan 9
Foundation, 2021) - see the root `LICENSE` and `NOTICE`, both re-fetched
during the survey. The crawl is fully reproducible with
`plan9_crawl.py` (in this directory); its raw output is committed next to this document
as `plan9-tree.json`.*

## What was examined

The crawler visited every directory listing under `/sources/plan9/`, one
HTTP request per directory, and recorded every file with its size, date and
owner. The totals:

| metric | value |
| --- | --- |
| directories swept | 894 |
| files recorded | 16,015 |
| bytes of file payloads | 276,937,077 (~277 MB) |
| directories with no files (mount stubs) | 199 |

The 199 empty directories are not crawl failures: `env`, `fd`, `tmp`,
`mnt/*` and `n/*` are mount points in a running Plan 9 system, and on the
source server they are intentionally empty stubs. Their role in the design
is documented below.

## The tree, directory by directory

Every top-level entry of the Plan 9 root, with the survey's own numbers and
the verdict on what happens to it in NamikazeOS:

| dir | dirs | files | MB | what it is in Plan 9 | NamikazeOS verdict |
| --- | --- | --- | --- | --- | --- |
| `sys/` | 499 | 10,019 | 113.99 | the system itself: kernel (`sys/src/9`), all userland (`sys/src/cmd`), libraries (`sys/src/lib*`), headers (`sys/include`), man pages (`sys/man`) | the semantics of its protocol layer, shell and build tool are adapted into Rust (`lib/namikaze-9p`, `tools/namikaze-rc`, `tools/namikaze-mk`); see the mapping section |
| `386/` | 21 | 626 | 118.23 | compiled x86 binaries and libraries for the 4th edition | not portable; NamikazeOS builds its own artifacts from source (the OneISO pipeline) |
| `lib/` | 141 | 4,900 | 42.21 | fonts, faces, keyboard maps, troff macros, zoneinfo, audio | data assets, not code; NamikazeOS ships its own `etc/` and `lib/` policy trees |
| `acme/` | 17 | 86 | 1.29 | the Acme editing environment (user-side data) | out of scope for this phase; a text UI is a project of its own |
| `adm/` | 1 | 73 | 0.07 | user/group databases, logging scaffolding | NamikazeOS keeps its own `etc/` identity model |
| `mail/` | 10 | 36 | 0.91 | the mail file system and upas suite | not adapted; no mail subsystem exists here |
| `rc/` | 11 | 193 | 0.11 | rc runtime data (`rcmain`, function libraries) | the shell itself is adapted in Rust as `tools/namikaze-rc` with its own startup; the data files would be meaningless without the same device namespace |
| `usr/` | 7 | 11 | 0.01 | skeleton home directories | NamikazeOS has its own `root/` and `usr/` layout |
| `arm/`, `mips/`, `power/`, `sparc/`, `power64/`, `amd64/` | ~88 | 38 | 0.06 | per-architecture binary dirs (mostly empty stubs on the mirror) | not portable; the workspace targets x86_64 and aarch64 musl from source |
| `dist/` | 3 | 16 | 0.01 | distribution packaging scripts | NamikazeOS has `namikaze-dist` and the OneISO pipeline |
| `cfg/` | 2 | 8 | 0.00 | plot filters and small config | folded into the "data, not code" verdict |
| `cron/` | 2 | 2 | 0.00 | cron spool skeleton | NamikazeOS runs its own `etc/cron.weekly` |
| `env/`, `fd/`, `tmp/` | 0 | 0 | 0.00 | mount points: the env device, the fd device, scratch space | the *idea* is adapted: `Synth` dynamic files in `namikaze-9p` serve generated content exactly like `#e`/`#d` do |
| `mnt/`, `n/` | 65 | 0 | 0.00 | per-service and per-namespace mount point trees | the *idea* is adapted: the 9P server framework exists so any service can expose a namespace |
| `lp/` | 4 | 0 | 0.00 | line printer spool stubs | not adapted |
| root files | 23 | 7 | 0.04 | `LICENSE`, `LICENSE.*`, `NOTICE*` | the MIT license and NOTICE text is what makes this adaptation lawful; they are cited, and the workspace carries MPL-2.0 for new code |

Inside `sys/`, the survey counted the load-bearing subtrees: `sys/src/cmd`
holds 109 program directories and 1,633 files (rc, mk, fossil, cwfs, upas,
acme, and the whole utility belt); `sys/src/9` holds 12 kernel architecture
trees (pc, bcm, kw, mtx, omap, teg2 and friends) plus `port` and `boot`;
`sys/src/lib*` holds 24 library trees, including `lib9p`, `libc`, `lib9`,
`libauth`, `libString`; `sys/include` carries `fcall.h`, the protocol
contract every 9P implementation on earth still checks against.

## What was adapted, and why these five

The userland tools of Plan 9 (cat, ls, wc, ...) already have their
equivalents in this system: `tools/namikaze-userland` provides 52 of them as
one binary, and duplicating them under a Plan 9 label would be dead weight.
What Plan 9 actually contributed to the world - the things worth carrying -
are its three load-bearing ideas and their implementations:

1. **9P2000, the protocol of "everything is a file"** - adapted as
   `lib/namikaze-9p`. The message set is transcribed from the surveyed
   `sys/include/fcall.h`; the server shape follows `sys/src/lib9p`
   (backend trait + fid table + connection loop); the synthetic tree
   follows `sys/src/lib9p/file.c`. The errno catalogue is transcribed from
   the surveyed `/sys/src/9/port/error.h` (58 canonical strings), and the
   server answers with those exact strings. 37 tests, including a hostile
   frame that must be answered with a salvaged tag and a session that
   survives it.
2. **rc, the list-valued shell** - adapted as `tools/namikaze-rc`. The
   grammar follows the surveyed `rc(1)`: single-quote-only quoting with
   `''` doubling, list variables, `(a b c)` literals, `^` concatenation
   with pairwise/singleton/cross rules, `$x(1 2)` subscripts, `$#x`,
   `~` pattern matching, `` ` ``{...} command substitution, if/while/for,
   `if not`, assignments scoped to a command per the manual's exact rule,
   globs on the result of substitution, pipelines, `< > >> <>`. 35 tests.
3. **mk, the dependency-driven build tool** - adapted as
   `tools/namikaze-mk`. Rule attributes D, E, N, Q, U, V; meta-rules with
   `%` (any stem) and `&` (no dot or slash); `$target $prereq
   $newprereq $stem $pid`; `<file` includes; command-line variable
   overrides that beat mkfile assignments in any argument position; cycle
   detection that prints the loop. 18 tests.
4. **a server and a probe to make the protocol user-visible** - adapted as
   `tools/namikaze-9srv`: `serve` exports a real directory read-only over
   9P2000 (a Rust rewrite of the DirFs pattern), `probe` runs a full
   session with `--trace` printing every T-message and R-message, so a
   misbehaving peer is debuggable wire frame by wire frame. 3 tests over
   real TCP sockets.
5. **the plumber** (3.0.0-alpha.6) - adapted as `tools/namikaze-plumber`:
   Plan 9's message router, the thing that turns `plumb(6)` messages
   into actions. The rules language is transcribed from
   `src/cmd/plumb/rules.c` (objects `arg attr data dst plumb src type
   wdir`, `kind` kept as the historic spelling of `type`, verbs `add
   client delete is isdir isfile matches set start to`, variable
   assignment with `$` expansion, `include` with the depth-10 guard,
   and the exact validation errors); the matcher from
   `src/cmd/plumb/match.c` (every pattern rule in order, rewrites on
   the way, a failed ruleset keeps its mutations, the click protocol,
   `isdir`/`isfile` through plan9 `cleanname`, and the
   start/client decision); the message wire format from
   `src/libplumb/mesg.c` (six header lines, quoted attributes,
   `plumbunpackpartial`'s complete/incomplete/bad outcomes); a Plan 9
   regular expression engine for the `matches` verb (leftmost,
   longest-overall, `$0..$99`, bounded at the C `NMATCHSUBEXP` of
   100, with a step budget where the C engine could smash its stack);
   and the file interface from `src/cmd/plumb/fsys.c` - `send`,
   `rules`, one read-only file per port - served over real 9P2000 on
   `namikaze-9p`, with blocking reads, a copy of each message per
   client, holds released when a port opens, and the exact wire
   errors. Where the C plumber could die at runtime (an expansion
   failure mid-match) this port answers the sender with `Rerror`,
   and where the C click matcher mixed byte offsets with character
   counts this port works in characters; both departures are marked
   at the code. 68 tests, including full 9P sessions over real
   sockets.

The five crates add 161 tests to the workspace, all std-only, zero
third-party dependencies, `#![forbid(unsafe_code)]`.

## What was deliberately not adapted

- **The kernel** (`sys/src/9`): NamikazeOS has its own no_std kernel and
  its own boot path. Two kernels in one repository would be two half
  kernels.
- **fossil/venti/cwfs** (`sys/src/cmd/fossil`, `cwfs`, `venti`): the
  NamFS encrypted volume in `lib/namikaze-fs` is this system's own
  storage format with different guarantees (AES-256-XTS, PBKDF2 gate,
  per-file SHA-256). A Plan 9 file system would add a second trust base,
  not a feature.
- **auth/factotum**: authentication machinery must not be ported
  opportunistically; the 9P stack answers Tauth with the honest
  "authentication required" until a real design exists.
- **Compiled binary trees** (`386/` and the per-arch dirs): not portable
  by definition; the OneISO pipeline builds everything from source.
- **Data assets** (`lib/` fonts, troff, zoneinfo): payload, not design.

## Method and reproduction

`plan9_crawl.py` (Python 3 stdlib only, kept next to this document) walks the source tree
breadth-first with a 0.2 s delay per request, caches listings under
`/tmp/plan9cache`, and writes the complete manifest:

```
python3 usr/src/namikaze/docs/plan9/plan9_crawl.py \
    --out usr/src/namikaze/docs/plan9/plan9-tree.json \
    --file LICENSE --file NOTICE --file sys/include/fcall.h \
    --file sys/src/cmd/mk/mk.h --file sys/src/9/port/error.h \
    --file sys/man/1/rc --file sys/man/1/mk
```

The plumber (3.0.0-alpha.6) grounds itself the same way, in the
plan9port mirror of the same sources: `src/cmd/plumb/{rules,match,
fsys,plumb,plumber}.c`, `src/libplumb/mesg.c`, `man/man4/plumber.4`
and the surveyed `plumb(6)` message format, read from
`github.com/9fans/plan9port` and `9p.io/magic/man2html/6/plumb`
after the crawl cache was pruned.

The `--file` payloads were read during this survey and are the ground
truth for the first four adaptations: `fcall.h` for the message set,
`error.h` for the errno strings, `rc(1)` for the shell grammar and
assignment rules, `mk(1)` for the attribute and stem semantics.
