# namikaze-9srv

The 9P2000 server and probe: `serve` exports a real directory
read-only over 9P2000, `probe` runs a full protocol session against
any 9P server and prints every frame. Together they make
`lib/namikaze-9p` user-visible - a misbehaving peer is debuggable
wire message by wire message.

## Modules

| module | provides |
| ------ | -------- |
| dirfs  | the read-only filesystem backend: the `Fsys` trait implemented over `std::fs`, real directory listings and stats, plan9 errno wording for failures ("file does not exist", "permission denied") |
| lib    | the re-export boundary so the probe binary and external tests share one namikaze_9p surface |
| main   | the two subcommands: `serve --addr H:P --root DIR` and `probe --addr H:P [--trace] [--stat P] [--read P] [--walk P] [--msize N]` |

## Design rules

- std-only, `#![forbid(unsafe_code)]`; the serve loop is one thread
  per connection over `TcpListener`, each connection getting its own
  `Fsys` instance from a factory closure.
- The export is strictly read-only by construction: `DirFs::open`
  refuses write modes before the protocol layer can reach a mutation,
  and a write on any fid answers `Ebadusefd` without touching the
  backend.
- The probe is honest about failures: a missing walk element exits 2
  with the full error chain (`Twalk: server: file does not exist`);
  `--trace` prints both the T-message and the R-message of every
  exchange, so the wire can be read without a sniffer.
- `--msize` clamps to the protocol bounds; the probe negotiates the
  smaller of its offer and the server's answer, per version(5).

## When to extend

A new backend (synthetic /proc-style views, an encrypted NamFS
export) is a new `Fsys` implementation, not a new server. The probe
grows one flag per question a debugging session actually asks; keep
the trace format stable so transcripts stay comparable.
