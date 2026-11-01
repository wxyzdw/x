# namikaze-trace

Tamper-evident execution activity ledger for NamikazeOS.

## Why

A deny-by-default system still needs a record of what actually ran.
`namikaze-trace` polls the process table and appends one hash-chained
JSONL entry per observed program start, using the same SHA-256 chain
construction as `namikaze-logd`, so both ledgers are verified with the
same mental model and the same tooling.

## Detection model

- Every scan resolves `/proc/PID/exe` and reads the scheduler start tick
  (field 22 of `/proc/PID/stat`).
- A PID is reported as a new execution when it was never seen before or
  when its executable / start tick changed. That second case is PID
  reuse: the strongest signal that something exec'd without your consent.
- Entries whose stat file disappears mid-scan (short-lived processes)
  are skipped for that round and picked up on the next one if they
  survive.

## Chain format

    chain = SHA256("{prev}|{ts}|{pid}|{start}|{exe}")

`namikaze-trace query --verify` walks the file and reports `trace chain
OK` or `trace chain BROKEN` (exit code 1).

## Commands

    namikaze-trace watch [--interval MS] [--proc DIR] [--out FILE] [--one-shot]
    namikaze-trace query [--out FILE] [--last N] [--verify]

Defaults: interval 1000 ms, proc root /proc, output
/var/log/namikaze/trace.jsonl. `--one-shot` seeds the snapshot, writes
one diff and exits (used by tests and CI).

## Service

`etc/init.d/namikaze-trace` runs the watcher under OpenRC,
writing to the canonical output path; the ledger ships in the same
directory as the log daemon's chained log.
