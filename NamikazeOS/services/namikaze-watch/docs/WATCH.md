# namikaze-watch

Filesystem tamper evidence: capture a baseline, detect every deviation.

## Why

On a live or persistent system the question is not only "is malware
running" but "did anything modify the boot path, the service files or
the config". `namikaze-watch` hashes a set of trees into a signed-off
baseline and makes every later change explicit: modified, new or
missing files, listed with their hashes.

## Commands

    namikaze-watch init   [--paths DIR,...]   capture a new baseline
    namikaze-watch check  [--paths DIR,...]   compare current tree to the baseline
    namikaze-watch daemon [--paths DIR,...] [--interval SECS]   live watcher

- `init` walks the trees and stores the baseline under
  `/var/lib/namikaze/watch`.
- `check` exits non-zero when the current state differs, so it plugs
  directly into OpenRC services and CI.
- `daemon` reruns the comparison on an interval and logs findings via
  `namikaze-logd`; its OpenRC service is `namikaze-trace`-friendly.

## Defaults

The default path set covers the sysroot boot path, the OpenRC service
directory and `/etc/namikaze`. Baselines are JSON, deliberately
human-readable, and re-`init` after an intended change is the only way
a change stops being reported.
