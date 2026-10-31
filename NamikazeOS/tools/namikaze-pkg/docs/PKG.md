# namikaze-pkg

Image-based package operations over the binhost: converge, verify,
snapshot, rollback.

## Why

A hardened system wants package state to be declarative and replayable.
`namikaze-pkg` drives the package manager toward the declared `@world`
plus the package sets in `overlay/package.sets/`, and keeps quickpkg
snapshots so a bad update is a rollback, not a rebuild.

## Commands

    namikaze-pkg converge         converge @world and all package sets
    namikaze-pkg check-collision  detect file collisions across packages
    namikaze-pkg verify           verify installed files exist
    namikaze-pkg snapshot         snapshot the installed set with quickpkg
    namikaze-pkg snapshots        list available snapshots
    namikaze-pkg rollback FILE    reinstall everything from a snapshot

## Semantics

- `converge` is idempotent: converged twice, the second run is a no-op.
- `check-collision` is the guard against two packages shipping the same
  path, which otherwise surfaces as a corrupted overlay later.
- `verify` checks installed-file presence and reports missing paths;
  pair it with `namikaze-watch` for tamper detection.
- `snapshot`/`rollback` wrap quickpkg output stored on the binhost;
  `rollback` reinstalls the exact set listed in a snapshot file.

## Security posture

The tool never fetches over the network itself; the binhost sync is the
cron-driven `namikaze-secpatch` path, and installed-set integrity is
verifiable with `xtask verify`-produced digests.
