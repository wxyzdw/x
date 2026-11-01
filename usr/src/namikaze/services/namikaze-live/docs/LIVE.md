# namikaze-live

Live boot runtime helper: snapshot, session flush and safe ejection for
the read-only squashfs root with a tmpfs overlay.

## Why

The live runtime is a read-only root plus a writable upper layer. Three
operations decide whether that is robust: flushing session state into
the upper layer, taking a portable snapshot, and releasing every mount
without corrupting the medium. `namikaze-live` implements exactly these
and is what `namikaze-eject.stop` and the desktop exit hooks call.

## Commands

    namikaze-live eject                              release live mounts safely
    namikaze-live session-flush                      flush session upper layer
    namikaze-live snapshot [--upper DIR] --out FILE  squashfs snapshot

- `eject` unmounts overlays and the ISO medium in dependency order,
  syncing before each step; it refuses when a process still holds the
  tree, listing the offenders.
- `session-flush` commits the session's upper-layer deltas so a reboot
  into `persist` mode keeps them.
- `snapshot` produces a squashfs image of the current overlay, usable
  as a bootable state or an archival point.

## Relation to other crates

`namikaze-live-core` holds the mount/overlay model shared with
`namikaze-init`; `namikaze-persist` handles the persistent (LUKS) side
of storage. This crate is the operator-facing surface of the live tier.
