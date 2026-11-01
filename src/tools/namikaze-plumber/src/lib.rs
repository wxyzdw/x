// SPDX-License-Identifier: MPL-2.0
//! namikaze-plumber: the Plan 9 plumber of NamikazeOS.
//!
//! Adapted from Plan 9 from Bell Labs and plan9port (MIT licensed) -
//! the daemon that receives, examines, rewrites and dispatches
//! `plumb(6)` messages between programs. What this crate carries
//! over, each piece transcribed against the surveyed C source:
//!
//! - the message and its wire format ([`msg`], from
//!   `src/libplumb/mesg.c`): six header lines and the raw data, with
//!   the quoted-attribute grammar and the three-way
//!   `plumbunpackpartial` outcome (complete / incomplete / bad);
//! - the rules language ([`rules`], from `src/cmd/plumb/rules.c`):
//!   objects `arg attr data dst plumb src type wdir` (`kind` accepted
//!   for `type`), verbs `add client delete is isdir isfile matches
//!   set start to`, variables, `include`, the exact validation
//!   errors, and the incremental `plumb/rules` write machinery;
//! - the matcher ([`matcher`], from `src/cmd/plumb/match.c`): every
//!   pattern rule in order, rewrites on the way, the click protocol,
//!   and the start/client decision for unlistened ports;
//! - the Plan 9 regular expression subset the rules need ([`regex`]):
//!   leftmost, longest-overall, `$0..$99` captures, bounded like the
//!   C `NMATCHSUBEXP`;
//! - the file interface ([`plumbfs`], from `src/cmd/plumb/fsys.c`)
//!   served over real 9P2000 on the [`namikaze-9p`] stack: `send`,
//!   `rules`, and one read-only file per port, with blocking reads,
//!   per-client copies, holds and the exact wire errors.
//!
//! Where the C original could die at runtime (an expansion failure
//! while matching) this port answers the sender with `Rerror`; where
//! the C click matcher mixed byte offsets with character counts this
//! port works in characters, which agrees with the manual. Both
//! departures are marked at the code that makes them.
//!
//! [`namikaze-9p`]: ../namikaze_9p/index.html

#![forbid(unsafe_code)]

pub mod matcher;
pub mod msg;
pub mod plumbfs;
pub mod regex;
pub mod rules;

pub use matcher::{match_ruleset, Exec};
pub use msg::{unpack_partial, Plumbmsg};
pub use plumbfs::{Plumber, PlumberFsys};
pub use regex::Regex;
pub use rules::{RulesParser, Ruleset};
