// SPDX-License-Identifier: MPL-2.0
//! namikaze-9p: the 9P2000 stack of NamikazeOS.
//!
//! Adapted from Plan 9 from Bell Labs (4th edition, MIT licensed) -
//! the historic milestone where "everything is a file" was taken to
//! its logical end. What this crate carries over:
//!
//! - the wire protocol of `/sys/include/fcall.h`: every T-message of
//!   9P2000, the qid and stat structures, framing and msize rules
//!   ([`proto`], [`codec`]);
//! - the server shape of `/sys/src/lib9p`: a backend trait
//!   ([`server::Fsys`]) plus a connection loop that owns the fid
//!   table, open-mode checks and walk semantics;
//! - the synthetic tree of `/sys/src/lib9p/file.c` ([`synth::Synth`]):
//!   build a virtual tree of directories, static and dynamic files in
//!   memory and serve it;
//! - a synchronous client ([`client::Conn`]) in the lib9pclient style;
//! - Plan 9 error culture: the wire carries human-readable `Rerror`
//!   strings, classified into an errno catalogue, and every layer
//!   wraps failures with context instead of erasing them ([`error`]).
//!
//! What it deliberately does not carry over: authentication (Tauth is
//! answered "authentication required"), 9P2000.u extensions, and
//! caching - this is a small, honest, auditable core.

#![forbid(unsafe_code)]

pub mod client;
pub mod codec;
pub mod error;
pub mod proto;
pub mod server;
pub mod synth;

pub use client::Conn;
pub use error::{Errno, Error, Result};
pub use proto::{Dir, Msg, Qid};
pub use server::{serve, serve_conn, Fsys};
pub use synth::Synth;
