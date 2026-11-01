// SPDX-License-Identifier: MPL-2.0
//! namikaze-kernel library: everything the bare-metal entry point drives.
//!
//! The crate is `no_std` and links against `core` only; the modules are
//! split by audit boundary - `limine` (boot protocol), `fb` (linear
//! framebuffer), `port` (raw I/O instructions), `boot` (command-line
//! options) plus the safe `draw` and `serial` layers on top. Unit tests
//! run through the lib target (`cargo test --lib`) so they never drag
//! the freestanding entry point onto a hosted linker.

#![no_std]
#![deny(unsafe_code)]

pub mod boot;
pub mod draw;
pub mod fb;
pub mod limine;
pub mod port;
pub mod serial;
