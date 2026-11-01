// SPDX-License-Identifier: MPL-2.0
//! namikaze-dist: the release pipeline library.
//!
//! Everything between "sources are green" and "artifacts exist" lives
//! here: SBOM, bootid seal, kernel build + validation, NamFS demo
//! volume, ISO image, checksums, ebuild regeneration and the source
//! zip. The `namikaze` tool's build script drives `pipeline::full_build`
//! on every plain `cargo build`; the same functions back the CLI
//! subcommands so CI and local runs share one implementation.

pub mod ebuilds;
pub mod kernel;
pub mod pipeline;
pub mod release;
pub mod rust_kernel;
pub mod verify;
