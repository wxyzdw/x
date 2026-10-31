// SPDX-License-Identifier: MPL-2.0
//! Build tasks: generators and packaging helpers behind `cargo xtask`.

pub(crate) mod bootid;
pub(crate) mod ci;
pub(crate) mod ebuilds;
pub(crate) mod iso;
pub(crate) mod kernel;
pub(crate) mod release;
pub(crate) mod rust_kernel;
pub(crate) mod sbom;
pub(crate) mod verify;
