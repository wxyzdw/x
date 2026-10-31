// SPDX-License-Identifier: MPL-2.0
//! namikaze-kernel: the bare-metal `no_std` kernel stage of NamikazeOS.
//!
//! Booted by Limine (boot protocol, base revision 2) straight into the
//! framebuffer: this stage paints the boot splash - the nine-tailed
//! chakra fox over a dark warm field, the project title, the running
//! version, the bootid seal and an animated progress bar - while
//! mirroring every step onto COM1. It ends in a deliberate quiescent
//! halt; the userland boot chain stages on from here in later releases.
//!
//! All logic lives in the library target (`src/lib.rs`); this binary is
//! only the freestanding entry point and the panic handler.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

use namikaze_kernel::{boot::BootOptions, draw, fb, limine, port, serial};

/// Kernel panic: crimson the screen, cry on COM1, park forever.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    serial::line("PANIC: kernel stage aborted");
    if let Some(fb) = limine::framebuffer().and_then(|info| fb::Framebuffer::new(&info)) {
        fb.clear(fb.color((0x8B, 0x1A, 0x1A)));
    }
    port::halt_forever()
}

/// Limine hands over a >= 64 KiB stack and jumps to the ELF entry with
/// interrupts disabled; the protocol ABI is System V without FP/SIMD,
/// which the integer-only splash respects by construction.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    serial::init();
    serial::line("namikaze-kernel 3.0.0-alpha.3 (no_std, bare metal)");

    let revision = limine::loaded_base_revision();
    if revision == 0 {
        serial::line("limine: base revision 2 locked");
    } else {
        serial::line("limine: requested revision unsupported, booted compatibility mode");
    }

    let (raw_cmdline, len) = limine::cmdline();
    let boot = BootOptions::parse(&raw_cmdline[..len]);
    if boot.ref_str().is_some() {
        serial::line("limine: bootid seal present");
    }
    if boot.safe_mode() {
        serial::line("limine: namikaze.safe=yes detected");
    }
    if let Some(label) = boot.namfs_label() {
        serial::line("limine: NamFS persistent layer label present");
        let _ = label;
    }

    let Some(info) = limine::framebuffer() else {
        serial::line("limine: no framebuffer granted, nothing to paint");
        port::halt_forever();
    };
    let Some(surface) = fb::Framebuffer::new(&info) else {
        serial::line("limine: framebuffer is not a linear RGB surface");
        port::halt_forever();
    };

    let version = draw::ArrayString::from(env!("CARGO_PKG_VERSION")).ascii_upper();
    let splash_info = draw::Splash {
        version: version.as_str(),
        bootid: boot.ref_str(),
        namfs: boot.namfs_label(),
    };

    draw::splash(&surface, &splash_info);
    serial::line("splash: frame painted");

    for step in [72u64, 76, 80, 84, 88, 92, 96, 100] {
        port::pause();
        draw::progress(&surface, step);
    }
    serial::line("splash: boot complete, stage quiescent");
    port::halt_forever()
}
