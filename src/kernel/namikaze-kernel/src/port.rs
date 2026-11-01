// SPDX-License-Identifier: MPL-2.0
//! port: the audited raw-hardware boundary of the kernel.
//!
//! The rest of the crate is safe Rust; these three instructions are the
//! only places that touch the machine directly. `outb` drives the serial
//! port and anything else that needs a byte on an I/O port, `inb` reads
//! one back, `hlt` parks the CPU until the next interrupt.

#![allow(unsafe_code)]

use core::arch::asm;

/// Write one byte to an x86 I/O port.
pub fn outb(port: u16, value: u8) {
    // SAFETY: I/O port writes are the documented mechanism for driving
    // legacy devices (COM1 at 0x3F8); ports used by callers are fixed.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
    }
}

/// Read one byte from an x86 I/O port.
pub fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: see `outb`; reads only from caller-chosen legacy ports.
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack));
    }
    value
}

/// Park the CPU until the next interrupt, forever (the kernel's quiescent state).
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: hlt is unprivileged; a wake (NMI/SMI) just re-enters the loop.
        unsafe { asm!("hlt", options(nomem, nostack)) }
    }
}

/// One tick of the boot-splash delay: a pure busy spin, long enough to be
/// visible on real hardware and completely deterministic in behavior.
pub fn pause() {
    for _ in 0..40_000_000 {
        core::hint::spin_loop();
    }
}
