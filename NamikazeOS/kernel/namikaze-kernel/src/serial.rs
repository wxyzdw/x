// SPDX-License-Identifier: MPL-2.0
//! serial: 16550 UART logging on COM1, the kernel's headless eyes.
//!
//! Boot progress is mirrored here so a machine without a usable
//! framebuffer still documents its boot; CI captures the same lines
//! from the QEMU/isa-debugcon side in future stages.

use crate::port::{inb, outb};

const COM1: u16 = 0x3F8;
const DATA: u16 = COM1;
const INTERRUPT_ENABLE: u16 = COM1 + 1;
const FIFO_CONTROL: u16 = COM1 + 2;
const LINE_CONTROL: u16 = COM1 + 3;
const MODEM_CONTROL: u16 = COM1 + 4;
const LINE_STATUS: u16 = COM1 + 5;

/// Bring COM1 up at 115200 8N1 with FIFOs enabled.
pub fn init() {
    outb(INTERRUPT_ENABLE, 0x00); // no interrupts from the UART
    outb(LINE_CONTROL, 0x80); // DLAB on: divisor latch selectable
    outb(DATA, 0x01); // divisor 1 -> 115200 baud
    outb(INTERRUPT_ENABLE, 0x00);
    outb(LINE_CONTROL, 0x03); // 8 data bits, no parity, 1 stop
    outb(FIFO_CONTROL, 0xC7); // enable + clear FIFOs, 14-byte threshold
    outb(MODEM_CONTROL, 0x0B); // DTR | RTS | OUT2
}

fn send(byte: u8) {
    // wait for the transmit holding register to empty (bit 5)
    let mut spins = 0;
    while inb(LINE_STATUS) & 0x20 == 0 {
        spins += 1;
        if spins > 1_000_000 {
            return; // never wedge the boot on a stuck line
        }
    }
    outb(DATA, byte);
}

/// Write a whole line to COM1; `\n` becomes CRLF for terminal viewers.
pub fn write(text: &str) {
    for byte in text.bytes() {
        match byte {
            b'\n' => {
                send(b'\r');
                send(b'\n');
            }
            other => send(other),
        }
    }
}

/// `write` plus a trailing newline.
pub fn line(text: &str) {
    write(text);
    write("\n");
}
