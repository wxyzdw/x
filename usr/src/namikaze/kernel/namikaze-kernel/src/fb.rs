// SPDX-License-Identifier: MPL-2.0
//! fb: a safe drawing surface over the bootloader's framebuffer.
//!
//! The raw pointer handed over by the boot protocol is wrapped once,
//! validated (RGB memory model, >= 24 bpp), and from there on every
//! pixel write goes through bounds-checked primitives. Channel masks
//! from the protocol are honored so any RGB ordering works.

#![allow(unsafe_code)]

use core::ptr;

use crate::limine::FramebufferInfo;

/// The linear framebuffer surface. Pixels are addressed `(x, y)` from
/// the top-left corner; the color is packed per the reported masks.
pub struct Framebuffer {
    base: *mut u8,
    width: u64,
    height: u64,
    pitch: u64,
    bpp: u16,
    red: (u8, u8),
    green: (u8, u8),
    blue: (u8, u8),
}

/// RGB memory model reported by the protocol (LIMINE_FRAMEBUFFER_RGB).
const MEMORY_MODEL_RGB: u8 = 1;

impl Framebuffer {
    /// Wrap the probed framebuffer; `None` when it is not a linear RGB
    /// surface this stage knows how to draw on.
    pub fn new(info: &FramebufferInfo) -> Option<Self> {
        if info.memory_model != MEMORY_MODEL_RGB || info.bpp < 24 || info.address == 0 {
            return None;
        }
        Some(Self {
            // SAFETY: the address is a valid, kernel-visible mapping the
            // bootloader created for exactly this purpose; every access
            // stays inside `pitch * height` bytes.
            base: info.address as *mut u8,
            width: info.width,
            height: info.height,
            pitch: info.pitch,
            bpp: info.bpp,
            red: (info.red_size, info.red_shift),
            green: (info.green_size, info.green_shift),
            blue: (info.blue_size, info.blue_shift),
        })
    }

    pub fn width(&self) -> u64 {
        self.width
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    /// Pack an 8-bit-per-channel RGB color into the surface's layout.
    pub fn color(&self, rgb: (u8, u8, u8)) -> u64 {
        let pack = |(size, shift): (u8, u8), value: u8| -> u64 {
            let max = if size == 0 || size >= 8 { u8::MAX as u64 } else { (1u64 << size) - 1 };
            ((u64::from(value) * max + 127) / 255) << shift
        };
        pack(self.red, rgb.0) | pack(self.green, rgb.1) | pack(self.blue, rgb.2)
    }

    fn write_pixel(&self, x: u64, y: u64, packed: u64) {
        if x >= self.width || y >= self.height {
            return;
        }
        let bytes = u64::from(self.bpp) / 8;
        let at = self.base as usize + (y * self.pitch + x * bytes) as usize;
        // SAFETY: inside pitch*height by construction; aligned since the
        // base is word aligned and x*bytes keeps the sub-word offset.
        unsafe {
            let p = at as *mut u8;
            for i in 0..bytes as usize {
                ptr::write_volatile(p.add(i), (packed >> (i * 8)) as u8);
            }
        }
    }

    /// Fill a rectangle with a pre-packed color; clipped to the surface.
    pub fn rect(&self, x: i64, y: i64, w: u64, h: u64, packed: u64) {
        for row in 0..h {
            let py = y + row as i64;
            if py < 0 {
                continue;
            }
            for col in 0..w {
                self.write_pixel((x + col as i64).max(0) as u64, py as u64, packed);
            }
        }
    }

    /// Fill the entire surface.
    pub fn clear(&self, packed: u64) {
        self.rect(0, 0, self.width, self.height, packed);
    }
}
