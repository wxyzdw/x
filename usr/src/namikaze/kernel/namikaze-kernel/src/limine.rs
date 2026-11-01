// SPDX-License-Identifier: MPL-2.0
//! limine: the Limine boot protocol boundary, pinned to base revision 2.
//!
//! Constants are transcribed from the protocol spec the bootloader ships
//! with (Limine-Bootloader/limine-protocol, commit 6e85ddd, the pin the
//! official C template uses); request placement follows the spec's
//! delimited-scanning rules: everything lives in `.limine_requests`
//! between the start and end markers, and the bootloader overwrites the
//! response slots at runtime, so every read goes through `read_volatile`.
//!
//! This is the only module that dereferences bootloader-owned pointers;
//! the rest of the kernel sees plain safe values.

#![allow(unsafe_code)]

use core::ptr;

/// Delimited-scan start marker (spec: "Requests Delimiters").
#[used]
#[no_mangle]
#[link_section = ".limine_requests"]
static REQUESTS_START: [u64; 4] =
    [0xf6b8f4b39de7d1ae, 0xfab91a6940fcb9cf, 0x785c6ed015d3e316, 0x181e920a7852b9d9];

/// Base revision tag: request revision 2 (delimiters are mandatory).
#[used]
#[no_mangle]
#[link_section = ".limine_requests"]
static BASE_REVISION: [u64; 3] = [0xf9562b2d5c95a6c8, 0x6a7b384944536bdc, 2];

/// Delimited-scan end marker.
#[used]
#[no_mangle]
#[link_section = ".limine_requests"]
static REQUESTS_END: [u64; 2] = [0xadc0e0531bb10d03, 0x9572709f31764c62];

/// Common request-id magic shared by every feature request.
const COMMON_MAGIC: [u64; 2] = [0xc7b1dd30df4c8b88, 0x0a82e883a194f07b];

const FRAMEBUFFER_REQUEST_ID: [u64; 4] =
    [COMMON_MAGIC[0], COMMON_MAGIC[1], 0x9d5827dcd881dd75, 0xa3148604f6fab11b];
const CMDLINE_REQUEST_ID: [u64; 4] =
    [COMMON_MAGIC[0], COMMON_MAGIC[1], 0x4b161536e598651e, 0xb390ad4a2f1f303a];

/// Wire layout of a protocol request: 4 id words, a request revision and
/// the response slot the bootloader fills in (or leaves null).
#[repr(C, align(8))]
struct Request {
    id: [u64; 4],
    revision: u64,
    response: u64,
}

/// Framebuffer feature request; revision 1 response layout.
#[used]
#[no_mangle]
#[link_section = ".limine_requests"]
static FRAMEBUFFER_REQUEST: Request =
    Request { id: FRAMEBUFFER_REQUEST_ID, revision: 1, response: 0 };

/// Executable cmdline request: carries the `namikaze.*` boot options.
#[used]
#[no_mangle]
#[link_section = ".limine_requests"]
static CMDLINE_REQUEST: Request = Request { id: CMDLINE_REQUEST_ID, revision: 0, response: 0 };

fn response_of(request: &Request) -> Option<u64> {
    // SAFETY: the bootloader wrote the response slot concurrently with
    // entry into the kernel; volatile reads observe the final value and
    // the slot's address is valid for the lifetime of the image.
    let response = unsafe { ptr::read_volatile(&request.response) };
    (response != 0).then_some(response)
}

/// Word `index` of the response structure at `response`.
fn response_word(response: u64, index: usize) -> u64 {
    // SAFETY: response structures live in bootloader-reclaimable memory
    // and stay valid until the kernel explicitly reclaims it (never, in
    // this stage); `index` stays inside the documented struct layout.
    unsafe { ptr::read_volatile((response as *const u64).add(index)) }
}

/// The base revision the bootloader actually loaded us with, per the
/// spec's tag rewrite rules (`0` = the requested revision is supported).
pub fn loaded_base_revision() -> u64 {
    // SAFETY: same concurrent-write contract as `response_of`.
    unsafe { ptr::read_volatile(&BASE_REVISION[2]) }
}

/// Raw framebuffer probe of the first framebuffer: address (already
/// virtually mapped), geometry, pitch, bpp and RGB channel masks.
pub struct FramebufferInfo {
    pub address: u64,
    pub width: u64,
    pub height: u64,
    pub pitch: u64,
    pub bpp: u16,
    pub memory_model: u8,
    pub red_size: u8,
    pub red_shift: u8,
    pub green_size: u8,
    pub green_shift: u8,
    pub blue_size: u8,
    pub blue_shift: u8,
}

/// Probe the first framebuffer, or `None` when the bootloader granted
/// none (headless boot): the caller then logs over serial and halts.
pub fn framebuffer() -> Option<FramebufferInfo> {
    let response = response_of(&FRAMEBUFFER_REQUEST)?;
    // response: {revision, framebuffer_count, framebuffers**}
    let count = response_word(response, 1);
    if count == 0 {
        return None;
    }
    // SAFETY: array of framebuffer pointers owned by the bootloader.
    let first = unsafe { ptr::read_volatile((response_word(response, 2) as *const u64).add(1)) };
    if first == 0 {
        return None;
    }
    // struct limine_framebuffer: address(0) width(8) height(16) pitch(24),
    // bpp u16 @32, memory_model u8 @34, then RGB size/shift byte pairs.
    let bpp = u16::from_le_bytes([byte_at(first, 32), byte_at(first, 33)]);
    Some(FramebufferInfo {
        address: response_word(first, 0),
        width: response_word(first, 1),
        height: response_word(first, 2),
        pitch: response_word(first, 3),
        bpp,
        memory_model: byte_at(first, 34),
        red_size: byte_at(first, 35),
        red_shift: byte_at(first, 36),
        green_size: byte_at(first, 37),
        green_shift: byte_at(first, 38),
        blue_size: byte_at(first, 39),
        blue_shift: byte_at(first, 40),
    })
}

fn byte_at(base: u64, offset: usize) -> u8 {
    // SAFETY: byte read inside the bootloader-owned framebuffer struct.
    unsafe { ptr::read_volatile((base as *const u8).add(offset)) }
}

/// The bootloader-provided kernel command line, NUL-truncated to 255
/// bytes, or an empty buffer when the request went unanswered.
pub fn cmdline() -> ([u8; 256], usize) {
    let mut buf = [0u8; 256];
    let Some(response) = response_of(&CMDLINE_REQUEST) else { return (buf, 0) };
    // SAFETY: NUL-terminated cmdline string owned by the bootloader.
    let mut len = 0;
    unsafe {
        let mut p = response as *const u8;
        while len < 255 {
            let b = ptr::read_volatile(p);
            if b == 0 {
                break;
            }
            buf[len] = b;
            p = p.add(1);
            len += 1;
        }
    }
    (buf, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_match_pinned_spec() {
        assert_eq!(
            REQUESTS_START,
            [0xf6b8f4b39de7d1ae, 0xfab91a6940fcb9cf, 0x785c6ed015d3e316, 0x181e920a7852b9d9]
        );
        assert_eq!(REQUESTS_END, [0xadc0e0531bb10d03, 0x9572709f31764c62]);
        assert_eq!(BASE_REVISION[0], 0xf9562b2d5c95a6c8);
        assert_eq!(BASE_REVISION[1], 0x6a7b384944536bdc);
        assert_eq!(BASE_REVISION[2], 2);
        assert_eq!(FRAMEBUFFER_REQUEST.id[2], 0x9d5827dcd881dd75);
        assert_eq!(FRAMEBUFFER_REQUEST.id[3], 0xa3148604f6fab11b);
        assert_eq!(CMDLINE_REQUEST.id[2], 0x4b161536e598651e);
    }

    #[test]
    fn request_layout_matches_spec_offsets() {
        // id[4] | revision | response: the offsets every consumer relies on
        assert_eq!(size_of::<Request>(), 48);
        let response_at = core::ptr::addr_of!(FRAMEBUFFER_REQUEST.response) as usize;
        let id_at = core::ptr::addr_of!(FRAMEBUFFER_REQUEST.id) as usize;
        assert_eq!(response_at - id_at, 40);
    }
}
