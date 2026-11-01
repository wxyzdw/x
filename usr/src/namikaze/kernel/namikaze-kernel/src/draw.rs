// SPDX-License-Identifier: MPL-2.0
//! draw: the boot splash, ported 1:1 from the design preview that was
//! approved on a rendered raster (scripts/kurama_splash.py).
//!
//! Palette and composition follow the reference scene the user picked:
//! a nine-tailed chakra fox emerging from a dark warm background, with
//! the project title, version and a boot progress bar underneath. All
//! geometry is proportional to the framebuffer height, so any GOP mode
//! gets the same frame. Integer math only - the boot ABI is soft-float.

use crate::fb::Framebuffer;

/// Warm near-black background of the reference scene.
const BG: (u8, u8, u8) = (0x13, 0x10, 0x09);
const FUR_LIGHT: (u8, u8, u8) = (0xF0, 0x8C, 0x3C);
const FUR_MID: (u8, u8, u8) = (0xD9, 0x6A, 0x24);
const FUR_DEEP: (u8, u8, u8) = (0xA3, 0x4A, 0x16);
const OUTLINE: (u8, u8, u8) = (0x2A, 0x1C, 0x14);
const EYE_GLOW: (u8, u8, u8) = (0xFF, 0x6A, 0x2A);
const WHITE: (u8, u8, u8) = (0xF5, 0xEF, 0xE4);
const INK: (u8, u8, u8) = (0x24, 0x1A, 0x14);
const CHAKRA_BRIGHT: (u8, u8, u8) = (0xFF, 0xD9, 0x8A);
const TITLE_TOP: (u8, u8, u8) = (0xFF, 0xC8, 0x66);
const TITLE_BOTTOM: (u8, u8, u8) = (0xE0, 0x6A, 0x1E);
const TAIL_BASE: (u8, u8, u8) = (0x8A, 0x3C, 0x14);
const TAIL_TIP: (u8, u8, u8) = (0xFF, 0x9A, 0x3C);
const FLOOR_GLOW: (u8, u8, u8) = (0x2E, 0x1A, 0x0C);
const TRACK: (u8, u8, u8) = (0x1D, 0x16, 0x0E);
const TRACK_EDGE: (u8, u8, u8) = (0x33, 0x24, 0x1A);

/// Pixel-art fox face, 38 columns x 26 rows ('.' = background).
/// Glyphs: d outline, O light fur, o mid fur, u deep fur, e eye glow,
/// w muzzle white, n nose/mouth.
const FACE: &[&str] = &[
    "........dd.................dd.........",
    ".......dOOd...............dOOd........",
    "......dOOOOd.............dOOOOd.......",
    ".....dOooooOd...........dOooooOd......",
    "....dOooooooOd.........dOooooooOd.....",
    "...dOoooooooOd.........dOoooooooOd....",
    ".......dOoooooooooooooooooooooOd......",
    ".....dOoooooooooooooooooooooooooOd....",
    "...dOood......doooooooood......dooOd..",
    "..dOooo.d....d.ooooooooo.d....d.oooOd.",
    ".dOooo.eeeeee.oooooooooo.eeeeee.ooooOd",
    ".dOoooweeeeeeeooooooooooeeeeeeewooooOd",
    ".dOoooeeeeeeeeooooooooooeeeeeeeeooooOd",
    ".dOooo.eeeeee.oooooooooo.eeeeee.ooooOd",
    "..dOooooooo..dwwwwwwwd..oooooooooooOd.",
    "...dOoooooo.dwwwwnnwwwwdooooooooooOd..",
    ".....douuuudwwwwwnnwwwwwduuuuuuuod....",
    ".......douudwwwwwnwwwwwwduuuuuod......",
    ".........do.dwwwwwwwwwwduuuuod........",
    "...........dw.dwwwwwwd.wuuod..........",
    ".............d.dwwwwd.d.od............",
    "...............dddd..uod..............",
    ".................douod................",
    "..................dood................",
    "......................................",
    "......................................",
];

/// 5x7 block glyphs for the project title.
const TITLE_FONT: &[(&str, [&str; 7])] = &[
    ("N", ["10001", "11001", "10101", "10011", "10001", "10001", "10001"]),
    ("A", ["01110", "10001", "10001", "11111", "10001", "10001", "10001"]),
    ("M", ["10001", "11011", "10101", "10101", "10001", "10001", "10001"]),
    ("I", ["11111", "00100", "00100", "00100", "00100", "00100", "11111"]),
    ("K", ["10001", "10010", "10100", "11000", "10100", "10010", "10001"]),
    ("Z", ["11111", "00001", "00010", "00100", "01000", "10000", "11111"]),
    ("E", ["11111", "10000", "10000", "11110", "10000", "10000", "11111"]),
];

/// 3x5 microfont, row-major bits: the subset of A-Z, digits and
/// punctuation the splash strings use.
const MICRO: &[(&str, &str)] = &[
    ("A", "010101111101101"),
    ("B", "110101110101110"),
    ("D", "110101101101110"),
    ("E", "111100110100111"),
    ("H", "101101111101101"),
    ("I", "111010010010111"),
    ("K", "101101110101101"),
    ("L", "100100100100111"),
    ("M", "101111111101101"),
    ("N", "101110111101101"),
    ("O", "010101101101010"),
    ("P", "110101110100100"),
    ("R", "110101110110101"),
    ("S", "011100010001110"),
    ("T", "111010010010010"),
    ("U", "101101101101111"),
    ("X", "101101010101101"),
    ("Z", "111001010100111"),
    ("0", "010101101101010"),
    ("1", "010110010010111"),
    ("2", "110001010100111"),
    ("3", "111001110001110"),
    ("4", "101101111001001"),
    ("5", "111100110001110"),
    ("6", "011100110101010"),
    ("7", "111001010010010"),
    ("8", "010101010101010"),
    ("9", "010101011001110"),
    ("C", "011100100100011"),
    ("F", "111100110100100"),
    (".", "000000000000010"),
    ("-", "000000111000000"),
    (" ", "000000000000000"),
];

/// Linear interpolation between two RGB colors; `num/den` in [0, 1].
fn lerp(a: (u8, u8, u8), b: (u8, u8, u8), num: u64, den: u64) -> (u8, u8, u8) {
    let ch = |x: u8, y: u8| -> u8 {
        let mix = (u64::from(x) * (den - num) + u64::from(y) * num) / den;
        mix as u8
    };
    (ch(a.0, b.0), ch(a.1, b.1), ch(a.2, b.2))
}

/// One fanned chakra tail: a quadratic bezier from behind the face
/// outward, brightening along the way with a chakra-bright tip. The
/// fan parameter `u_m` runs in [-1000, 1000] (per-mille of the spread).
fn draw_tail(fb: &Framebuffer, base: (i64, i64), u_m: i64, length: i64) {
    let au = u_m.abs();
    let tip_x = base.0 + u_m * length * 135 / 100_000;
    let tip_y = base.1 - length * (500 - 175 * au / 1000) / 1000;
    let ctl_x = base.0 + u_m * length * 80 / 100_000;
    let ctl_y = base.1 - length * 95 / 100;
    let steps = (length / 2).max(8);
    for s in 0..steps {
        let t = (s * 255) / steps;
        let it = 255 - t;
        let x = (it * it * base.0 + 2 * it * t * ctl_x + t * t * tip_x) / (255 * 255);
        let y = (it * it * base.1 + 2 * it * t * ctl_y + t * t * tip_y) / (255 * 255);
        let radius = (5 * it / 255 + 1).max(2);
        let rgb = if t > 235 { CHAKRA_BRIGHT } else { lerp(TAIL_BASE, TAIL_TIP, t as u64, 255) };
        let packed = fb.color(rgb);
        for dy in -radius..=radius {
            for dx in -radius..=radius {
                if dx * dx + dy * dy <= radius * radius {
                    fb.rect(x + dx, y + dy, 1, 1, packed);
                }
            }
        }
    }
}

/// The fox face with a light-to-deep vertical fur gradient.
fn draw_face(fb: &Framebuffer, ox: i64, oy: i64, k: u64) {
    let rows = FACE.len() as u64 - 1;
    for (j, row) in FACE.iter().enumerate() {
        let fur = lerp(FUR_LIGHT, FUR_DEEP, j as u64, rows);
        let fur_mid = lerp(FUR_MID, FUR_DEEP, j as u64, rows);
        for (i, ch) in row.chars().enumerate() {
            let rgb = match ch {
                'O' | 'u' => fur,
                'o' => fur_mid,
                'd' => OUTLINE,
                'e' => EYE_GLOW,
                'w' => WHITE,
                'n' => INK,
                _ => continue,
            };
            let packed = fb.color(rgb);
            fb.rect(ox + i as i64 * k as i64, oy + j as i64 * k as i64, k, k, packed);
        }
    }
}

fn draw_block_text(fb: &Framebuffer, text: &str, cx: i64, y: i64, scale: u64) {
    let s = scale as i64;
    let width = text.chars().count() as i64 * 6 * s - s;
    let mut x = cx - width / 2;
    for ch in text.chars() {
        if let Some((_, glyph)) = TITLE_FONT.iter().find(|(name, _)| name.starts_with(ch)) {
            for (j, rowbits) in glyph.iter().enumerate() {
                let packed = fb.color(lerp(TITLE_TOP, TITLE_BOTTOM, j as u64, 6));
                for (i, b) in rowbits.chars().enumerate() {
                    if b == '1' {
                        fb.rect(x + i as i64 * s, y + j as i64 * s, scale, scale, packed);
                    }
                }
            }
        }
        x += 6 * s;
    }
}

fn draw_micro(fb: &Framebuffer, text: &str, cx: i64, y: i64, scale: u64, rgb: (u8, u8, u8)) {
    let s = scale as i64;
    let width = text.chars().count() as i64 * 4 * s - s;
    let mut x = cx - width / 2;
    let packed = fb.color(rgb);
    for ch in text.chars() {
        if let Some((_, bits)) = MICRO.iter().find(|(name, _)| name.starts_with(ch)) {
            for j in 0..5usize {
                for i in 0..3usize {
                    if bits.as_bytes()[j * 3 + i] == b'1' {
                        fb.rect(x + i as i64 * s, y + j as i64 * s, scale, scale, packed);
                    }
                }
            }
        }
        x += 4 * s;
    }
}

/// Everything the splash needs besides the framebuffer geometry.
pub struct Splash<'a> {
    pub version: &'a str,
    pub bootid: Option<&'a str>,
    pub namfs: Option<&'a str>,
}

fn bar_geometry(fb: &Framebuffer) -> (i64, i64, u64, u64) {
    let (w, h) = (fb.width(), fb.height());
    let bw = h * 340 / 540;
    let bh = 10 * h / 540;
    let bx = (w / 2) as i64 - bw as i64 / 2;
    let by = (h * 90 / 100) as i64;
    (bx, by, bw, bh)
}

/// Draw the complete splash frame: background glow, nine chakra tails,
/// the fox face, title, version, optional bootid and the progress track.
pub fn splash(fb: &Framebuffer, info: &Splash) {
    let bg = fb.color(BG);
    fb.clear(bg);
    let (w, h) = (fb.width(), fb.height());
    let cx = (w / 2) as i64;
    let cy = (h * 42 / 100) as i64;

    // floor glow toward the bottom of the frame
    let glow_h = (h * 140 / 540).max(8);
    for row in 0..glow_h {
        let c = fb.color(lerp(BG, FLOOR_GLOW, row, glow_h));
        fb.rect(0, (h - glow_h + row) as i64, w, 1, c);
    }

    // nine chakra tails fanned from behind the face
    let base_y = cy + (h * 120 / 540) as i64;
    for i in 0..9i64 {
        let u_m = -1000 + i * 250;
        let length = (if u_m.abs() > 700 { h * 260 / 540 } else { h * 300 / 540 }) as i64;
        draw_tail(fb, (cx, base_y), u_m, length);
    }

    // face
    let k = (h / 60).clamp(3, 12);
    let fw = 38 * k as i64;
    draw_face(fb, cx - fw / 2, cy - 13 * k as i64, k);

    // title, version, optional bootid
    let title_y = (h * 76 / 100) as i64;
    let scale = (h / 90).max(2);
    draw_block_text(fb, "NAMIKAZE", cx, title_y, scale);
    let micro_scale = (h / 180).max(2);
    let line_gap = (h * 8 / 540).max(4) as i64;
    draw_micro(fb, info.version, cx, title_y + 7 * scale as i64 + line_gap, micro_scale, WHITE);
    let mut footer_line = 2u64;
    if let Some(seal) = info.bootid {
        let mut line = ArrayString::from("BOOTID ");
        line.push_str(seal);
        draw_micro(
            fb,
            line.as_str(),
            cx,
            title_y + 7 * scale as i64 + footer_line as i64 * line_gap,
            micro_scale,
            FUR_MID,
        );
        footer_line += 1;
    }
    if let Some(label) = info.namfs {
        let mut line = ArrayString::from("NAMFS ");
        line.push_str(label);
        draw_micro(
            fb,
            line.as_str(),
            cx,
            title_y + 7 * scale as i64 + footer_line as i64 * line_gap,
            micro_scale,
            FUR_MID,
        );
    }

    // progress track with the design's 68% pre-fill
    let (bx, by, bw, bh) = bar_geometry(fb);
    fb.rect(bx - 2, by - 2, bw + 4, bh + 4, fb.color(TRACK_EDGE));
    fb.rect(bx, by, bw, bh, fb.color(TRACK));
    fb.rect(bx, by, bw * 68 / 100, bh, fb.color(lerp(TITLE_BOTTOM, CHAKRA_BRIGHT, 217, 255)));
}

/// Animate the progress fill to `percent` (0-100) without touching the
/// rest of the frame.
pub fn progress(fb: &Framebuffer, percent: u64) {
    let (bx, by, bw, bh) = bar_geometry(fb);
    let fill = fb.color(lerp(TITLE_BOTTOM, CHAKRA_BRIGHT, 217, 255));
    fb.rect(bx, by, bw * percent.min(100) / 100, bh, fill);
}

/// Fixed-capacity ASCII string for splash lines (no allocator).
pub struct ArrayString {
    bytes: [u8; 96],
    len: usize,
}

impl ArrayString {
    pub fn from(text: &str) -> Self {
        let mut out = Self { bytes: [0; 96], len: 0 };
        out.push_str(text);
        out
    }

    pub fn push_str(&mut self, extra: &str) {
        for byte in extra.bytes() {
            if self.len < self.bytes.len() {
                self.bytes[self.len] = byte;
                self.len += 1;
            }
        }
    }

    /// Append one raw byte, keeping only printable ASCII.
    pub fn push_ascii(&mut self, byte: u8) {
        if (0x20..0x7F).contains(&byte) {
            self.push_str(core::str::from_utf8(&[byte]).unwrap_or(""));
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Uppercase ASCII form of the string (versions draw from the
    /// microfont, which has no lowercase glyphs).
    pub fn ascii_upper(&self) -> Self {
        let mut out = Self { bytes: [0; 96], len: self.len };
        for (i, byte) in self.bytes[..self.len].iter().enumerate() {
            out.bytes[i] = byte.to_ascii_uppercase();
        }
        out
    }

    pub fn as_str(&self) -> &str {
        // SAFETY (audited): only ASCII bytes from const strings and hex
        // seals ever enter `bytes`, so UTF-8 cannot be violated.
        #[allow(unsafe_code)]
        unsafe {
            core::str::from_utf8_unchecked(&self.bytes[..self.len])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn face_rows_are_rectangular() {
        assert!(FACE.iter().all(|r| r.len() == FACE[0].len()));
        assert_eq!(FACE[0].len(), 38);
    }

    #[test]
    fn splash_strings_fit_the_microfont() {
        for text in ["3.0.0-ALPHA.3", "NAMIKAZE", "BOOTID 0123456789ABCDEF"] {
            for ch in text.chars() {
                assert!(
                    TITLE_FONT.iter().any(|(name, _)| name.starts_with(ch))
                        || MICRO.iter().any(|(name, _)| name.starts_with(ch)),
                    "glyph missing for {ch} in {text}"
                );
            }
        }
    }

    #[test]
    fn arraystring_uppercases_and_bounds() {
        let mut s = ArrayString::from("3.0.0-alpha.3");
        s.push_str(" BOOTID ABCDEF0123456789");
        assert_eq!(s.ascii_upper().as_str(), "3.0.0-ALPHA.3 BOOTID ABCDEF0123456789");
    }
}
