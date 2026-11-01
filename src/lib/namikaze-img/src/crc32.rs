// SPDX-License-Identifier: MPL-2.0
//! CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320) - the checksum the
//! UEFI GPT spec mandates for the header and the partition entry
//! array. Table-driven, `no` dependencies; the standard check value
//! (`123456789` -> `0xCBF43926`) is a test.

#![forbid(unsafe_code)]

/// The canonical CRC-32/ISO-HDLC check value for the ASCII digits.
pub const CHECK: u32 = 0xCBF4_3926;

fn table() -> &'static [u32; 256] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut crc = i as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
            }
            *slot = crc;
        }
        t
    })
}

/// CRC-32 of `data`, standard init and final xor.
pub fn crc32(data: &[u8]) -> u32 {
    let t = table();
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = t[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_check_value() {
        assert_eq!(crc32(b"123456789"), CHECK);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn known_vectors() {
        // classic zlib vectors
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414F_A339);
        assert_eq!(crc32(&[0x00]), 0xD202_EF8D);
    }
}
