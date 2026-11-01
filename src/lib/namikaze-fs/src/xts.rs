// SPDX-License-Identifier: MPL-2.0
//! xts: XTS-AES-256 (IEEE 1619) for NamFS data units.
//!
//! A data unit (4 KiB sector) is encrypted with AES-256-XTS: the 32-byte
//! key splits into two AES-256 keys (data key, tweak key). The tweak is
//! the data-unit number, serialized little-endian into a 16-byte block;
//! every 16-byte AES block inside the unit advances the tweak by
//! multiplication with x in GF(2^128).

use crate::aes::Aes256;

/// NamFS data unit size.
pub const DATA_UNIT: usize = 4096;

/// Advance one tweak through GF(2^128) (multiplication by x, poly x^128 + x^7 + x^2 + x + 1).
fn mulx(tweak: &mut [u8; 16]) {
    let mut carry = 0u8;
    for byte in tweak.iter_mut() {
        let new_carry = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = new_carry;
    }
    if carry != 0 {
        tweak[0] ^= 0x87;
    }
}

fn whitening_value(number: u64) -> [u8; 16] {
    let mut tweak = [0u8; 16];
    tweak[..8].copy_from_slice(&number.to_le_bytes());
    tweak
}

/// Encrypt one data unit in place (`data.len()` must be a multiple of 16,
/// and at most [`DATA_UNIT`]).
pub fn encrypt_unit(keys: &Aes256, tweak_keys: &Aes256, number: u64, data: &mut [u8]) {
    // XTS: the data-unit number is encrypted with the tweak key to form
    // the initial whitening value T (XEX with GF(2^128) increments)
    let mut tweak = whitening_value(number);
    tweak_keys.encrypt_block(&mut tweak);
    for chunk in data.chunks_mut(16) {
        for (b, t) in chunk.iter_mut().zip(tweak.iter()) {
            *b ^= t;
        }
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        keys.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        for (b, t) in chunk.iter_mut().zip(tweak.iter()) {
            *b ^= t;
        }
        mulx(&mut tweak);
    }
}

/// Decrypt one data unit in place (the exact inverse of [`encrypt_unit`]).
pub fn decrypt_unit(keys: &Aes256, tweak_keys: &Aes256, number: u64, data: &mut [u8]) {
    let mut tweak = whitening_value(number);
    tweak_keys.encrypt_block(&mut tweak);
    for chunk in data.chunks_mut(16) {
        for (b, t) in chunk.iter_mut().zip(tweak.iter()) {
            *b ^= t;
        }
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        keys.decrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        for (b, t) in chunk.iter_mut().zip(tweak.iter()) {
            *b ^= t;
        }
        mulx(&mut tweak);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::Aes256;

    const KEY: [u8; 64] = {
        let mut k = [0u8; 64];
        let mut i = 0;
        while i < 64 {
            k[i] = i as u8;
            i += 1;
        }
        k
    };

    fn key_pair() -> ([u8; 32], [u8; 32]) {
        let mut dk = [0u8; 32];
        let mut tk = [0u8; 32];
        dk.copy_from_slice(&KEY[..32]);
        tk.copy_from_slice(&KEY[32..]);
        (dk, tk)
    }

    #[test]
    fn unit_roundtrip() {
        let (dk, tk) = key_pair();
        let keys = Aes256::new(&dk);
        let tweak_keys = Aes256::new(&tk);
        let plain: Vec<u8> = (0..DATA_UNIT).map(|i| (i % 251) as u8).collect();
        let mut data = plain.clone();
        encrypt_unit(&keys, &tweak_keys, 7, &mut data);
        assert_ne!(data, plain);
        assert_ne!(&data[..16], &data[16..32], "identical plaintext blocks must not collide");
        decrypt_unit(&keys, &tweak_keys, 7, &mut data);
        assert_eq!(data, plain);
    }

    #[test]
    fn tweak_changes_ciphertext() {
        let (dk, tk) = key_pair();
        let keys = Aes256::new(&dk);
        let tweak_keys = Aes256::new(&tk);
        let plain = vec![0x42u8; DATA_UNIT];
        let mut a = plain.clone();
        let mut b = plain.clone();
        encrypt_unit(&keys, &tweak_keys, 0, &mut a);
        encrypt_unit(&keys, &tweak_keys, 1, &mut b);
        assert_ne!(a, b, "same plaintext under a different tweak must differ");
    }

    #[test]
    fn partial_unit_is_supported() {
        let (dk, tk) = key_pair();
        let keys = Aes256::new(&dk);
        let tweak_keys = Aes256::new(&tk);
        let plain: Vec<u8> = (0..48u32).map(|i| i as u8).collect();
        let mut data = plain.clone();
        encrypt_unit(&keys, &tweak_keys, 3, &mut data);
        decrypt_unit(&keys, &tweak_keys, 3, &mut data);
        assert_eq!(data, plain);
    }
}
