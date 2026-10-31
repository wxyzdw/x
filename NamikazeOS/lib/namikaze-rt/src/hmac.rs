// SPDX-License-Identifier: MPL-2.0
//! HMAC-SHA256 (RFC 2104) and PBKDF2-HMAC-SHA256 (RFC 2898/8018).
//!
//! These back the vault KDF and the manifest signing path; both are pinned
//! by published test vectors.

use crate::sha256::Sha256;

const BLOCK: usize = 64;

/// HMAC-SHA256 of `data` under `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&ih);
    outer.finalize()
}

/// PBKDF2-HMAC-SHA256 producing `out_len` bytes.
pub fn pbkdf2_hmac_sha256(pass: &[u8], salt: &[u8], iterations: u32, out_len: usize) -> Vec<u8> {
    assert!(iterations >= 1, "pbkdf2 needs at least one iteration");
    let mut out = Vec::with_capacity(out_len);
    let mut block: u32 = 1;
    while out.len() < out_len {
        let mut salt_block = salt.to_vec();
        salt_block.extend_from_slice(&block.to_be_bytes());
        let mut u = hmac_sha256(pass, &salt_block);
        let mut f = u;
        for _ in 1..iterations {
            u = hmac_sha256(pass, &u);
            for (fi, ui) in f.iter_mut().zip(u) {
                *fi ^= ui;
            }
        }
        let take = (out_len - out.len()).min(32);
        out.extend_from_slice(&f[..take]);
        block += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn rfc4231_case1() {
        // RFC 4231 test case 1
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex::encode(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn rfc4231_case2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn long_key_is_hashed() {
        let key = [0xaau8; 131];
        let mac = hmac_sha256(&key, b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(
            hex::encode(&mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn pbkdf2_rfc7914_vector() {
        // RFC 7914 section 11 lists PBKDF2-HMAC-SHA256 vectors
        let dk = pbkdf2_hmac_sha256(b"passwd", b"salt", 1, 64);
        assert_eq!(
            hex::encode(&dk[..32]),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
        let dk = pbkdf2_hmac_sha256(b"Password", b"NaCl", 80000, 64);
        assert_eq!(
            hex::encode(&dk[..32]),
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
        );
    }
}
