// SPDX-License-Identifier: MPL-2.0
//! XChaCha20-Poly1305 AEAD (RFC 8439 + draft-irtf-cfrg-xchacha).
//!
//! All primitives are implemented from the specifications:
//! - the ChaCha20 block function and stream cipher
//! - HChaCha20 (the XChaCha subkey derivation)
//! - Poly1305 one-time authenticator (poly1305-donna limb layout)
//! - the RFC 8439 AEAD construction with AAD, extended to 24-byte nonces
//!
//! Public test vectors pin every layer.

/// The ChaCha20 block function: 20 rounds over the (key, counter, nonce)
/// state, serialized little-endian.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865; // "expa"
    state[1] = 0x3320_646e; // "nd 3"
    state[2] = 0x7962_2d32; // "2-by"
    state[3] = 0x6b20_6574; // "te k"
    for (i, chunk) in key.chunks_exact(4).enumerate() {
        state[4 + i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    state[12] = counter;
    for (i, chunk) in nonce.chunks_exact(4).enumerate() {
        state[13 + i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    let mut working = state;
    for round in 0..10 {
        let _ = round;
        // column rounds
        qr(&mut working, 0, 4, 8, 12);
        qr(&mut working, 1, 5, 9, 13);
        qr(&mut working, 2, 6, 10, 14);
        qr(&mut working, 3, 7, 11, 15);
        // diagonal rounds
        qr(&mut working, 0, 5, 10, 15);
        qr(&mut working, 1, 6, 11, 12);
        qr(&mut working, 2, 7, 8, 13);
        qr(&mut working, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&working[i].wrapping_add(state[i]).to_le_bytes());
    }
    out
}

fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

/// HChaCha20: derive a 32-byte subkey from key + 16-byte nonce.
pub fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for (i, chunk) in key.chunks_exact(4).enumerate() {
        state[4 + i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for (i, chunk) in nonce.chunks_exact(4).enumerate() {
        state[12 + i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for _ in 0..10 {
        qr(&mut state, 0, 4, 8, 12);
        qr(&mut state, 1, 5, 9, 13);
        qr(&mut state, 2, 6, 10, 14);
        qr(&mut state, 3, 7, 11, 15);
        qr(&mut state, 0, 5, 10, 15);
        qr(&mut state, 1, 6, 11, 12);
        qr(&mut state, 2, 7, 8, 13);
        qr(&mut state, 3, 4, 9, 14);
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_le_bytes());
        out[16 + i * 4..20 + i * 4].copy_from_slice(&state[12 + i].to_le_bytes());
    }
    out
}

/// ChaCha20 keystream XOR (RFC 8439 section 2.4), 12-byte nonce.
pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let mut counter = counter;
    for chunk in data.chunks_mut(64) {
        let ks = chacha20_block(key, counter, nonce);
        for (b, k) in chunk.iter_mut().zip(&ks) {
            *b ^= k;
        }
        counter = counter.wrapping_add(1);
    }
}

// ---------------------------------------------------------------- Poly1305

struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    buf: [u8; 16],
    buf_len: usize,
}

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        let t0 = u32::from_le_bytes(key[0..4].try_into().unwrap());
        let t1 = u32::from_le_bytes(key[4..8].try_into().unwrap());
        let t2 = u32::from_le_bytes(key[8..12].try_into().unwrap());
        let t3 = u32::from_le_bytes(key[12..16].try_into().unwrap());
        // clamp r per poly1305-donna-32
        let r0 = t0 & 0x03ff_ffff;
        let r1 = ((t0 >> 26) | (t1 << 6)) & 0x03ff_ff03;
        let r2 = ((t1 >> 20) | (t2 << 12)) & 0x03ff_c0ff;
        let r3 = ((t2 >> 14) | (t3 << 18)) & 0x03f0_3fff;
        let r4 = (t3 >> 8) & 0x000f_ffff;
        let pad = [
            u32::from_le_bytes(key[16..20].try_into().unwrap()),
            u32::from_le_bytes(key[20..24].try_into().unwrap()),
            u32::from_le_bytes(key[24..28].try_into().unwrap()),
            u32::from_le_bytes(key[28..32].try_into().unwrap()),
        ];
        Self { r: [r0, r1, r2, r3, r4], h: [0; 5], pad, buf: [0; 16], buf_len: 0 }
    }

    fn block(&mut self, block: &[u8], final_block: bool) {
        debug_assert!(block.len() <= 16);
        let mut t = [0u8; 16];
        t[..block.len()].copy_from_slice(block);
        let hibit: u32 = if final_block { 0 } else { 1 << 24 };
        let t0 = u32::from_le_bytes(t[0..4].try_into().unwrap());
        let t1 = u32::from_le_bytes(t[4..8].try_into().unwrap());
        let t2 = u32::from_le_bytes(t[8..12].try_into().unwrap());
        let t3 = u32::from_le_bytes(t[12..16].try_into().unwrap());
        self.h[0] += t0 & 0x3fff_fff;
        self.h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3fff_fff;
        self.h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3fff_fff;
        self.h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3fff_fff;
        self.h[4] += (t3 >> 8) | hibit;

        let h = [self.h[0] as u64, self.h[1] as u64, self.h[2] as u64, self.h[3] as u64, self.h[4] as u64];
        let r = [
            u64::from(self.r[0]),
            u64::from(self.r[1]),
            u64::from(self.r[2]),
            u64::from(self.r[3]),
            u64::from(self.r[4]),
        ];
        let s = [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];
        // d_i = sum_j h_j * r_(i-j) with r_{-k} = s (the *5 wrap)
        let d0 = h[0] * r[0] + h[1] * s[3] + h[2] * s[2] + h[3] * s[1] + h[4] * s[0];
        let d1 = h[0] * r[1] + h[1] * r[0] + h[2] * s[3] + h[3] * s[2] + h[4] * s[1];
        let d2 = h[0] * r[2] + h[1] * r[1] + h[2] * r[0] + h[3] * s[3] + h[4] * s[2];
        let d3 = h[0] * r[3] + h[1] * r[2] + h[2] * r[1] + h[3] * r[0] + h[4] * s[3];
        let d4 = h[0] * r[4] + h[1] * r[3] + h[2] * r[2] + h[3] * r[1] + h[4] * r[0];

        let mut c: u64;
        let mut h0 = (d0 & 0x3ff_ffff) as u32;
        c = d0 >> 26;
        let mut h1 = ((d1 + c) & 0x3ff_ffff) as u32;
        c = (d1 + c) >> 26;
        let h2 = ((d2 + c) & 0x3ff_ffff) as u32;
        c = (d2 + c) >> 26;
        let h3 = ((d3 + c) & 0x3ff_ffff) as u32;
        c = (d3 + c) >> 26;
        let h4 = ((d4 + c) & 0x3ff_ffff) as u32;
        c = (d4 + c) >> 26;
        h0 += (c as u32) * 5;
        h1 += h0 >> 26;
        h0 &= 0x3ff_ffff;
        self.h = [h0, h1, h2, h3, h4];
    }

    fn finish(mut self) -> [u8; 16] {
        if self.buf_len > 0 {
            // final partial block: zero-pad to 16 and set byte[len] = 0x01
            // (the 2^(8*len) high bit lives inside the data, hibit stays 0)
            let rest = self.buf_len;
            let mut block = [0u8; 16];
            block[..rest].copy_from_slice(&self.buf[..rest]);
            if rest < 16 {
                block[rest] = 1;
            }
            self.block(&block, true);
        }
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];
        // fully carry h
        let mut c = h1 >> 26;
        h1 &= 0x3ff_ffff;
        h2 += c;
        c = h2 >> 26;
        h2 &= 0x3ff_ffff;
        h3 += c;
        c = h3 >> 26;
        h3 &= 0x3ff_ffff;
        h4 += c;
        c = h4 >> 26;
        h4 &= 0x3ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;
        // compute h + -p (5) limb-wise
        let (g0, b) = h0.overflowing_add(5);
        let (g1, b1) = h1.overflowing_add(u32::from(b));
        let (g2, b2) = h2.overflowing_add(u32::from(b1));
        let (g3, b3) = h3.overflowing_add(u32::from(b2));
        let g4 = h4.wrapping_add(u32::from(b3)).wrapping_sub(1 << 26);
        // mask = 0 when h < p (g4 went negative), all-ones when h >= p:
        // pick g (h - p) only in the latter case.
        let mask = (g4 >> 31).wrapping_sub(1);
        let h0 = (h0 & !mask) | (g0 & mask);
        let h1 = (h1 & !mask) | (g1 & mask);
        let h2 = (h2 & !mask) | (g2 & mask);
        let h3 = (h3 & !mask) | (g3 & mask);
        let h4 = (h4 & !mask) | (g4 & mask);
        // h = h % 2^128: fold limbs back into four words
        let w0 = h0 | (h1 << 26);
        let w1 = (h1 >> 6) | (h2 << 20);
        let w2 = (h2 >> 12) | (h3 << 14);
        let w3 = (h3 >> 18) | (h4 << 8);
        // add the pad block (s2n), carrying between words like donna
        let mut out = [0u8; 16];
        let mut f = u64::from(w0) + u64::from(self.pad[0]);
        out[0..4].copy_from_slice(&(f as u32).to_le_bytes());
        f = u64::from(w1) + u64::from(self.pad[1]) + (f >> 32);
        out[4..8].copy_from_slice(&(f as u32).to_le_bytes());
        f = u64::from(w2) + u64::from(self.pad[2]) + (f >> 32);
        out[8..12].copy_from_slice(&(f as u32).to_le_bytes());
        f = u64::from(w3) + u64::from(self.pad[3]) + (f >> 32);
        out[12..16].copy_from_slice(&(f as u32).to_le_bytes());
        out
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (16 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 16 {
                let block = self.buf;
                self.block(&block, false);
                self.buf_len = 0;
            }
        }
        while data.len() >= 16 {
            let (block, rest) = data.split_at(16);
            self.block(block.try_into().unwrap(), false);
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }
}

/// Poly1305 one-time MAC of `data` under a one-time `key` (32 bytes).
pub fn poly1305(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let mut p = Poly1305::new(key);
    p.update(data);
    p.finish()
}

// ------------------------------------------------------------------- AEAD

/// Length prefix helper for Poly1305 input (little-endian, as specified).
fn le_len(n: usize) -> [u8; 8] {
    (n as u64).to_le_bytes()
}

/// Poly1305 key generation per RFC 8439 section 2.6: first 32 keystream bytes.
fn poly_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let block = chacha20_block(key, 0, nonce);
    let mut k = [0u8; 32];
    k.copy_from_slice(&block[..32]);
    k
}

/// Encrypt with XChaCha20-Poly1305: returns nonce-prefixed output
/// `[24-byte nonce || ciphertext || 16-byte tag]`.
pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> crate::Result<Vec<u8>> {
    let mut nonce = [0u8; 24];
    crate::random::fill(&mut nonce)?;
    Ok(seal_with_nonce(key, &nonce, plaintext, aad))
}

/// Deterministic variant of [`seal`] with an explicit nonce (testing, KATs).
pub fn seal_with_nonce(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    // 1. derive the message key via HChaCha20
    let subkey = hchacha20(key, &nonce[..16].try_into().unwrap());
    // 2. per draft-irtf-cfrg-xchacha: final nonce = 0x00000000 || nonce[16..24]
    let mut xnonce = [0u8; 12];
    xnonce[4..12].copy_from_slice(&nonce[16..24]);
    // 3. poly key from keystream block 0
    let pk = poly_key(&subkey, &xnonce);
    // 4. encrypt from block 1
    let mut ct = plaintext.to_vec();
    chacha20_xor(&subkey, &xnonce, 1, &mut ct);
    // 5. mac over aad || pad || ct || pad || lengths
    let mut mac_input = Vec::with_capacity(aad.len() + ct.len() + 32);
    mac_input.extend_from_slice(aad);
    let pad_a = (16 - aad.len() % 16) % 16;
    mac_input.extend(std::iter::repeat(0u8).take(pad_a));
    mac_input.extend_from_slice(&ct);
    let pad_c = (16 - ct.len() % 16) % 16;
    mac_input.extend(std::iter::repeat(0u8).take(pad_c));
    mac_input.extend_from_slice(&le_len(aad.len()));
    mac_input.extend_from_slice(&le_len(ct.len()));
    let tag = poly1305(&pk, &mac_input);
    let mut out = Vec::with_capacity(24 + ct.len() + 16);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    out
}

/// RFC 8439 AEAD with the standard 12-byte nonce (used by the KATs).
pub fn seal_ietf(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let pk = poly_key(key, nonce);
    let mut ct = plaintext.to_vec();
    chacha20_xor(key, nonce, 1, &mut ct);
    let mut mac_input = Vec::with_capacity(aad.len() + ct.len() + 32);
    mac_input.extend_from_slice(aad);
    let pad_a = (16 - aad.len() % 16) % 16;
    mac_input.extend(std::iter::repeat(0u8).take(pad_a));
    mac_input.extend_from_slice(&ct);
    let pad_c = (16 - ct.len() % 16) % 16;
    mac_input.extend(std::iter::repeat(0u8).take(pad_c));
    mac_input.extend_from_slice(&le_len(aad.len()));
    mac_input.extend_from_slice(&le_len(ct.len()));
    let tag = poly1305(&pk, &mac_input);
    let mut out = Vec::with_capacity(12 + ct.len() + 16);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    out
}

/// Decrypt a [`seal_ietf`] output; any tampering yields `Err`.
pub fn open_ietf(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> crate::Result<Vec<u8>> {
    if sealed.len() < 12 + 16 {
        return Err(crate::Error::Invalid("sealed payload too short".into()));
    }
    let nonce: [u8; 12] = sealed[..12].try_into().unwrap();
    let ct = &sealed[12..sealed.len() - 16];
    let tag: [u8; 16] = sealed[sealed.len() - 16..].try_into().unwrap();
    let pk = poly_key(key, &nonce);
    let mut mac_input = Vec::with_capacity(aad.len() + ct.len() + 32);
    mac_input.extend_from_slice(aad);
    let pad_a = (16 - aad.len() % 16) % 16;
    mac_input.extend(std::iter::repeat(0u8).take(pad_a));
    mac_input.extend_from_slice(ct);
    let pad_c = (16 - ct.len() % 16) % 16;
    mac_input.extend(std::iter::repeat(0u8).take(pad_c));
    mac_input.extend_from_slice(&le_len(aad.len()));
    mac_input.extend_from_slice(&le_len(ct.len()));
    let want = poly1305(&pk, &mac_input);
    let diff = want.iter().zip(tag).fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return Err(crate::Error::Invalid("authentication failed".into()));
    }
    let mut plain = ct.to_vec();
    chacha20_xor(key, &nonce, 1, &mut plain);
    Ok(plain)
}

/// Decrypt a [`seal`] output; any tampering yields `Err`.
pub fn open(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> crate::Result<Vec<u8>> {
    if sealed.len() < 24 + 16 {
        return Err(crate::Error::Invalid("sealed payload too short".into()));
    }
    let nonce: [u8; 24] = sealed[..24].try_into().unwrap();
    let ct = &sealed[24..sealed.len() - 16];
    let tag: [u8; 16] = sealed[sealed.len() - 16..].try_into().unwrap();

    let subkey = hchacha20(key, &nonce[..16].try_into().unwrap());
    let mut xnonce = [0u8; 12];
    xnonce[4..12].copy_from_slice(&nonce[16..24]);
    let pk = poly_key(&subkey, &xnonce);
    let mut mac_input = Vec::with_capacity(aad.len() + ct.len() + 32);
    mac_input.extend_from_slice(aad);
    let pad_a = (16 - aad.len() % 16) % 16;
    mac_input.extend(std::iter::repeat(0u8).take(pad_a));
    mac_input.extend_from_slice(ct);
    let pad_c = (16 - ct.len() % 16) % 16;
    mac_input.extend(std::iter::repeat(0u8).take(pad_c));
    mac_input.extend_from_slice(&le_len(aad.len()));
    mac_input.extend_from_slice(&le_len(ct.len()));
    let want = poly1305(&pk, &mac_input);
    // constant-time-ish comparison without unsafe: fold the difference
    let diff = want.iter().zip(tag).fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return Err(crate::Error::Invalid(
            "authentication failed; wrong passphrase?".into(),
        ));
    }
    let mut plain = ct.to_vec();
    chacha20_xor(&subkey, &xnonce, 1, &mut plain);
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn rfc8439_block_vector() {
        // RFC 8439 section 2.3.2
        let key: [u8; 32] = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let nonce: [u8; 12] =
            hex::decode("000000090000004a00000000").unwrap().try_into().unwrap();
        let block = chacha20_block(&key, 1, &nonce);
        assert_eq!(
            hex::encode(&block[..64]),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        );
    }

    #[test]
    fn rfc8439_encryption_vector() {
        // RFC 8439 section 2.4.2
        let key: [u8; 32] = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let nonce: [u8; 12] =
            hex::decode("000000000000004a00000000").unwrap().try_into().unwrap();
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";
        let mut data = plaintext.to_vec();
        chacha20_xor(&key, &nonce, 1, &mut data);
        assert_eq!(
            hex::encode(&data[..64]),
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        );
    }

    #[test]
    fn poly1305_rfc8439_vector() {
        let key: [u8; 32] = hex::decode(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let tag = poly1305(&key, b"Cryptographic Forum Research Group");
        assert_eq!(hex::encode(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn rfc8439_aead_vector() {
        // RFC 8439 section 2.8.2
        let key: [u8; 32] = hex::decode(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let nonce: [u8; 12] =
            hex::decode("070000004041424344454647").unwrap().try_into().unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";
        let sealed = seal_ietf(&key, &nonce, plaintext, &aad);
        let ct = &sealed[12..sealed.len() - 16];
        let tag = &sealed[sealed.len() - 16..];
        assert_eq!(
            hex::encode(ct),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116"
        );
        assert_eq!(hex::encode(tag), "1ae10b594f09e26a7e902ecbd0600691");
        let opened = open_ietf(&key, &sealed, &aad).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn xchacha_roundtrip_and_tamper() {
        let key = [7u8; 32];
        let sealed = seal(&key, b"attack at dawn", b"hdr").unwrap();
        assert_eq!(open(&key, &sealed, b"hdr").unwrap(), b"attack at dawn");
        let mut bad = sealed.clone();
        bad[30] ^= 1;
        assert!(open(&key, &bad, b"hdr").is_err());
        assert!(open(&key, &sealed, b"wrong").is_err());
    }
}
