// SPDX-License-Identifier: MPL-2.0
//! LZ4-block-format compression with NamikazeOS framing ("nkz").
//!
//! The block layer is the public LZ4 block format (min match 4, 64 KiB
//! window, token + literals + little-endian offset). The container adds:
//!
//! ```text
//! "NKZ1" | u32 LE original length | repeated: u32 LE block_len + block
//! ```
//!
//! Each block covers at most 8 MiB of input. Any structural mismatch makes
//! the decoder fail instead of producing garbage.

const MAX_BLOCK_INPUT: usize = 8 * 1024 * 1024;
const MAGIC: &[u8; 4] = b"NKZ1";
const MIN_MATCH: usize = 4;
const WINDOW: usize = 0xFFFF;

/// Compress `data`; the result always round-trips through [`decompress`].
pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 2 + 16);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    for chunk in data.chunks(MAX_BLOCK_INPUT) {
        let block = compress_block(chunk);
        out.extend_from_slice(&(block.len() as u32).to_le_bytes());
        out.extend_from_slice(&block);
    }
    out
}

/// Decompress an [`compress`] container.
pub fn decompress(data: &[u8]) -> crate::Result<Vec<u8>> {
    if data.len() < 8 || &data[..4] != MAGIC {
        return Err(crate::Error::Invalid("not an nkz container".into()));
    }
    let orig = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let mut out = Vec::with_capacity(orig);
    let mut pos = 8;
    while pos < data.len() {
        if data.len() < pos + 4 {
            return Err(crate::Error::Invalid("truncated block length".into()));
        }
        let blen = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
            as usize;
        pos += 4;
        if data.len() < pos + blen {
            return Err(crate::Error::Invalid("truncated block".into()));
        }
        decompress_block(&data[pos..pos + blen], &mut out)?;
        pos += blen;
    }
    if out.len() != orig {
        return Err(crate::Error::Invalid(format!(
            "size mismatch: got {}, want {orig}",
            out.len()
        )));
    }
    Ok(out)
}

fn compress_block(src: &[u8]) -> Vec<u8> {
    // Greedy matcher with a 4-byte hash table over the 64 KiB window.
    let mut out = Vec::with_capacity(src.len() / 2 + 64);
    let mut table = vec![usize::MAX; 1 << 16];
    let hash = |b: &[u8]| -> usize {
        let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        (((v.wrapping_mul(2654435761)) >> 16) as usize) & 0xFFFF
    };
    // token + literal-length extension + literals (+ offset + match-length
    // extension unless `last`, which encodes literals only)
    let emit = |out: &mut Vec<u8>, lit: &[u8], offset: usize, match_len: usize, last: bool| {
        let lit_len = lit.len();
        let mut token = if lit_len < 15 { lit_len as u8 } else { 15 };
        if !last {
            let ml = match_len - MIN_MATCH;
            token |= if ml < 15 { (ml as u8) << 4 } else { 15 << 4 };
        }
        out.push(token);
        if lit_len >= 15 {
            let mut rem = lit_len - 15;
            while rem >= 255 {
                out.push(255);
                rem -= 255;
            }
            out.push(rem as u8);
        }
        out.extend_from_slice(lit);
        if last {
            return;
        }
        out.extend_from_slice(&(offset as u16).to_le_bytes());
        let ml = match_len - MIN_MATCH;
        if ml >= 15 {
            let mut rem = ml - 15;
            while rem >= 255 {
                out.push(255);
                rem -= 255;
            }
            out.push(rem as u8);
        }
    };
    let mut lit_start = 0usize;
    let mut i = 0usize;
    while i + MIN_MATCH <= src.len() {
        let mut best_len = 0usize;
        let mut best_off = 0usize;
        let h = hash(&src[i..]);
        let cand = table[h];
        if cand == usize::MAX {
            table[h] = i;
            i += 1;
            continue;
        }
        table[h] = i;
        let offset = i - cand;
        if offset <= WINDOW {
            let max = (src.len() - i).min(0xFFFF + MIN_MATCH);
            let mut l = 0usize;
            while l < max && src[cand + l] == src[i + l] {
                l += 1;
            }
            if l >= MIN_MATCH {
                best_len = l;
                best_off = offset;
            }
        }
        if best_len >= MIN_MATCH {
            emit(&mut out, &src[lit_start..i], best_off, best_len, false);
            let end = i + best_len;
            i += 1;
            while i < end {
                if i + MIN_MATCH <= src.len() {
                    let hj = hash(&src[i..]);
                    if table[hj] == usize::MAX {
                        table[hj] = i;
                    }
                }
                i += 1;
            }
            lit_start = i;
        } else {
            i += 1;
        }
    }
    emit(&mut out, &src[lit_start..], 0, MIN_MATCH, true);
    out
}

fn decompress_block(src: &[u8], out: &mut Vec<u8>) -> crate::Result<()> {
    let mut pos = 0usize;
    while pos < src.len() {
        let token = src[pos];
        pos += 1;
        let mut lit_len = (token & 0x0F) as usize;
        if lit_len == 15 {
            loop {
                let b = *src.get(pos).ok_or_else(|| crate::Error::Invalid("bad lit len".into()))?;
                pos += 1;
                lit_len += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        if src.len() < pos + lit_len {
            return Err(crate::Error::Invalid("truncated literals".into()));
        }
        out.extend_from_slice(&src[pos..pos + lit_len]);
        pos += lit_len;
        if pos >= src.len() {
            break; // last sequence: literals only
        }
        if src.len() < pos + 2 {
            return Err(crate::Error::Invalid("truncated offset".into()));
        }
        let offset = u16::from_le_bytes([src[pos], src[pos + 1]]) as usize;
        pos += 2;
        if offset == 0 || offset > out.len() {
            return Err(crate::Error::Invalid("invalid offset".into()));
        }
        let mut match_len = ((token >> 4) & 0x0F) as usize + MIN_MATCH;
        if (token >> 4) & 0x0F == 15 {
            loop {
                let b = *src.get(pos).ok_or_else(|| crate::Error::Invalid("bad ml".into()))?;
                pos += 1;
                match_len += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        let start = out.len() - offset;
        for k in 0..match_len {
            let b = out[start + k];
            out.push(b);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_shapes() {
        let empty: Vec<u8> = Vec::new();
        for sample in [
            &empty[..],
            b"a",
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"abcabcabcabcabcabcabcabcabcabc1234567890",
            &[7u8; 100_000][..],
        ] {
            let c = compress(sample);
            assert_eq!(decompress(&c).unwrap(), sample);
        }
    }

    #[test]
    fn compresses_repetitive_input() {
        let data = b"namikaze ".repeat(10_000);
        let c = compress(&data);
        assert!(c.len() < data.len() / 4, "compression ineffective: {}", c.len());
        assert_eq!(decompress(&c).unwrap(), data);
    }

    #[test]
    fn corrupt_containers_fail() {
        let good = compress(b"hello world hello world hello world");
        assert!(decompress(&good).is_ok());
        let mut bad = good.clone();
        bad[0] = b'X';
        assert!(decompress(&bad).is_err());
        let mut short = good.clone();
        short.truncate(short.len() - 3);
        assert!(decompress(&short).is_err());
    }

    #[test]
    fn multi_block_files() {
        let data: Vec<u8> = (0..=255u8).cycle().take(MAX_BLOCK_INPUT + 1234).collect();
        let c = compress(&data);
        assert_eq!(decompress(&c).unwrap(), data);
    }
}
