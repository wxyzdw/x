// SPDX-License-Identifier: MPL-2.0
//! Lowercase hexadecimal encoding (and strict decoding).

/// Encode bytes as lowercase hex.
pub fn encode(data: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(T[(b >> 4) as usize] as char);
        out.push(T[(b & 0xf) as usize] as char);
    }
    out
}

/// Decode a hex string; odd length or non-hex bytes yield `None`.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    fn val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        out.push((val(pair[0])? << 4) | val(pair[1])?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for sample in [&b""[..], b"\x00\xff\x7f", b"namikaze"] {
            assert_eq!(decode(&encode(sample)).unwrap(), sample);
        }
        assert_eq!(encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn decode_rejects_odd_and_garbage() {
        assert!(decode("abc").is_none());
        assert!(decode("zz").is_none());
    }
}
