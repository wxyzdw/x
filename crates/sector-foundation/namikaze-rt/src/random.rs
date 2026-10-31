// SPDX-License-Identifier: MPL-2.0
//! Kernel entropy via /dev/urandom. The standard library has no RNG; this is
//! the smallest honest bridge to the kernel CSPRNG.

use std::io::Read;

/// Fill `buf` with kernel-provided random bytes.
pub fn fill(buf: &mut [u8]) -> crate::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| crate::Error::Invalid(format!("cannot open /dev/urandom: {e}")))?;
    f.read_exact(buf)?;
    Ok(())
}

/// A random 16-byte value rendered as lowercase hex (boot/session ids).
pub fn id_hex() -> crate::Result<String> {
    let mut b = [0u8; 16];
    fill(&mut b)?;
    Ok(crate::hex::encode(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_and_differs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        assert_ne!(a, b);
        assert!(a.iter().any(|x| *x != 0));
    }
}
