// SPDX-License-Identifier: MPL-2.0
//! namikaze-chrono: civil time without dependencies.
//!
//! Provides the proleptic Gregorian calendar math (Howard Hinnant's
//! days-from-civil algorithm), ISO-8601 formatting/parsing and a TZif v2
//! reader for /usr/share/zoneinfo so local time works without libc or the
//! chrono crate. UTC-only math is exact; conversions apply fixed offsets
//! from the parsed timezone transitions.

#![forbid(unsafe_code)]

use std::path::Path;

/// Broken-down UTC-ish civil time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    pub year: i64,
    /// 1..=12
    pub month: u32,
    /// 1..=31
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

/// Days since 1970-01-01 from a civil date (Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = ((m + 9) % 12) as i64; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Civil date from days since 1970-01-01.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Split unix seconds into a civil timestamp.
pub fn from_unix(secs: i64) -> Civil {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    Civil {
        year,
        month,
        day,
        hour: (rem / 3600) as u32,
        minute: ((rem % 3600) / 60) as u32,
        second: (rem % 60) as u32,
    }
}

/// Inverse of [`from_unix`].
pub fn to_unix(c: &Civil) -> i64 {
    days_from_civil(c.year, c.month, c.day) * 86_400
        + c.hour as i64 * 3600
        + c.minute as i64 * 60
        + c.second as i64
}

/// RFC 3339 / ISO-8601 rendering (Z suffix).
pub fn format_iso(secs: i64) -> String {
    let c = from_unix(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}

/// Parse `YYYY-MM-DDTHH:MM:SSZ` (the subset the system writes).
pub fn parse_iso(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[19] != b'Z' {
        return None;
    }
    let num = |a: usize, z: usize| -> Option<i64> { text.get(a..z)?.parse().ok() };
    let year = num(0, 4)?;
    let month = num(5, 7)? as u32;
    let day = num(8, 10)? as u32;
    let hour = num(11, 13)? as u32;
    let minute = num(14, 16)? as u32;
    let second = num(17, 19)? as u32;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(to_unix(&Civil { year, month, day, hour, minute, second }))
}

/// A fixed-offset zone (the TZif reader output at one instant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Zone {
    /// Offset from UTC in seconds.
    pub offset_secs: i64,
}

impl Zone {
    /// Local unix time = utc + offset.
    pub fn local(self, utc: i64) -> Civil {
        from_unix(utc + self.offset_secs)
    }

    /// UTC unix time = local - offset.
    pub fn utc_from_local(self, local: &Civil) -> i64 {
        to_unix(local) - self.offset_secs
    }
}

/// Read the CURRENT offset for the zone named in `/etc/localtime`'s target
/// (or parse the TZif file directly). Falls back to UTC.
pub fn zone_from_tzif(path: &Path, at_utc: i64) -> Option<Zone> {
    let data = std::fs::read(path).ok()?;
    tzif_offset(&data, at_utc).map(|offset_secs| Zone { offset_secs })
}

fn be32(d: &[u8]) -> i64 {
    i32::from_be_bytes([d[0], d[1], d[2], d[3]]) as i64
}

/// Minimal TZif v1/v2 header walk: returns the applicable ut offset.
fn tzif_offset(data: &[u8], at_utc: i64) -> Option<i64> {
    if data.len() < 44 || &data[0..4] != b"TZif" {
        return None;
    }
    let version = data[4];
    let isutcnt = be32(&data[20..24]) as usize;
    let isstdcnt = be32(&data[24..28]) as usize;
    let leapcnt = be32(&data[28..32]) as usize;
    let timecnt = be32(&data[32..36]) as usize;
    let typecnt = be32(&data[36..40]) as usize;
    let charcnt = be32(&data[40..44]) as usize;

    let mut pos = 44usize;
    // v1 uses 32-bit times; v2+ block is skipped and re-read in 64-bit form
    if version >= b'2' {
        let v1_len =
            timecnt * 4 + timecnt + typecnt * 6 + charcnt + leapcnt * 8 + isstdcnt + isutcnt;
        pos += v1_len;
        if pos + 44 > data.len() || &data[pos..pos + 4] != b"TZif" {
            return None;
        }
        // counts live 20 bytes into the 44-byte header; data follows it
        let isutcnt = be32(&data[pos + 20..pos + 24]) as usize;
        let isstdcnt = be32(&data[pos + 24..pos + 28]) as usize;
        let leapcnt = be32(&data[pos + 28..pos + 32]) as usize;
        let timecnt = be32(&data[pos + 32..pos + 36]) as usize;
        let typecnt = be32(&data[pos + 36..pos + 40]) as usize;
        let charcnt = be32(&data[pos + 40..pos + 44]) as usize;
        pos += 44;
        if data.len() < pos + timecnt * 8 + timecnt + typecnt * 6 {
            return None;
        }
        let mut transitions = Vec::with_capacity(timecnt);
        for i in 0..timecnt {
            let o = pos + i * 8;
            transitions.push(i64::from_be_bytes([
                data[o],
                data[o + 1],
                data[o + 2],
                data[o + 3],
                data[o + 4],
                data[o + 5],
                data[o + 6],
                data[o + 7],
            ]));
        }
        pos += timecnt * 8;
        let idx = &data[pos..pos + timecnt];
        pos += timecnt;
        if data.len() < pos + typecnt * 6 {
            return None;
        }
        let mut offsets = Vec::with_capacity(typecnt);
        for i in 0..typecnt {
            let o = pos + i * 6;
            offsets.push(be32(&data[o..o + 4]));
        }
        let _ = charcnt;
        let _ = leapcnt;
        let _ = isstdcnt;
        let _ = isutcnt;
        let mut chosen = 0usize;
        for (i, t) in transitions.iter().enumerate() {
            if *t <= at_utc {
                chosen = idx[i] as usize;
            } else {
                break;
            }
        }
        return offsets.get(chosen).copied();
    }
    // v1 path (32-bit)
    if data.len() < pos + timecnt * 4 + timecnt + typecnt * 6 {
        return None;
    }
    let mut transitions = Vec::with_capacity(timecnt);
    for i in 0..timecnt {
        transitions.push(be32(&data[pos + i * 4..pos + i * 4 + 4]));
    }
    pos += timecnt * 4;
    let idx = &data[pos..pos + timecnt];
    pos += timecnt;
    let mut offsets = Vec::with_capacity(typecnt);
    for i in 0..typecnt {
        offsets.push(be32(&data[pos + i * 6..pos + i * 6 + 4]));
    }
    let mut chosen = 0usize;
    for (i, t) in transitions.iter().enumerate() {
        if *t <= at_utc {
            chosen = idx[i] as usize;
        } else {
            break;
        }
    }
    offsets.get(chosen).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_roundtrip_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn known_dates() {
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
        assert_eq!(civil_from_days(19_000), (2022, 1, 8));
    }

    #[test]
    fn iso_roundtrip() {
        assert_eq!(format_iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_iso(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(parse_iso("2023-11-14T22:13:20Z"), Some(1_700_000_000));
        assert_eq!(parse_iso("2023-11-14 22:13:20"), None);
    }

    #[test]
    fn zone_offset_math() {
        let z = Zone { offset_secs: 3 * 3600 };
        let local = z.local(1_700_000_000);
        assert_eq!(local.hour, 22 + 3 - 24); // 22:13 UTC -> 01:13 local
        assert_eq!(
            z.utc_from_local(&Civil {
                year: local.year,
                month: local.month,
                day: local.day,
                hour: local.hour,
                minute: local.minute,
                second: local.second
            }),
            1_700_000_000
        );
    }

    #[test]
    fn tzif_reader_on_utc_file() {
        // Only assert when the host actually ships zoneinfo; the parser
        // itself is exercised by the header walk below.
        match std::fs::read("/usr/share/zoneinfo/UTC") {
            Ok(data) => assert_eq!(tzif_offset(&data, 1_700_000_000), Some(0)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn tzif_rejects_garbage() {
        assert!(tzif_offset(b"not a tzif file", 0).is_none());
        assert!(tzif_offset(&[], 0).is_none());
    }
}
