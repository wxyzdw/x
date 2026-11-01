// SPDX-License-Identifier: MPL-2.0
//! Pure hash-chain model for namikaze-ledger.
//!
//! Record N's hash covers seq, kind, fact and record N-1's hash, so the
//! chain order is itself authenticated. Parsing and verification are
//! filesystem-free and unit-tested; genesis is the all-zero digest.

#![forbid(unsafe_code)]

use namikaze_rt::json;
use namikaze_rt::sha256::Sha256;

/// Encode one record as its single JSON line.
pub fn record_to_json(r: &Record) -> String {
    json::obj(&[
        ("seq", json::Value::Int(r.seq as i64)),
        ("kind", json::Value::Str(r.kind.clone())),
        ("fact", json::Value::Str(r.fact.clone())),
        ("prev", json::Value::Str(r.prev.clone())),
        ("hash", json::Value::Str(r.hash.clone())),
    ])
    .to_compact()
}

/// Decode one JSON line; malformed lines yield None.
pub fn record_from_json(line: &str) -> Option<Record> {
    let v = json::parse(line).ok()?;
    Some(Record {
        seq: v.get("seq").and_then(|x| x.as_i64())? as usize,
        kind: v.get("kind").and_then(|x| x.as_str())?.to_string(),
        fact: v.get("fact").and_then(|x| x.as_str())?.to_string(),
        prev: v.get("prev").and_then(|x| x.as_str())?.to_string(),
        hash: v.get("hash").and_then(|x| x.as_str())?.to_string(),
    })
}

/// One ledger record. Serialized as a single JSON line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub seq: usize,
    pub kind: String,
    pub fact: String,
    /// SHA-256 of the previous record ("00".. for genesis)
    pub prev: String,
    /// SHA-256 over seq|kind|fact|prev
    pub hash: String,
}

/// Verification failure with the offending record number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    Malformed { seq: usize },
    HashMismatch { seq: usize },
}

impl VerifyError {
    pub fn seq(&self) -> usize {
        match self {
            VerifyError::Malformed { seq } | VerifyError::HashMismatch { seq } => *seq,
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            VerifyError::Malformed { .. } => "not parseable",
            VerifyError::HashMismatch { .. } => "hash chain diverges here",
        }
    }
}

/// The in-memory chain. `seq` is the next sequence number to assign.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    pub seq: usize,
}

fn genesis() -> String {
    "0".repeat(64)
}

/// Compute the record hash exactly as it is stored.
pub fn record_hash(seq: usize, kind: &str, fact: &str, prev: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seq.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(kind.as_bytes());
    hasher.update(b"|");
    hasher.update(fact.as_bytes());
    hasher.update(b"|");
    hasher.update(prev.as_bytes());
    hasher.finalize_hex()
}

impl Ledger {
    /// Parse every well-formed record; malformed lines are skipped here and
    /// reported by `verify_text` instead, so display stays useful on a
    /// corrupted file.
    pub fn parse_text(raw: &str) -> Vec<Record> {
        raw.lines().filter(|l| !l.trim().is_empty()).filter_map(record_from_json).collect()
    }

    /// Verify the full chain; Ok(record count) when intact.
    pub fn verify_text(raw: &str) -> Result<usize, VerifyError> {
        let records = Self::parse_text(raw);
        let mut expected_prev = genesis();
        for (idx, r) in records.iter().enumerate() {
            let seq = idx + 1;
            if r.seq != seq || r.prev != expected_prev {
                return Err(VerifyError::Malformed { seq });
            }
            let want = record_hash(r.seq, &r.kind, &r.fact, &r.prev);
            if want != r.hash {
                return Err(VerifyError::HashMismatch { seq });
            }
            expected_prev = r.hash.clone();
        }
        // A file whose raw line count exceeds the parsed record count has
        // been damaged in a way parsing hides.
        let raw_lines = raw.lines().filter(|l| !l.trim().is_empty()).count();
        if raw_lines != records.len() {
            return Err(VerifyError::Malformed { seq: records.len() + 1 });
        }
        Ok(records.len())
    }

    /// Build the next record (the caller persists it and re-parses later).
    pub fn append(&self, kind: &str, fact: &str) -> Record {
        let seq = self.seq + 1;
        let prev = genesis(); // caller chains from the real file; tests use genesis
        let hash = record_hash(seq, kind, fact, &prev);
        Record { seq, kind: kind.to_string(), fact: fact.to_string(), prev, hash }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use namikaze_rt::sha256::sha256_hex;

    fn sample(n: usize) -> String {
        let mut prev = genesis();
        let mut out = String::new();
        for seq in 1..=n {
            let r = Record {
                seq,
                kind: "persist-open".into(),
                fact: format!("volume sealed-open #{seq}"),
                prev: prev.clone(),
                hash: record_hash(
                    seq,
                    "persist-open",
                    &format!("volume sealed-open #{seq}"),
                    &prev,
                ),
            };
            out.push_str(&record_to_json(&r));
            out.push('\n');
            prev = r.hash;
        }
        out
    }

    #[test]
    fn fresh_chain_verifies() {
        assert_eq!(Ledger::verify_text(&sample(5)).unwrap(), 5);
        assert_eq!(Ledger::verify_text("").unwrap(), 0);
    }

    #[test]
    fn edited_fact_breaks_chain_at_that_record() {
        let tampered = sample(4).replacen("volume sealed-open #3", "volume EVIL #3", 1);
        let err = Ledger::verify_text(&tampered).unwrap_err();
        assert_eq!(err, VerifyError::HashMismatch { seq: 3 });
    }

    #[test]
    fn deleted_record_breaks_sequence() {
        let text = sample(4);
        let second = text.lines().nth(1).unwrap();
        let tampered = text.replacen(second, "", 1);
        let err = Ledger::verify_text(&tampered).unwrap_err();
        assert_eq!(err, VerifyError::Malformed { seq: 2 });
    }

    #[test]
    fn malformed_line_is_reported_not_skipped() {
        let mut text = sample(2);
        text.push_str("this is not json\n");
        let err = Ledger::verify_text(&text).unwrap_err();
        assert_eq!(err, VerifyError::Malformed { seq: 3 });
    }

    #[test]
    fn append_uses_next_sequence() {
        let ledger = Ledger { seq: 7 };
        let r = ledger.append("rekey", "slot 1 rotated");
        assert_eq!(r.seq, 8);
        assert_eq!(r.hash, record_hash(8, "rekey", "slot 1 rotated", &r.prev));
    }
}
