use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// The standard EICAR antivirus test string. Detecting it is a deliberate,
/// well-known convention (not a real threat), used to verify a scanner is
/// wired up correctly. See https://www.eicar.org/download-anti-malware-testfile/
pub const EICAR_TEST_STRING: &str =
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// A loaded set of known-malware SHA-256 hashes. Phase 1 loads this from a
/// static, pre-seeded file; Phase 2 adds live MalwareBazaar sync on top of
/// the same in-memory structure.
#[derive(Debug, Default)]
pub struct SignatureSet {
    hashes: HashSet<String>,
}

impl SignatureSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_hashes<I: IntoIterator<Item = String>>(hashes: I) -> Self {
        Self {
            hashes: hashes.into_iter().map(|h| h.to_lowercase()).collect(),
        }
    }

    /// Loads the persisted signature_cache table into memory, plus the
    /// EICAR SHA-256 seeded unconditionally, matching
    /// ThreatIntelSignatureService.init() on the Java side exactly: this
    /// hash is present whether or not a sync has ever run, it's a distinct
    /// mechanism from hash_match::content_is_eicar's substring check, both
    /// exist, both catch EICAR, via different paths.
    pub fn load_from_cache(conn: &rusqlite::Connection) -> rusqlite::Result<Self> {
        let mut stmt = conn.prepare("SELECT sha256 FROM signature_cache")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

        let mut hashes: HashSet<String> = rows
            .collect::<rusqlite::Result<Vec<String>>>()?
            .into_iter()
            .map(|h| h.to_lowercase())
            .collect();

        hashes.insert(crate::signature_sync::EICAR_SIGNATURE_SHA256.to_lowercase());

        Ok(Self { hashes })
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    pub fn contains(&self, sha256_hex: &str) -> bool {
        self.hashes.contains(&sha256_hex.to_lowercase())
    }
}

/// Result of the fast hash-based check, run before anything more expensive
/// (YARA-X, entropy) since an exact known-malware match short-circuits the
/// rest of the pipeline.
pub enum HashCheck {
    /// Exact match against the known-malware signature set.
    KnownMalicious,
    /// The EICAR test file, flagged distinctly so callers can label it
    /// clearly rather than reporting it as a real threat.
    EicarTestFile,
    NoMatch,
}

pub fn check_hash(content: &[u8], sha256: &str, signatures: &SignatureSet) -> HashCheck {
    if content_is_eicar(content) {
        return HashCheck::EicarTestFile;
    }
    if signatures.contains(sha256) {
        return HashCheck::KnownMalicious;
    }
    HashCheck::NoMatch
}

fn content_is_eicar(content: &[u8]) -> bool {
    // The EICAR file is plain ASCII and tiny; a direct substring check
    // against the decoded content is the correct approach (not a hash
    // comparison), since some test harnesses append trailing
    // whitespace/newlines to the canonical string.
    if let Ok(text) = std::str::from_utf8(content) {
        text.trim_end().ends_with(EICAR_TEST_STRING)
            || text.contains(EICAR_TEST_STRING)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_eicar_string() {
        let content = EICAR_TEST_STRING.as_bytes();
        assert!(matches!(
            check_hash(content, &sha256_hex(content), &SignatureSet::new()),
            HashCheck::EicarTestFile
        ));
    }

    #[test]
    fn detects_known_malicious_hash() {
        let content = b"totally-not-malware-bytes";
        let hash = sha256_hex(content);
        let signatures = SignatureSet::from_hashes(vec![hash.clone()]);
        assert!(matches!(
            check_hash(content, &hash, &signatures),
            HashCheck::KnownMalicious
        ));
    }

    #[test]
    fn clean_content_has_no_match() {
        let content = b"just a normal file";
        let hash = sha256_hex(content);
        assert!(matches!(
            check_hash(content, &hash, &SignatureSet::new()),
            HashCheck::NoMatch
        ));
    }

    #[test]
    fn hash_matching_is_case_insensitive() {
        let content = b"case-test";
        let hash = sha256_hex(content);
        let signatures = SignatureSet::from_hashes(vec![hash.to_uppercase()]);
        assert!(matches!(
            check_hash(content, &hash, &signatures),
            HashCheck::KnownMalicious
        ));
    }

    #[test]
    fn load_from_cache_seeds_eicar_even_with_an_empty_database() {
        let conn = crate::storage::open_in_memory().unwrap();
        let signatures = SignatureSet::load_from_cache(&conn).unwrap();
        assert!(
            signatures.contains(crate::signature_sync::EICAR_SIGNATURE_SHA256),
            "EICAR hash must be seeded unconditionally, even before any sync has run"
        );
    }

    #[test]
    fn load_from_cache_picks_up_persisted_signatures() {
        let conn = crate::storage::open_in_memory().unwrap();
        let hash = "1".repeat(64); // a valid-length placeholder hash, exact content doesn't matter
        conn.execute(
            "INSERT INTO signature_cache (sha256, source, added_at) VALUES (?1, 'test', 0)",
            rusqlite::params![hash],
        )
        .unwrap();

        let signatures = SignatureSet::load_from_cache(&conn).unwrap();
        assert!(signatures.contains(&hash));
    }
}
