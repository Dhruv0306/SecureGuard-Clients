pub mod dir_behavior;
pub mod entropy;
pub mod extension;
pub mod hash_match;
pub mod rootkit;
pub mod scoring;
pub mod signature_sync;
pub mod storage;
pub mod text_patterns;
pub mod types;
pub mod yara_scan;
pub mod zip_scan;

use hash_match::SignatureSet;
use std::fs;
use std::path::Path;
use types::ScanResult;
use yara_scan::RuleSet;

/// Default rule set for Phase 1. This is intentionally minimal, it exists
/// to prove the YARA-X integration end-to-end; the real signature/rule
/// content is a Phase 2 threat-intel concern, not part of this crate's
/// initial scope.
pub const DEFAULT_RULES: &str =
    r#"
rule eicar_marker_present {
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
"#;

/// Scans a file on disk and returns a ScanResult. This is the primary
/// public entry point both the CLI harness and (later) the desktop/Android
/// UIs call. Passes the real path through to scoring so the
/// path-dependent signals (rootkit driver-location gate, ransomware
/// directory behavior) can apply, unlike scoring::score_file called
/// directly on in-memory content with no path.
pub fn scan_file(
    path: &Path,
    signatures: &SignatureSet,
    rules: &RuleSet
) -> std::io::Result<ScanResult> {
    let content = fs::read(path)?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string_lossy().to_string());
    Ok(scoring::score_file(&file_name, &content, signatures, rules, Some(path)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn scans_a_real_file_on_disk() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"an ordinary file with nothing unusual").unwrap();

        let rules = RuleSet::compile(DEFAULT_RULES).unwrap();
        let result = scan_file(tmp.path(), &SignatureSet::new(), &rules).unwrap();

        assert_eq!(result.verdict, types::Verdict::Clean);
    }

    #[test]
    #[cfg_attr(
        windows,
        ignore = "Windows Defender (and most real-time AV) blocks writing the raw \
                   EICAR string to disk, this is expected OS behavior, not a bug. \
                   The in-memory equivalent is covered by \
                   scoring::tests::eicar_is_malicious_and_labeled_distinctly. Run \
                   this one manually with an AV exclusion on the temp dir if you \
                   need to exercise the disk-read path specifically."
    )]
    fn scans_an_eicar_file_on_disk() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(hash_match::EICAR_TEST_STRING.as_bytes()).unwrap();

        let rules = RuleSet::compile(DEFAULT_RULES).unwrap();
        let result = scan_file(tmp.path(), &SignatureSet::new(), &rules).unwrap();

        assert_eq!(result.verdict, types::Verdict::Malicious);
        assert_eq!(result.threat_type.as_deref(), Some("EICAR_TEST_FILE"));
    }
}
