use crate::entropy::{ shannon_entropy, ENTROPY_SAMPLE_BYTES, THRESHOLD_HIGH_ENTROPY };
use crate::extension::{
    check_extension_masquerade,
    get_file_extension,
    is_executable_like_for_entropy,
    is_expected_native_library,
    RANSOMWARE_EXTENSIONS,
    TROJAN_NAME_SIGNATURES,
};
use crate::hash_match::{ check_hash, HashCheck, SignatureSet };
use crate::rootkit::score_rootkit;
use crate::text_patterns::{ contains_ransomware_pattern, score_text_patterns };
use crate::types::{ ScanResult, ScoreContribution, Verdict };
use crate::yara_scan::RuleSet;
use crate::zip_scan::{ is_zip_name, scan_zip, ZipCheck };
use std::path::Path;

/// Ported from SecurityServiceImpl. An exact known-malware hash match or
/// EICAR scores 100 outright, not merely enough to cross
/// THRESHOLD_MALICIOUS, the two are numerically different even though both
/// currently land on the same verdict tier.
pub const SCORE_KNOWN_HASH: i32 = 100;
pub const SCORE_EXTENSION_MASQUERADE: i32 = 70;
pub const SCORE_RANSOMWARE_EXTENSION: i32 = 60;
pub const SCORE_RANSOMWARE_TEXT_PATTERN: i32 = 45;
pub const SCORE_RANSOMWARE_DIR_BEHAVIOR: i32 = 55;
pub const SCORE_ROOTKIT_BINARY: i32 = 65;
pub const SCORE_ROOTKIT_TEXT: i32 = 20;
pub const SCORE_TROJAN_NAME: i32 = 35;
pub const SCORE_STRONG_PATTERN: i32 = 30;
pub const SCORE_WEAK_PATTERN: i32 = 8;
/// Weak text patterns (eval, fromCharCode, document.write and similar) appear in
/// ordinary bundled JavaScript, build scripts and installers. Capped just below
/// THRESHOLD_SUSPICIOUS so they can add to a verdict but never produce one on
/// their own. The Java engine caps at 32, which is enough to flag any bundled
/// script by itself; see docs/java-engine-false-positive-fixes.md.
pub const MAX_WEAK_PATTERN_SCORE: i32 = THRESHOLD_SUSPICIOUS - 1;
// Weak patterns alone must never be enough to flag a file.
const _: () = assert!(MAX_WEAK_PATTERN_SCORE < THRESHOLD_SUSPICIOUS);
pub const SCORE_HIGH_ENTROPY: i32 = 30;

/// Ported from SecurityServiceImpl. A file crossing this total is convicted
/// outright.
pub const THRESHOLD_MALICIOUS: i32 = 60;
/// A file crossing this total (but not THRESHOLD_MALICIOUS) is flagged for
/// review rather than convicted.
pub const THRESHOLD_SUSPICIOUS: i32 = 25;

/// Ported from SecurityServiceImpl's `score = Math.min(score, 100)`: the
/// composite score is capped even though no individual signal can exceed
/// it alone, several signals stacking (masquerade + ransomware ext + text +
/// trojan name + rootkit + entropy + patterns) can otherwise sum well past
/// 100.
const MAX_SCORE: i32 = 100;

/// `path` is the real filesystem path when the caller has one (the local
/// disk-scan entry point does), None for pure in-memory scoring such as
/// tests or content that never touches disk. Two signals depend on it:
/// the rootkit binary check's driver-location gate, and the ransomware
/// directory-behavior heuristic, both no-ops without a path, matching the
/// Java engine's own File-based requirements for those two checks.
pub fn score_file(
    file_name: &str,
    content: &[u8],
    signatures: &SignatureSet,
    rules: &RuleSet,
    path: Option<&Path>
) -> ScanResult {
    score_impl(file_name, content, signatures, rules, path, None, None)
}

/// Same as [`score_file`] for a file on disk, but with the folder's
/// ransomware-behavior score supplied by the caller (see
/// `dir_behavior::score_from_names`). A scanner walking a folder computes it
/// once per folder; without this, every file triggers a fresh read of its whole
/// folder, which is quadratic in the number of files per folder.
pub fn score_file_in_directory(
    file_name: &str,
    content: &[u8],
    signatures: &SignatureSet,
    rules: &RuleSet,
    path: &Path,
    directory_score: i32
) -> ScanResult {
    score_impl(file_name, content, signatures, rules, Some(path), Some(directory_score), None)
}

/// Like [`score_file_in_directory`], for a caller that has already computed the
/// content's SHA-256 (lowercase hex) and does not want it computed again.
pub fn score_file_in_directory_with_hash(
    file_name: &str,
    content: &[u8],
    signatures: &SignatureSet,
    rules: &RuleSet,
    path: &Path,
    directory_score: i32,
    sha256: &str
) -> ScanResult {
    score_impl(file_name, content, signatures, rules, Some(path), Some(directory_score), Some(sha256))
}

fn score_impl(
    file_name: &str,
    content: &[u8],
    signatures: &SignatureSet,
    rules: &RuleSet,
    path: Option<&Path>,
    directory_score: Option<i32>,
    sha256: Option<&str>
) -> ScanResult {
    let sha256 = match sha256 {
        Some(hash) => hash.to_string(),
        None => crate::hash_match::sha256_hex(content),
    };

    // Fast path: an exact known-malware hash match or the EICAR test file
    // short-circuits everything else, matching the Java engine's ordering.
    match check_hash(content, &sha256, signatures) {
        HashCheck::EicarTestFile => {
            return ScanResult {
                file_name: file_name.to_string(),
                sha256,
                verdict: Verdict::Malicious,
                score: SCORE_KNOWN_HASH,
                threat_type: Some("EICAR_TEST_FILE".to_string()),
                contributions: vec![ScoreContribution {
                    reason: "EICAR standard antivirus test file detected".to_string(),
                    points: SCORE_KNOWN_HASH,
                }],
            };
        }
        HashCheck::KnownMalicious => {
            return ScanResult {
                file_name: file_name.to_string(),
                sha256,
                verdict: Verdict::Malicious,
                score: SCORE_KNOWN_HASH,
                threat_type: Some("VIRUS".to_string()),
                contributions: vec![ScoreContribution {
                    reason: "Known malware signature detected".to_string(),
                    points: SCORE_KNOWN_HASH,
                }],
            };
        }
        HashCheck::NoMatch => {}
    }

    // Zip bomb check takes priority: if it fires, we don't attempt further
    // analysis of the archive contents, matching the Java engine's early
    // return for this case. Only computed once, reused below for the
    // suspicious-entry contribution if it's not a bomb.
    let zip_check = if is_zip_name(&file_name.to_lowercase()) {
        scan_zip(content)
    } else {
        ZipCheck::NotAZip
    };
    if let ZipCheck::LikelyZipBomb = zip_check {
        return ScanResult {
            file_name: file_name.to_string(),
            sha256,
            verdict: Verdict::Suspicious,
            score: THRESHOLD_SUSPICIOUS,
            threat_type: Some("WARNING".to_string()),
            contributions: vec![ScoreContribution {
                reason: "ZIP_BOMB_LIMIT_EXCEEDED".to_string(),
                points: THRESHOLD_SUSPICIOUS,
            }],
        };
    }

    let mut score = 0;
    let mut contributions = Vec::new();

    let header = &content[..content.len().min(8)];
    let extension = get_file_extension(file_name);

    // 1. Extension masquerade: executable header behind a non-executable,
    // non-suspicious extension.
    let masquerade_score = if is_expected_native_library(&file_name.to_lowercase(), header) {
        0
    } else {
        check_extension_masquerade(&extension, header)
    };
    if masquerade_score > 0 {
        score += masquerade_score;
        contributions.push(ScoreContribution {
            reason: "EXTENSION_MASQUERADE: header bytes don't match the file's extension".to_string(),
            points: masquerade_score,
        });
    }

    // 2. High entropy, gated to files that already look executable (by
    // extension or real header bytes), not applied to every compressed or
    // encrypted file type on the system.
    if is_executable_like_for_entropy(&extension, header) {
        let sample = &content[..content.len().min(ENTROPY_SAMPLE_BYTES)];
        let entropy = shannon_entropy(sample);
        if entropy >= THRESHOLD_HIGH_ENTROPY {
            score += SCORE_HIGH_ENTROPY;
            contributions.push(ScoreContribution {
                reason: format!(
                    "HIGH_ENTROPY_EXECUTABLE ({entropy:.2} bits/byte, threshold {THRESHOLD_HIGH_ENTROPY})"
                ),
                points: SCORE_HIGH_ENTROPY,
            });
        }
    }

    // 3. Ransomware extension.
    if RANSOMWARE_EXTENSIONS.contains(&extension.as_str()) {
        score += SCORE_RANSOMWARE_EXTENSION;
        contributions.push(ScoreContribution {
            reason: "RANSOMWARE_EXTENSION".to_string(),
            points: SCORE_RANSOMWARE_EXTENSION,
        });
    }

    // 4. Ransomware note text.
    if contains_ransomware_pattern(content) {
        score += SCORE_RANSOMWARE_TEXT_PATTERN;
        contributions.push(ScoreContribution {
            reason: "RANSOMWARE_NOTE_TEXT".to_string(),
            points: SCORE_RANSOMWARE_TEXT_PATTERN,
        });
    }

    // 5. Ransomware directory behavior, only meaningful with a real path.
    if let Some(p) = path {
        let dir_score = directory_score.unwrap_or_else(||
            crate::dir_behavior::score_ransomware_directory_behavior(p)
        );
        if dir_score > 0 {
            score += dir_score;
            contributions.push(ScoreContribution {
                reason: "RANSOMWARE_DIRECTORY_BEHAVIOR".to_string(),
                points: dir_score,
            });
        }
    }

    // 6. Trojan filename signature, scores at most once even if multiple
    // signatures match, matching Java's break-on-first-match loop.
    let file_name_lower = file_name.to_lowercase();
    if TROJAN_NAME_SIGNATURES.iter().any(|sig| file_name_lower.contains(sig)) {
        score += SCORE_TROJAN_NAME;
        contributions.push(ScoreContribution {
            reason: "TROJAN_NAME_SIGNATURE".to_string(),
            points: SCORE_TROJAN_NAME,
        });
    }

    // 7. Strong/weak text patterns.
    let pattern_score = score_text_patterns(content);
    if pattern_score.strong_score > 0 {
        score += pattern_score.strong_score;
        contributions.push(ScoreContribution {
            reason: format!("STRONG_CODE_PATTERN(x{})", pattern_score.strong_matches),
            points: pattern_score.strong_score,
        });
    }
    if pattern_score.weak_score > 0 {
        score += pattern_score.weak_score;
        contributions.push(ScoreContribution {
            reason: format!("WEAK_CODE_PATTERN(x{})", pattern_score.weak_matches),
            points: pattern_score.weak_score,
        });
    }

    // 8. Rootkit signals (binary, location-gated; text, unconditional).
    let rootkit = score_rootkit(path, content);
    if rootkit.binary_flagged {
        score += SCORE_ROOTKIT_BINARY;
        contributions.push(ScoreContribution {
            reason: "ROOTKIT_BINARY_IN_DRIVER_LOCATION".to_string(),
            points: SCORE_ROOTKIT_BINARY,
        });
    }
    if rootkit.text_flagged {
        score += SCORE_ROOTKIT_TEXT;
        contributions.push(ScoreContribution {
            reason: "ROOTKIT_TEXT_PATTERN".to_string(),
            points: SCORE_ROOTKIT_TEXT,
        });
    }

    // 9. YARA-X pattern matching: an additional signal beyond Java parity
    // (the Java engine has no YARA-X integration at all), scored the same
    // as a strong text pattern match since it represents the same
    // confidence tier.
    if let Ok(matches) = rules.scan(content) {
        for m in matches {
            score += SCORE_STRONG_PATTERN;
            contributions.push(ScoreContribution {
                reason: format!("YARA-X pattern match: {}", m.identifier),
                points: SCORE_STRONG_PATTERN,
            });
            if score >= THRESHOLD_MALICIOUS {
                break;
            }
        }
    }

    // 10. Zip suspicious entries (not a bomb, already handled above).
    if let ZipCheck::Scored(zip_score) = zip_check {
        if zip_score > 0 {
            score += zip_score;
            contributions.push(ScoreContribution {
                reason: "ZIP_CONTAINS_EXECUTABLE_ENTRY".to_string(),
                points: zip_score,
            });
        }
    }

    let score = score.min(MAX_SCORE);

    let verdict = if score >= THRESHOLD_MALICIOUS {
        Verdict::Malicious
    } else if score >= THRESHOLD_SUSPICIOUS {
        Verdict::Suspicious
    } else {
        Verdict::Clean
    };

    let threat_type = match verdict {
        Verdict::Malicious => Some("VIRUS".to_string()),
        Verdict::Suspicious => Some("SUSPICIOUS".to_string()),
        Verdict::Clean => None,
    };

    ScanResult {
        file_name: file_name.to_string(),
        sha256,
        verdict,
        score,
        threat_type,
        contributions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_rules() -> RuleSet {
        RuleSet::compile(
            r#"
            rule placeholder {
                condition:
                    false
            }
            "#
        ).expect("placeholder rule should compile")
    }

    #[test]
    fn clean_content_scores_below_suspicious() {
        let content = b"an entirely ordinary text file with nothing unusual in it";
        let result = score_file("clean.txt", content, &SignatureSet::new(), &empty_rules(), None);
        assert_eq!(result.verdict, Verdict::Clean);
    }

    #[test]
    fn known_hash_is_malicious_regardless_of_content_analysis() {
        let content = b"arbitrary bytes";
        let hash = crate::hash_match::sha256_hex(content);
        let signatures = SignatureSet::from_hashes(vec![hash]);
        let result = score_file("bad.bin", content, &signatures, &empty_rules(), None);
        assert_eq!(result.verdict, Verdict::Malicious);
        assert_eq!(result.threat_type.as_deref(), Some("VIRUS"));
        assert_eq!(
            result.score,
            SCORE_KNOWN_HASH,
            "known-hash matches score SCORE_KNOWN_HASH (100), not merely enough to cross \
             THRESHOLD_MALICIOUS, these are numerically different in the Java source"
        );
    }

    #[test]
    fn eicar_is_malicious_and_labeled_distinctly() {
        let content = crate::hash_match::EICAR_TEST_STRING.as_bytes();
        let result = score_file("eicar.com", content, &SignatureSet::new(), &empty_rules(), None);
        assert_eq!(result.verdict, Verdict::Malicious);
        assert_eq!(result.threat_type.as_deref(), Some("EICAR_TEST_FILE"));
        assert_eq!(result.score, SCORE_KNOWN_HASH);
    }

    #[test]
    fn high_entropy_alone_reaches_suspicious_not_malicious() {
        let mut content = Vec::with_capacity(4096);
        for _ in 0..16 {
            for b in 0u8..=255 {
                content.push(b);
            }
        }
        // .bin is in SUSPICIOUS_EXTENSIONS, so entropy scoring is gated "on"
        // for this filename, matching the Java engine's gating behavior.
        let result = score_file("packed.bin", &content, &SignatureSet::new(), &empty_rules(), None);
        assert_eq!(
            result.verdict,
            Verdict::Suspicious,
            "high entropy alone should not reach MALICIOUS: score was {}",
            result.score
        );
    }

    #[test]
    fn high_entropy_on_a_non_executable_extension_is_not_scored_at_all() {
        // Same high-entropy content as above, but a .dat extension: not in
        // SUSPICIOUS_EXTENSIONS and no MZ/ELF header, so per the Java
        // engine's gating, entropy is never even computed for this file.
        let mut content = Vec::with_capacity(4096);
        for _ in 0..16 {
            for b in 0u8..=255 {
                content.push(b);
            }
        }
        let result = score_file("data.dat", &content, &SignatureSet::new(), &empty_rules(), None);
        assert_eq!(
            result.verdict,
            Verdict::Clean,
            "entropy must not be scored for a non-executable-like extension: score was {}",
            result.score
        );
    }

    #[test]
    fn extension_masquerade_is_detected() {
        let mut content = vec![0x4d, 0x5a]; // "MZ"
        content.extend(std::iter::repeat(0u8).take(100));
        let result = score_file(
            "invoice.pdf",
            &content,
            &SignatureSet::new(),
            &empty_rules(),
            None
        );
        assert!(result.contributions.iter().any(|c| c.reason.contains("EXTENSION_MASQUERADE")));
    }

    #[test]
    fn genuine_exe_with_mz_header_is_not_masquerade() {
        let mut content = vec![0x4d, 0x5a];
        content.extend(std::iter::repeat(0u8).take(100));
        let result = score_file("tool.exe", &content, &SignatureSet::new(), &empty_rules(), None);
        assert!(!result.contributions.iter().any(|c| c.reason.contains("EXTENSION_MASQUERADE")));
    }

    #[test]
    fn ransomware_extension_is_scored() {
        let result = score_file(
            "document.locked",
            b"arbitrary encrypted-looking content",
            &SignatureSet::new(),
            &empty_rules(),
            None
        );
        assert!(result.score >= SCORE_RANSOMWARE_EXTENSION);
    }

    #[test]
    fn ransomware_note_text_is_scored() {
        let content = b"Your files have been encrypted. Send payment to our BTC wallet.";
        let result = score_file("README.txt", content, &SignatureSet::new(), &empty_rules(), None);
        assert!(result.score >= SCORE_RANSOMWARE_TEXT_PATTERN);
        assert_ne!(result.verdict, Verdict::Clean);
    }

    #[test]
    fn trojan_filename_signature_is_scored_once_even_with_multiple_matches() {
        let result = score_file(
            "backdoor_trojan_tool.txt",
            b"ordinary content",
            &SignatureSet::new(),
            &empty_rules(),
            None
        );
        let trojan_contributions: Vec<_> = result.contributions
            .iter()
            .filter(|c| c.reason == "TROJAN_NAME_SIGNATURE")
            .collect();
        assert_eq!(trojan_contributions.len(), 1);
        assert_eq!(trojan_contributions[0].points, SCORE_TROJAN_NAME);
    }

    #[test]
    fn rootkit_text_pattern_is_scored() {
        let result = score_file(
            "notes.txt",
            b"details on a syscall table hook implementation",
            &SignatureSet::new(),
            &empty_rules(),
            None
        );
        assert!(result.score >= SCORE_ROOTKIT_TEXT);
    }

    #[test]
    fn score_is_capped_at_100_even_with_many_stacked_signals() {
        // Stack ransomware extension + ransomware text + trojan name +
        // rootkit text, comfortably over 100 before capping.
        let content =
            b"Your files have been encrypted, contact our btc wallet, \
                         syscall table hook detected";
        let result = score_file(
            "trojan_backdoor.locked",
            content,
            &SignatureSet::new(),
            &empty_rules(),
            None
        );
        assert!(result.score <= 100);
    }

    #[test]
    fn yara_match_contributes_to_score() {
        let rules = RuleSet::compile(
            r#"
            rule marker_rule {
                strings:
                    $a = "MALWARE_MARKER"
                condition:
                    $a
            }
            "#
        ).unwrap();
        let content = b"benign wrapper MALWARE_MARKER more benign content";
        let result = score_file("suspect.bin", content, &SignatureSet::new(), &rules, None);
        assert!(result.score >= SCORE_STRONG_PATTERN);
        assert_ne!(result.verdict, Verdict::Clean);
    }

    #[test]
    fn a_supplied_directory_score_replaces_reading_the_folder() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("README.txt"), b"pay us").unwrap();
        for i in 0..5 {
            fs::write(dir.path().join(format!("doc{i}.xyz123")), b"x").unwrap();
        }
        let path = dir.path().join("doc0.xyz123");
        let signatures = SignatureSet::new();
        let rules = empty_rules();

        let read_it = score_file("doc0.xyz123", b"x", &signatures, &rules, Some(&path));
        let supplied = score_file_in_directory(
            "doc0.xyz123", b"x", &signatures, &rules, &path, SCORE_RANSOMWARE_DIR_BEHAVIOR
        );
        assert!(read_it.contributions.iter().any(|c| c.reason == "RANSOMWARE_DIRECTORY_BEHAVIOR"));
        assert_eq!(read_it.score, supplied.score);

        // Proof the supplied value is what is used: 0 wins even though the
        // folder on disk would score.
        let overridden = score_file_in_directory("doc0.xyz123", b"x", &signatures, &rules, &path, 0);
        assert!(!overridden.contributions.iter().any(|c| c.reason == "RANSOMWARE_DIRECTORY_BEHAVIOR"));
    }

    // --- false-positive fixes (docs/java-engine-false-positive-fixes.md) ---

    fn all_byte_values(copies: usize) -> Vec<u8> {
        // Entropy of exactly 8 bits per byte.
        (0..copies).flat_map(|_| 0u8..=255).collect()
    }

    fn masquerade_flagged(result: &ScanResult) -> bool {
        result.contributions.iter().any(|c| c.reason.starts_with("EXTENSION_MASQUERADE"))
    }

    #[test]
    fn a_jar_or_msi_is_not_flagged_just_for_being_compressed() {
        let content = all_byte_values(16);
        for name in ["library.jar", "Setup.msi", "LIBRARY.JAR"] {
            let result = score_file(name, &content, &SignatureSet::new(), &empty_rules(), None);
            assert_eq!(result.verdict, Verdict::Clean, "{name}: score {}", result.score);
        }
        // The same bytes under an executable-looking extension are still flagged.
        let result = score_file("packed.bin", &content, &SignatureSet::new(), &empty_rules(), None);
        assert_eq!(result.verdict, Verdict::Suspicious);
    }

    #[test]
    fn a_real_executable_named_jar_is_still_checked_for_entropy() {
        let mut content = b"MZ".to_vec();
        content.extend(all_byte_values(16));
        let result = score_file("fake.jar", &content, &SignatureSet::new(), &empty_rules(), None);
        assert_eq!(result.verdict, Verdict::Suspicious);
        assert!(result.contributions.iter().any(|c| c.reason.starts_with("HIGH_ENTROPY")));
    }

    #[test]
    fn an_archive_full_of_executables_is_not_flagged_by_its_contents_alone() {
        let names: Vec<String> = (0..30).map(|i| format!("driver{i}.dll")).collect();
        let entries: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"x"[..])).collect();
        let zip = crate::zip_scan::tests::build_test_zip(&entries);

        let result = score_file("drivers.zip", &zip, &SignatureSet::new(), &empty_rules(), None);
        assert_eq!(result.verdict, Verdict::Clean, "score was {}", result.score);
        let zip_points: Vec<i32> = result
            .contributions
            .iter()
            .filter(|c| c.reason == "ZIP_CONTAINS_EXECUTABLE_ENTRY")
            .map(|c| c.points)
            .collect();
        assert_eq!(zip_points, vec![crate::zip_scan::SCORE_ZIP_SUSPICIOUS_ENTRY], "scored once, not per entry");
    }

    #[test]
    fn zip_analysis_follows_the_file_name_like_the_java_engine() {
        let bomb = crate::zip_scan::tests::build_test_zip(&[("zeros.bin", &vec![0u8; 400_000])]);
        let with_exe = crate::zip_scan::tests::build_test_zip(&[("setup.exe", b"x")]);
        let has = |r: &ScanResult, reason: &str| r.contributions.iter().any(|c| c.reason == reason);

        let as_zip = score_file("x.zip", &bomb, &SignatureSet::new(), &empty_rules(), None);
        assert!(has(&as_zip, "ZIP_BOMB_LIMIT_EXCEEDED"));
        let as_docx = score_file("report.docx", &bomb, &SignatureSet::new(), &empty_rules(), None);
        assert!(!has(&as_docx, "ZIP_BOMB_LIMIT_EXCEEDED"), "a zip container that is not named .zip/.jar/.war is not analyzed");

        let as_jar = score_file("x.jar", &with_exe, &SignatureSet::new(), &empty_rules(), None);
        assert!(has(&as_jar, "ZIP_CONTAINS_EXECUTABLE_ENTRY"));
        let as_docx = score_file("x.docx", &with_exe, &SignatureSet::new(), &empty_rules(), None);
        assert!(!has(&as_docx, "ZIP_CONTAINS_EXECUTABLE_ENTRY"));
    }

    #[test]
    fn weak_patterns_alone_never_flag_a_file_but_a_strong_one_still_does() {
        let weak = b"eval(x); document.write(y); shell_exec(z); system(w); \
                     passthru(v); base64_decode(u); runtime.exec(t);";
        let result = score_file("bundle.js", weak, &SignatureSet::new(), &empty_rules(), None);
        assert_eq!(result.verdict, Verdict::Clean, "weak patterns alone scored {}", result.score);
        assert!(result.score > 0, "they should still count for something");

        let mut with_strong = weak.to_vec();
        with_strong.extend_from_slice(b" powershell -w hidden -Command whatever");
        let result = score_file("bundle.js", &with_strong, &SignatureSet::new(), &empty_rules(), None);
        assert_eq!(result.verdict, Verdict::Suspicious, "score was {}", result.score);
    }

    #[test]
    fn an_elf_shared_library_is_not_extension_masquerade_but_a_disguised_one_is() {
        let mut elf = b"\x7fELF\x02\x01\x01\x00".to_vec();
        elf.extend(std::iter::repeat_n(0u8, 64));

        for name in ["libfoo.so", "libfoo.so.1.2.3", "mod.ko", "addon.node"] {
            let result = score_file(name, &elf, &SignatureSet::new(), &empty_rules(), None);
            assert!(!masquerade_flagged(&result), "{name} wrongly flagged");
            assert_eq!(result.verdict, Verdict::Clean, "{name}");
        }

        let disguised = score_file("report.pdf", &elf, &SignatureSet::new(), &empty_rules(), None);
        assert!(masquerade_flagged(&disguised));
        assert_eq!(disguised.verdict, Verdict::Malicious);

        let mut pe = b"MZ\x90\x00".to_vec();
        pe.extend(std::iter::repeat_n(0u8, 64));
        let windows_exe_named_so = score_file("libfoo.so", &pe, &SignatureSet::new(), &empty_rules(), None);
        assert!(masquerade_flagged(&windows_exe_named_so));
    }
}
