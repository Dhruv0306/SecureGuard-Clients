use crate::entropy::{is_high_entropy, THRESHOLD_HIGH_ENTROPY};
use crate::hash_match::{check_hash, HashCheck, SignatureSet};
use crate::types::{ScanResult, ScoreContribution, Verdict};
use crate::yara_scan::RuleSet;
use crate::zip_scan::{scan_zip, ZipCheck};

/// Ported from SecurityServiceImpl. A file crossing this total is convicted
/// outright.
pub const THRESHOLD_MALICIOUS: i32 = 60;
/// A file crossing this total (but not THRESHOLD_MALICIOUS) is flagged for
/// review rather than convicted.
pub const THRESHOLD_SUSPICIOUS: i32 = 25;

/// Points contributed by a high-entropy sample. Calibrated (per the Java
/// engine's own comment on THRESHOLD_HIGH_ENTROPY) to reach SUSPICIOUS on
/// its own but not MALICIOUS on its own.
pub const SCORE_HIGH_ENTROPY: i32 = 30;
/// Points contributed by each strong YARA-X pattern match.
pub const SCORE_STRONG_PATTERN: i32 = 30;

pub fn score_file(
    file_name: &str,
    content: &[u8],
    signatures: &SignatureSet,
    rules: &RuleSet,
) -> ScanResult {
    let sha256 = crate::hash_match::sha256_hex(content);

    // Fast path: an exact known-malware hash match or the EICAR test file
    // short-circuits everything else, matching the Java engine's ordering.
    match check_hash(content, &sha256, signatures) {
        HashCheck::EicarTestFile => {
            return ScanResult {
                file_name: file_name.to_string(),
                sha256,
                verdict: Verdict::Malicious,
                score: THRESHOLD_MALICIOUS,
                threat_type: Some("EICAR_TEST_FILE".to_string()),
                contributions: vec![ScoreContribution {
                    reason: "EICAR standard antivirus test file detected".to_string(),
                    points: THRESHOLD_MALICIOUS,
                }],
            };
        }
        HashCheck::KnownMalicious => {
            return ScanResult {
                file_name: file_name.to_string(),
                sha256,
                verdict: Verdict::Malicious,
                score: THRESHOLD_MALICIOUS,
                threat_type: Some("VIRUS".to_string()),
                contributions: vec![ScoreContribution {
                    reason: "Known malware signature detected".to_string(),
                    points: THRESHOLD_MALICIOUS,
                }],
            };
        }
        HashCheck::NoMatch => {}
    }

    let mut score = 0;
    let mut contributions = Vec::new();

    // Zip bomb check takes priority: if it fires, we don't attempt further
    // analysis of the archive contents, matching the Java engine's early
    // return for this case.
    if let ZipCheck::LikelyZipBomb = scan_zip(content) {
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
    if let ZipCheck::Scored(zip_score) = scan_zip(content) {
        if zip_score > 0 {
            score += zip_score;
            contributions.push(ScoreContribution {
                reason: "Archive contains suspicious file entries".to_string(),
                points: zip_score,
            });
        }
    }

    let (entropy, high_entropy) = is_high_entropy(content);
    if high_entropy {
        score += SCORE_HIGH_ENTROPY;
        contributions.push(ScoreContribution {
            reason: format!(
                "High entropy content ({entropy:.2} bits/byte, threshold {THRESHOLD_HIGH_ENTROPY})"
            ),
            points: SCORE_HIGH_ENTROPY,
        });
    }

    match rules.scan(content) {
        Ok(matches) => {
            for m in matches {
                score += SCORE_STRONG_PATTERN;
                contributions.push(ScoreContribution {
                    reason: format!("YARA-X pattern match: {}", m.identifier),
                    points: SCORE_STRONG_PATTERN,
                });
                // Short-circuit once MALICIOUS is reached, no need to keep
                // accumulating further matches, matches the Java engine's
                // early-exit behavior in matchesAnyStrongPattern.
                if score >= THRESHOLD_MALICIOUS {
                    break;
                }
            }
        }
        Err(_) => {
            // A YARA-X scan failure (e.g. malformed input the engine can't
            // parse) is not itself a verdict; the other signals still apply.
        }
    }

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
            "#,
        )
        .expect("placeholder rule should compile")
    }

    #[test]
    fn clean_content_scores_below_suspicious() {
        let content = b"an entirely ordinary text file with nothing unusual in it";
        let result = score_file("clean.txt", content, &SignatureSet::new(), &empty_rules());
        assert_eq!(result.verdict, Verdict::Clean);
    }

    #[test]
    fn known_hash_is_malicious_regardless_of_content_analysis() {
        let content = b"arbitrary bytes";
        let hash = crate::hash_match::sha256_hex(content);
        let signatures = SignatureSet::from_hashes(vec![hash]);
        let result = score_file("bad.bin", content, &signatures, &empty_rules());
        assert_eq!(result.verdict, Verdict::Malicious);
        assert_eq!(result.threat_type.as_deref(), Some("VIRUS"));
    }

    #[test]
    fn eicar_is_malicious_and_labeled_distinctly() {
        let content = crate::hash_match::EICAR_TEST_STRING.as_bytes();
        let result = score_file("eicar.com", content, &SignatureSet::new(), &empty_rules());
        assert_eq!(result.verdict, Verdict::Malicious);
        assert_eq!(result.threat_type.as_deref(), Some("EICAR_TEST_FILE"));
    }

    #[test]
    fn high_entropy_alone_reaches_suspicious_not_malicious() {
        let mut content = Vec::with_capacity(4096);
        for _ in 0..16 {
            for b in 0u8..=255 {
                content.push(b);
            }
        }
        let result = score_file("packed.bin", &content, &SignatureSet::new(), &empty_rules());
        assert_eq!(
            result.verdict,
            Verdict::Suspicious,
            "high entropy alone should not reach MALICIOUS: score was {}",
            result.score
        );
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
            "#,
        )
        .unwrap();
        let content = b"benign wrapper MALWARE_MARKER more benign content";
        let result = score_file("suspect.bin", content, &SignatureSet::new(), &rules);
        assert!(result.score >= SCORE_STRONG_PATTERN);
        assert_ne!(result.verdict, Verdict::Clean);
    }
}
