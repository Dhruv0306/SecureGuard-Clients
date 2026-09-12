//! Ported verbatim from SecurityServiceImpl's regex pattern lists. Rust's
//! `regex` crate supports the same inline-flag and word-boundary syntax
//! Java's `java.util.regex.Pattern` uses ((?i), \b, {0,N} quantifiers), so
//! these translate essentially unchanged, only Rust's `regex::Regex` type in
//! place of `java.util.regex.Pattern`.
//!
//! Java streams these over a file with a bounded sliding window
//! (MAX_PATTERN_SCAN_BYTES / MAX_PATTERN_WINDOW_CHARS) purely for memory
//! efficiency on large files; this crate already holds the full content in
//! memory by the time scoring runs, so that windowing is a memory-efficiency
//! detail with no bearing on correctness here, not reproduced. The content
//! is still bounded to MAX_PATTERN_SCAN_BYTES before matching, mirroring the
//! limit itself, not the streaming mechanism used to enforce it.

use regex::Regex;
use std::sync::OnceLock;

/// Ported from SecurityServiceImpl.MAX_PATTERN_SCAN_BYTES.
pub const MAX_PATTERN_SCAN_BYTES: usize = 10 * 1024 * 1024;

fn strong_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            r"(?i)\bpowershell\b.{0,120}(?:-enc\b|-encodedcommand|-w\s+hidden)",
            r"(?i)\bpowershell\b.{0,120}downloadstring",
            r"(?i)\bpowershell\b.{0,120}\bbypass\b",
            r"(?i)\bicacls\b.{0,80}\bgrant\b.{0,80}\beveryone\b",
            r"(?i)\bconnect\s*\(.*\d{1,3}(?:\.\d{1,3}){3}",
            r"(?i)\bpost\b.{0,80}\bpassword\b.{0,80}(?:https?://|socket|connect)",
            r"(?i)\bkeylog(?:ger)?\b.{0,80}(?:getasynckeystate|setwindowshookex|keyboard_event)",
        ]
            .iter()
            .map(|p| Regex::new(p).expect("strong pattern regex must compile"))
            .collect()
    })
}

fn weak_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            r"(?i)\beval\s*\(",
            r"(?i)\bdocument\.write\s*\(",
            r"(?i)<script\b",
            r"(?i)\bbase64_decode\b",
            r"(?i)\bshell_exec\s*\(",
            r"(?i)\bruntime\.exec\s*\(",
            r"(?i)\bsystem\s*\(",
            r"(?i)\bpassthru\s*\(",
            r"(?i)\bprocess\.spawn\b",
            r"(?i)\bcreateprocess\w*\b",
            r"(?i)\bnew\s+socket\s*\(",
            r"(?i)\bwget\s+https?://",
            r"(?i)\bcurl\b.{0,80}\s-O\b",
            r"(?i)\breg\b.{0,80}\badd\b",
            r"(?i)\bregistry\.setvalue\b",
            r"(?i)\.encrypt\s*\(",
            r"(?i)\bchmod\b.{0,40}\b777\b",
            r"(?i)\.upload\s*\(",
            r"(?i)\\startup\\",
            r"(?i)\\system32\\drivers\\",
            r"(?i)\\tasks\\",
            r"(?i)\bunescape\b",
            r"(?i)\bdecode(?:uri)?\b",
            r"(?i)\bfromcharcode\b",
        ]
            .iter()
            .map(|p| Regex::new(p).expect("weak pattern regex must compile"))
            .collect()
    })
}

fn ransomware_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            r"(?i)\byour files have been encrypted\b",
            r"(?i)\byour important files\b",
            r"(?i)\bbtc wallet\b",
            r"(?i)\.(?:onion|tor)\b",
            r"(?i)\bdecrypt.{0,30}ransom|ransom.{0,30}decrypt\b",
            r"(?i)\bbitcoin\b.{0,80}(?:wallet|payment|transfer)",
            r"(?i)\bransom\b.{0,80}(?:payment|demand|note)",
        ]
            .iter()
            .map(|p| Regex::new(p).expect("ransomware pattern regex must compile"))
            .collect()
    })
}

/// Ported from SecurityServiceImpl.KERNEL_PATTERNS (narrower kernel-manipulation
/// phrases, the old bare "driver load" pattern was intentionally dropped
/// there for matching routine driver documentation/logs too often).
fn kernel_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            r"(?i)kernel.{0,20}hook",
            r"(?i)syscall.{0,20}table",
            r"(?i)interrupt.{0,20}descriptor.{0,20}table",
            r"(?i)idt.{0,20}hook",
            r"(?i)process.{0,20}hiding",
        ]
            .iter()
            .map(|p| Regex::new(p).expect("kernel pattern regex must compile"))
            .collect()
    })
}

fn bounded_text(content: &[u8]) -> String {
    let bound = content.len().min(MAX_PATTERN_SCAN_BYTES);
    String::from_utf8_lossy(&content[..bound]).into_owned()
}

pub struct PatternScore {
    pub strong_matches: usize,
    pub weak_matches: usize,
    pub strong_score: i32,
    pub weak_score: i32,
}

/// Ported from SecurityServiceImpl.scorePatterns's scoring formula:
/// strongScore = matchedStrong.size() * SCORE_STRONG_PATTERN, weakScore
/// capped at MAX_WEAK_PATTERN_SCORE. Each pattern counts at most once
/// (matching Java's Set<String> dedup), not once per occurrence.
pub fn score_text_patterns(content: &[u8]) -> PatternScore {
    let text = bounded_text(content);

    let strong_matches = strong_patterns()
        .iter()
        .filter(|p| p.is_match(&text))
        .count();
    let weak_matches = weak_patterns()
        .iter()
        .filter(|p| p.is_match(&text))
        .count();

    let strong_score = (strong_matches as i32) * crate::scoring::SCORE_STRONG_PATTERN;
    let weak_score = ((weak_matches as i32) * crate::scoring::SCORE_WEAK_PATTERN).min(
        crate::scoring::MAX_WEAK_PATTERN_SCORE
    );

    PatternScore {
        strong_matches,
        weak_matches,
        strong_score,
        weak_score,
    }
}

/// Ported from SecurityServiceImpl.containsRansomwarePatterns.
pub fn contains_ransomware_pattern(content: &[u8]) -> bool {
    let text = bounded_text(content);
    ransomware_patterns()
        .iter()
        .any(|p| p.is_match(&text))
}

/// Ported from the kernel-pattern loop inside SecurityServiceImpl.scoreRootkit:
/// scores once (break on first match), not once per pattern.
pub fn contains_kernel_pattern(content: &[u8]) -> bool {
    let text = bounded_text(content);
    kernel_patterns()
        .iter()
        .any(|p| p.is_match(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_strong_pattern() {
        let content = b"powershell -w hidden -Command whatever";
        let result = score_text_patterns(content);
        assert_eq!(result.strong_matches, 1);
        assert_eq!(result.strong_score, crate::scoring::SCORE_STRONG_PATTERN);
    }

    #[test]
    fn detects_and_caps_weak_patterns() {
        // Many weak patterns at once, score should cap at MAX_WEAK_PATTERN_SCORE.
        let content =
            b"eval(x); document.write(y); shell_exec(z); system(w); \
                         passthru(v); base64_decode(u); runtime.exec(t);";
        let result = score_text_patterns(content);
        assert!(result.weak_matches >= 5);
        assert!(result.weak_score <= crate::scoring::MAX_WEAK_PATTERN_SCORE);
    }

    #[test]
    fn clean_text_matches_nothing() {
        let result = score_text_patterns(b"an entirely ordinary sentence with no signals");
        assert_eq!(result.strong_matches, 0);
        assert_eq!(result.weak_matches, 0);
    }

    #[test]
    fn detects_ransomware_note_text() {
        assert!(
            contains_ransomware_pattern(
                b"Your files have been encrypted. Send payment to our BTC wallet."
            )
        );
        assert!(!contains_ransomware_pattern(b"just an ordinary document"));
    }

    #[test]
    fn detects_kernel_pattern() {
        assert!(contains_kernel_pattern(b"installing a syscall table hook"));
        assert!(!contains_kernel_pattern(b"ordinary driver documentation"));
    }
}
