//! Ported from SecurityServiceImpl.scoreRootkit. Two independent signals:
//! a binary-pattern check gated on the file living in a driver-relevant
//! location, and a kernel-manipulation text-pattern check with no location
//! gate. Both source from the same header/content the rest of scoring
//! already has, plus (for the location gate only) the file's real
//! filesystem path when one is available.

use crate::text_patterns::contains_kernel_pattern;
use std::path::Path;

/// Ported verbatim from SecurityServiceImpl.detectRootkitBinaryPatterns: a
/// substring search for three ASCII byte sequences ("hideproc", "syscall",
/// "kernel32") within the sampled header, matched against a 4096-byte prefix
/// exactly as the Java engine does.
fn detect_rootkit_binary_patterns(content: &[u8]) -> bool {
    const SIGNATURES: &[&[u8]] = &[b"hideproc", b"syscall", b"kernel32"];
    SIGNATURES.iter().any(|sig| contains_sequence(content, sig))
}

fn contains_sequence(content: &[u8], sequence: &[u8]) -> bool {
    if content.len() < sequence.len() {
        return false;
    }
    content.windows(sequence.len()).any(|window| window == sequence)
}

fn in_rootkit_location(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    path_str.contains("/lib/modules/")
        || path_str.contains("/boot/")
        || path_str.contains("\\system32\\drivers\\")
        || path_str.contains("\\syswow64\\drivers\\")
}

pub struct RootkitScore {
    pub binary_flagged: bool,
    pub text_flagged: bool,
}

/// `path` is the real filesystem path when one is available (None for
/// pure in-memory scoring, e.g. tests or content received without ever
/// touching disk); the location gate can only apply when a path exists,
/// matching Java's own File-based check.
pub fn score_rootkit(path: Option<&Path>, content: &[u8]) -> RootkitScore {
    let binary_flagged = match path {
        Some(p) if in_rootkit_location(p) => {
            let header = &content[..content.len().min(4096)];
            detect_rootkit_binary_patterns(header)
        }
        _ => false,
    };

    let text_flagged = contains_kernel_pattern(content);

    RootkitScore {
        binary_flagged,
        text_flagged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_path_never_flags_binary_signal() {
        let result = score_rootkit(None, b"arbitrary content");
        assert!(!result.binary_flagged);
    }

    #[test]
    fn text_signal_independent_of_path() {
        let result = score_rootkit(None, b"installing an idt hook");
        assert!(result.text_flagged);
    }

    #[test]
    fn recognizes_windows_driver_location() {
        let path = Path::new(r"C:\Windows\System32\drivers\suspicious.sys");
        assert!(in_rootkit_location(path));
        let ordinary = Path::new(r"C:\Users\name\Downloads\file.txt");
        assert!(!in_rootkit_location(ordinary));
    }

    #[test]
    fn binary_signal_only_fires_in_rootkit_location_with_matching_bytes() {
        let driver_path = Path::new(r"C:\Windows\System32\drivers\suspicious.sys");
        let flagged = score_rootkit(Some(driver_path), b"contains syscall table reference");
        assert!(flagged.binary_flagged);

        // Same content, ordinary location: no binary signal.
        let ordinary_path = Path::new(r"C:\Users\name\Downloads\file.txt");
        let not_flagged = score_rootkit(Some(ordinary_path), b"contains syscall table reference");
        assert!(!not_flagged.binary_flagged);
    }
}
