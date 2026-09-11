//! Ported from SecurityServiceImpl.scoreRansomwareDirectoryBehavior. Only
//! meaningful when scanning a real file on disk with real siblings, not a
//! standalone in-memory buffer, matching Java's own `file.getParentFile()`
//! requirement. Deliberately conservative: Java only scores this when a
//! ransom-note-like filename is present in the same directory AND five or
//! more sibling files share an unrecognized extension, a lone weird
//! extension or a lone note-like filename alone is not enough evidence.

use crate::extension::{get_file_extension, COMMON_EXTENSIONS, RANSOMWARE_EXTENSIONS};
use std::collections::HashMap;
use std::path::Path;

fn looks_like_ransom_note(file_name_lowercase: &str) -> bool {
    (file_name_lowercase.contains("readme") && file_name_lowercase.contains("txt"))
        || file_name_lowercase.contains("how_to_decrypt")
        || file_name_lowercase.contains("recovery")
        || file_name_lowercase.contains("help_decrypt")
        || file_name_lowercase.contains("decrypt_instructions")
}

/// `path` is the file being scanned; its parent directory's other entries
/// are listed once per call. Returns the score contribution (0 or
/// SCORE_RANSOMWARE_DIR_BEHAVIOR).
pub fn score_ransomware_directory_behavior(path: &Path) -> i32 {
    let Some(parent) = path.parent() else {
        return 0;
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return 0;
    };

    let mut has_ransom_note = false;
    let mut unknown_ext_counts: HashMap<String, i32> = HashMap::new();

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_lowercase();

        if looks_like_ransom_note(&name) {
            has_ransom_note = true;
        }

        let ext = get_file_extension(&name);
        if !ext.is_empty()
            && !COMMON_EXTENSIONS.contains(&ext.as_str())
            && !RANSOMWARE_EXTENSIONS.contains(&ext.as_str())
        {
            *unknown_ext_counts.entry(ext).or_insert(0) += 1;
        }
    }

    if !has_ransom_note {
        return 0;
    }

    let max_same_unknown_ext = unknown_ext_counts.values().copied().max().unwrap_or(0);
    if max_same_unknown_ext >= 5 {
        crate::scoring::SCORE_RANSOMWARE_DIR_BEHAVIOR
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn no_score_without_a_ransom_note_present() {
        let dir = tempdir().unwrap();
        for i in 0..6 {
            fs::write(dir.path().join(format!("file{i}.xyz123")), b"content").unwrap();
        }
        let target = dir.path().join("file0.xyz123");
        assert_eq!(score_ransomware_directory_behavior(&target), 0);
    }

    #[test]
    fn no_score_with_ransom_note_but_too_few_matching_unknown_extensions() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("README.txt"), b"note").unwrap();
        for i in 0..3 {
            fs::write(dir.path().join(format!("file{i}.xyz123")), b"content").unwrap();
        }
        let target = dir.path().join("file0.xyz123");
        assert_eq!(score_ransomware_directory_behavior(&target), 0);
    }

    #[test]
    fn scores_when_ransom_note_and_five_plus_matching_unknown_extensions_present() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("README.txt"), b"note").unwrap();
        for i in 0..5 {
            fs::write(dir.path().join(format!("file{i}.xyz123")), b"content").unwrap();
        }
        let target = dir.path().join("file0.xyz123");
        assert_eq!(
            score_ransomware_directory_behavior(&target),
            crate::scoring::SCORE_RANSOMWARE_DIR_BEHAVIOR
        );
    }

    #[test]
    fn ordinary_project_directory_scores_zero() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("README.txt"), b"a totally normal readme").unwrap();
        fs::write(dir.path().join("main.py"), b"print('hi')").unwrap();
        fs::write(dir.path().join("data.json"), b"{}").unwrap();
        let target = dir.path().join("main.py");
        // README.txt matches the note-name heuristic on filename alone, but
        // with no cluster of 5+ shared unknown extensions, this must still
        // score zero, an ordinary project directory is not ransomware.
        assert_eq!(score_ransomware_directory_behavior(&target), 0);
    }
}
