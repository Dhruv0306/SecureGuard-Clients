//! Ported from SecurityServiceImpl.scoreRansomwareDirectoryBehavior, with two
//! deliberate differences (docs/java-engine-false-positive-fixes.md, fix 4):
//! only regular files are counted, not subfolders, and the score is given only
//! to the files it is about, not to every file in the folder.
//!
//! Only meaningful when scanning a real file on disk with real siblings, not a
//! standalone in-memory buffer, matching Java's own `file.getParentFile()`
//! requirement. Deliberately conservative: a folder qualifies only when a
//! ransom-note-like filename is present AND five or more files share an
//! unrecognized extension; a lone weird extension or a lone note-like filename
//! alone is not enough evidence. When it qualifies, the note-like files and the
//! files with the clustered extension score; a `.py` file next to them does not.

use crate::extension::{ get_file_extension, COMMON_EXTENSIONS, RANSOMWARE_EXTENSIONS };
use std::collections::{ HashMap, HashSet };
use std::path::Path;

/// Files that must share one unrecognized extension to count as a cluster.
const MIN_CLUSTER_SIZE: i32 = 5;

fn looks_like_ransom_note(file_name_lowercase: &str) -> bool {
    (file_name_lowercase.contains("readme") && file_name_lowercase.contains("txt")) ||
        file_name_lowercase.contains("how_to_decrypt") ||
        file_name_lowercase.contains("recovery") ||
        file_name_lowercase.contains("help_decrypt") ||
        file_name_lowercase.contains("decrypt_instructions")
}

/// What the file names in one folder say about ransomware behavior, and which
/// of those files it applies to. Pure: no filesystem access. A scanner that
/// walks a folder builds it once from the listing it already has instead of
/// re-reading the folder for every file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FolderBehavior {
    /// Lowercase names of the files that look like a ransom note.
    note_names: HashSet<String>,
    /// Unrecognized extensions (with the dot, lowercase) shared by at least
    /// MIN_CLUSTER_SIZE files.
    cluster_extensions: HashSet<String>,
}

impl FolderBehavior {
    /// `names` must be the names of regular files only. Subfolders, such as the
    /// many `*.dist-info` folders in a Python `site-packages`, are not evidence.
    pub fn from_names<I, S>(names: I) -> Self where I: IntoIterator<Item = S>, S: AsRef<str> {
        let mut note_names = HashSet::new();
        let mut unknown_ext_counts: HashMap<String, i32> = HashMap::new();

        for name in names {
            let name = name.as_ref().to_lowercase();

            let ext = get_file_extension(&name);
            if
                !ext.is_empty() &&
                !COMMON_EXTENSIONS.contains(&ext.as_str()) &&
                !RANSOMWARE_EXTENSIONS.contains(&ext.as_str())
            {
                *unknown_ext_counts.entry(ext).or_insert(0) += 1;
            }

            if looks_like_ransom_note(&name) {
                note_names.insert(name);
            }
        }

        let cluster_extensions = unknown_ext_counts
            .into_iter()
            .filter(|(_, count)| *count >= MIN_CLUSTER_SIZE)
            .map(|(ext, _)| ext)
            .collect();
        Self { note_names, cluster_extensions }
    }

    /// Reads `dir` and builds the behavior from its regular files. An
    /// unreadable directory has no behavior.
    pub fn of_directory(dir: &Path) -> Self {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Self::default();
        };
        let names: Vec<String> = entries
            .flatten()
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        Self::from_names(names)
    }

    /// True when the folder has both a ransom-note-like file and a cluster of
    /// files with one unrecognized extension.
    pub fn is_ransomware_like(&self) -> bool {
        !self.note_names.is_empty() && !self.cluster_extensions.is_empty()
    }

    /// The score for one file in the folder: 0 or SCORE_RANSOMWARE_DIR_BEHAVIOR.
    /// Only the note-like files and the clustered-extension files score.
    pub fn score_for(&self, file_name: &str) -> i32 {
        if !self.is_ransomware_like() {
            return 0;
        }
        let name = file_name.to_lowercase();
        if
            self.note_names.contains(&name) ||
            self.cluster_extensions.contains(&get_file_extension(&name))
        {
            crate::scoring::SCORE_RANSOMWARE_DIR_BEHAVIOR
        } else {
            0
        }
    }
}

/// The score for a folder as a whole, from the names of the regular files in
/// it: 0 or SCORE_RANSOMWARE_DIR_BEHAVIOR. Which files in it score is
/// [`FolderBehavior::score_for`].
pub fn score_from_names<I, S>(names: I) -> i32 where I: IntoIterator<Item = S>, S: AsRef<str> {
    if FolderBehavior::from_names(names).is_ransomware_like() {
        crate::scoring::SCORE_RANSOMWARE_DIR_BEHAVIOR
    } else {
        0
    }
}

/// Lists `dir` and scores it as a whole with [`score_from_names`]. An unreadable
/// directory scores 0.
pub fn directory_behavior_score(dir: &Path) -> i32 {
    if FolderBehavior::of_directory(dir).is_ransomware_like() {
        crate::scoring::SCORE_RANSOMWARE_DIR_BEHAVIOR
    } else {
        0
    }
}

/// `path` is the file being scanned; its parent directory is listed once per
/// call. Returns the score for that file (0 or SCORE_RANSOMWARE_DIR_BEHAVIOR).
/// Scanners that visit many files in the same folder should build a
/// [`FolderBehavior`] once per folder instead.
pub fn score_ransomware_directory_behavior(path: &Path) -> i32 {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) =>
            FolderBehavior::of_directory(parent).score_for(&name.to_string_lossy()),
        _ => 0,
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

    #[test]
    fn score_from_names_matches_the_directory_reading_version() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("README.txt"), b"pay us").unwrap();
        for i in 0..5 {
            fs::write(dir.path().join(format!("doc{i}.xyz123")), b"x").unwrap();
        }

        let from_names = score_from_names([
            "README.txt", "doc0.xyz123", "doc1.xyz123", "doc2.xyz123", "doc3.xyz123", "doc4.xyz123",
        ]);
        assert_eq!(from_names, crate::scoring::SCORE_RANSOMWARE_DIR_BEHAVIOR);
        assert_eq!(directory_behavior_score(dir.path()), from_names);
        assert_eq!(score_ransomware_directory_behavior(&dir.path().join("doc0.xyz123")), from_names);
    }

    #[test]
    fn score_from_names_is_case_insensitive_and_needs_five_matching_extensions() {
        assert_eq!(score_from_names(["HOW_TO_DECRYPT.TXT", "A.XYZ123", "B.xyz123", "c.Xyz123", "d.xyz123"]), 0);
        assert_eq!(
            score_from_names(["HOW_TO_DECRYPT.TXT", "A.XYZ123", "B.xyz123", "c.Xyz123", "d.xyz123", "e.xyz123"]),
            crate::scoring::SCORE_RANSOMWARE_DIR_BEHAVIOR
        );
        assert_eq!(score_from_names(Vec::<String>::new()), 0);
    }

    #[test]
    fn an_unreadable_or_missing_directory_scores_zero() {
        let dir = tempdir().unwrap();
        assert_eq!(directory_behavior_score(&dir.path().join("does-not-exist")), 0);
    }

    #[test]
    fn subfolders_are_not_counted_as_files() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("README.txt"), b"note").unwrap();
        for i in 0..5 {
            fs::create_dir(dir.path().join(format!("pkg{i}-1.0.dist-info"))).unwrap();
        }
        fs::write(dir.path().join("six.py"), b"x").unwrap();
        // A Python site-packages folder looks like this. It is not ransomware.
        assert_eq!(directory_behavior_score(dir.path()), 0);
        assert_eq!(score_ransomware_directory_behavior(&dir.path().join("six.py")), 0);
    }

    #[test]
    fn only_the_note_and_the_cluster_files_are_scored() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("README.txt"), b"note").unwrap();
        for i in 0..5 {
            fs::write(dir.path().join(format!("file{i}.xyz123")), b"x").unwrap();
        }
        fs::write(dir.path().join("main.py"), b"x").unwrap();
        fs::write(dir.path().join("data.json"), b"{}").unwrap();

        let score = |name: &str| score_ransomware_directory_behavior(&dir.path().join(name));
        let flagged = crate::scoring::SCORE_RANSOMWARE_DIR_BEHAVIOR;
        assert_eq!(score("README.txt"), flagged);
        assert_eq!(score("file0.xyz123"), flagged);
        assert_eq!(score("main.py"), 0);
        assert_eq!(score("data.json"), 0);
        // The folder as a whole still scores.
        assert_eq!(directory_behavior_score(dir.path()), flagged);
    }

    #[test]
    fn a_fonts_folder_with_readmes_scores_only_the_readmes_and_the_font_files() {
        // The shape of reportlab's fonts folder: readmes, a license, one .ttf and
        // a cluster of .afm files.
        let mut names: Vec<String> = vec![
            "00readme.txt".into(),
            "bitstream-vera-license.txt".into(),
            "Vera.ttf".into()
        ];
        for i in 0..5 {
            names.push(format!("face{i}.afm"));
        }
        let behavior = FolderBehavior::from_names(&names);
        let flagged = crate::scoring::SCORE_RANSOMWARE_DIR_BEHAVIOR;
        assert!(behavior.is_ransomware_like());
        assert_eq!(behavior.score_for("00readme.txt"), flagged);
        assert_eq!(behavior.score_for("FACE0.AFM"), flagged);
        assert_eq!(behavior.score_for("bitstream-vera-license.txt"), 0);
        assert_eq!(behavior.score_for("Vera.ttf"), 0, "one .ttf is not a cluster");
    }

    #[test]
    fn a_folder_that_does_not_qualify_scores_nothing_for_any_file() {
        let behavior = FolderBehavior::from_names(["README.txt", "a.xyz123", "b.xyz123"]);
        assert!(!behavior.is_ransomware_like());
        assert_eq!(behavior.score_for("README.txt"), 0);
        assert_eq!(behavior.score_for("a.xyz123"), 0);
        assert!(!FolderBehavior::default().is_ransomware_like());
    }
}
