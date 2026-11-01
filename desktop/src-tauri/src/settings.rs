//! The app's small settings file, `settings.json` next to the database. For
//! now it holds one value, the abuse.ch Auth-Key.
//!
//! The key is stored as plain text: any process running as the same user can
//! read the file. That is accepted because the key is free, rate limited and
//! revocable; moving it to the OS credential store later changes only this
//! module.
//!
//! The key must never leave this crate through an error, a log line or a
//! `Debug` print. In particular a settings parse error is never passed on,
//! because serde's text can quote the value it choked on.

use secureguard_core::signature_sync::auth_key_from;
use serde::{ Deserialize, Serialize };
use std::fmt;
use std::io::Write;
use std::path::{ Path, PathBuf };

/// The longest key accepted, in bytes. The real format of an abuse.ch key is
/// not documented here, so this is only a sanity limit.
pub const MAX_KEY_LEN: usize = 256;

#[derive(Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abuse_ch_auth_key: Option<String>,
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("abuse_ch_auth_key", &self.abuse_ch_auth_key.as_ref().map(|_| "<hidden>"))
            .finish()
    }
}

fn unreadable(path: &Path) -> String {
    format!("The settings file {} could not be read. Fix it or delete it.", path.display())
}

/// Reads the settings. A missing file is no settings at all. A file that
/// cannot be read or parsed is an error naming the path; it is never repaired,
/// overwritten or deleted here, and the parse error is not passed on.
pub fn load(path: &Path) -> Result<Settings, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Settings::default());
        }
        Err(_) => {
            return Err(unreadable(path));
        }
    };
    serde_json::from_str(&text).map_err(|_| unreadable(path))
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

fn write_temp(temp: &Path, settings: &Settings) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(settings).map_err(std::io::Error::other)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(temp)?;
    #[cfg(unix)]
    {
        // A leftover temporary file keeps its old mode when reopened.
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(&bytes)?;
    file.sync_all()
}

/// Writes the settings to a temporary file and renames it over the real one,
/// so a crash leaves either the old file or the new one, never half of one.
pub fn save(path: &Path, settings: &Settings) -> Result<(), String> {
    let temp = temp_path(path);
    let result = write_temp(&temp, settings).and_then(|_| std::fs::rename(&temp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
        return Err(format!("The settings file {} could not be saved.", path.display()));
    }
    Ok(())
}

/// Checks a key typed by the user and returns it trimmed. The error texts are
/// fixed strings and never contain the input.
pub fn validate_auth_key(raw: &str) -> Result<String, &'static str> {
    let key = raw.trim();
    if key.is_empty() {
        return Err("Enter the key.");
    }
    if key.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("The key cannot contain spaces or control characters.");
    }
    if key.len() > MAX_KEY_LEN {
        return Err("The key is too long.");
    }
    Ok(key.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    Environment,
    Settings,
}

/// The key to use and where it came from: the environment first, then the
/// saved key. Blank values count as none.
pub fn resolve_auth_key(
    env: Option<String>,
    saved: Option<String>
) -> Option<(String, KeySource)> {
    auth_key_from(env)
        .map(|key| (key, KeySource::Environment))
        .or_else(|| auth_key_from(saved).map(|key| (key, KeySource::Settings)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const KEY: &str = "distinct-key-AbC123";

    fn dir_and_path() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        (dir, path)
    }

    fn with_key(key: &str) -> Settings {
        Settings { abuse_ch_auth_key: Some(key.to_string()) }
    }

    #[test]
    fn a_missing_file_means_no_key() {
        let (_dir, path) = dir_and_path();
        assert_eq!(load(&path).unwrap(), Settings::default());
    }

    #[test]
    fn save_then_load_round_trips() {
        let (_dir, path) = dir_and_path();
        save(&path, &with_key(KEY)).unwrap();
        assert_eq!(load(&path).unwrap(), with_key(KEY));
    }

    #[test]
    fn saving_twice_replaces_the_file_and_leaves_no_temp_file() {
        let (dir, path) = dir_and_path();
        save(&path, &with_key("one")).unwrap();
        save(&path, &with_key("two")).unwrap();

        assert_eq!(load(&path).unwrap(), with_key("two"));
        let names: Vec<String> = std::fs
            ::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["settings.json".to_string()]);
    }

    #[test]
    fn a_corrupt_file_is_an_error_that_names_the_path_and_never_echoes_its_content() {
        let (_dir, path) = dir_and_path();
        std::fs::write(&path, r#"{"abuse_ch_auth_key": 5, "x": "SECRETLOOKING"}"#).unwrap();

        let error = load(&path).unwrap_err();

        assert!(error.contains("settings.json"), "{error}");
        assert!(!error.contains("SECRETLOOKING"), "{error}");
        assert!(!error.contains("expected"), "a serde error must not be passed on: {error}");
    }

    #[test]
    fn an_empty_file_is_corrupt_not_missing() {
        let (_dir, path) = dir_and_path();
        std::fs::write(&path, b"").unwrap();
        assert!(load(&path).is_err());
    }

    #[test]
    fn debug_output_hides_the_key() {
        let text = format!("{:?}", with_key(KEY));
        assert!(!text.contains(KEY), "{text}");
        assert!(text.contains("hidden"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn on_unix_the_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = dir_and_path();
        save(&path, &with_key(KEY)).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn validation_trims_and_accepts_an_ordinary_key() {
        assert_eq!(validate_auth_key("  abc123 \n").unwrap(), "abc123");
    }

    #[test]
    fn validation_rejects_empty_and_blank() {
        assert!(validate_auth_key("").is_err());
        assert!(validate_auth_key("   \t ").is_err());
    }

    #[test]
    fn validation_rejects_whitespace_and_control_characters_inside_the_key() {
        for bad in ["ab cd", "ab\tcd", "ab\ncd", "ab\u{0}cd"] {
            assert!(validate_auth_key(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn validation_accepts_256_bytes_and_rejects_257() {
        assert!(validate_auth_key(&"a".repeat(256)).is_ok());
        assert!(validate_auth_key(&"a".repeat(257)).is_err());
    }

    #[test]
    fn no_validation_error_contains_its_input() {
        for bad in ["bad key SECRETLOOKING", "SECRETLOOKING\u{0}x", &"SECRETLOOKING".repeat(40)] {
            let error = validate_auth_key(bad).unwrap_err();
            assert!(!error.contains("SECRETLOOKING"), "{error}");
        }
    }

    fn some(value: &str) -> Option<String> {
        Some(value.to_string())
    }

    #[test]
    fn the_environment_key_wins_over_the_saved_one() {
        let (key, source) = resolve_auth_key(some("env"), some("saved")).unwrap();
        assert_eq!((key.as_str(), source), ("env", KeySource::Environment));
    }

    #[test]
    fn a_blank_environment_value_falls_through_to_the_saved_key() {
        let (key, source) = resolve_auth_key(some("   "), some("saved")).unwrap();
        assert_eq!((key.as_str(), source), ("saved", KeySource::Settings));
    }

    #[test]
    fn both_blank_or_missing_is_no_key_and_whitespace_is_trimmed() {
        assert!(resolve_auth_key(None, None).is_none());
        assert!(resolve_auth_key(some(" "), some("\t")).is_none());
        let (key, _) = resolve_auth_key(None, some("  saved \n")).unwrap();
        assert_eq!(key, "saved");
    }
}
