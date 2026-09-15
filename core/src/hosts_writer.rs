//! Ported from system-agent/HostsFileWriter.java. This code itself needs no
//! privilege, any process that can write the target path can run it, the
//! privilege boundary is entirely about who's allowed to write that
//! specific file (see docs/phase4-desktop-privileged-helper-plan.md's "core
//! design question"). Kept here in `core` rather than in the `helper` crate
//! specifically so it's testable against a throwaway file exactly like the
//! Java tests do, with no elevation and no real hosts file touched by
//! `cargo test`.
//!
//! Marker string is `# SECUREGUARD_BLOCKED_DOMAIN`, not Java's
//! `# ANTIVIRUS_BLOCKED_DOMAIN`: this is a separate, unrelated product line
//! (no shared installation, no interop requirement with the main repo's web
//! app or system-agent), so there's no reason to match that exact string,
//! only the mechanism.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const MARKER: &str = "# SECUREGUARD_BLOCKED_DOMAIN";

/// Ported from AgentConfig.getHostsFilePath(): exact platform paths, not
/// guessed. `cfg!(windows)` covers Windows; every other target (macOS,
/// Linux, BSDs) uses the same POSIX hosts path.
pub fn default_hosts_path() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
    } else {
        PathBuf::from("/etc/hosts")
    }
}

pub struct HostsFileWriter {
    hosts_path: PathBuf,
    backup_path: PathBuf,
}

impl HostsFileWriter {
    pub fn new(hosts_path: impl Into<PathBuf>) -> Self {
        let hosts_path = hosts_path.into();
        let mut backup_path = hosts_path.clone().into_os_string();
        backup_path.push(".backup");
        Self {
            hosts_path,
            backup_path: PathBuf::from(backup_path),
        }
    }

    /// Best-effort writability probe, mirrors the Java version's own check:
    /// exists and is writable, not merely "the path is spelled correctly."
    pub fn is_writable(&self) -> bool {
        let Ok(metadata) = fs::metadata(&self.hosts_path) else {
            return false;
        };
        !metadata.permissions().readonly()
    }

    /// Rewrites the hosts file: keeps every line that isn't one of ours,
    /// appends one `127.0.0.1 <domain> # SECUREGUARD_BLOCKED_DOMAIN` line
    /// per active domain. Backs up first; on write failure, restores from
    /// that backup rather than leaving a partially-written file in place,
    /// same behavior as the Java version, ported line for line, not just
    /// in spirit.
    pub fn write(&self, active_domains: &[String]) -> io::Result<()> {
        let existing = fs::read_to_string(&self.hosts_path)?;

        let system_entries: Vec<&str> = existing
            .lines()
            .filter(|line| !line.contains(MARKER))
            .collect();

        let blocked_entries: Vec<String> = active_domains
            .iter()
            .map(|domain| format!("127.0.0.1 {domain} {MARKER}"))
            .collect();

        let mut new_content = system_entries.join("\n");
        for entry in &blocked_entries {
            new_content.push('\n');
            new_content.push_str(entry);
        }
        new_content.push('\n');

        fs::copy(&self.hosts_path, &self.backup_path)?;

        match fs::write(&self.hosts_path, &new_content) {
            Ok(()) => Ok(()),
            Err(write_err) => {
                // Original failure is the one worth surfacing; a failed
                // restore is a second, related problem, not a reason to
                // hide the first one, matching the Java version's
                // addSuppressed approach (Rust has no direct equivalent on
                // io::Error, so the restore attempt is best-effort and its
                // own failure is silently accepted rather than replacing
                // the original error).
                let _ = fs::copy(&self.backup_path, &self.hosts_path);
                Err(write_err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn writer_for(content: &str) -> (HostsFileWriter, NamedTempFile) {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        let writer = HostsFileWriter::new(file.path());
        (writer, file)
    }

    #[test]
    fn writes_blocked_domains_with_marker() {
        let (writer, file) = writer_for("127.0.0.1 localhost\n");
        writer
            .write(&["malware.example.com".to_string()])
            .unwrap();

        let content = fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("127.0.0.1 localhost"));
        assert!(content.contains("127.0.0.1 malware.example.com # SECUREGUARD_BLOCKED_DOMAIN"));
    }

    #[test]
    fn removes_stale_marker_lines_not_in_the_active_set() {
        let (writer, file) = writer_for(
            "127.0.0.1 localhost\n\
             127.0.0.1 old-blocked.example.com # SECUREGUARD_BLOCKED_DOMAIN\n",
        );

        writer
            .write(&["new-blocked.example.com".to_string()])
            .unwrap();

        let content = fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("127.0.0.1 localhost"));
        assert!(!content.contains("old-blocked.example.com"));
        assert!(content.contains("new-blocked.example.com"));
    }

    #[test]
    fn empty_active_set_removes_all_marker_lines_but_keeps_system_entries() {
        let (writer, file) = writer_for(
            "127.0.0.1 localhost\n\
             127.0.0.1 blocked.example.com # SECUREGUARD_BLOCKED_DOMAIN\n",
        );

        writer.write(&[]).unwrap();

        let content = fs::read_to_string(file.path()).unwrap();
        assert!(content.contains("127.0.0.1 localhost"));
        assert!(!content.contains("SECUREGUARD_BLOCKED_DOMAIN"));
    }

    #[test]
    fn creates_a_backup_before_writing() {
        let (writer, file) = writer_for("127.0.0.1 localhost\n");
        writer.write(&["x.example.com".to_string()]).unwrap();

        let mut backup_path = file.path().as_os_str().to_owned();
        backup_path.push(".backup");
        let backup_content = fs::read_to_string(&backup_path).unwrap();
        assert_eq!(backup_content, "127.0.0.1 localhost\n");

        let _ = fs::remove_file(&backup_path);
    }

    #[test]
    fn is_writable_reflects_real_file_permissions() {
        let (writer, _file) = writer_for("127.0.0.1 localhost\n");
        assert!(writer.is_writable());
    }

    #[test]
    fn nonexistent_path_is_not_writable() {
        let writer = HostsFileWriter::new("/this/path/does/not/exist/hosts");
        assert!(!writer.is_writable());
    }

    #[test]
    fn default_hosts_path_matches_the_current_platform() {
        let path = default_hosts_path();
        if cfg!(windows) {
            assert_eq!(path, Path::new(r"C:\Windows\System32\drivers\etc\hosts"));
        } else {
            assert_eq!(path, Path::new("/etc/hosts"));
        }
    }
}
