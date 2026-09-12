//! Tauri commands wrapping secureguard-core directly, in-process, no HTTP,
//! no backend. Each #[tauri::command] is a thin wrapper delegating to a
//! plain function taking &AppState, so tests exercise the real logic
//! directly without touching Tauri's IPC/mock-runtime test infrastructure
//! at all, see the tests module below.

use rusqlite::Connection;
use secureguard_core::hash_match::SignatureSet;
use secureguard_core::signature_sync::{self, SyncResult};
use secureguard_core::storage;
use secureguard_core::types::ScanResult;
use secureguard_core::yara_scan::RuleSet;
use secureguard_core::DEFAULT_RULES;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::State;

/// Shared app state, initialized once at startup, not per command call. The
/// CLI reopens its DB and recompiles the rule set on every invocation,
/// fine for a short-lived process, wasteful here. `signatures` is a Mutex
/// specifically so `do_sync` can replace it in place after a successful
/// sync, a scan run right after a sync must see the newly learned hashes
/// without restarting the app.
pub struct AppState {
    pub conn: Mutex<Connection>,
    pub rules: RuleSet,
    pub signatures: Mutex<SignatureSet>,
}

impl AppState {
    pub fn new(db_path: &str) -> Result<Self, String> {
        let conn = storage::open(db_path).map_err(|e| format!("failed to open database: {e}"))?;
        let rules = RuleSet::compile(DEFAULT_RULES)
            .map_err(|e| format!("failed to compile rule set: {e}"))?;
        let signatures = SignatureSet::load_from_cache(&conn)
            .map_err(|e| format!("failed to load signatures: {e}"))?;

        Ok(Self {
            conn: Mutex::new(conn),
            rules,
            signatures: Mutex::new(signatures),
        })
    }
}

// --- Plain functions: the actual logic, testable directly, no Tauri types ---

pub fn do_scan(state: &AppState, path: &str) -> Result<ScanResult, String> {
    let signatures = state
        .signatures
        .lock()
        .map_err(|_| "signature set lock poisoned".to_string())?;

    let result = secureguard_core::scan_file(&PathBuf::from(path), &signatures, &state.rules)
        .map_err(|e| format!("failed to scan {path}: {e}"))?;

    let conn = state
        .conn
        .lock()
        .map_err(|_| "database lock poisoned".to_string())?;
    // Matches the CLI's own behavior: a failure to record history is
    // logged, not fatal, the scan itself succeeded and the caller still
    // gets a real verdict either way.
    if let Err(e) = storage::record_scan(&conn, &result) {
        eprintln!("warning: failed to record scan to history: {e}");
    }

    Ok(result)
}

pub fn do_recent_scans(state: &AppState, limit: i64) -> Result<Vec<ScanResult>, String> {
    let conn = state
        .conn
        .lock()
        .map_err(|_| "database lock poisoned".to_string())?;
    storage::recent_scans(&conn, limit).map_err(|e| format!("failed to load history: {e}"))
}

pub fn do_sync(state: &AppState) -> Result<SyncResult, String> {
    let conn = state
        .conn
        .lock()
        .map_err(|_| "database lock poisoned".to_string())?;

    let result = signature_sync::sync_signatures(&[signature_sync::DEFAULT_FEED_URL], &conn)
        .map_err(|e| format!("sync failed: {e}"))?;

    // Reload in-memory signatures so a scan run immediately after this
    // sync sees the newly learned hashes, not just on next app restart.
    let refreshed = SignatureSet::load_from_cache(&conn)
        .map_err(|e| format!("sync succeeded but reloading signatures failed: {e}"))?;
    *state
        .signatures
        .lock()
        .map_err(|_| "signature set lock poisoned".to_string())? = refreshed;

    Ok(result)
}

// --- Thin Tauri command wrappers, the only place tauri::State is touched ---

#[tauri::command]
pub fn scan_file_cmd(state: State<AppState>, path: String) -> Result<ScanResult, String> {
    do_scan(&state, &path)
}

#[tauri::command]
pub fn recent_scans_cmd(state: State<AppState>, limit: i64) -> Result<Vec<ScanResult>, String> {
    do_recent_scans(&state, limit)
}

#[tauri::command]
pub fn sync_signatures_cmd(state: State<AppState>) -> Result<SyncResult, String> {
    do_sync(&state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Builds AppState against a fresh temp-file database, exercising the
    /// exact same open/compile/load path the real app startup uses, not a
    /// simplified test-only shortcut.
    fn test_state() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let state = AppState::new(&db_path.to_string_lossy()).unwrap();
        (state, dir)
    }

    #[test]
    fn do_scan_scans_and_records_history() {
        let (state, dir) = test_state();
        let file_path = dir.path().join("clean.txt");
        std::fs::write(&file_path, b"an entirely ordinary file").unwrap();

        // This is the automatable half of the Phase 3 test gate: does the
        // command layer's logic produce the right verdict against the same
        // corpus logic Phase 1/2 already validated. The "does the UI
        // display it correctly" half stays manual, see the plan doc.
        let result = do_scan(&state, &file_path.to_string_lossy()).unwrap();
        assert_eq!(result.verdict, secureguard_core::types::Verdict::Clean);

        let history = do_recent_scans(&state, 10).unwrap();
        assert_eq!(
            history.len(),
            1,
            "do_scan must record to history, this is the exact gap Phase 3 closed"
        );
    }

    #[test]
    #[cfg_attr(
        windows,
        ignore = "Windows Defender blocks writing the raw EICAR string to disk, \
                   same issue documented in core/src/lib.rs's own EICAR disk test. \
                   Not a bug, the OS's own AV correctly recognizing EICAR."
    )]
    fn do_scan_detects_eicar() {
        let (state, dir) = test_state();
        let file_path = dir.path().join("eicar_test.txt");
        std::fs::write(&file_path, secureguard_core::hash_match::EICAR_TEST_STRING.as_bytes())
            .unwrap();

        let result = do_scan(&state, &file_path.to_string_lossy()).unwrap();
        assert_eq!(result.verdict, secureguard_core::types::Verdict::Malicious);
        assert_eq!(result.threat_type.as_deref(), Some("EICAR_TEST_FILE"));
    }

    #[test]
    fn do_recent_scans_respects_limit() {
        let (state, dir) = test_state();
        for i in 0..5 {
            let file_path = dir.path().join(format!("file{i}.txt"));
            let mut f = std::fs::File::create(&file_path).unwrap();
            f.write_all(format!("content {i}").as_bytes()).unwrap();
            do_scan(&state, &file_path.to_string_lossy()).unwrap();
        }

        let history = do_recent_scans(&state, 3).unwrap();
        assert_eq!(history.len(), 3);
    }
}
