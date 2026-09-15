//! Tauri commands wrapping secureguard-core directly, in-process, no HTTP,
//! no backend. Each #[tauri::command] is a thin wrapper delegating to a
//! plain function taking &AppState, so tests exercise the real logic
//! directly without touching Tauri's IPC/mock-runtime test infrastructure
//! at all, see the tests module below.

use secureguard_core::rusqlite::Connection;
use secureguard_core::hash_match::SignatureSet;
use secureguard_core::signature_sync::{ self, SyncResult };
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
        let rules = RuleSet::compile(DEFAULT_RULES).map_err(|e|
            format!("failed to compile rule set: {e}")
        )?;
        let signatures = SignatureSet::load_from_cache(&conn).map_err(|e|
            format!("failed to load signatures: {e}")
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
            rules,
            signatures: Mutex::new(signatures),
        })
    }
}

// --- Plain functions: the actual logic, testable directly, no Tauri types ---

pub fn do_scan(state: &AppState, path: &str) -> Result<ScanResult, String> {
    let signatures = state.signatures
        .lock()
        .map_err(|_| "signature set lock poisoned".to_string())?;

    let result = secureguard_core
        ::scan_file(&PathBuf::from(path), &signatures, &state.rules)
        .map_err(|e| format!("failed to scan {path}: {e}"))?;

    let conn = state.conn.lock().map_err(|_| "database lock poisoned".to_string())?;
    // Matches the CLI's own behavior: a failure to record history is
    // logged, not fatal, the scan itself succeeded and the caller still
    // gets a real verdict either way.
    if let Err(e) = storage::record_scan(&conn, &result) {
        eprintln!("warning: failed to record scan to history: {e}");
    }

    Ok(result)
}

pub fn do_recent_scans(state: &AppState, limit: i64) -> Result<Vec<ScanResult>, String> {
    let conn = state.conn.lock().map_err(|_| "database lock poisoned".to_string())?;
    storage::recent_scans(&conn, limit).map_err(|e| format!("failed to load history: {e}"))
}

pub fn do_sync(state: &AppState) -> Result<SyncResult, String> {
    let conn = state.conn.lock().map_err(|_| "database lock poisoned".to_string())?;

    let result = signature_sync
        ::sync_signatures(&[signature_sync::DEFAULT_FEED_URL], &conn)
        .map_err(|e| format!("sync failed: {e}"))?;

    // Reload in-memory signatures so a scan run immediately after this
    // sync sees the newly learned hashes, not just on next app restart.
    let refreshed = SignatureSet::load_from_cache(&conn).map_err(|e|
        format!("sync succeeded but reloading signatures failed: {e}")
    )?;
    *state.signatures.lock().map_err(|_| "signature set lock poisoned".to_string())? = refreshed;

    Ok(result)
}

/// DB-only, no IPC to the helper, so it's directly testable. Returns the
/// new full active list so the caller (the Tauri command) knows exactly
/// what to send the helper next, rather than re-querying.
pub fn do_block_domain(
    state: &AppState,
    domain: &str,
    reason: Option<&str>
) -> Result<Vec<String>, String> {
    let conn = state.conn.lock().map_err(|_| "database lock poisoned".to_string())?;
    storage
        ::add_blocked_domain(&conn, domain, reason)
        .map_err(|e| format!("failed to record blocked domain: {e}"))?;
    storage::list_blocked_domains(&conn).map_err(|e| format!("failed to list blocked domains: {e}"))
}

/// DB-only, same reasoning as do_block_domain.
pub fn do_unblock_domain(state: &AppState, domain: &str) -> Result<Vec<String>, String> {
    let conn = state.conn.lock().map_err(|_| "database lock poisoned".to_string())?;
    storage
        ::remove_blocked_domain(&conn, domain)
        .map_err(|e| format!("failed to remove blocked domain: {e}"))?;
    storage::list_blocked_domains(&conn).map_err(|e| format!("failed to list blocked domains: {e}"))
}

pub fn do_list_blocked_domains(state: &AppState) -> Result<Vec<String>, String> {
    let conn = state.conn.lock().map_err(|_| "database lock poisoned".to_string())?;
    storage::list_blocked_domains(&conn).map_err(|e| format!("failed to list blocked domains: {e}"))
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

/// Unlike the other commands, this one's DB step (do_block_domain) and its
/// IPC step (sending the updated list to the helper) are deliberately
/// separate calls here, not both inside one testable "do_" function, since
/// the IPC step can't be safely exercised in a unit test against the real
/// hosts file. On a helper failure, the DB insert is rolled back so local
/// state doesn't claim a domain is blocked when it demonstrably isn't.
#[tauri::command]
pub fn block_domain_cmd(
    state: State<AppState>,
    domain: String,
    reason: Option<String>
) -> Result<(), String> {
    let active = do_block_domain(&state, &domain, reason.as_deref())?;

    match crate::helper_client::send_domain_list(&active) {
        Ok(response) if response.success => Ok(()),
        Ok(response) => {
            let _ = do_unblock_domain(&state, &domain); // roll back, it isn't actually blocked
            Err(response.error.unwrap_or_else(|| "helper reported failure".to_string()))
        }
        Err(e) => {
            let _ = do_unblock_domain(&state, &domain);
            Err(e)
        }
    }
}

#[tauri::command]
pub fn unblock_domain_cmd(state: State<AppState>, domain: String) -> Result<(), String> {
    // Need the domain's prior reason to roll back accurately; simplest
    // correct approach is re-adding without a reason on rollback, losing
    // the original reason string in that specific failure case is an
    // acceptable tradeoff, the domain still ends up correctly re-blocked.
    let active = do_unblock_domain(&state, &domain)?;

    match crate::helper_client::send_domain_list(&active) {
        Ok(response) if response.success => Ok(()),
        Ok(response) => {
            let _ = do_block_domain(&state, &domain, None);
            Err(response.error.unwrap_or_else(|| "helper reported failure".to_string()))
        }
        Err(e) => {
            let _ = do_block_domain(&state, &domain, None);
            Err(e)
        }
    }
}

#[tauri::command]
pub fn list_blocked_domains_cmd(state: State<AppState>) -> Result<Vec<String>, String> {
    do_list_blocked_domains(&state)
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
        std::fs
            ::write(&file_path, secureguard_core::hash_match::EICAR_TEST_STRING.as_bytes())
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

    #[test]
    fn do_block_domain_adds_to_the_active_list() {
        let (state, _dir) = test_state();
        let active = do_block_domain(&state, "malware.example.com", Some("test")).unwrap();
        assert_eq!(active, vec!["malware.example.com"]);
    }

    #[test]
    fn do_unblock_domain_removes_from_the_active_list() {
        let (state, _dir) = test_state();
        do_block_domain(&state, "malware.example.com", None).unwrap();
        let active = do_unblock_domain(&state, "malware.example.com").unwrap();
        assert!(active.is_empty());
    }

    #[test]
    fn do_list_blocked_domains_reflects_current_state() {
        let (state, _dir) = test_state();
        do_block_domain(&state, "a.example.com", None).unwrap();
        do_block_domain(&state, "b.example.com", None).unwrap();
        let active = do_list_blocked_domains(&state).unwrap();
        assert_eq!(active, vec!["a.example.com", "b.example.com"]);
    }
}
