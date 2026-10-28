//! Tauri commands wrapping secureguard-core directly, in-process, no HTTP,
//! no backend. Each #[tauri::command] is a thin wrapper delegating to a
//! plain function taking &AppState, so tests exercise the real logic
//! directly without touching Tauri's IPC/mock-runtime test infrastructure
//! at all, see the tests module below.
//!
//! Every command is an `async fn` that runs its plain function on Tauri's
//! blocking thread pool (see `run_blocking`). A plain `fn` command runs on
//! the main thread and blocks every other command until it returns; the
//! Phase 5.3 spike measured an 8.5 s stall for a 10 s plain command against
//! 3 ms for the async shape (docs/phase5-3-spike-results.md).

use secureguard_core::rusqlite::Connection;
use secureguard_core::blocked_domain::{ BlockedDomain, MAX_BLOCKED_DOMAINS };
use secureguard_core::dir_scan::{ self, Progress, ScanOptions, ScanReport };
use secureguard_core::hash_match::SignatureSet;
use secureguard_core::signature_sync::{ self, SyncResult };
use secureguard_core::storage;
use secureguard_core::types::ScanResult;
use crate::scan_control::ScanControl;
use secureguard_core::yara_scan::RuleSet;
use secureguard_core::DEFAULT_RULES;
use std::path::PathBuf;
use std::sync::{ Arc, Mutex };
use tauri::{ AppHandle, Emitter, Manager };

/// Shared app state, initialized once at startup, not per command call. The
/// CLI reopens its DB and recompiles the rule set on every invocation,
/// fine for a short-lived process, wasteful here. `signatures` is a Mutex
/// around an `Arc` snapshot so `do_sync` can swap in a new set after a
/// successful sync (a scan run right after a sync must see the newly learned
/// hashes without restarting the app) while scans never hold the lock: they
/// clone the `Arc` under a momentary lock and scan against that snapshot.
///
/// Lock discipline: no code path holds `conn` and `signatures` at the same
/// time. That is what rules out a lock-order deadlock between `do_scan` and
/// `do_sync`; keep it that way when adding code here.
pub struct AppState {
    pub conn: Mutex<Connection>,
    pub rules: RuleSet,
    pub signatures: Mutex<Arc<SignatureSet>>,
    /// The one running scan, if any. Its lock is never held together with
    /// `conn` or `signatures`, or across a scan.
    pub scan: ScanControl,
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
            signatures: Mutex::new(Arc::new(signatures)),
            scan: ScanControl::new(),
        })
    }
}

// --- Plain functions: the actual logic, testable directly, no Tauri types ---

/// Clones the current signature snapshot and releases the lock immediately,
/// so the caller scans without holding it.
fn snapshot_signatures(state: &AppState) -> Result<Arc<SignatureSet>, String> {
    state.signatures
        .lock()
        .map(|guard| Arc::clone(&guard))
        .map_err(|_| "signature set lock poisoned".to_string())
}

pub fn do_scan(state: &AppState, path: &str) -> Result<ScanResult, String> {
    let signatures = snapshot_signatures(state)?;

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

/// Scans `roots` as one run, one scan at a time. Takes one signature snapshot
/// (a momentary lock), scans without holding any lock, then records the
/// non-clean results in one transaction. A scan that was cancelled or hit the
/// findings cap records what it found. A failure to record history is logged,
/// not fatal, as in `do_scan`.
pub fn do_scan_roots(
    state: &AppState,
    roots: Vec<PathBuf>,
    opts: ScanOptions,
    on_progress: &mut dyn FnMut(&Progress)
) -> Result<ScanReport, String> {
    let guard = state.scan.start()?;
    let signatures = snapshot_signatures(state)?;

    let report = dir_scan::scan_roots(
        &roots,
        &opts,
        &signatures,
        &state.rules,
        guard.cancel_flag(),
        on_progress
    );

    let results: Vec<ScanResult> = report.findings
        .iter()
        .map(|finding| finding.result.clone())
        .collect();
    match state.conn.lock() {
        Ok(conn) => {
            if let Err(e) = storage::record_scans(&conn, &results) {
                eprintln!("warning: failed to record scan to history: {e}");
            }
        }
        Err(_) => eprintln!("warning: database lock poisoned, scan history not recorded"),
    }

    Ok(report)
}

/// A folder the user chose. Anything that is not an existing folder is an
/// error here (the core would otherwise report one unreadable folder).
pub fn do_scan_folder(
    state: &AppState,
    path: &str,
    recursive: bool,
    on_progress: &mut dyn FnMut(&Progress)
) -> Result<ScanReport, String> {
    let root = PathBuf::from(path);
    if !root.is_dir() {
        return Err(format!("Not a folder: {path}"));
    }
    do_scan_roots(state, vec![root], ScanOptions::directory(recursive), on_progress)
}

/// A scan of a computed list of folders. An empty list is an error with the
/// message the caller gives, as the CLI does, instead of a scan of nothing.
fn do_scan_listed(
    state: &AppState,
    roots: Vec<PathBuf>,
    opts: ScanOptions,
    empty_error: &str,
    on_progress: &mut dyn FnMut(&Progress)
) -> Result<ScanReport, String> {
    if roots.is_empty() {
        return Err(empty_error.to_string());
    }
    do_scan_roots(state, roots, opts, on_progress)
}

pub fn do_scan_quick(
    state: &AppState,
    on_progress: &mut dyn FnMut(&Progress)
) -> Result<ScanReport, String> {
    do_scan_listed(
        state,
        dir_scan::quick_scan_roots(),
        ScanOptions::quick(),
        "No standard folders were found to scan.",
        on_progress
    )
}

pub fn do_scan_full(
    state: &AppState,
    on_progress: &mut dyn FnMut(&Progress)
) -> Result<ScanReport, String> {
    do_scan_listed(
        state,
        dir_scan::full_scan_roots(),
        ScanOptions::full(),
        "No folders were found to scan.",
        on_progress
    )
}

/// True while a scan is running: the window must not just close, because the
/// scan and its results would be lost without the user agreeing to that.
pub fn close_is_blocked(state: &AppState) -> bool {
    state.scan.is_running()
}

pub fn do_recent_scans(state: &AppState, limit: i64) -> Result<Vec<ScanResult>, String> {
    let conn = state.conn.lock().map_err(|_| "database lock poisoned".to_string())?;
    storage::recent_scans(&conn, limit).map_err(|e| format!("failed to load history: {e}"))
}

pub fn do_sync(state: &AppState) -> Result<SyncResult, String> {
    // The database lock is released at the end of this block, before the
    // signature lock is taken below, so this function never holds both.
    let (result, refreshed) = {
        let conn = state.conn.lock().map_err(|_| "database lock poisoned".to_string())?;

        let result = signature_sync
            ::sync_signatures(&[signature_sync::DEFAULT_FEED_URL], &conn)
            .map_err(|e| format!("sync failed: {e}"))?;

        // Reload in-memory signatures so a scan run immediately after this
        // sync sees the newly learned hashes, not just on next app restart.
        let refreshed = SignatureSet::load_from_cache(&conn).map_err(|e|
            format!("sync succeeded but reloading signatures failed: {e}")
        )?;
        (result, Arc::new(refreshed))
    };

    *state.signatures.lock().map_err(|_| "signature set lock poisoned".to_string())? = refreshed;

    Ok(result)
}

/// DB-only, no IPC to the helper, so it's directly testable. Returns the
/// new full active list so the caller (the Tauri command) knows exactly
/// what to send the helper next, rather than re-querying.
/// Checks and normalizes what the user typed (trims, lowercases, drops one
/// trailing dot). Only names that pass can be blocked, so the list that
/// reaches the helper holds nothing that could add or change another hosts
/// entry. The helper checks again on its side; this just gives the user the
/// reason straight away.
pub fn normalize_domain(input: &str) -> Result<String, String> {
    BlockedDomain::parse(input.trim())
        .map(|d| d.as_str().to_string())
        .map_err(|e| format!("not a valid domain name: {e}"))
}

/// Refuses a new entry once the list is at its limit. Re-blocking a name that
/// is already on the list is always fine.
fn check_capacity(current_len: usize, already_present: bool) -> Result<(), String> {
    if current_len >= MAX_BLOCKED_DOMAINS && !already_present {
        return Err(format!("the blocklist is full ({MAX_BLOCKED_DOMAINS} domains)"));
    }
    Ok(())
}

pub fn do_block_domain(
    state: &AppState,
    domain: &str,
    reason: Option<&str>
) -> Result<Vec<String>, String> {
    let domain = normalize_domain(domain)?;
    let conn = state.conn.lock().map_err(|_| "database lock poisoned".to_string())?;

    let current = storage
        ::list_blocked_domains(&conn)
        .map_err(|e| format!("failed to list blocked domains: {e}"))?;
    check_capacity(current.len(), current.iter().any(|d| d == &domain))?;

    storage
        ::add_blocked_domain(&conn, &domain, reason)
        .map_err(|e| format!("failed to record blocked domain: {e}"))?;
    storage::list_blocked_domains(&conn).map_err(|e| format!("failed to list blocked domains: {e}"))
}

/// Puts a name back exactly as it was, without validating it. Used only to
/// undo an unblock when the helper fails: the entry was on the list before,
/// and an older entry that would not pass today's checks must not be lost
/// just because the helper happened to be unreachable.
fn restore_blocked_domain(state: &AppState, domain: &str) {
    if let Ok(conn) = state.conn.lock() {
        let _ = storage::add_blocked_domain(&conn, domain, None);
    }
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

// --- Thin Tauri command wrappers, the only place Tauri types are touched ---

/// Runs `work` against the managed `AppState` on Tauri's blocking thread
/// pool, so a slow database call, a network fetch or a file scan never runs
/// on, or queues behind, the main thread. The `AppHandle` is moved into the
/// closure because blocking work needs an owned, `'static` handle, not the
/// borrowed `State` a plain command would take.
async fn run_blocking<T, F>(app: AppHandle, label: &'static str, work: F) -> Result<T, String>
    where F: FnOnce(&AppState) -> Result<T, String> + Send + 'static, T: Send + 'static
{
    tauri::async_runtime
        ::spawn_blocking(move || {
            let state = app.state::<AppState>();
            work(&state)
        })
        .await
        .map_err(|e| format!("{label} task failed: {e}"))?
}

#[tauri::command]
pub async fn scan_file_cmd(app: AppHandle, path: String) -> Result<ScanResult, String> {
    run_blocking(app, "scan", move |state| do_scan(state, &path)).await
}

/// Runs a scan on the blocking pool and sends each progress report to the
/// window as a `scan-progress` event. A failed send is ignored: the scan
/// still finishes and its report is returned to the caller.
async fn run_scan<F>(app: AppHandle, label: &'static str, scan: F) -> Result<ScanReport, String>
    where F: FnOnce(&AppState, &mut dyn FnMut(&Progress)) -> Result<ScanReport, String> + Send + 'static
{
    let emitter = app.clone();
    run_blocking(app, label, move |state| {
        scan(state, &mut |progress| {
            let _ = emitter.emit("scan-progress", progress);
        })
    }).await
}

#[tauri::command]
pub async fn scan_folder_cmd(
    app: AppHandle,
    path: String,
    recursive: bool
) -> Result<ScanReport, String> {
    run_scan(app, "folder scan", move |state, on_progress| {
        do_scan_folder(state, &path, recursive, on_progress)
    }).await
}

#[tauri::command]
pub async fn scan_quick_cmd(app: AppHandle) -> Result<ScanReport, String> {
    run_scan(app, "quick scan", do_scan_quick).await
}

#[tauri::command]
pub async fn scan_full_cmd(app: AppHandle) -> Result<ScanReport, String> {
    run_scan(app, "full scan", do_scan_full).await
}

/// Asks the running scan to stop. True if a scan was running. Only an atomic
/// flag and a momentary lock, so a plain command is fine here.
#[tauri::command]
pub fn cancel_scan_cmd(state: tauri::State<AppState>) -> bool {
    state.scan.cancel()
}

/// Ends the app. The page calls this after the user agrees to cancel a
/// running scan and exit.
#[tauri::command]
pub fn exit_app_cmd(app: AppHandle) {
    app.exit(0);
}

#[tauri::command]
pub async fn recent_scans_cmd(app: AppHandle, limit: i64) -> Result<Vec<ScanResult>, String> {
    run_blocking(app, "history", move |state| do_recent_scans(state, limit)).await
}

#[tauri::command]
pub async fn sync_signatures_cmd(app: AppHandle) -> Result<SyncResult, String> {
    run_blocking(app, "sync", do_sync).await
}

/// Unlike the other commands, this one's DB step (do_block_domain) and its
/// IPC step (sending the updated list to the helper) are deliberately
/// separate calls here, not both inside one testable "do_" function, since
/// the IPC step can't be safely exercised in a unit test against the real
/// hosts file. On a helper failure, the DB insert is rolled back so local
/// state doesn't claim a domain is blocked when it demonstrably isn't.
#[tauri::command]
pub async fn block_domain_cmd(
    app: AppHandle,
    domain: String,
    reason: Option<String>
) -> Result<(), String> {
    run_blocking(app, "block domain", move |state| {
        // Normalize once up front: the rollback below must remove the same
        // string that was stored, not the raw text the user typed.
        let domain = normalize_domain(&domain)?;
        let active = do_block_domain(state, &domain, reason.as_deref())?;

        match crate::helper_client::send_domain_list(&active) {
            Ok(response) if response.success => Ok(()),
            Ok(response) => {
                let _ = do_unblock_domain(state, &domain); // roll back, it isn't actually blocked
                Err(response.error.unwrap_or_else(|| "helper reported failure".to_string()))
            }
            Err(e) => {
                let _ = do_unblock_domain(state, &domain);
                Err(e)
            }
        }
    }).await
}

#[tauri::command]
pub async fn unblock_domain_cmd(app: AppHandle, domain: String) -> Result<(), String> {
    run_blocking(app, "unblock domain", move |state| {
        // Need the domain's prior reason to roll back accurately; simplest
        // correct approach is re-adding without a reason on rollback, losing
        // the original reason string in that specific failure case is an
        // acceptable tradeoff, the domain still ends up correctly re-blocked.
        let active = do_unblock_domain(state, &domain)?;

        match crate::helper_client::send_domain_list(&active) {
            Ok(response) if response.success => Ok(()),
            Ok(response) => {
                restore_blocked_domain(state, &domain);
                Err(response.error.unwrap_or_else(|| "helper reported failure".to_string()))
            }
            Err(e) => {
                restore_blocked_domain(state, &domain);
                Err(e)
            }
        }
    }).await
}

#[tauri::command]
pub async fn list_blocked_domains_cmd(app: AppHandle) -> Result<Vec<String>, String> {
    run_blocking(app, "list blocked domains", do_list_blocked_domains).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use secureguard_core::dir_scan::StopReason;
    use std::io::Write;
    use std::time::Duration;

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

    /// Regression test for a lock-order inversion. do_scan used to hold the
    /// signatures lock while it waited for the database lock, while do_sync
    /// takes them the other way round, so a scan racing a sync could
    /// deadlock. Simulates a sync in progress by holding the database lock,
    /// starts a scan, and checks the scan is not sitting on the signatures
    /// lock while it waits. The sleep can only make this test pass too early,
    /// never fail wrongly.
    #[test]
    fn do_scan_does_not_hold_the_signature_lock_while_waiting_for_the_database() {
        let (state, dir) = test_state();
        let file_path = dir.path().join("clean.txt");
        std::fs::write(&file_path, b"an entirely ordinary file").unwrap();
        let state = Arc::new(state);

        let db_guard = state.conn.lock().unwrap();

        let scanner_state = Arc::clone(&state);
        let path = file_path.to_string_lossy().to_string();
        let scanner = std::thread::spawn(move || do_scan(&scanner_state, &path));

        std::thread::sleep(std::time::Duration::from_millis(500));
        assert!(
            state.signatures.try_lock().is_ok(),
            "do_scan is holding the signatures lock while waiting for the database lock"
        );

        drop(db_guard);
        let result = scanner.join().unwrap().unwrap();
        assert_eq!(result.verdict, secureguard_core::types::Verdict::Clean);
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
    fn do_block_domain_normalizes_what_the_user_typed() {
        let (state, _dir) = test_state();
        let active = do_block_domain(&state, "  Malware.Example.COM. ", None).unwrap();
        assert_eq!(active, vec!["malware.example.com"]);
    }

    #[test]
    fn do_block_domain_rejects_injection_and_stores_nothing() {
        let (state, _dir) = test_state();
        for bad in [
            "ok.example.com\n93.184.216.34 bank.example",
            "evil.example.com # x",
            "localhost",
            "127.0.0.1",
            "",
            "exa mple.com",
        ] {
            let error = do_block_domain(&state, bad, None).unwrap_err();
            assert!(error.starts_with("not a valid domain name"), "{bad:?}: {error}");
        }
        assert!(do_list_blocked_domains(&state).unwrap().is_empty());
    }

    #[test]
    fn a_full_blocklist_refuses_new_names_but_not_ones_already_on_it() {
        assert!(check_capacity(MAX_BLOCKED_DOMAINS - 1, false).is_ok());
        assert!(check_capacity(MAX_BLOCKED_DOMAINS, false).is_err());
        assert!(check_capacity(MAX_BLOCKED_DOMAINS, true).is_ok());
    }

    #[test]
    fn an_older_entry_that_fails_todays_checks_can_still_be_removed_and_restored() {
        let (state, _dir) = test_state();
        {
            let conn = state.conn.lock().unwrap();
            storage::add_blocked_domain(&conn, "Legacy Entry", None).unwrap();
        }
        assert_eq!(do_list_blocked_domains(&state).unwrap(), vec!["Legacy Entry"]);

        let after = do_unblock_domain(&state, "Legacy Entry").unwrap();
        assert!(after.is_empty());

        restore_blocked_domain(&state, "Legacy Entry");
        assert_eq!(do_list_blocked_domains(&state).unwrap(), vec!["Legacy Entry"]);
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

    // --- scans of many files (5.2b) ---

    /// A folder inside the temp directory holding a Malicious file (a
    /// `.locked` file, because Windows Defender blocks the EICAR string on
    /// disk) and a clean one.
    fn folder_with_one_bad_and_one_clean_file(dir: &tempfile::TempDir) -> PathBuf {
        let target = dir.path().join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("bad.locked"), b"x").unwrap();
        std::fs::write(target.join("ok.txt"), b"fine").unwrap();
        target
    }

    /// One worker and a progress report on every step, so tests that count
    /// exactly (cancel after the first finding) are deterministic.
    fn every_step() -> ScanOptions {
        ScanOptions {
            min_progress_interval: Duration::ZERO,
            workers: 1,
            ..ScanOptions::directory(true)
        }
    }

    #[test]
    fn a_second_scan_is_refused_while_one_is_running() {
        let (state, dir) = test_state();
        let target = folder_with_one_bad_and_one_clean_file(&dir);
        let _running = state.scan.start().unwrap();

        let error = do_scan_folder(&state, &target.to_string_lossy(), true, &mut |_| {}).unwrap_err();
        assert!(error.contains("already running"), "{error}");
    }

    #[test]
    fn a_folder_scan_records_only_non_clean_results_in_history() {
        let (state, dir) = test_state();
        let target = folder_with_one_bad_and_one_clean_file(&dir);

        let report = do_scan_folder(&state, &target.to_string_lossy(), true, &mut |_| {}).unwrap();
        assert_eq!(report.scanned, 2);
        assert_eq!(report.malicious, 1);
        assert!(!state.scan.is_running(), "the session must be cleared when the scan ends");

        let history = do_recent_scans(&state, 10).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].file_name, "bad.locked");
    }

    #[test]
    fn a_folder_that_does_not_exist_is_an_error() {
        let (state, dir) = test_state();
        let missing = dir.path().join("nope");
        let error = do_scan_folder(&state, &missing.to_string_lossy(), true, &mut |_| {}).unwrap_err();
        assert!(error.starts_with("Not a folder"), "{error}");

        let file = dir.path().join("a_file.txt");
        std::fs::write(&file, b"x").unwrap();
        let error = do_scan_folder(&state, &file.to_string_lossy(), true, &mut |_| {}).unwrap_err();
        assert!(error.starts_with("Not a folder"), "{error}");
        assert!(!state.scan.is_running());
    }

    #[test]
    fn progress_reaches_the_callback_and_carries_the_findings() {
        let (state, dir) = test_state();
        let target = folder_with_one_bad_and_one_clean_file(&dir);

        let mut calls = 0;
        let mut announced: Vec<String> = Vec::new();
        let report = do_scan_roots(&state, vec![target], every_step(), &mut |p| {
            calls += 1;
            announced.extend(p.new_findings.iter().map(|f| f.path.clone()));
        }).unwrap();

        let in_report: Vec<String> = report.findings.iter().map(|f| f.path.clone()).collect();
        assert!(calls > 0);
        assert_eq!(announced, in_report);
        assert_eq!(in_report.len(), 1);
    }

    #[test]
    fn a_cancelled_scan_ends_with_the_cancelled_reason_and_clears_the_session() {
        let (state, dir) = test_state();
        let target = dir.path().join("many");
        std::fs::create_dir_all(&target).unwrap();
        for i in 0..5 {
            std::fs::write(target.join(format!("f{i}.txt")), b"x").unwrap();
        }

        let report = do_scan_roots(&state, vec![target], every_step(), &mut |_| {
            state.scan.cancel();
        }).unwrap();

        assert_eq!(report.stop_reason, StopReason::Cancelled);
        assert!(report.scanned < 5, "scanned {}", report.scanned);
        assert!(!state.scan.is_running());
        assert!(state.scan.start().is_ok(), "a new scan can start after a cancelled one");
    }

    #[test]
    fn a_cancelled_scan_still_records_what_it_found() {
        let (state, dir) = test_state();
        let target = dir.path().join("many_bad");
        std::fs::create_dir_all(&target).unwrap();
        for i in 0..4 {
            std::fs::write(target.join(format!("bad{i}.locked")), b"x").unwrap();
        }

        let report = do_scan_roots(&state, vec![target], every_step(), &mut |p| {
            if p.findings >= 1 {
                state.scan.cancel();
            }
        }).unwrap();

        assert_eq!(report.stop_reason, StopReason::Cancelled);
        assert!(!report.findings.is_empty());
        assert_eq!(do_recent_scans(&state, 100).unwrap().len(), report.findings.len());
    }

    #[test]
    fn an_empty_list_of_folders_is_an_error_and_starts_no_scan() {
        let (state, _dir) = test_state();
        let error = do_scan_listed(
            &state,
            Vec::new(),
            ScanOptions::quick(),
            "No standard folders were found to scan.",
            &mut |_| {}
        ).unwrap_err();
        assert_eq!(error, "No standard folders were found to scan.");
        assert!(!state.scan.is_running());
    }

    #[test]
    fn closing_the_window_is_blocked_only_while_a_scan_runs() {
        let (state, _dir) = test_state();
        assert!(!close_is_blocked(&state));
        {
            let _running = state.scan.start().unwrap();
            assert!(close_is_blocked(&state));
        }
        assert!(!close_is_blocked(&state));
    }
}
