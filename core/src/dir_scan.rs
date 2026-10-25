//! Directory and system scan engine.
//!
//! Walks a folder (or every fixed drive) and scores each regular file with the
//! same engine `scan_file` uses. It is a plain library function: it takes a
//! cancel flag and a progress callback and returns a [`ScanReport`], so the
//! desktop app, the CLI and the tests all drive the same code.
//!
//! Ported from `SecurityServiceImpl.scanDirectory` / `performSystemScan`, with
//! these deliberate differences (docs/phase5-2-5-3-design-plan.md):
//!
//! - The 2,000 cap applies to findings kept, not files scanned (Java counts
//!   clean files too, so its system scan effectively stops after 2,000 files).
//! - System folders are skipped by whole name, and only directly under a
//!   filesystem root. Java matches a substring of the full path, so a project
//!   folder named `windows` anywhere would be skipped.
//! - A folder the caller chose explicitly is never skipped, even if it is
//!   named like a system folder. (An exclusion that silently emptied a scan
//!   has bitten this project before.)
//! - Symlinks and junctions are not followed, and only regular files are
//!   read, so a link loop cannot hang a scan and a device file cannot block it.
//! - Each folder is listed once and its ransomware-behavior score is computed
//!   once, not once per file.
//!
//! Only non-clean results are kept; counts cover everything. Paths in the
//! report are `String`s (lossy), because serde refuses to serialize a path that
//! is not valid Unicode and one odd filename must not lose a whole report.

use crate::dir_behavior;
use crate::hash_match::{ sha256_hex, SignatureSet };
use crate::rootkit;
use crate::scoring;
use crate::types::{ ScanResult, Verdict };
use crate::yara_scan::RuleSet;
use serde::{ Deserialize, Serialize };
use sha2::{ Digest, Sha256 };
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{ Path, PathBuf };
use std::sync::atomic::{ AtomicBool, Ordering };
use std::sync::mpsc::{ self, Receiver, Sender, SyncSender, TrySendError };
use std::sync::{ Condvar, Mutex };
use std::time::{ Duration, Instant };

/// Files larger than this are counted, not scanned. Matches the Java engine.
pub const MAX_FILE_BYTES: u64 = 100 * 1024 * 1024;
/// How long a system scan may run. Matches the Java engine.
pub const SYSTEM_SCAN_MAX_DURATION: Duration = Duration::from_secs(5 * 60);
/// How long a quick scan may run.
pub const QUICK_SCAN_MAX_DURATION: Duration = Duration::from_secs(5 * 60);
/// Most findings kept in a report.
pub const MAX_FINDINGS: usize = 2_000;
/// Progress callbacks are at most this often unless the caller asks otherwise.
pub const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
/// Most results remembered for reuse in one scan (about 50 bytes each).
pub const MAX_REUSABLE_RESULTS: usize = 500_000;
/// Most bytes of file content all scan threads hold in memory at once.
pub const IN_FLIGHT_BYTES_LIMIT: u64 = 256 * 1024 * 1024;
/// Most scan threads used by default, however many cores there are.
pub const MAX_DEFAULT_WORKERS: usize = 8;

/// Half the cores (the machine stays usable while scanning), between 1 and 8.
pub fn default_workers() -> usize {
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    (cores / 2).clamp(1, MAX_DEFAULT_WORKERS)
}

#[derive(Debug, Clone)]
pub struct ScanLimits {
    pub max_file_bytes: u64,
    /// None means no time limit (a folder the user chose; they can cancel).
    pub max_duration: Option<Duration>,
    /// At least 1. The scan stops once this many findings are kept.
    pub max_findings: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self { max_file_bytes: MAX_FILE_BYTES, max_duration: None, max_findings: MAX_FINDINGS }
    }
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub recursive: bool,
    pub limits: ScanLimits,
    pub min_progress_interval: Duration,
    /// Reuse the verdict for a file that is identical (same bytes, same name,
    /// same folder score) to one already scanned in this run, instead of
    /// running every check again. Copies of the same library, extension or
    /// package are common; this skips the expensive part of scanning them.
    pub reuse_identical_results: bool,
    /// Scan threads. 0 or 1 scans on the calling thread, with no extra threads.
    /// With more, the calling thread walks folders and reports progress, and
    /// this many workers read and score files. The report is the same either
    /// way, apart from `reused_results`, which can be lower in parallel when
    /// two copies of a file are scanned at the same moment, and the counts at a
    /// findings cap, which can include a few more files than a sequential scan
    /// (the findings kept are the same).
    pub workers: usize,
}

impl ScanOptions {
    /// A folder the user chose.
    pub fn directory(recursive: bool) -> Self {
        Self {
            recursive,
            limits: ScanLimits::default(),
            min_progress_interval: PROGRESS_INTERVAL,
            reuse_identical_results: true,
            workers: default_workers(),
        }
    }

    /// The places malware usually lands first (see [`quick_scan_roots`]), with a
    /// 5-minute budget.
    pub fn quick() -> Self {
        Self {
            limits: ScanLimits {
                max_duration: Some(QUICK_SCAN_MAX_DURATION),
                ..ScanLimits::default()
            },
            ..Self::directory(true)
        }
    }

    /// Everything, with no time limit: the quick-scan places first, then every
    /// fixed drive (see [`full_scan_roots`]). It runs until it is done or the
    /// caller cancels.
    pub fn full() -> Self {
        Self::directory(true)
    }

    /// Every fixed drive, with the 5-minute budget.
    pub fn system() -> Self {
        Self {
            recursive: true,
            limits: ScanLimits {
                max_duration: Some(SYSTEM_SCAN_MAX_DURATION),
                ..ScanLimits::default()
            },
            min_progress_interval: PROGRESS_INTERVAL,
            reuse_identical_results: true,
            workers: default_workers(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Completed,
    Cancelled,
    TimeBudget,
    FindingsCap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFinding {
    pub path: String,
    pub result: ScanResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// Suspicious and malicious files only, in the order they were found.
    pub findings: Vec<FileFinding>,
    pub scanned: u64,
    pub clean: u64,
    pub suspicious: u64,
    pub malicious: u64,
    /// Files skipped by name, and system folders skipped whole. A skipped
    /// folder counts once; what is inside it is not counted.
    pub skipped_excluded: u64,
    pub skipped_too_large: u64,
    /// Symlinks, junctions and anything that is not a regular file or folder.
    pub skipped_links_or_special: u64,
    pub unreadable_files: u64,
    pub unreadable_dirs: u64,
    /// Files whose result was reused from an identical file scanned earlier in
    /// this run. They are included in `scanned` and the verdict counts.
    #[serde(default)]
    pub reused_results: u64,
    pub stop_reason: StopReason,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Progress {
    pub current_dir: String,
    pub scanned: u64,
    pub findings: u64,
}

#[cfg(windows)]
const SYSTEM_DIR_NAMES: &[&str] = &[
    "windows",
    "program files",
    "program files (x86)",
    "programdata",
    "$recycle.bin",
    "system volume information",
    "recovery",
    "config.msi",
    "documents and settings",
];
#[cfg(not(windows))]
const SYSTEM_DIR_NAMES: &[&str] = &["proc", "sys", "dev", "run"];

/// Hidden files and a short list of known noise. Names only: folders are
/// handled by the system-folder rule.
fn is_file_excluded(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.starts_with('.') || lower == "thumbs.db" || lower == "desktop.ini"
}

fn is_volume_root(path: &Path) -> bool {
    path.parent().is_none()
}

fn is_system_dir_name(name: &str, names: &[&str]) -> bool {
    let lower = name.to_lowercase();
    names.iter().any(|n| *n == lower)
}

/// The roots a system scan covers. Windows: fixed drives only, because probing
/// a disconnected network drive can hang. Elsewhere: `/`.
pub fn system_roots() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        windows_fixed_drives()
    }
    #[cfg(not(windows))]
    {
        vec![PathBuf::from("/")]
    }
}

/// The places malware usually lands first, in the order to scan them: Downloads,
/// Desktop, Documents, the temp folder and the startup folders. Only folders
/// that exist are returned. A quick scan covers these; a full scan scans them
/// first and then everything else, so a scan that is cancelled early has still
/// checked the likeliest places.
pub fn quick_scan_roots() -> Vec<PathBuf> {
    quick_roots_from(cfg!(windows), &|name| std::env::var_os(name), &|path| path.is_dir())
}

/// [`quick_scan_roots`] followed by [`system_roots`], without repeats.
pub fn full_scan_roots() -> Vec<PathBuf> {
    combine_roots(quick_scan_roots(), system_roots())
}

fn combine_roots(first: Vec<PathBuf>, then: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut roots = first;
    for root in then {
        if !roots.iter().any(|existing| same_path(existing, &root)) {
            roots.push(root);
        }
    }
    roots
}

/// The list, with the platform and the environment injected so both platforms'
/// lists can be tested anywhere.
fn quick_roots_from(
    windows: bool,
    env: &dyn Fn(&str) -> Option<OsString>,
    is_dir: &dyn Fn(&Path) -> bool
) -> Vec<PathBuf> {
    let var = |name: &str| env(name).filter(|value| !value.is_empty()).map(PathBuf::from);

    let mut candidates: Vec<PathBuf> = Vec::new();
    if windows {
        if let Some(profile) = var("USERPROFILE") {
            candidates.push(profile.join("Downloads"));
            candidates.push(profile.join("Desktop"));
            candidates.push(profile.join("Documents"));
        }
        if let Some(temp) = var("TEMP") {
            candidates.push(temp);
        }
        if let Some(local) = var("LOCALAPPDATA") {
            candidates.push(local.join("Temp"));
        }
        if let Some(roaming) = var("APPDATA") {
            candidates.push(roaming.join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
        }
        if let Some(shared) = var("PROGRAMDATA") {
            candidates.push(shared.join(r"Microsoft\Windows\Start Menu\Programs\StartUp"));
        }
    } else {
        if let Some(home) = var("HOME") {
            candidates.push(home.join("Downloads"));
            candidates.push(home.join("Desktop"));
            candidates.push(home.join("Documents"));
        }
        candidates.push(var("TMPDIR").unwrap_or_else(|| PathBuf::from("/tmp")));
        if let Some(home) = var("HOME") {
            candidates.push(home.join(".config/autostart"));
            candidates.push(home.join("Library/LaunchAgents"));
        }
    }

    let mut roots: Vec<PathBuf> = Vec::new();
    for candidate in candidates {
        if is_dir(&candidate) && !roots.iter().any(|existing| same_path(existing, &candidate)) {
            roots.push(candidate);
        }
    }
    roots
}

/// Path equality for "have we scanned this already". Compared component by
/// component, so the separator style (slash or backslash) and a trailing separator
/// do not matter. On Windows the comparison is also case-insensitive, like the file
/// system.
fn same_path(a: &Path, b: &Path) -> bool {
    if cfg!(windows) {
        let lowered = |path: &Path| -> Vec<String> {
            path.components()
                .map(|part| part.as_os_str().to_string_lossy().to_ascii_lowercase())
                .collect()
        };
        lowered(a) == lowered(b)
    } else {
        a == b
    }
}

#[cfg(windows)]
fn windows_fixed_drives() -> Vec<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{ GetDriveTypeW, GetLogicalDrives };

    // Documented value of DRIVE_FIXED (it lives in a different windows-sys
    // feature, not worth enabling for one constant).
    const DRIVE_FIXED: u32 = 3;

    // SAFETY: GetLogicalDrives takes no arguments and only returns a bit mask.
    let mask = unsafe { GetLogicalDrives() };
    (0..26u32)
        .filter(|bit| mask & (1 << bit) != 0)
        .filter_map(|bit| {
            let root = format!("{}:\\", (b'A' + (bit as u8)) as char);
            let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call.
            let kind = unsafe { GetDriveTypeW(wide.as_ptr()) };
            (kind == DRIVE_FIXED).then(|| PathBuf::from(root))
        })
        .collect()
}

/// Scans one folder, or one file's folder tree, as the user chose it.
pub fn scan_path(
    root: &Path,
    opts: &ScanOptions,
    signatures: &SignatureSet,
    rules: &RuleSet,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(&Progress)
) -> ScanReport {
    scan_roots(&[root.to_path_buf()], opts, signatures, rules, cancel, on_progress)
}

/// Scans several roots as one run: one time budget, one findings cap, one report.
pub fn scan_roots(
    roots: &[PathBuf],
    opts: &ScanOptions,
    signatures: &SignatureSet,
    rules: &RuleSet,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(&Progress)
) -> ScanReport {
    scan_roots_with(roots, opts, signatures, rules, cancel, on_progress, &is_volume_root, SYSTEM_DIR_NAMES)
}

/// The walker, with the two platform rules injectable so tests can exercise
/// them inside a temporary folder instead of a real drive root.
#[allow(clippy::too_many_arguments)]
fn scan_roots_with(
    roots: &[PathBuf],
    opts: &ScanOptions,
    signatures: &SignatureSet,
    rules: &RuleSet,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(&Progress),
    is_volume_root: &dyn Fn(&Path) -> bool,
    system_dir_names: &[&str]
) -> ScanReport {
    let shared = Shared {
        signatures,
        rules,
        max_file_bytes: opts.limits.max_file_bytes,
        reuse: opts.reuse_identical_results,
        cache: Mutex::new(ResultCache::new(MAX_REUSABLE_RESULTS)),
    };
    let workers = opts.workers;

    if workers <= 1 {
        let mut run = Run::new(opts, &shared, cancel, on_progress, is_volume_root, system_dir_names, None);
        run.walk_roots(roots);
        return run.finish();
    }

    // The walker (this thread) lists folders and queues files; workers read and
    // score them. They share nothing mutable except through the channels and
    // the result cache's mutex. Everything that reports (progress, counts,
    // findings, cancel and time checks) stays on this thread.
    // Declared outside the scope: the worker threads borrow them, so they must
    // outlive it.
    let (job_tx, job_rx) = mpsc::sync_channel::<Job>(workers * 2);
    let job_rx = Mutex::new(job_rx);
    let stop = AtomicBool::new(false);
    let budget = ByteBudget::new(IN_FLIGHT_BYTES_LIMIT);

    std::thread::scope(|scope| {
        let (done_tx, done_rx) = mpsc::channel::<Done>();

        for _ in 0..workers {
            let done_tx = done_tx.clone();
            let (shared, job_rx, stop, budget) = (&shared, &job_rx, &stop, &budget);
            scope.spawn(move || worker_loop(job_rx, &done_tx, shared, stop, budget));
        }
        drop(done_tx);

        let pool = Pool { job_tx: Some(job_tx), done_rx, in_flight: 0, stop: &stop };
        let mut run = Run::new(
            opts,
            &shared,
            cancel,
            on_progress,
            is_volume_root,
            system_dir_names,
            Some(pool)
        );
        run.walk_roots(roots);
        run.finish()
    })
}

/// What every scan thread needs. Read-only except the result cache.
struct Shared<'a> {
    signatures: &'a SignatureSet,
    rules: &'a RuleSet,
    max_file_bytes: u64,
    reuse: bool,
    cache: Mutex<ResultCache>,
}

// The rules and signatures are shared by reference across scan threads. If a
// future dependency version makes either type non-Sync, this fails to compile
// here instead of somewhere less obvious.
const _: fn() = || {
    fn assert_sync<T: Sync>() {}
    assert_sync::<RuleSet>();
    assert_sync::<SignatureSet>();
};

/// One file for a worker: everything but its bytes, which the worker reads.
struct Job {
    seq: u64,
    path: PathBuf,
    name: String,
    dir_score: i32,
    size: u64,
}

enum Outcome {
    Clean { reused: bool },
    Flagged { result: ScanResult, reused: bool },
    /// Grew past the size limit after the walker checked it.
    TooLarge,
    Unreadable,
    /// Queued but dropped because the scan was stopping.
    Skipped,
}

struct Done {
    seq: u64,
    path: PathBuf,
    outcome: Outcome,
}

/// Reads, hashes and scores one file. Runs on the calling thread when
/// `workers` is 1, on a worker thread otherwise.
fn scan_job(job: &Job, ctx: &Shared) -> Outcome {
    let content = match read_bounded(&job.path, ctx.max_file_bytes) {
        Ok(Some(content)) => content,
        Ok(None) => {
            return Outcome::TooLarge;
        }
        Err(_) => {
            return Outcome::Unreadable;
        }
    };

    let sha256 = sha256_hex(&content);
    let key = ctx.reuse.then(||
        result_key(&sha256, &job.name, rootkit::in_rootkit_location(&job.path), job.dir_score)
    );

    if let Some(key) = key {
        let cached = ctx.cache.lock().expect("result cache lock poisoned").get(key);
        match cached {
            Some(Cached::Clean) => {
                return Outcome::Clean { reused: true };
            }
            Some(Cached::Flagged(result)) => {
                return Outcome::Flagged { result, reused: true };
            }
            None => {}
        }
    }

    let result = scoring::score_file_in_directory_with_hash(
        &job.name,
        &content,
        ctx.signatures,
        ctx.rules,
        &job.path,
        job.dir_score,
        &sha256
    );

    if let Some(key) = key {
        let outcome = if result.verdict == Verdict::Clean {
            Cached::Clean
        } else {
            Cached::Flagged(result.clone())
        };
        ctx.cache.lock().expect("result cache lock poisoned").put(key, outcome);
    }

    if result.verdict == Verdict::Clean {
        Outcome::Clean { reused: false }
    } else {
        Outcome::Flagged { result, reused: false }
    }
}

/// Caps the bytes of file content held in memory by all workers at once: each
/// worker reads a whole file, up to 100 MB, so without this eight workers could
/// hold 800 MB. A file larger than the limit still runs, alone.
struct ByteBudget {
    used: Mutex<u64>,
    freed: Condvar,
    limit: u64,
}

impl ByteBudget {
    fn new(limit: u64) -> Self {
        Self { used: Mutex::new(0), freed: Condvar::new(), limit }
    }

    fn acquire(&self, bytes: u64) {
        let mut used = self.used.lock().expect("byte budget lock poisoned");
        while *used > 0 && *used + bytes > self.limit {
            used = self.freed.wait(used).expect("byte budget lock poisoned");
        }
        *used += bytes;
    }

    fn release(&self, bytes: u64) {
        let mut used = self.used.lock().expect("byte budget lock poisoned");
        *used -= bytes;
        self.freed.notify_all();
    }
}

fn worker_loop(
    jobs: &Mutex<Receiver<Job>>,
    done: &Sender<Done>,
    shared: &Shared,
    stop: &AtomicBool,
    budget: &ByteBudget
) {
    loop {
        // The lock is held only while waiting for the next job.
        let job = match jobs.lock().expect("job queue lock poisoned").recv() {
            Ok(job) => job,
            Err(_) => {
                return;
            }
        };
        let outcome = if stop.load(Ordering::Relaxed) {
            Outcome::Skipped
        } else {
            budget.acquire(job.size);
            let outcome = scan_job(&job, shared);
            budget.release(job.size);
            outcome
        };
        // Every job gets exactly one reply, so the walker's count of jobs in
        // flight is exact and it can never wait for a result that will not come.
        if done.send(Done { seq: job.seq, path: job.path, outcome }).is_err() {
            return;
        }
    }
}

/// The walker's side of the worker pool.
struct Pool<'a> {
    /// None once the walk is over: closing it lets workers finish and exit.
    job_tx: Option<SyncSender<Job>>,
    done_rx: Receiver<Done>,
    in_flight: usize,
    stop: &'a AtomicBool,
}

struct Run<'a> {
    opts: &'a ScanOptions,
    shared: &'a Shared<'a>,
    cancel: &'a AtomicBool,
    on_progress: &'a mut dyn FnMut(&Progress),
    is_volume_root: &'a dyn Fn(&Path) -> bool,
    system_dir_names: &'a [&'a str],
    pool: Option<Pool<'a>>,
    /// Roots already scanned in this run. A folder that is one of them is not
    /// entered again when it turns up under a later root (a full scan walks the
    /// drive after the quick-scan folders, which are inside it).
    scanned_roots: Vec<PathBuf>,
    started: Instant,
    last_progress: Option<Instant>,
    current_dir: PathBuf,
    next_seq: u64,
    /// Findings with the order their file was queued in. Workers can finish out
    /// of order; sorting by this at the end makes the report the same however
    /// many workers there were.
    found: Vec<(u64, FileFinding)>,
    stop: Option<StopReason>,
    report: ScanReport,
}

impl<'a> Run<'a> {
    fn new(
        opts: &'a ScanOptions,
        shared: &'a Shared<'a>,
        cancel: &'a AtomicBool,
        on_progress: &'a mut dyn FnMut(&Progress),
        is_volume_root: &'a dyn Fn(&Path) -> bool,
        system_dir_names: &'a [&'a str],
        pool: Option<Pool<'a>>
    ) -> Self {
        Self {
            opts,
            shared,
            cancel,
            on_progress,
            is_volume_root,
            system_dir_names,
            pool,
            scanned_roots: Vec::new(),
            started: Instant::now(),
            last_progress: None,
            current_dir: PathBuf::new(),
            next_seq: 0,
            found: Vec::new(),
            stop: None,
            report: ScanReport {
                findings: Vec::new(),
                scanned: 0,
                clean: 0,
                suspicious: 0,
                malicious: 0,
                skipped_excluded: 0,
                skipped_too_large: 0,
                skipped_links_or_special: 0,
                unreadable_files: 0,
                unreadable_dirs: 0,
                reused_results: 0,
                stop_reason: StopReason::Completed,
                elapsed_ms: 0,
            },
        }
    }

    fn walk_roots(&mut self, roots: &[PathBuf]) {
        for root in roots {
            // Absolute, but links are not resolved: the paths stay as the user
            // would write them (no `\\?\` prefix in the UI).
            let root = std::path::absolute(root).unwrap_or_else(|_| root.clone());
            if self.scanned_roots.iter().any(|done| same_path(done, &root)) {
                continue;
            }
            self.walk_root(&root);
            self.scanned_roots.push(root);
            if self.stop.is_some() {
                break;
            }
        }
    }

    fn finish(mut self) -> ScanReport {
        self.finish_pool();

        self.found.sort_by_key(|(seq, _)| *seq);
        self.found.truncate(self.opts.limits.max_findings.max(1));
        self.report.findings = self.found.into_iter().map(|(_, finding)| finding).collect();
        self.report.stop_reason = self.stop.unwrap_or(StopReason::Completed);
        self.report.elapsed_ms = self.started.elapsed().as_millis() as u64;
        self.report
    }

    /// Records the first stop reason found, and stops queuing files.
    ///
    /// Cancel and the time limit also tell workers to skip what is already
    /// queued, so the scan ends promptly. The findings cap does not: the files
    /// already queued finish, so every file before the last one queued has been
    /// scanned and the first findings by walk order are the same as a
    /// sequential scan would keep. The cost is at most a few more files
    /// scanned than the cap alone would need.
    fn raise_stop(&mut self, reason: StopReason) {
        if self.stop.is_none() {
            self.stop = Some(reason);
        }
        if reason != StopReason::FindingsCap {
            if let Some(pool) = &self.pool {
                pool.stop.store(true, Ordering::Relaxed);
            }
        }
    }

    /// True once the scan must end.
    fn should_stop(&mut self) -> bool {
        if self.stop.is_some() {
            return true;
        }
        if self.cancel.load(Ordering::Relaxed) {
            self.raise_stop(StopReason::Cancelled);
            return true;
        }
        if let Some(max) = self.opts.limits.max_duration {
            if self.started.elapsed() >= max {
                self.raise_stop(StopReason::TimeBudget);
                return true;
            }
        }
        false
    }

    fn progress(&mut self) {
        let now = Instant::now();
        let due = self.last_progress.is_none_or(|t| {
            now.duration_since(t) >= self.opts.min_progress_interval
        });
        if due {
            self.last_progress = Some(now);
            (self.on_progress)(
                &(Progress {
                    current_dir: self.current_dir.to_string_lossy().into_owned(),
                    scanned: self.report.scanned,
                    findings: self.found.len() as u64,
                })
            );
        }
    }

    fn walk_root(&mut self, root: &Path) {
        let mut stack = vec![root.to_path_buf()];

        while let Some(dir) = stack.pop() {
            if self.should_stop() {
                return;
            }
            self.current_dir = dir.clone();
            self.progress();

            let listing = match fs::read_dir(&dir) {
                Ok(listing) => listing,
                Err(_) => {
                    self.report.unreadable_dirs += 1;
                    continue;
                }
            };
            let mut entries = Vec::new();
            for entry in listing {
                match entry {
                    Ok(entry) => entries.push(entry),
                    Err(_) => self.report.unreadable_dirs += 1,
                }
            }
            // Stable order: reproducible reports, and progress that reads sensibly.
            entries.sort_by_key(|entry| entry.file_name());

            // One listing per folder, and the ransomware-behavior score for the
            // whole folder is computed once from it.
            let names: Vec<String> = entries
                .iter()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            let dir_score = dir_behavior::score_from_names(&names);
            let dir_is_volume_root = (self.is_volume_root)(&dir);

            let mut subdirs = Vec::new();
            for entry in &entries {
                if self.should_stop() {
                    return;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                let Ok(file_type) = entry.file_type() else {
                    self.report.unreadable_files += 1;
                    continue;
                };

                if file_type.is_symlink() {
                    self.report.skipped_links_or_special += 1;
                } else if file_type.is_dir() {
                    if !self.opts.recursive {
                        continue;
                    }
                    if dir_is_volume_root && is_system_dir_name(&name, self.system_dir_names) {
                        self.report.skipped_excluded += 1;
                    } else if self.scanned_roots.iter().any(|done| same_path(done, &entry.path())) {
                        // Already scanned as a root of this run; not an exclusion.
                    } else {
                        subdirs.push(entry.path());
                    }
                } else if file_type.is_file() {
                    self.submit_file(entry, &name, dir_score);
                } else {
                    self.report.skipped_links_or_special += 1;
                }
            }

            // Pushed in reverse so folders are visited in name order.
            stack.extend(subdirs.into_iter().rev());
        }
    }

    /// The cheap checks, done by the walker; the expensive part is `scan_job`.
    fn submit_file(&mut self, entry: &fs::DirEntry, name: &str, dir_score: i32) {
        if is_file_excluded(name) {
            self.report.skipped_excluded += 1;
            return;
        }

        let max = self.opts.limits.max_file_bytes;
        let size = match entry.metadata() {
            Ok(meta) if meta.len() > max => {
                self.report.skipped_too_large += 1;
                return;
            }
            Ok(meta) => meta.len(),
            Err(_) => {
                self.report.unreadable_files += 1;
                return;
            }
        };

        let job = Job {
            seq: self.next_seq,
            path: entry.path(),
            name: name.to_string(),
            dir_score,
            size,
        };
        self.next_seq += 1;
        self.dispatch(job);
    }

    fn dispatch(&mut self, mut job: Job) {
        if self.pool.is_none() {
            let outcome = scan_job(&job, self.shared);
            self.apply(Done { seq: job.seq, path: job.path, outcome });
            return;
        }

        loop {
            let sent = {
                let pool = self.pool.as_mut().expect("pool checked above");
                match pool.job_tx.as_ref() {
                    Some(tx) => tx.try_send(job),
                    None => {
                        return;
                    }
                }
            };
            match sent {
                Ok(()) => {
                    if let Some(pool) = self.pool.as_mut() {
                        pool.in_flight += 1;
                    }
                    break;
                }
                // Queue full: collect finished results while waiting for room.
                Err(TrySendError::Full(returned)) => {
                    job = returned;
                    self.drain_results(Duration::from_millis(10));
                    if self.should_stop() {
                        return;
                    }
                }
                Err(TrySendError::Disconnected(_)) => {
                    return;
                }
            }
        }
        self.drain_results(Duration::ZERO);
    }

    /// Takes finished results from the workers, waiting up to `wait` for the first.
    fn drain_results(&mut self, wait: Duration) {
        let mut finished = Vec::new();
        if let Some(pool) = self.pool.as_mut() {
            if let Ok(done) = pool.done_rx.recv_timeout(wait) {
                finished.push(done);
            }
            while let Ok(done) = pool.done_rx.try_recv() {
                finished.push(done);
            }
            pool.in_flight -= finished.len();
        }
        for done in finished {
            self.apply(done);
        }
    }

    /// After the walk: stop accepting files and wait for the queued ones.
    fn finish_pool(&mut self) {
        if let Some(pool) = self.pool.as_mut() {
            pool.job_tx = None;
        }
        while self.pool.as_ref().is_some_and(|pool| pool.in_flight > 0) {
            self.drain_results(Duration::from_millis(50));
            // Cancel and the time budget still apply while waiting; this makes
            // workers skip whatever is still queued.
            self.should_stop();
        }
    }

    fn apply(&mut self, done: Done) {
        match done.outcome {
            Outcome::Clean { reused } => {
                self.report.reused_results += u64::from(reused);
                self.report.scanned += 1;
                self.report.clean += 1;
            }
            Outcome::Flagged { result, reused } => {
                self.report.reused_results += u64::from(reused);
                self.record(done.seq, &done.path, result);
            }
            Outcome::TooLarge => self.report.skipped_too_large += 1,
            Outcome::Unreadable => self.report.unreadable_files += 1,
            Outcome::Skipped => {}
        }
        self.progress();
    }

    fn record(&mut self, seq: u64, path: &Path, result: ScanResult) {
        self.report.scanned += 1;
        match result.verdict {
            Verdict::Suspicious => self.report.suspicious += 1,
            Verdict::Malicious => self.report.malicious += 1,
            Verdict::Clean => {
                self.report.clean += 1;
                return;
            }
        }

        self.found.push((seq, FileFinding { path: path.to_string_lossy().into_owned(), result }));
        if self.found.len() >= self.opts.limits.max_findings.max(1) {
            self.raise_stop(StopReason::FindingsCap);
        }
    }
}

/// What a file's score depends on besides the signature set and rules, which are
/// fixed for a run: its bytes (the hash), its exact name, whether its path is in
/// a place kernel drivers live, and its folder's ransomware-behavior score. Two
/// files with equal keys get equal results. The key is a 128-bit digest, so the
/// map stays small (clean files are remembered as a marker only).
fn result_key(sha256_hex: &str, file_name: &str, in_rootkit_location: bool, dir_score: i32) -> u128 {
    let mut hasher = Sha256::new();
    hasher.update(sha256_hex.as_bytes());
    hasher.update([0u8]);
    hasher.update(file_name.as_bytes());
    hasher.update([0u8, u8::from(in_rootkit_location)]);
    hasher.update(dir_score.to_le_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    u128::from_le_bytes(bytes)
}

#[derive(Clone)]
enum Cached {
    Clean,
    Flagged(ScanResult),
}

/// Bounded: once full it stops remembering new results (existing ones stay).
struct ResultCache {
    entries: HashMap<u128, Cached>,
    max: usize,
}

impl ResultCache {
    fn new(max: usize) -> Self {
        Self { entries: HashMap::new(), max }
    }

    fn get(&self, key: u128) -> Option<Cached> {
        self.entries.get(&key).cloned()
    }

    fn put(&mut self, key: u128, outcome: Cached) {
        if self.entries.len() < self.max {
            self.entries.insert(key, outcome);
        }
    }
}

/// Reads at most `max` bytes. Returns None if the file is longer, without ever
/// holding more than `max + 1` bytes: a file that grows after its size was
/// checked cannot exhaust memory.
fn read_bounded(path: &Path, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    let file = fs::File::open(path)?;
    let mut content = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut content)?;
    if (content.len() as u64) > max { Ok(None) } else { Ok(Some(content)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_match::sha256_hex;
    use crate::DEFAULT_RULES;
    use tempfile::tempdir;

    const BAD: &[u8] = b"known-bad-bytes";

    fn rules() -> RuleSet {
        RuleSet::compile(DEFAULT_RULES).unwrap()
    }

    /// Known-bad content by hash, never raw EICAR on disk (Defender blocks it).
    fn bad_signatures() -> SignatureSet {
        SignatureSet::from_hashes(vec![sha256_hex(BAD)])
    }

    /// One worker: the walker scans on the calling thread, so tests that count
    /// exactly (cancel after the second file, the cap) are deterministic.
    fn opts(recursive: bool) -> ScanOptions {
        ScanOptions {
            min_progress_interval: Duration::ZERO,
            workers: 1,
            ..ScanOptions::directory(recursive)
        }
    }

    fn parallel(workers: usize) -> ScanOptions {
        ScanOptions { workers, ..opts(true) }
    }

    fn scan(root: &Path, opts: &ScanOptions, signatures: &SignatureSet) -> ScanReport {
        scan_path(root, opts, signatures, &rules(), &AtomicBool::new(false), &mut |_| {})
    }

    fn write(root: &Path, relative: &str, content: &[u8]) -> PathBuf {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        path
    }

    // --- walking ---

    #[test]
    fn scans_only_the_top_folder_when_not_recursive() {
        let dir = tempdir().unwrap();
        write(dir.path(), "a.txt", b"one");
        write(dir.path(), "sub/b.txt", b"two");

        let report = scan(dir.path(), &opts(false), &SignatureSet::new());
        assert_eq!(report.scanned, 1);
        assert_eq!(report.stop_reason, StopReason::Completed);
    }

    #[test]
    fn descends_into_subfolders_when_recursive() {
        let dir = tempdir().unwrap();
        write(dir.path(), "a.txt", b"one");
        write(dir.path(), "sub/b.txt", b"two");
        write(dir.path(), "sub/deeper/c.txt", b"three");

        let report = scan(dir.path(), &opts(true), &SignatureSet::new());
        assert_eq!(report.scanned, 3);
        assert_eq!(report.clean, 3);
    }

    #[test]
    fn a_folder_with_nothing_in_it_completes_with_an_empty_report() {
        let dir = tempdir().unwrap();
        let report = scan(dir.path(), &opts(true), &SignatureSet::new());
        assert_eq!(report.scanned, 0);
        assert!(report.findings.is_empty());
        assert_eq!(report.stop_reason, StopReason::Completed);
    }

    #[test]
    fn a_missing_root_is_one_unreadable_folder_not_a_panic() {
        let dir = tempdir().unwrap();
        let report = scan(&dir.path().join("does-not-exist"), &opts(true), &SignatureSet::new());
        assert_eq!(report.unreadable_dirs, 1);
        assert_eq!(report.scanned, 0);
        assert_eq!(report.stop_reason, StopReason::Completed);
    }

    #[test]
    fn findings_are_non_clean_only_and_the_counts_add_up() {
        let dir = tempdir().unwrap();
        write(dir.path(), "ok1.txt", b"fine");
        write(dir.path(), "ok2.txt", b"also fine");
        write(dir.path(), "nested/bad.bin", BAD);

        let report = scan(dir.path(), &opts(true), &bad_signatures());
        assert_eq!(report.scanned, 3);
        assert_eq!(report.clean + report.suspicious + report.malicious, report.scanned);
        assert_eq!(report.malicious, 1);
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].path.ends_with("bad.bin"), "{}", report.findings[0].path);
        assert_eq!(report.findings[0].result.verdict, Verdict::Malicious);
    }

    // --- exclusions ---

    #[test]
    fn hidden_and_noise_files_are_skipped_and_counted() {
        let dir = tempdir().unwrap();
        for name in [".hidden", "Thumbs.db", "desktop.ini", ".DS_Store"] {
            write(dir.path(), name, b"noise");
        }
        write(dir.path(), "real.txt", b"content");

        let report = scan(dir.path(), &opts(true), &SignatureSet::new());
        assert_eq!(report.skipped_excluded, 4);
        assert_eq!(report.scanned, 1);
    }

    #[test]
    fn the_file_exclusion_list_matches_the_java_engine() {
        for name in [".git", ".hidden", "thumbs.db", "THUMBS.DB", "Desktop.ini", ".ds_store"] {
            assert!(is_file_excluded(name), "{name} should be excluded");
        }
        for name in ["thumbs.db.txt", "readme.txt", "my.desktop.ini.bak", "a.exe"] {
            assert!(!is_file_excluded(name), "{name} should not be excluded");
        }
    }

    #[test]
    fn system_named_folders_under_a_volume_root_are_skipped_whole() {
        let dir = tempdir().unwrap();
        write(dir.path(), "Windows/x.txt", b"x");
        write(dir.path(), "ProgramData/y.txt", b"y");
        write(dir.path(), "keep/z.txt", b"z");

        let root = dir.path().to_path_buf();
        let report = scan_roots_with(
            std::slice::from_ref(&root),
            &opts(true),
            &SignatureSet::new(),
            &rules(),
            &AtomicBool::new(false),
            &mut |_| {},
            &|p: &Path| p == root,
            &["windows", "programdata"]
        );
        assert_eq!(report.scanned, 1, "only keep/z.txt should be scanned");
        assert_eq!(report.skipped_excluded, 2);
    }

    #[test]
    fn the_same_folder_names_deeper_in_the_tree_are_scanned() {
        let dir = tempdir().unwrap();
        write(dir.path(), "src/windows/a.txt", b"a");
        write(dir.path(), "src/programdata/b.txt", b"b");

        let root = dir.path().to_path_buf();
        let report = scan_roots_with(
            std::slice::from_ref(&root),
            &opts(true),
            &SignatureSet::new(),
            &rules(),
            &AtomicBool::new(false),
            &mut |_| {},
            &|p: &Path| p == root,
            &["windows", "programdata"]
        );
        assert_eq!(report.scanned, 2);
        assert_eq!(report.skipped_excluded, 0);
    }

    #[test]
    fn a_folder_chosen_explicitly_is_scanned_even_if_named_like_a_system_folder() {
        let dir = tempdir().unwrap();
        let chosen = dir.path().join("Windows");
        write(&chosen, "inside.txt", b"inside");

        let parent = dir.path().to_path_buf();
        let report = scan_roots_with(
            &[chosen],
            &opts(true),
            &SignatureSet::new(),
            &rules(),
            &AtomicBool::new(false),
            &mut |_| {},
            &|p: &Path| p == parent,
            &["windows"]
        );
        assert_eq!(report.scanned, 1);
        assert_eq!(report.skipped_excluded, 0);
    }

    #[test]
    fn the_platform_rules_name_the_right_folders() {
        #[cfg(windows)]
        {
            assert!(SYSTEM_DIR_NAMES.contains(&"windows"));
            assert!(SYSTEM_DIR_NAMES.contains(&"$recycle.bin"));
            // A developer's C:\dev must not be treated as a system folder.
            assert!(!SYSTEM_DIR_NAMES.contains(&"dev"));
            assert!(is_volume_root(Path::new("C:\\")));
            assert!(!is_volume_root(Path::new("C:\\Users")));
        }
        #[cfg(not(windows))]
        {
            for name in ["proc", "sys", "dev", "run"] {
                assert!(SYSTEM_DIR_NAMES.contains(&name));
            }
            assert!(!SYSTEM_DIR_NAMES.contains(&"windows"));
            assert!(is_volume_root(Path::new("/")));
            assert!(!is_volume_root(Path::new("/tmp")));
        }
        assert!(is_system_dir_name("WINDOWS", &["windows"]));
        assert!(!is_system_dir_name("windows-notes", &["windows"]));
    }

    #[test]
    fn system_roots_are_not_empty() {
        let roots = system_roots();
        assert!(!roots.is_empty());
        #[cfg(windows)]
        assert!(roots.iter().all(|r| r.to_string_lossy().ends_with(":\\")));
        #[cfg(not(windows))]
        assert_eq!(roots, vec![PathBuf::from("/")]);
    }

    // --- limits ---

    #[test]
    fn a_file_over_the_size_limit_is_counted_not_scanned() {
        let dir = tempdir().unwrap();
        write(dir.path(), "big.bin", b"0123456789");
        let mut options = opts(true);
        options.limits.max_file_bytes = 5;

        let report = scan(dir.path(), &options, &SignatureSet::new());
        assert_eq!(report.skipped_too_large, 1);
        assert_eq!(report.scanned, 0);
    }

    #[test]
    fn read_bounded_never_returns_more_than_the_limit() {
        let dir = tempdir().unwrap();
        let path = write(dir.path(), "f.bin", b"0123456789");
        assert_eq!(read_bounded(&path, 10).unwrap(), Some(b"0123456789".to_vec()));
        assert_eq!(read_bounded(&path, 11).unwrap().map(|c| c.len()), Some(10));
        assert_eq!(read_bounded(&path, 9).unwrap(), None);
        assert_eq!(read_bounded(&path, 0).unwrap(), None);
    }

    #[test]
    fn a_zero_time_budget_stops_before_the_first_file() {
        let dir = tempdir().unwrap();
        write(dir.path(), "a.txt", b"a");
        let mut options = opts(true);
        options.limits.max_duration = Some(Duration::ZERO);

        let report = scan(dir.path(), &options, &SignatureSet::new());
        assert_eq!(report.stop_reason, StopReason::TimeBudget);
        assert_eq!(report.scanned, 0);
    }

    #[test]
    fn cancel_set_before_the_start_stops_immediately() {
        let dir = tempdir().unwrap();
        write(dir.path(), "a.txt", b"a");

        let cancel = AtomicBool::new(true);
        let report = scan_path(dir.path(), &opts(true), &SignatureSet::new(), &rules(), &cancel, &mut |_| {});
        assert_eq!(report.stop_reason, StopReason::Cancelled);
        assert_eq!(report.scanned, 0);
    }

    #[test]
    fn cancel_during_the_scan_keeps_what_was_found_so_far() {
        let dir = tempdir().unwrap();
        for i in 0..6 {
            write(dir.path(), &format!("f{i}.txt"), b"x");
        }

        let cancel = AtomicBool::new(false);
        let report = scan_path(
            dir.path(),
            &opts(true),
            &SignatureSet::new(),
            &rules(),
            &cancel,
            &mut |p| {
                if p.scanned >= 2 {
                    cancel.store(true, Ordering::Relaxed);
                }
            }
        );
        assert_eq!(report.stop_reason, StopReason::Cancelled);
        assert_eq!(report.scanned, 2);
    }

    #[test]
    fn the_findings_cap_stops_the_scan() {
        let dir = tempdir().unwrap();
        for name in ["a.bin", "b.bin", "c.bin"] {
            write(dir.path(), name, BAD);
        }
        let mut options = opts(true);
        options.limits.max_findings = 1;

        let report = scan(dir.path(), &options, &bad_signatures());
        assert_eq!(report.stop_reason, StopReason::FindingsCap);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.scanned, 1);
    }

    #[test]
    fn progress_is_throttled_by_the_interval() {
        let dir = tempdir().unwrap();
        for i in 0..5 {
            write(dir.path(), &format!("f{i}.txt"), b"x");
        }

        let mut quiet_calls = 0;
        let mut slow = opts(true);
        slow.min_progress_interval = Duration::from_secs(3600);
        scan_path(dir.path(), &slow, &SignatureSet::new(), &rules(), &AtomicBool::new(false), &mut |_| {
            quiet_calls += 1;
        });
        assert_eq!(quiet_calls, 1, "only the first call is due within an hour");

        let mut every_call = 0;
        scan_path(dir.path(), &opts(true), &SignatureSet::new(), &rules(), &AtomicBool::new(false), &mut |_| {
            every_call += 1;
        });
        assert!(every_call >= 5, "expected a call per file, got {every_call}");
    }

    #[test]
    fn option_presets_match_the_agreed_limits() {
        let directory = ScanOptions::directory(true);
        assert_eq!(directory.limits.max_duration, None);
        assert_eq!(directory.limits.max_file_bytes, 100 * 1024 * 1024);
        assert_eq!(directory.limits.max_findings, 2_000);

        let system = ScanOptions::system();
        assert!(system.recursive);
        assert_eq!(system.limits.max_duration, Some(Duration::from_secs(300)));
    }

    // --- the folder score ---

    #[test]
    fn a_ransomware_style_folder_flags_its_files_through_the_folder_score() {
        let dir = tempdir().unwrap();
        write(dir.path(), "locked/README.txt", b"pay us");
        for i in 0..5 {
            write(dir.path(), &format!("locked/doc{i}.xyz123"), b"x");
        }
        write(dir.path(), "calm/notes.txt", b"hello");

        let report = scan(dir.path(), &opts(true), &SignatureSet::new());
        assert_eq!(report.findings.len(), 6, "every file in the locked folder is flagged");
        assert!(
            report.findings.iter().all(|f|
                f.result.contributions.iter().any(|c| c.reason == "RANSOMWARE_DIRECTORY_BEHAVIOR")
            )
        );
        assert!(report.findings.iter().all(|f| f.path.contains("locked")));
    }

    // --- the report ---

    #[test]
    fn the_report_serializes_with_readable_names_and_survives_a_round_trip() {
        let dir = tempdir().unwrap();
        write(dir.path(), "bad.bin", BAD);
        let report = scan(dir.path(), &opts(true), &bad_signatures());

        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["stop_reason"], "completed");
        assert!(json["elapsed_ms"].is_u64());
        assert!(json["findings"][0]["path"].is_string());

        let back: ScanReport = serde_json::from_value(json).unwrap();
        assert_eq!(back.findings.len(), 1);
        assert_eq!(back.stop_reason, StopReason::Completed);
    }

    // --- Unix-only: links, odd names, permissions ---

    #[cfg(unix)]
    #[test]
    fn a_symlink_loop_does_not_hang_and_links_are_counted() {
        let dir = tempdir().unwrap();
        write(dir.path(), "a/file.txt", b"x");
        std::os::unix::fs::symlink(dir.path(), dir.path().join("a/loop")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("a/file.txt"), dir.path().join("a/link-to-file")).unwrap();

        let report = scan(dir.path(), &opts(true), &SignatureSet::new());
        assert_eq!(report.scanned, 1);
        assert_eq!(report.skipped_links_or_special, 2);
        assert_eq!(report.stop_reason, StopReason::Completed);
    }

    #[cfg(unix)]
    #[test]
    fn a_name_that_is_not_valid_unicode_does_not_break_the_report() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempdir().unwrap();
        let odd = dir.path().join(OsStr::from_bytes(b"b\xffd.bin"));
        fs::write(&odd, BAD).unwrap();

        let report = scan(dir.path(), &opts(true), &bad_signatures());
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].path.contains('\u{FFFD}'));
        serde_json::to_string(&report).expect("the report must still serialize");
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_folder_is_counted_and_the_scan_continues() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        write(dir.path(), "ok.txt", b"fine");
        let locked = dir.path().join("locked");
        fs::create_dir(&locked).unwrap();
        write(&locked, "hidden.txt", b"never read");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

        // Running as root ignores permissions; nothing to prove then.
        let enforced = fs::read_dir(&locked).is_err();
        let report = scan(dir.path(), &opts(true), &SignatureSet::new());
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();

        if enforced {
            assert_eq!(report.unreadable_dirs, 1);
            assert_eq!(report.scanned, 1);
        }
    }

    // --- reusing the result for an identical file ---

    #[test]
    fn identical_files_with_the_same_name_reuse_the_first_result() {
        let dir = tempdir().unwrap();
        for folder in ["one", "two"] {
            write(dir.path(), &format!("{folder}/lib.bin"), BAD);
            write(dir.path(), &format!("{folder}/notes.txt"), b"hello");
        }

        let report = scan(dir.path(), &opts(true), &bad_signatures());
        assert_eq!(report.scanned, 4);
        assert_eq!(report.reused_results, 2, "one clean and one flagged file were repeats");
        assert_eq!((report.malicious, report.clean), (2, 2));
        let paths: Vec<&str> = report.findings.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths.len(), 2);
        assert_ne!(paths[0], paths[1], "each copy is reported at its own path");
        assert!(report.findings.iter().all(|f| f.result.file_name == "lib.bin"));
    }

    #[test]
    fn the_same_bytes_under_a_different_name_are_scored_separately() {
        // 4,096 bytes of every value: entropy of 8. Flagged as .bin, ignored as .jar.
        let packed: Vec<u8> = (0..16).flat_map(|_| 0u8..=255).collect();
        let dir = tempdir().unwrap();
        write(dir.path(), "a/payload.bin", &packed);
        write(dir.path(), "b/payload.jar", &packed);

        let report = scan(dir.path(), &opts(true), &SignatureSet::new());
        assert_eq!(report.reused_results, 0);
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].path.ends_with("payload.bin"));
    }

    #[test]
    fn the_folder_score_is_part_of_the_key() {
        let dir = tempdir().unwrap();
        write(dir.path(), "locked/README.txt", b"pay us");
        for i in 0..5 {
            write(dir.path(), &format!("locked/doc{i}.xyz123"), b"x");
        }
        write(dir.path(), "calm/doc0.xyz123", b"x");

        let report = scan(dir.path(), &opts(true), &SignatureSet::new());
        // Same name and bytes as locked/doc0.xyz123, but not in a ransomware-style
        // folder, so it must not inherit that verdict.
        assert_eq!(report.findings.len(), 6);
        assert!(report.findings.iter().all(|f| f.path.contains("locked")));
        assert_eq!(report.reused_results, 0);
    }

    #[test]
    fn reusing_results_changes_nothing_but_the_count() {
        let dir = tempdir().unwrap();
        for folder in ["a", "b", "c"] {
            write(dir.path(), &format!("{folder}/bad.bin"), BAD);
            write(dir.path(), &format!("{folder}/ok.txt"), b"fine");
            write(dir.path(), &format!("{folder}/unique-{folder}.txt"), folder.as_bytes());
        }

        let reused = scan(dir.path(), &opts(true), &bad_signatures());
        let mut options = opts(true);
        options.reuse_identical_results = false;
        let fresh = scan(dir.path(), &options, &bad_signatures());

        assert_eq!(fresh.reused_results, 0);
        assert_eq!(reused.reused_results, 4);
        let summary = |r: &ScanReport| {
            let findings: Vec<(String, Verdict, i32)> = r
                .findings
                .iter()
                .map(|f| (f.path.clone(), f.result.verdict, f.result.score))
                .collect();
            (r.scanned, r.clean, r.suspicious, r.malicious, findings)
        };
        assert_eq!(summary(&reused), summary(&fresh));
    }

    #[test]
    fn the_result_cache_stops_remembering_when_full_but_keeps_what_it_has() {
        let mut cache = ResultCache::new(1);
        cache.put(1, Cached::Clean);
        cache.put(2, Cached::Clean);
        assert!(cache.get(1).is_some());
        assert!(cache.get(2).is_none());
    }

    #[test]
    fn the_result_key_separates_every_input() {
        let base = result_key("abc", "a.bin", false, 0);
        assert_eq!(base, result_key("abc", "a.bin", false, 0));
        assert_ne!(base, result_key("abd", "a.bin", false, 0));
        assert_ne!(base, result_key("abc", "b.bin", false, 0));
        assert_ne!(base, result_key("abc", "a.bin", true, 0));
        assert_ne!(base, result_key("abc", "a.bin", false, 55));
    }

    // --- parallel scanning ---

    /// A tree with clean files, duplicates, folders and known-bad files.
    fn mixed_tree(dir: &Path) {
        for folder in 0..6 {
            for file in 0..12 {
                write(dir, &format!("f{folder}/file{file}.txt"), format!("content {folder} {file}").as_bytes());
            }
            write(dir, &format!("f{folder}/bad{folder}.bin"), format!("{}-{folder}", "known-bad-bytes").as_bytes());
            write(dir, &format!("f{folder}/dup.txt"), b"the same everywhere");
            write(dir, &format!("f{folder}/sub/deep.txt"), b"deeper");
        }
    }

    fn signatures_for_mixed_tree() -> SignatureSet {
        SignatureSet::from_hashes((0..6).map(|i| sha256_hex(format!("known-bad-bytes-{i}").as_bytes())))
    }

    /// Everything a sequential and a parallel scan must agree on.
    type ReportSummary = (u64, u64, u64, u64, Vec<(String, Verdict, i32)>);

    fn summary(report: &ScanReport) -> ReportSummary {
        let findings = report
            .findings
            .iter()
            .map(|f| (f.path.clone(), f.result.verdict, f.result.score))
            .collect();
        (report.scanned, report.clean, report.suspicious, report.malicious, findings)
    }

    #[test]
    fn a_parallel_scan_reports_exactly_what_a_sequential_one_does() {
        let dir = tempdir().unwrap();
        mixed_tree(dir.path());
        let signatures = signatures_for_mixed_tree();

        let sequential = scan(dir.path(), &opts(true), &signatures);
        assert_eq!(sequential.malicious, 6);
        for workers in [2, 4, 8] {
            let report = scan(dir.path(), &parallel(workers), &signatures);
            assert_eq!(summary(&report), summary(&sequential), "{workers} workers");
            assert_eq!(report.stop_reason, StopReason::Completed);
            assert!(
                report.reused_results <= sequential.reused_results,
                "parallel can only reuse less, never more"
            );
        }
    }

    #[test]
    fn a_parallel_scan_is_repeatable() {
        let dir = tempdir().unwrap();
        mixed_tree(dir.path());
        let signatures = signatures_for_mixed_tree();

        let first = summary(&scan(dir.path(), &parallel(4), &signatures));
        for _ in 0..5 {
            assert_eq!(summary(&scan(dir.path(), &parallel(4), &signatures)), first);
        }
    }

    #[test]
    fn a_parallel_scan_stops_when_cancelled() {
        let dir = tempdir().unwrap();
        mixed_tree(dir.path());

        let cancel = AtomicBool::new(true);
        let report = scan_path(dir.path(), &parallel(4), &SignatureSet::new(), &rules(), &cancel, &mut |_| {});
        assert_eq!(report.stop_reason, StopReason::Cancelled);
        assert_eq!(report.scanned, 0);

        // Cancelled partway: the scan ends promptly and keeps what finished.
        let cancel = AtomicBool::new(false);
        let report = scan_path(
            dir.path(),
            &parallel(4),
            &SignatureSet::new(),
            &rules(),
            &cancel,
            &mut |p| {
                if p.scanned >= 10 {
                    cancel.store(true, Ordering::Relaxed);
                }
            }
        );
        assert_eq!(report.stop_reason, StopReason::Cancelled);
        assert!(report.scanned >= 10, "scanned {}", report.scanned);
        assert!(report.scanned < 90, "it should not have finished: {}", report.scanned);
    }

    #[test]
    fn a_parallel_scan_keeps_only_the_first_findings_at_the_cap() {
        let dir = tempdir().unwrap();
        for i in 0..30 {
            // Every file is flagged; the names differ so the order is checkable.
            write(dir.path(), &format!("bad{i:02}.bin"), BAD);
        }
        let mut options = parallel(4);
        options.limits.max_findings = 3;
        options.reuse_identical_results = false;

        let report = scan(dir.path(), &options, &bad_signatures());
        assert_eq!(report.stop_reason, StopReason::FindingsCap);
        assert_eq!(report.findings.len(), 3);
        let names: Vec<&str> = report.findings.iter().map(|f| f.result.file_name.as_str()).collect();
        assert_eq!(names, ["bad00.bin", "bad01.bin", "bad02.bin"], "the first three, in order");
    }

    #[test]
    fn a_parallel_scan_honors_the_time_budget_and_size_limit() {
        let dir = tempdir().unwrap();
        mixed_tree(dir.path());
        let mut options = parallel(4);
        options.limits.max_duration = Some(Duration::ZERO);
        let report = scan(dir.path(), &options, &SignatureSet::new());
        assert_eq!(report.stop_reason, StopReason::TimeBudget);
        assert_eq!(report.scanned, 0);

        let mut small = parallel(4);
        small.limits.max_file_bytes = 8;
        let report = scan(dir.path(), &small, &SignatureSet::new());
        assert!(report.skipped_too_large > 0);
        assert_eq!(report.scanned + report.skipped_too_large, 6 * 15);
    }

    #[test]
    fn progress_in_a_parallel_scan_never_goes_backwards() {
        let dir = tempdir().unwrap();
        mixed_tree(dir.path());

        let mut last = 0;
        let mut monotonic = true;
        scan_path(
            dir.path(),
            &parallel(4),
            &SignatureSet::new(),
            &rules(),
            &AtomicBool::new(false),
            &mut |p| {
                monotonic &= p.scanned >= last;
                last = p.scanned;
            }
        );
        assert!(monotonic);
    }

    #[test]
    fn the_byte_budget_admits_one_oversized_file_and_blocks_the_next_until_it_is_released() {
        let budget = std::sync::Arc::new(ByteBudget::new(10));
        budget.acquire(100); // larger than the limit, allowed because nothing else is in flight

        let waiter = {
            let budget = std::sync::Arc::clone(&budget);
            let (tx, rx) = std::sync::mpsc::channel();
            let handle = std::thread::spawn(move || {
                budget.acquire(5);
                tx.send(()).unwrap();
                budget.release(5);
            });
            (handle, rx)
        };
        assert!(
            waiter.1.recv_timeout(Duration::from_millis(200)).is_err(),
            "the second acquire must wait while 100 bytes are held"
        );
        budget.release(100);
        waiter.1.recv_timeout(Duration::from_secs(5)).expect("it should proceed after the release");
        waiter.0.join().unwrap();
    }

    #[test]
    fn the_default_worker_count_is_between_one_and_the_maximum() {
        let workers = default_workers();
        assert!((1..=MAX_DEFAULT_WORKERS).contains(&workers), "{workers}");
        assert_eq!(ScanOptions::directory(true).workers, workers);
        assert_eq!(ScanOptions::system().workers, workers);
    }

    // --- quick and full scan targets ---

    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |name| pairs.iter().find(|(k, _)| *k == name).map(|(_, v)| OsString::from(*v))
    }

    #[test]
    fn the_windows_quick_list_has_the_expected_folders_in_priority_order() {
        let env = env_of(&[
            ("USERPROFILE", r"C:\Users\Pat"),
            ("TEMP", r"D:\scratch"),
            ("LOCALAPPDATA", r"C:\Users\Pat\AppData\Local"),
            ("APPDATA", r"C:\Users\Pat\AppData\Roaming"),
            ("PROGRAMDATA", r"C:\ProgramData"),
        ]);
        let roots = quick_roots_from(true, &env, &|_| true);

        let as_text: Vec<String> = roots.iter().map(|p| p.to_string_lossy().into_owned()).collect();
        assert_eq!(as_text.len(), 7, "{as_text:?}");
        assert!(as_text[0].contains("Downloads"));
        assert!(as_text[1].contains("Desktop"));
        assert!(as_text[2].contains("Documents"));
        assert!(as_text[3].ends_with("scratch"), "{as_text:?}");
        assert!(as_text[4].ends_with("Temp"), "{as_text:?}");
        assert!(as_text[5].contains("Startup"));
        assert!(as_text[6].contains("StartUp"));
    }

    #[test]
    fn the_unix_quick_list_uses_home_and_the_temp_dir() {
        let env = env_of(&[("HOME", "/home/pat"), ("TMPDIR", "/var/tmp")]);
        let roots = quick_roots_from(false, &env, &|_| true);
        // Compared as paths, not text: `join` uses the separator of the machine
        // running the test, so on Windows the text is "/home/pat\\Downloads".
        let expected: Vec<PathBuf> = [
            "/home/pat/Downloads",
            "/home/pat/Desktop",
            "/home/pat/Documents",
            "/var/tmp",
            "/home/pat/.config/autostart",
            "/home/pat/Library/LaunchAgents",
        ]
            .into_iter()
            .map(PathBuf::from)
            .collect();
        assert_eq!(roots, expected);

        let no_tmpdir = env_of(&[("HOME", "/home/pat")]);
        let roots = quick_roots_from(false, &no_tmpdir, &|_| true);
        assert!(roots.contains(&PathBuf::from("/tmp")));
    }

    #[test]
    fn missing_folders_and_empty_variables_are_left_out_and_repeats_removed() {
        let env = env_of(&[("HOME", "/home/pat"), ("TMPDIR", "")]);
        let only_documents = |p: &Path| p == Path::new("/home/pat/Documents") || p == Path::new("/tmp");
        let roots = quick_roots_from(false, &env, &only_documents);
        assert_eq!(roots, [PathBuf::from("/home/pat/Documents"), PathBuf::from("/tmp")]);

        let nothing = quick_roots_from(false, &env_of(&[]), &|_| false);
        assert!(nothing.is_empty());

        let same = env_of(&[("HOME", "/h"), ("TMPDIR", "/h/Downloads")]);
        let roots = quick_roots_from(false, &same, &|_| true);
        assert_eq!(roots.iter().filter(|p| p.as_path() == Path::new("/h/Downloads")).count(), 1);
    }

    #[test]
    fn same_path_ignores_a_trailing_separator_and_the_separator_style() {
        assert!(same_path(Path::new("/h/Downloads/"), Path::new("/h/Downloads")));
        assert!(!same_path(Path::new("/h/Downloads"), Path::new("/h/Desktop")));
        if cfg!(windows) {
            assert!(same_path(Path::new("/h\\Downloads"), Path::new("/h/Downloads")));
            assert!(same_path(Path::new(r"C:\Users\Pat"), Path::new(r"c:\users\pat\")));
        }
    }

    #[test]
    fn the_full_list_is_the_quick_list_then_the_drives_without_repeats() {
        let combined = combine_roots(
            vec![PathBuf::from("/a"), PathBuf::from("/b")],
            vec![PathBuf::from("/b"), PathBuf::from("/")]
        );
        assert_eq!(combined, [PathBuf::from("/a"), PathBuf::from("/b"), PathBuf::from("/")]);
        assert!(full_scan_roots().len() >= system_roots().len().min(1));
    }

    #[test]
    fn quick_scans_have_a_time_limit_and_full_scans_do_not() {
        assert_eq!(ScanOptions::quick().limits.max_duration, Some(Duration::from_secs(300)));
        assert!(ScanOptions::quick().recursive);
        assert_eq!(ScanOptions::full().limits.max_duration, None);
        assert!(ScanOptions::full().recursive);
    }

    #[test]
    fn a_folder_scanned_as_an_earlier_root_is_not_scanned_again_under_a_later_one() {
        let dir = tempdir().unwrap();
        write(dir.path(), "priority/a.txt", b"a");
        write(dir.path(), "priority/inner/b.txt", b"b");
        write(dir.path(), "other/c.txt", b"c");
        write(dir.path(), "top.txt", b"top");

        let priority = dir.path().join("priority");
        let report = scan_roots(
            &[priority, dir.path().to_path_buf()],
            &opts(true),
            &SignatureSet::new(),
            &rules(),
            &AtomicBool::new(false),
            &mut |_| {}
        );
        assert_eq!(report.scanned, 4, "each file once");
        assert_eq!(report.skipped_excluded, 0, "an already-scanned root is not an exclusion");

        // The same root given twice is scanned once.
        let twice = scan_roots(
            &[dir.path().to_path_buf(), dir.path().to_path_buf()],
            &opts(true),
            &SignatureSet::new(),
            &rules(),
            &AtomicBool::new(false),
            &mut |_| {}
        );
        assert_eq!(twice.scanned, 4);
    }
}

