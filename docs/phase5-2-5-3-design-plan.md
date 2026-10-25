# Phase 5.2 and 5.3: design plan

Date: 13/10/2026. Replaces the 5.2 and 5.3 sections of
[phase5-1-to-5-3-scan-ui-plan.md](phase5-1-to-5-3-scan-ui-plan.md). Evidence behind the
decisions is in [phase5-3-spike-results.md](phase5-3-spike-results.md) and
[helper-security-model.md](helper-security-model.md).

## Where things stand

| Phase | State |
|---|---|
| 5.1 domain blocking | UI and backend done. Works for a normal user only after the helper pipe fix (PR 1 below) |
| 5.2 directory and system scan | Not started. The lock fix and async command pattern it needs are merged |
| 5.3 network scan | Not started. Crates, MSRV and feed access are validated |

## Decisions (agreed 13/10/2026)

| # | Decision |
|---|---|
| D1 | Helper pipe: SYSTEM and Administrators full, the interactive user read and write, nobody else |
| D2 | System scan limits: cap the findings kept (2,000) and a 5-minute time budget; do not copy Java's cap on files scanned |
| D3 | Skip lists match whole folder names, not substrings of the path |
| D4 | Windows system scan covers fixed drives only |
| D5 | Single-threaded scanning first; measure before adding parallelism |
| D6 | Run core's tests on Windows and macOS in CI |
| D7 | System folders are skipped by whole name, and only directly under a filesystem root |
| D8 | One skip list for both scan modes, not Java's two |
| D9 | Hidden dot-files stay excluded as in Java; an "include hidden" switch can come later |
| D10 | A small `scg-scan scan-dir` developer command ships with the engine; the user feature is in the app (5.2b) |
| D11 | Fix false positives in the Rust engine now; document the same changes for the Java engine (docs/java-engine-false-positive-fixes.md) |
| D12 | In the app: a Quick scan (priority places) and a Full scan (no time limit); the CLI `--system` keeps its 5-minute limit |
| D13 | Scan on a bounded pool of worker threads |
| D14 | Reuse the result for an identical file within one scan |

## What the Java source shows

Re-read from `SecurityServiceImpl` while designing. Items marked "confirm" are readings
of the code that should be checked again when the port is written.

- The system scan stops at 2,000 recorded results, and clean files count as results
  (confirm). In effect it scans the first 2,000 files. That is a memory guard, not a
  feature. D2 replaces it.
- The skip list is a substring match on the full path, so `C:\Users\x\windows-notes`
  would be skipped. D3 replaces it.
- The system-scan walker does not apply the directory-scan exclusions, and the 100 MB file
  limit lives in `scanFile`, not in the walker.
- The ransomware directory check is cached per directory in Java. The Rust version
  re-reads the folder for every file, which is quadratic. Fix it by computing it once per
  directory.
- The Java directory walk filters to regular files. The earlier Rust handoff design did
  not, which would hang on a device file or FIFO on Linux.

Kept as in Java: the 100 MB file limit, the 5-minute system-scan budget, and the
directory-scan exclusions.

## Phase 5.2: design

### Core: `core/src/dir_scan.rs`

```rust
pub struct ScanOptions { pub recursive: bool, pub limits: ScanLimits, pub min_progress_interval: Duration }
impl ScanOptions {
    pub fn directory(recursive: bool) -> Self;   // no time limit; the user can cancel
    pub fn system() -> Self;                     // recursive, 5-minute budget
}
pub struct ScanLimits {
    pub max_file_bytes: u64,            // 100 MB
    pub max_duration: Option<Duration>, // system scan: 5 minutes
    pub max_findings: usize,            // 2,000, at least 1
}
pub struct FileFinding { pub path: String, pub result: ScanResult }   // non-clean only; lossy path
pub struct ScanReport {
    pub findings: Vec<FileFinding>,
    pub scanned: u64, pub clean: u64, pub suspicious: u64, pub malicious: u64,
    pub skipped_excluded: u64, pub skipped_too_large: u64, pub skipped_links_or_special: u64,
    pub unreadable_files: u64, pub unreadable_dirs: u64,
    pub stop_reason: StopReason,        // completed | cancelled | time_budget | findings_cap
    pub elapsed_ms: u64,
}
pub struct Progress { pub current_dir: String, pub scanned: u64, pub findings: u64 }

pub fn scan_path(root: &Path, opts: &ScanOptions, signatures: &SignatureSet, rules: &RuleSet,
                 cancel: &AtomicBool, on_progress: &mut dyn FnMut(&Progress)) -> ScanReport;
pub fn scan_roots(roots: &[PathBuf], /* same arguments */) -> ScanReport;   // one budget, one report
pub fn system_roots() -> Vec<PathBuf>;   // Windows: fixed drives; Unix: "/"
```

Built in Phase 5.2a (`core/src/dir_scan.rs`). Also added there: `storage::record_scans` (one
transaction) and a `rowid` tie-break in `recent_scans`.

Behavior:

- **Walk.** Iterative, no recursion, one `read_dir` per folder. Uses
  `DirEntry::file_type()`, which does not follow links, so symlinks (and junctions, to be
  confirmed on Windows) are skipped. Only regular files are scanned.
- **System folders.** Skipped only when the folder sits directly under a filesystem root and its
  whole name matches (case-insensitive). Windows: `Windows`, `Program Files`,
  `Program Files (x86)`, `ProgramData`, `$Recycle.Bin`, `System Volume Information`, `Recovery`,
  `Config.Msi`, `Documents and Settings`. Elsewhere: `proc`, `sys`, `dev`, `run`. The platform
  lists are separate, so a developer's `C:\dev` is never skipped. A folder the caller chose
  explicitly is never skipped. A skipped folder counts once in `skipped_excluded`.
- **Hidden files.** Names starting with `.`, `thumbs.db` and `desktop.ini` are skipped and counted
  (files only, as in Java).
- **Limits.** Checked per file and per folder entry: cancel flag, time budget, findings cap.
  A file over `max_file_bytes` is counted, not scanned.
- **Per-directory work.** Split the ransomware directory check into "summarize this folder"
  and "score this file from the summary", computed once per folder. Keep the old function
  as a wrapper so its tests still apply.
- **Progress.** Throttled to at most about 10 calls a second.
- **Memory.** Only non-clean results are kept. Counts cover everything.
- **System roots on Windows.** `GetLogicalDrives` and `GetDriveTypeW`, fixed drives only,
  because probing a disconnected network drive can hang.

### CLI

`scg-scan scan-dir <path> [--recursive] [--json] [--db <file>]` and
`scg-scan scan-dir --system [--json] [--db <file>]`. A developer and diagnostic tool: the user
feature is in the app. The report goes to stdout; a progress line goes to stderr only on a terminal
and never with `--json`. Exit code 0 means the scan ran (a finding is not an error), 1 means it
could not run. Non-clean results are recorded to the history database in one transaction.

### Desktop

- Commands: `scan_directory_cmd(path, recursive)`, `scan_system_cmd()` and
  `cancel_scan_cmd()`, all `async` through `run_blocking`.
- One scan at a time, held in a managed `ScanControl` (a mutex around the running session's
  cancel flag). A second request is refused with a clear message.
- The scan takes one `Arc<SignatureSet>` snapshot at the start and holds no lock while
  walking. History is written once, in one transaction, after the scan, non-clean results
  only (a later migration is documented).
- Events: `scan-progress` with the `Progress` payload.
- UI: a folder picker (dialog plugin) with a "include subfolders" box and Scan button; a
  "Scan this PC" button behind a confirm dialog; a progress line with a Cancel button; a
  summary, a findings list, and a banner that states the stop reason. All text through
  `textContent`. The UI says plainly that there is no quarantine or removal.

### Tests

- Temp-folder trees: exclusions, size limit (with an injected small limit), symlink loop
  (Unix), unreadable folder (Unix, skipped when running as root), junction (manual on
  Windows).
- Limits: cancel flag set before the start, zero time budget, findings cap of 1.
- Known-bad files use `SignatureSet::from_hashes`, never raw EICAR on disk (Defender blocks it).
- Skip-list matching as pure string tests, including `windows-notes`.
- Progress throttling with a fake clock.
- A manual benchmark on a large tree, to confirm the per-folder fix.
- CI: a Windows and macOS job for `core` (the Windows job already exists once PR 1 lands).

## Phase 5.2 follow-up: detection quality and throughput (built)

Measured in a release build on a developer's Windows machine: a system scan covered 11,508 files in
301.7 s (about 38 files a second, one thread), flagged 528 files (4.6%), and never got past hidden
folders in the user profile, so it never reached Desktop, Documents or Downloads. Nearly all
flagged files were legitimate. The engine work that followed, all in `secureguard-core`:

- **False positives (D11).** `.jar` and `.msi` are no longer entropy-checked by extension alone;
  weak text patterns are capped below the suspicious threshold; an ELF `.so`/`.ko`/`.node` or a
  Windows `.pyd`/`.node` with a matching header is not "extension masquerade"; zip suspicious-entry
  points are added once and only for `.zip`, `.jar` and `.war` names, as in Java (the port added
  them per entry for any zip-shaped file). See docs/java-engine-false-positive-fixes.md.
- **Throughput (D13, D14).** A pool of worker threads (default half the cores, 1 to 8) with a
  256 MB cap on file content held at once, and reuse of the result for an identical file. Re-run
  the system scan in a release build to see the new rate.
- **Targets (D12, core part).** `quick_scan_roots()`, `full_scan_roots()`, `ScanOptions::quick()`
  and `full()`, and CLI `--quick` and `--full`.

Still for 5.2b: the app commands and screens for Quick scan and Full scan, progress, cancel and
results; running a full scan in the background; and wiring the worker count.

## Phase 5.3a: local network scan

- `core/src/net_scan.rs`. A `SocketSource` trait returns listeners, connections and
  interfaces; the system implementation uses `listeners`, `netstat2` and `if-addrs`. Tests use
  a fake source.
- `evaluate(&[Listener], ...) -> Vec<Finding>` is a pure function. Severity comes from the Java
  port tables (confirm the exact table when porting), lowered one level for loopback-only
  listeners. Each finding has a recommendation.
- A row with no resolved process name is shown as "unknown", never hidden.
- Not ported: the Java service's hardcoded suspicious address, its in-app firewall and web-
  protection flags, and its port probing. The OS already reports what is listening.
- CLI `scg-scan net-scan [--json]`; desktop `net_scan_cmd` (async) and a panel grouping
  "exposed to the network" and "this machine only".

## Phase 5.3b: threat-intel connection matching

- Storage: a `bad_ips` table, and a small table of per-feed last-sync time and count.
- A shared feed fetcher (timeout and User-Agent already exist) used by the hash sync and the
  IP sync. Each feed fails independently.
- The Feodo recommended list holds very few entries (one when checked), so tests use fixture
  lists. Parser: comments, blank lines, IPv4 and IPv6.
- Matcher: established connections against the set, ignoring private and loopback addresses and
  normalizing IPv4-mapped IPv6. A match is a high-severity finding with the process and address.
- Keyless by default. An optional abuse.ch key is read from the environment, and a 401 or
  403 reports that a key may now be required.
- The UI shows how old each list is.

## Pull requests, in order

| # | Branch | Depends on |
|---|---|---|
| 1 | `fix/helper-pipe-access-and-validation` (pipe access, hostname validation, Windows CI job) | none |
| 2 | `phase5.2a-dir-scan-core` (core, CLI, macOS CI job) | none |
| 3 | `phase5.2b-dir-scan-desktop` | 2 |
| 4 | `phase5.3a-net-scan` | 3 (shared UI files) |
| 5 | `phase5.3b-threat-ip-match` | 4 |

Each PR carries its own changelog entry and doc changes, and a manual smoke checklist.

## Risks

| Risk | Handling |
|---|---|
| A scan reads up to 100 MB per file and runs YARA on it | Single thread first, measure, then decide on a bounded worker pool |
| Windows junctions and reparse points | Do not follow links; check a junction by hand on Windows |
| Defender blocks test files | Hash fixtures, no raw EICAR on disk |
| Progress events flood the UI | Throttle in the core |
| Helper reachable by any interactive user | Validation in the helper (PR 1); stricter caller checks are a later option |
| Helper socket permissions on Linux and macOS | Unverified, listed in the helper security doc; fix before shipping there |

## Corrections to the earlier plan

- It says the Java network scan is "confirmed real, not simulated". The suspicious-connection
  result is a hardcoded address, and the firewall and web-protection values are in-app flags.
- It describes 5.2 as a synchronous scan. The design above adds progress and cancel.
