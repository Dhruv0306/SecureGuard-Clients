use clap::{ Parser, Subcommand };
use secureguard_core::dir_scan::{ self, Progress, ScanOptions, ScanReport, StopReason };
use secureguard_core::hash_match::SignatureSet;
use secureguard_core::yara_scan::RuleSet;
use secureguard_core::{ scan_file, signature_sync, storage, DEFAULT_RULES };
use std::io::IsTerminal;
use std::path::{ Path, PathBuf };
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

/// SecureGuard detection core CLI. Used both for manual testing and as the
/// harness the corpus/cross-engine validation jobs invoke.
///
/// Note for anyone who used this before Phase 2: this is a breaking CLI
/// change. `scg-scan path/to/file` (a bare positional argument) no longer
/// works, it's now `scg-scan scan path/to/file`, to make room for the new
/// `sync` subcommand. See core/README.md for the updated usage.
#[derive(Parser)]
#[command(name = "scg-scan")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a file and print its verdict.
    Scan {
        /// Path to the file to scan.
        path: PathBuf,

        /// Output the full ScanResult as JSON instead of a human-readable line.
        #[arg(long)]
        json: bool,

        /// Path to the local signature database. Created (with an empty
        /// schema) if it doesn't exist yet; a scan against a fresh database
        /// still has the EICAR signature seeded, per
        /// SignatureSet::load_from_cache, but no synced malware hashes
        /// until `sync` has been run at least once.
        #[arg(long, default_value = "secureguard.db")]
        db: PathBuf,
    },
    /// Scan a folder, or every fixed drive with --system, and print a report.
    ///
    /// A developer and diagnostic tool: the desktop app has the same scan
    /// built in. Exit code 0 means the scan ran, not that nothing was found;
    /// 1 means it could not run (bad path, unreadable database).
    ScanDir {
        /// Folder to scan. Not used with --system.
        #[arg(required_unless_present = "system", conflicts_with = "system")]
        path: Option<PathBuf>,

        /// Include subfolders.
        #[arg(long)]
        recursive: bool,

        /// Scan every fixed drive (Windows) or `/`, stopping after 5 minutes.
        /// Always includes subfolders.
        #[arg(long)]
        system: bool,

        /// Print the whole report as JSON on stdout.
        #[arg(long)]
        json: bool,

        /// Path to the local signature database; non-clean results are
        /// recorded to its history.
        #[arg(long, default_value = "secureguard.db")]
        db: PathBuf,
    },
    /// Fetch and persist known-malware signatures from the configured feed(s).
    /// Meant to be invoked periodically by the OS's own scheduler (cron,
    /// Task Scheduler), not run continuously, see
    /// docs/phase2-threat-intel-sync-plan.md for why this crate has no
    /// background daemon.
    Sync {
        /// Path to the local signature database.
        #[arg(long, default_value = "secureguard.db")]
        db: PathBuf,

        /// Feed URL(s) to sync from. Defaults to MalwareBazaar's recent-hashes
        /// export if none are given.
        #[arg(long)]
        feed_url: Vec<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan { path, json, db } => run_scan(&path, json, &db),
        Command::ScanDir { path, recursive, system, json, db } =>
            run_scan_dir(path.as_deref(), recursive, system, json, &db),
        Command::Sync { db, feed_url } => run_sync(&db, &feed_url),
    }
}

fn stop_reason_text(reason: StopReason) -> &'static str {
    match reason {
        StopReason::Completed => "completed",
        StopReason::Cancelled => "cancelled",
        StopReason::TimeBudget => "stopped at the time limit",
        StopReason::FindingsCap => "stopped at the findings limit",
    }
}

fn print_report(report: &ScanReport) {
    println!(
        "Scanned {} files in {:.1} s ({})",
        report.scanned,
        (report.elapsed_ms as f64) / 1000.0,
        stop_reason_text(report.stop_reason)
    );
    println!(
        "  clean {}, suspicious {}, malicious {}",
        report.clean, report.suspicious, report.malicious
    );
    if report.reused_results > 0 {
        println!("  {} results reused from identical files", report.reused_results);
    }
    println!(
        "  skipped: {} excluded, {} too large, {} links or special files, {} unreadable files, {} unreadable folders",
        report.skipped_excluded,
        report.skipped_too_large,
        report.skipped_links_or_special,
        report.unreadable_files,
        report.unreadable_dirs
    );
    if !report.findings.is_empty() {
        println!("Findings:");
        for finding in &report.findings {
            let threat = finding.result.threat_type.as_deref().unwrap_or("-");
            println!(
                "  {} ({}) {} [{}]",
                finding.result.verdict,
                finding.result.score,
                finding.path,
                threat
            );
        }
    }
}

fn run_scan_dir(
    path: Option<&Path>,
    recursive: bool,
    system: bool,
    json: bool,
    db: &Path
) -> ExitCode {
    if let Some(path) = path {
        if !path.is_dir() {
            eprintln!("{} is not a folder", path.display());
            return ExitCode::FAILURE;
        }
    }

    let rules = match RuleSet::compile(DEFAULT_RULES) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("failed to compile rule set: {e}");
            return ExitCode::FAILURE;
        }
    };
    let conn = match storage::open(&db.to_string_lossy()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to open signature database at {}: {e}", db.display());
            return ExitCode::FAILURE;
        }
    };
    let signatures = match SignatureSet::load_from_cache(&conn) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to load signatures from {}: {e}", db.display());
            return ExitCode::FAILURE;
        }
    };

    let (roots, options) = if system {
        (dir_scan::system_roots(), ScanOptions::system())
    } else {
        (vec![path.expect("clap requires a path without --system").to_path_buf()], ScanOptions::directory(recursive))
    };

    // Progress is for a person watching: only on a terminal, never mixed into
    // --json output. Ctrl+C simply ends the process; the desktop app is where
    // cancel is wired up.
    let show_progress = !json && std::io::stderr().is_terminal();
    let cancel = AtomicBool::new(false);
    let mut on_progress = |p: &Progress| {
        if show_progress {
            eprint!("\r{} files scanned, {} flagged        ", p.scanned, p.findings);
        }
    };
    let report = dir_scan::scan_roots(&roots, &options, &signatures, &rules, &cancel, &mut on_progress);
    if show_progress {
        eprintln!();
    }

    // History gets the non-clean results only, in one transaction.
    let flagged: Vec<_> = report.findings.iter().map(|f| f.result.clone()).collect();
    if let Err(e) = storage::record_scans(&conn, &flagged) {
        eprintln!("warning: failed to record scan history: {e}");
    }

    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(text) => println!("{text}"),
            Err(e) => {
                eprintln!("failed to serialize report: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        print_report(&report);
    }
    ExitCode::SUCCESS
}

fn run_scan(path: &Path, json: bool, db: &Path) -> ExitCode {
    let rules = match RuleSet::compile(DEFAULT_RULES) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("failed to compile rule set: {e}");
            return ExitCode::FAILURE;
        }
    };

    let conn = match storage::open(&db.to_string_lossy()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to open signature database at {}: {e}", db.display());
            return ExitCode::FAILURE;
        }
    };

    let signatures = match SignatureSet::load_from_cache(&conn) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to load signatures from {}: {e}", db.display());
            return ExitCode::FAILURE;
        }
    };

    match scan_file(path, &signatures, &rules) {
        Ok(result) => {
            // Persist every scan to history. This was never wired up before
            // Phase 3, storage::record_scan existed and was tested since
            // Phase 1 but nothing actually called it in a real code path,
            // history was buildable but never actually built.
            if let Err(e) = storage::record_scan(&conn, &result) {
                eprintln!("warning: failed to record scan to history: {e}");
                // Not fatal: the scan itself succeeded and its result is
                // still reported below, losing a history row shouldn't
                // hide a real verdict from the user.
            }

            if json {
                match serde_json::to_string_pretty(&result) {
                    Ok(text) => println!("{text}"),
                    Err(e) => {
                        eprintln!("failed to serialize result: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                println!("{}: {} (score {})", result.file_name, result.verdict, result.score);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("failed to scan {}: {e}", path.display());
            ExitCode::FAILURE
        }
    }
}

fn run_sync(db: &Path, feed_urls: &[String]) -> ExitCode {
    let conn = match storage::open(&db.to_string_lossy()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to open signature database at {}: {e}", db.display());
            return ExitCode::FAILURE;
        }
    };

    let urls: Vec<&str> = if feed_urls.is_empty() {
        vec![signature_sync::DEFAULT_FEED_URL]
    } else {
        feed_urls.iter().map(String::as_str).collect()
    };

    match signature_sync::sync_signatures(&urls, &conn) {
        Ok(result) => {
            println!(
                "synced {} new signature(s), {} total in database",
                result.new_signatures,
                result.total_signatures
            );
            if !result.feed_errors.is_empty() {
                eprintln!("{} feed(s) failed (others still applied):", result.feed_errors.len());
                for err in &result.feed_errors {
                    eprintln!("  - {err}");
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sync failed: {e}");
            ExitCode::FAILURE
        }
    }
}
