use clap::{Parser, Subcommand};
use secureguard_core::hash_match::SignatureSet;
use secureguard_core::yara_scan::RuleSet;
use secureguard_core::{scan_file, signature_sync, storage, DEFAULT_RULES};
use std::path::PathBuf;
use std::process::ExitCode;

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
        Command::Sync { db, feed_url } => run_sync(&db, &feed_url),
    }
}

fn run_scan(path: &PathBuf, json: bool, db: &PathBuf) -> ExitCode {
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
            if json {
                match serde_json::to_string_pretty(&result) {
                    Ok(text) => println!("{text}"),
                    Err(e) => {
                        eprintln!("failed to serialize result: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                println!(
                    "{}: {} (score {})",
                    result.file_name, result.verdict, result.score
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("failed to scan {}: {e}", path.display());
            ExitCode::FAILURE
        }
    }
}

fn run_sync(db: &PathBuf, feed_urls: &[String]) -> ExitCode {
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
                result.new_signatures, result.total_signatures
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
