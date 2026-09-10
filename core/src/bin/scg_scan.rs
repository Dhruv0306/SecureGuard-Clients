use clap::Parser;
use secureguard_core::hash_match::SignatureSet;
use secureguard_core::yara_scan::RuleSet;
use secureguard_core::{scan_file, DEFAULT_RULES};
use std::path::PathBuf;
use std::process::ExitCode;

/// SecureGuard detection core CLI: scans a file and prints the verdict.
/// Used both for manual testing and as the harness the corpus/cross-engine
/// validation jobs invoke.
#[derive(Parser)]
#[command(name = "scg-scan")]
struct Args {
    /// Path to the file to scan.
    path: PathBuf,

    /// Output the full ScanResult as JSON instead of a human-readable line.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let rules = match RuleSet::compile(DEFAULT_RULES) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("failed to compile rule set: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Phase 1 uses an empty signature set (no persisted known-malware hashes
    // yet); Phase 2 wires this up to the local signature cache populated by
    // MalwareBazaar sync.
    let signatures = SignatureSet::new();

    match scan_file(&args.path, &signatures, &rules) {
        Ok(result) => {
            if args.json {
                match serde_json::to_string_pretty(&result) {
                    Ok(json) => println!("{json}"),
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
            eprintln!("failed to scan {}: {e}", args.path.display());
            ExitCode::FAILURE
        }
    }
}
