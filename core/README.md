# secureguard-core

Detection engine core: exact-hash matching, YARA-X pattern matching, Shannon-entropy
packer detection, and weighted scoring, tied together into a `CLEAN`/`SUSPICIOUS`/
`MALICIOUS` verdict. All scoring constants are ported directly from the Java backend's
`SecurityServiceImpl` (see comments at each constant's definition), not re-derived.

## Requirements

Rust 1.93+. The floor is set by the YARA-X and wasmtime versions in `Cargo.lock`
(both declare `rust-version = "1.93.0"`), so it will rise whenever those do. CI checks
it on exactly 1.93 with `--locked`. Install or update with `rustup update stable`; a
distro-packaged compiler is very unlikely to be new enough.

## Build and test

```bash
cargo build
cargo test
```

## CLI usage

**Note:** this is a breaking change from Phase 1. `scg-scan path/to/file` (a bare
positional argument) no longer works, scanning and syncing are now subcommands.

```bash
cargo run --bin scg-scan -- scan path/to/file
cargo run --bin scg-scan -- scan --json path/to/file      # machine-readable output
cargo run --bin scg-scan -- scan --db mydb.db path/to/file  # custom signature DB location

cargo run --bin scg-scan -- scan-dir path/to/folder --recursive           # scan a folder, summary on stdout
cargo run --bin scg-scan -- scan-dir path/to/folder --recursive --json    # the full report as JSON
cargo run --bin scg-scan -- scan-dir --system                             # every fixed drive, stops at 5 minutes
cargo run --release --bin scg-scan -- scan-dir --quick                    # Downloads, Desktop, Documents, temp and startup folders, stops at 5 minutes
cargo run --release --bin scg-scan -- scan-dir --full                     # those first, then every fixed drive, no time limit
cargo run --release --bin scg-scan -- scan-dir path --recursive --workers 4   # number of scan threads

cargo run --bin scg-scan -- sync                          # fetch from MalwareBazaar, default DB
cargo run --bin scg-scan -- sync --db mydb.db             # sync into a specific DB
cargo run --bin scg-scan -- sync --feed-url https://example.com/feed.txt  # override the feed(s)
```

`scan-dir` walks a folder with the same engine and prints a report; it records only
suspicious and malicious results to the history database. Exit code 0 means the scan ran, not
that nothing was found. It is a developer and diagnostic tool: the desktop app has the same scan
built in. Use `--release` for real scans: a debug build is about ten times slower. Files are
scored on a pool of worker threads (default: half the cores, 1 to 8), and a file identical to one
already scanned in the same run (same bytes, name and folder score) reuses that result.
Symlinks and junctions are not followed, hidden files and a few system folders
are skipped and counted, files over 100 MB are counted but not scanned (see
docs/phase5-2-5-3-design-plan.md).

`sync` is a one-shot fetch-and-persist pass, not a background service. Nothing in this
crate runs continuously yet, so periodic syncing is left to the OS's own scheduler (cron,
Task Scheduler) invoking this command, see docs/phase2-threat-intel-sync-plan.md for the
full reasoning. `scan` always loads whatever signatures are currently in the database
(plus the EICAR hash, seeded unconditionally), a scan against a database that's never
been synced still works, it just won't recognize anything beyond EICAR and whatever
`scan_file`'s own content-analysis signals catch.

## What's implemented so far

**Phase 1** (detection core): hash matching, YARA-X integration, entropy detection
(gated to executable-like files), extension masquerade, ransomware extension/text/
directory-behavior detection, rootkit detection, trojan filename signatures,
strong/weak text pattern matching, ZIP/archive scanning, weighted scoring capped at 100,
local SQLite storage.

**Phase 2** (threat-intel sync): live MalwareBazaar signature sync (`sync_signatures`),
ported with the same rolling-window-safe persistence and per-feed error isolation as
the Java backend's `ThreatIntelSignatureService`, plus `SignatureSet::load_from_cache`
to load persisted signatures (and the always-seeded EICAR hash) before scanning.

**Not yet implemented**: no UI (Phase 3), no privileged operations (Phase 4), no
UniFFI/Android bindings (Phase 6).
