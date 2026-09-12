# secureguard-core

Detection engine core: exact-hash matching, YARA-X pattern matching, Shannon-entropy
packer detection, and weighted scoring, tied together into a `CLEAN`/`SUSPICIOUS`/
`MALICIOUS` verdict. All scoring constants are ported directly from the Java backend's
`SecurityServiceImpl` (see comments at each constant's definition), not re-derived.

## Requirements

Rust 1.74+ (matches YARA-X's own MSRV). If you're on a Rust toolchain installed any
time in the last couple of years via `rustup`, you're fine, this only matters if
you're relying on a distro-packaged compiler that may be older.

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

cargo run --bin scg-scan -- sync                          # fetch from MalwareBazaar, default DB
cargo run --bin scg-scan -- sync --db mydb.db             # sync into a specific DB
cargo run --bin scg-scan -- sync --feed-url https://example.com/feed.txt  # override the feed(s)
```

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
