# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Core: quick and full scan targets. `quick_scan_roots()` lists the places malware usually lands
  (Downloads, Desktop, Documents, the temp folder, startup folders; only those that exist);
  `full_scan_roots()` is those followed by every fixed drive, and a folder already scanned as an
  earlier root is not scanned again. `ScanOptions::quick()` has a 5-minute limit,
  `ScanOptions::full()` none. CLI: `scg-scan scan-dir --quick` and `--full`.
- Core: scanning on a pool of worker threads (`ScanOptions::workers`, default half the cores, 1 to
  8; CLI `--workers N`). The report is the same for any count. A 256 MB byte budget bounds the
  file content held in memory at once.
- Core: a file identical to one already scanned in the same run (same SHA-256, name and folder
  score) reuses its result (`ScanReport::reused_results`, `ScanOptions::reuse_identical_results`).
- Core: a directory and system scan engine (`secureguard_core::dir_scan`) with a cancel flag,
  throttled progress, a findings cap, a time budget for system scans, and a report of what was
  scanned, flagged and skipped. Symlinks and junctions are not followed; system folders are
  skipped by name directly under a drive root; a folder chosen explicitly is never skipped.
- CLI: `scg-scan scan-dir <path> [--recursive] [--json]` and `scg-scan scan-dir --system`.
- Core: `storage::record_scans` records many results in one transaction.
- CI: a macOS job runs the core tests.

### Changed
- The ransomware directory heuristic is computed once per folder instead of re-reading the
  folder for every file scanned (`dir_behavior::score_from_names`,
  `scoring::score_file_in_directory`). Existing functions keep their behavior.
- `recent_scans` breaks ties by insertion order, so newest-first is deterministic for rows
  written in the same second.
- Declared `rust-version` raised from 1.74 to 1.93 in `secureguard-core`,
  `secureguard-helper` and `secureguard-desktop`. The old value was never true for the
  committed `Cargo.lock`: `yara-x` and `wasmtime` require 1.93 and several other
  dependencies need edition 2024 manifests. A new `msrv` CI job runs
  `cargo check --workspace --locked` on Rust 1.93, so a dependency bump that raises the
  floor again fails CI instead of silently breaking older toolchains.

### Fixed
- Detection: a system scan of a developer machine flagged about 4.6% of files, nearly all
  legitimate. Four fixes (details and the Java follow-up in
  `docs/java-engine-false-positive-fixes.md`): `.jar` and `.msi` are no longer penalized for
  entropy because they are compressed by design; weak text patterns alone can no longer produce a
  verdict (cap 32 to 24); an ELF `.so`/`.ko`/`.node` or a Windows `.pyd`/`.node` with a matching
  header is no longer "extension masquerade"; and zip suspicious-entry points are added once, only
  for `.zip`, `.jar` and `.war` names, as in the Java engine (the port added them per entry for
  any zip-shaped file, so a driver archive scored 435 and was convicted).
- Desktop: every Tauri command was a plain `fn`, so it ran on the main thread and
  blocked all other commands until it returned (including `sync_signatures_cmd`, which
  does network I/O). All six commands are now `async fn` and run on Tauri's blocking
  thread pool.
- Signature feed requests had no timeout and used the library's default User-Agent. They
  now time out after 30 s, send a named `SecureGuard-Clients` User-Agent, and a 401 or
  403 reports that the feed may now require an Auth-Key.
- Desktop: `do_scan` held the signature-set lock while waiting for the database lock,
  and `do_sync` took the two locks in the opposite order, so a scan racing a sync could
  deadlock. The signature set is now an `Arc` snapshot: scans clone it under a momentary
  lock and no code path holds both locks at once.

### Security
- Helper: the named pipe had no explicit access control, so only elevated processes could
  connect and a normal desktop app was refused ("Access is denied"). It now allows SYSTEM,
  administrators and the interactive user, and nobody else (Windows). See
  `docs/helper-security-model.md`.
- Helper: the hosts-file writer wrote whatever domain string it received, so a name
  containing a newline could add arbitrary hosts entries. Hostnames are now checked by a
  `BlockedDomain` type that the writer requires, in the helper (which rejects the whole
  request if any entry is bad), and in the desktop app. A blocklist is limited to 5,000
  entries.

## [0.1.0] - 17/09/2026

Standalone, no-backend Rust detection engine plus desktop client and privileged helper.
First five phases of the [standalone clients plan](docs/standalone-native-clients-plan.md),
nothing tagged yet.

### Added
- `secureguard-core`: standalone detection engine, no server dependency. Hash-based
  signature matching, EICAR detection, YARA-X pattern matching, Shannon-entropy
  packer detection (gated to executable-like files), extension masquerade detection,
  ransomware extension/text-pattern/directory-behavior detection, rootkit binary/text
  detection, trojan filename signatures, weighted scoring capped at 100, ZIP/archive
  scanning including zip-bomb limits, all ported from `SecurityServiceImpl.java` with
  parity verified against the same scoring constants (Phase 1)
- Local SQLite storage: scan history, signature cache, blocked-domains table (Phase 1)
- `scg-scan` CLI: `scan` and `sync` subcommands, JSON output, persists every scan to
  history (Phase 1, history persistence fixed in Phase 3)
- Corpus validation test against real known-good archives (jq, ripgrep, shellcheck) and
  known-malware IOC hashes (WannaCry, NotPetya), fetched from the main repo's test data
  at a pinned commit and integrity-checked before use (Phase 1)
- Cross-engine CI: runs the Rust corpus test and the Java backend's
  `ScanAccuracyIT`/`ScanEvasionIT` against the same pinned commit in the same workflow
  run, so drift between the two engines on a known-labeled case surfaces directly
  (Phase 1)
- Live threat-intel sync (`sync_signatures`) against MalwareBazaar's recent-hashes feed,
  ported from `ThreatIntelSignatureService.java` with the same rolling-window-safe
  persistence (never loses a previously-learned hash) and per-feed error isolation. No
  background daemon, a one-shot function meant for the OS's own scheduler or a future
  desktop timer (Phase 2)
- `SignatureSet::load_from_cache`: loads persisted signatures plus the always-seeded
  EICAR hash before scanning starts (Phase 2)
- `secureguard-desktop`: Tauri shell wrapping `secureguard-core` directly, in-process,
  no HTTP, no backend server. File-picker-driven scanning, scan history view, manual
  signature sync with immediate in-memory reload (Phase 3)
- `secureguard-helper`: a genuinely separate, privileged process, the only thing that
  ever writes the OS hosts file. Ported hosts-file writer (marker-based rewrite,
  backup-before-write, restore-on-failure) from `system-agent/HostsFileWriter.java`.
  Talks to the desktop app over local IPC (named pipe on Windows, Unix domain socket
  elsewhere), event-driven, not polled (Phase 4)
- `blocked_domains` CRUD (`add_blocked_domain`/`remove_blocked_domain`/
  `list_blocked_domains`) and desktop commands (`block_domain_cmd`/`unblock_domain_cmd`/
  `list_blocked_domains_cmd`) with rollback on helper failure, so local state never
  claims a domain is blocked when the real hosts file wasn't actually updated (Phase 4)
- Release workflow (`release.yml`): triggered on `v*` tags, matrix build across
  Windows/macOS (arm64+x86_64)/Linux via the official `tauri-apps/tauri-action`,
  SHA-256 checksums, GPG-signed checksums file, all attached to a draft GitHub Release
  for manual review before publishing (Phase 5)
- `[workspace.package]` version, single source of truth across all three crates
  (`core`, `desktop/src-tauri`, `helper`), checked against the pushed tag before the
  release workflow builds anything (Phase 5)
- GPG release-signing key setup documentation and install instructions for Windows,
  macOS, and Linux; public key committed to the repo (Phase 5)

### Changed
- Repository split from the main `Dhruv0306/Antivirus` monorepo: the standalone clients
  don't share the `/api/**` contract with the web app, so there's no reason to keep
  them in the same repo, and the toolchain mismatch (Maven/npm vs. cargo/Node) cuts the
  other way, mixing them is more CI complexity, not less
- Repo `.gitignore` fixed twice: originally inherited the main repo's entire Java/Maven
  `.gitignore` by accident (including a generic Eclipse `bin/` rule that shadowed this
  project's own `core/src/bin/`), replaced with one correct for what this repo actually
  is

### Fixed
- **Detection parity:** known-hash and EICAR matches were scoring `THRESHOLD_MALICIOUS`
  (60) instead of the distinct `SCORE_KNOWN_HASH` (100); the verdict tier happened to
  still be correct, the numeric score didn't match `SecurityServiceImpl.java`
- **Detection parity:** entropy scoring had no gating at all originally, applied to
  every file; the Java engine only scores it for files that already look executable (by
  extension or MZ/ELF header), now matched exactly
- **Detection parity:** `ENTROPY_SAMPLE_BYTES` was an unverified guess (8192 bytes) from
  early implementation; the real value is 10 MB (`MAX_PATTERN_SCAN_BYTES`)
- **Detection parity:** the initial scoring engine only implemented 4 of 9 Java scoring
  signals (hash, entropy, generic pattern matching, zip); extension masquerade,
  ransomware extension/text/directory-behavior, rootkit, and trojan-name detection were
  entirely missing, found via a post-implementation checklist review against source,
  not by a test failure
- **Detection parity:** the composite score had no `min(100)` cap, several signals
  stacking could exceed 100 with no ceiling
- `zip_scan.rs`'s suspicious-extension list was an incomplete 10-entry bare-word subset
  of the real 27-entry, dot-prefixed `SUSPICIOUS_EXTENSIONS` set
- `storage::record_scan` existed and was unit-tested since Phase 1 but was never called
  from a real code path; `scg-scan scan` and the desktop app's scan command both
  reported a verdict and silently discarded it instead of recording history
- A hand-typed placeholder hash in a `signature_sync` test was 62 characters instead of
  64, causing a deterministic (not flaky) test failure, all hash fixtures switched to
  `.repeat(64)` construction to remove the whole bug class
- `list_blocked_domains` ordered by `added_at` (second resolution), risking a
  nondeterministic order if two domains were added within the same second in a test;
  switched to `rowid`, monotonic per insert
- `tauri-build`'s build script requires `icon.ico` to exist for any `cargo build` on
  Windows, not only packaging; placeholder icons committed instead of left as a manual
  pre-build step every contributor would otherwise have to remember
- `tauri.conf.json` has its own independent `version` field that only Tauri's own CLI
  syncs automatically from `Cargo.toml`, not a plain `cargo build`; `build.rs` now
  syncs it from `CARGO_PKG_VERSION` explicitly
- CI (`rust-ci.yml`) predated Phase 3's `desktop/src-tauri` workspace member and never
  installed Tauri's Linux system dependencies (GTK/WebKit via pkg-config), failing
  `cargo build --workspace` on a bare `ubuntu-latest` runner

[Unreleased]: https://github.com/Dhruv0306/SecureGuard-Clients/commits/main
