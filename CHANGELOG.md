# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project uses [Semantic Versioning](https://semver.org/).

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
