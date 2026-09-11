# Phase 1: Detection Core — Detailed Plan

Branch: `phase1-detection-core` (in `SecureGuard-Clients`, no `clients/` prefix needed
here since there's no longer a numbering collision with the main repo).

## Scope boundary

A Rust library crate that scans a file and returns a verdict (`CLEAN`/`SUSPICIOUS`/
`MALICIOUS`) using the same rules as the Java backend's `SecurityServiceImpl`, plus a
CLI binary for testing it and a local SQLite store for results. No UI, no Tauri, no
Android, no privileged operations, no network sync beyond loading a pre-seeded signature
set from disk. Phase 2 adds live MalwareBazaar sync; Phase 3 adds the desktop UI around
this crate.

## Constants ported as spec, not reverse-engineered

Pulled directly from `SecurityServiceImpl.java` so there's no ambiguity about what
"parity" means:

```rust
const THRESHOLD_HIGH_ENTROPY: f64 = 7.2;   // bits/byte, packer detection
const THRESHOLD_MALICIOUS: i32 = 60;
const THRESHOLD_SUSPICIOUS: i32 = 25;
const SCORE_ZIP_SUSPICIOUS_ENTRY: i32 = 15;
```
Other scoring weights (`SCORE_HIGH_ENTROPY`, `SCORE_STRONG_PATTERN`, rootkit-specific
scoring) need pulling from the same file during implementation, this list is the ones
already confirmed, not the complete set. Treat `SecurityServiceImpl.java` as the source
of truth for every constant, don't estimate or re-derive any of them.

## Crate layout

```
core/
├── Cargo.toml
├── src/
│   ├── lib.rs              # public API: scan_file(path) -> ScanResult
│   ├── types.rs            # ScanResult, Verdict, ThreatType (serde-serializable)
│   ├── hash_match.rs       # exact-hash signature matching (fast path), EICAR handling
│   ├── yara_scan.rs        # YARA-X integration: rule compilation, buffer scanning
│   ├── entropy.rs          # Shannon entropy calc, THRESHOLD_HIGH_ENTROPY packer flag
│   ├── zip_scan.rs         # archive scanning: zip bomb limits, suspicious entries
│   ├── scoring.rs          # weighted scoring engine, ties the above into a verdict
│   └── storage/
│       ├── mod.rs
│       ├── schema.rs       # SQLite schema (rusqlite)
│       └── migrations/     # versioned .sql files
├── src/bin/
│   └── scg-scan.rs         # CLI: scans a path, prints/exports ScanResult as JSON
└── tests/
    ├── corpus_test.rs      # runs the shared IOC/known-good/EICAR corpus, asserts verdicts
    └── fixtures/           # small local fixtures that don't need network fetch (EICAR etc.)
```

## Dependencies (pinned, tracked under Dependabot's new `cargo` ecosystem)

| Crate | Purpose |
|---|---|
| `yara-x` | Pattern-based signature matching (VirusTotal, BSD-3-Clause) |
| `rusqlite` | Local embedded storage |
| `sha2` | Hash-based signature matching |
| `serde` / `serde_json` | `ScanResult` serialization, corpus fixture format |
| `clap` | CLI argument parsing for `scg-scan` |
| `zip` | Archive extraction for `zip_scan.rs` |

`zip` and any file-type-sniffing crate added later are supply-chain-relevant per the
risk register, pin versions and let Dependabot flag advisories rather than pulling
latest unpinned.

## Work breakdown (commits within the branch, grouped by theme)

1. **Workspace + crate scaffold.** `Cargo.toml`, dependency pins, empty module stubs,
   CI skeleton (`cargo build`, `cargo test` on push). No detection logic yet, this just
   proves the crate builds and CI runs.
2. **Hash-based matching + EICAR handling.** The fast, low-risk path: exact SHA-256
   comparison against a locally loaded signature set. Port the existing EICAR test-file
   handling exactly, that's the file most likely to be used for a first sanity check.
3. **Entropy detection.** `entropy.rs`, Shannon entropy over a byte sample, flags at
   `THRESHOLD_HIGH_ENTROPY`. Self-contained, easy to unit-test independently with
   synthetic high/low-entropy byte buffers before touching real files.
4. **YARA-X integration.** Compile a rule set, scan a buffer, surface matches through
   `types.rs`. This is the piece most worth extra test time, since it's the third-party
   dependency this plan is built around.
5. **Archive scanning.** `zip_scan.rs`, zip bomb size/ratio limits and
   `SCORE_ZIP_SUSPICIOUS_ENTRY` scoring, ported from the Java implementation's ZIP
   handling.
6. **Scoring engine.** `scoring.rs` ties hash/YARA/entropy/zip signals into the
   `THRESHOLD_SUSPICIOUS`/`THRESHOLD_MALICIOUS` verdict tiers. This is where drift from
   the Java engine is most likely to creep in, so it's the last piece before corpus
   validation, everything it depends on should already be individually tested.
7. **Local storage.** SQLite schema for scan results and the signature cache table
   (signature *sync* is Phase 2, but the table shape belongs in Phase 1 alongside the
   rest of the schema).
8. **CLI harness.** `scg-scan` binary, JSON output, this is what both the corpus test
   and the cross-engine diff job actually invoke.
9. **Corpus validation.** `tests/corpus_test.rs` fetches the shared test corpus from
   `raw.githubusercontent.com` at a pinned commit SHA in the main `Antivirus` repo (per
   the repo-split plan), runs it through `scg-scan`, asserts verdicts match the expected
   labels (known-malware IOCs, known-good set, EICAR).
10. **Cross-engine diff job.** A CI job, not a Rust test, since it needs to run the Java
    backend too: both engines scan the same corpus and each emits a JSON report
    (file hash → verdict). A script diffs the two reports. Exact match required for
    hash-based and EICAR cases; scoring-based edge cases are allowed to warn rather than
    fail initially, tightened to a hard fail once parity is actually reached, tracked as
    a named follow-up rather than silently left permissive forever.

## Exit criteria for Phase 1

- `cargo test` passes locally and in CI.
- `corpus_test.rs` passes against the pinned corpus commit.
- Cross-engine diff job runs and reports zero mismatches on hash/EICAR cases (scoring
  parity can still be in "warn" mode at this point, see item 10).
- `scg-scan somefile` produces a verdict from the command line with no server, no
  network call beyond the one-time corpus fetch in tests, and no privileged operation of
  any kind.

## Explicit non-goals for Phase 1

- No UI (Phase 3).
- No live threat-intel sync (Phase 2), Phase 1 loads a static, pre-seeded signature set.
- No UniFFI/Android bindings (Phase 6).
- No privileged helper (Phase 4), nothing in this phase touches hosts files, firewall
  rules, or DNS.
