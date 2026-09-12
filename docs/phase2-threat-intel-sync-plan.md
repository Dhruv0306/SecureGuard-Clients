# Phase 2: Threat-Intel Sync — Detailed Plan

Branch: `phase2-threat-intel-sync` in `SecureGuard-Clients`.

## Source of truth

Ported from `ThreatIntelSignatureService.java` in the main repo, read in full before
writing this plan, not assumed from its name. Key behaviors that must carry over
exactly:

- Feed: `https://bazaar.abuse.ch/export/txt/sha256/recent/` (multi-URL capable,
  comma/semicolon/whitespace-separated in Java's config string).
- Hash extraction is regex-based (`\b[a-fA-F0-9]{64}\b`) over raw response text, not
  strict line parsing, tolerant of whatever formatting quirks the feed has.
- **Persists the full accumulated signature set on every refresh, not just the new
  fetch.** The feed is a rolling "recent" window; a hash learned on an earlier refresh
  can drop out of a later response. Persisting only the latest fetch would silently
  lose previously-learned signatures on restart. This is the single most important
  behavior to preserve.
- EICAR's own SHA-256 (`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`)
  is seeded into the signature set unconditionally, every run, regardless of whether any
  fetch has ever succeeded. Note this is a *different* mechanism from
  `hash_match::content_is_eicar`'s substring check, both exist, both catch EICAR, via
  different paths, matching Java's own dual coverage.
- Per-feed error handling is deliberately broad: a timeout, non-2xx, or malformed body
  from one feed URL must not abort the refresh or affect other feed URLs, only logs and
  continues.
- No network call ever blocks anything, Java achieves this via a background daemon
  thread; see "Scheduling model" below for how this maps onto a CLI-first crate.

## Storage: reuse the existing `signature_cache` table

No new file format needed. Phase 1's schema already has the right shape:

```sql
CREATE TABLE IF NOT EXISTS signature_cache (
    sha256 TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    added_at INTEGER NOT NULL
);
```

Insert-or-ignore per hash gives the "never lose an old entry" property Java's
full-set-rewrite achieves, for free, without rewriting a whole file each sync.

## Scheduling model: no daemon, a callable sync function

Java runs as a long-lived service with a background thread. Nothing in this crate runs
continuously yet, Phase 3's desktop shell doesn't exist. Inventing a daemon just to have
somewhere to put a background thread would be scope creep, not parity.

Instead: `sync_signatures()` is a plain library function doing one fetch-persist pass,
exposed via a flag/subcommand on `scg-scan` (e.g. `scg-scan --sync-signatures`), left for
the OS's own scheduler (cron, Task Scheduler) to invoke periodically. This is
forward-compatible: when Phase 3's desktop app exists, it can call the same function on
its own schedule instead, no rework needed.

## `SignatureSet` gains a load path

Phase 1's `SignatureSet` is constructed fresh from an explicit hash list per call
(`scg-scan` currently passes an empty one). Phase 2 adds
`SignatureSet::load_from_cache(&Connection) -> SignatureSet`, pulling the persisted
table into memory once at startup, not re-queried per scanned file. The EICAR hash is
seeded unconditionally at load time, matching Java's `init()` behavior exactly, whether
or not a sync has ever run.

`hash_match.rs`'s actual matching logic (`check_hash`, `HashSet<String>` lookup) doesn't
change at all, this phase only changes how the set gets populated before scanning
starts.

## HTTP client

`ureq` is already a dev-dependency (used by the corpus test's fetch). Promoted to a real
dependency here rather than introducing a second HTTP crate.

## Work breakdown

1. **`signature_sync.rs` module**: `sync_signatures(feed_urls: &[&str], conn: &Connection) -> SyncResult`, one fetch-persist pass, broad per-feed error handling (one bad feed logs and continues, never aborts the others).
2. **Regex extraction**: `extract_sha256_signatures(text: &str) -> HashSet<String>`, ported from the Java regex exactly.
3. **`SignatureSet::load_from_cache`**: pulls `signature_cache` into memory, seeds EICAR hash unconditionally.
4. **CLI wiring**: `--sync-signatures` flag/subcommand on `scg-scan`, and `scan` now loads the persisted signature set via step 3 instead of an empty `SignatureSet::new()`.
5. **Test harness**: a local test HTTP server (`ureq` can hit `127.0.0.1` directly, no mocking framework needed) for the stale-cache and fetch-failure test gate the original plan doc specifies.

## Test gate (from the original plan doc, now concrete)

- Local DB populates from a real fetch against the actual MalwareBazaar feed (one
  integration-style test, network-dependent, matching the corpus test's precedent).
- **Stale-cache behavior**: a sync that returns zero new hashes must not delete or shrink
  the existing cache, previously-learned signatures survive an empty/failed fetch.
- **Fetch-failure behavior**: a feed URL returning non-2xx, timing out, or returning
  unparseable content must not crash `sync_signatures()`, must log/report the failure,
  and must leave the existing cache untouched, tested against a local test server
  returning each of these cases deliberately.

## Explicit non-goals for Phase 2

- No background daemon thread or always-running process (see Scheduling model above).
- No UI for triggering or viewing sync status (Phase 3).
- No change to the actual hash-matching logic in `hash_match.rs`.

## Implementation notes (post-planning)

A few decisions made during implementation, not anticipated in the original plan:

- The CLI was restructured from a single positional-argument command into `scan` and
  `sync` subcommands, a deliberate breaking change from Phase 1's `scg-scan <path>`
  usage, to make room for sync as a distinct mode. See `core/README.md` for the updated
  usage.
- The local test HTTP server for the stale-cache/fetch-failure tests is a minimal
  hand-rolled `TcpListener`-based responder (accept one connection, write a fixed
  response, close), not a crate dependency, kept deliberately small since only a handful
  of fixed-response scenarios are needed.
- The "real fetch against the actual MalwareBazaar feed" integration test from the test
  gate above was **not** included: the local-test-server tests already cover the fetch,
  parse, and persistence logic end to end, and a live test against the real feed would
  make CI depend on a third-party service's uptime and content for a signal the local
  tests already provide. Worth revisiting if a live smoke test is wanted later, flagged
  here rather than silently dropped.
