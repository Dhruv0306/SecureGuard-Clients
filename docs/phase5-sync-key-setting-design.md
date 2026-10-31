# Sync that works in an installed app: design

Date: 31/10/2026. Status: written for review, not yet planned or built.

Item 1 of the next-steps order in the 31/10/2026 handoff. Decision from Dhruv: the Auth-Key
lives in a settings file in the app data folder, not in the OS credential store, for now.

## Problem

Since PR 52, Sync needs a free abuse.ch Auth-Key, read from `ABUSE_CH_AUTH_KEY` (environment
or a `.env` file). An installed app has no `.env` and users do not set environment variables,
so every installed copy answers "MalwareBazaar needs a free Auth-Key". abuse.ch also asks for
no more than one fetch per 5 minutes, and nothing enforces that today.

## Goal and success criteria

A user pastes the key once in the app and Sync works from then on.

- The key survives a restart and is never shown again, logged, or sent to the page.
- No fetch is made less than 5 minutes after the previous one, across restarts.
- A developer's `.env` and the CLI keep working.
- Nothing else changes: scans, the lock rule (no code path holds `conn` and `signatures` at
  once) and the one-scan-or-sync-at-a-time rule stay as they are.

## Two PRs, in this order

PR A adds the cooldown in `secureguard-core`. PR B adds the key setting in the desktop app.
PR A is independent, helps the CLI too, and PR 5.3b can reuse its table.

## PR A: cooldown (core)

Storage. `core/src/storage/migrations/0001_init.sql` gains:

```sql
CREATE TABLE IF NOT EXISTS feed_sync (
    feed TEXT PRIMARY KEY,
    last_attempt_at INTEGER NOT NULL
);
```

`storage::open` runs this file on every open with `execute_batch`, and every statement is
`IF NOT EXISTS`, so existing databases gain the table with no migrator.

Logic. A new function in `signature_sync.rs`:

```rust
pub const MIN_FETCH_GAP_SECS: u64 = 300;
pub fn sync_default_feeds_throttled(conn: &Connection, auth_key: Option<&str>, now: i64)
    -> rusqlite::Result<SyncResult>;
```

- No usable key: behaves as `sync_default_feeds` does now (no request, the missing-key
  message). No cooldown is read or written.
- A key and the last attempt for feed `malwarebazaar` is under `MIN_FETCH_GAP_SECS` ago: no
  request. The result has no new signatures, the current total, no errors, and
  `retry_after_secs: Some(remaining)`.
- Otherwise: record `now` as the last attempt, then fetch. The attempt is recorded before the
  request, so a timeout or a crash still starts the cooldown. That errs on the safe side of
  abuse.ch's limit.
- `remaining = MIN_FETCH_GAP_SECS - (now - last)`, clamped to `0..=MIN_FETCH_GAP_SECS`, so a
  stored time in the future (a clock moved back) waits at most 5 minutes.
- `now` is a parameter so tests need no clock. Callers pass the real time.
- `sync_signatures(&[urls], conn)` is unchanged and is not throttled. The CLI `--feed-url`
  path uses it, and a feed the user names is their choice.

`SyncResult` gains `retry_after_secs: Option<u64>` with `#[serde(default)]`.

Callers. The CLI default sync and `do_sync_with` switch to the throttled function, each
reading the real clock. `do_sync_with(state, key)` keeps its shape, and tests call a variant
that also takes `now`. The CLI prints "synced recently, try again in N s" when throttled.

Missing-key message. It names only `ABUSE_CH_AUTH_KEY` today. It becomes: "MalwareBazaar
needs a free Auth-Key. Get one at https://auth.abuse.ch/ and add it in the app, or set
ABUSE_CH_AUTH_KEY in the environment or a .env file." The test that checks for "Auth-Key"
still holds.

Frontend. `ScanView.syncText` shows "Synced a moment ago. Next fetch allowed in {time}." when
`retry_after_secs` is set, using the existing `formatDuration`.

## PR B: key setting (desktop)

### Storage

- File: `settings.json` next to `secureguard.db` in the app data folder. `AppState` derives the
  path from the database path (`Path::with_file_name`), so `AppState::new` keeps its
  signature and tests use their temp folder.
- Content: `{ "abuse_ch_auth_key": "<key>" }`, written with `serde_json`.
- New module `desktop/src-tauri/src/settings.rs`. No new dependency (`serde` and
  `serde_json` are already used by the crate).
- Writes go to `settings.json.tmp`, then `std::fs::rename` over the real file, so a crash
  leaves the old file or the new one. On Unix the temporary file is created with mode 0600.
  On Windows the app data folder is already private to the user, and no extra ACL is set.
- Plain text. Any process running as the user can read the key. That is accepted because the
  key is free, rate-limited and revocable. Moving to the OS credential store later changes
  only this module.
- A missing file means no key. A file that cannot be parsed is an error that names the path
  and says to fix or delete it. It is never overwritten or deleted automatically, and Save
  and Remove refuse while it is corrupt.

### Which key is used

1. The environment variable. `ABUSE_CH_AUTH_KEY`, then `ABUSECH_AUTH_KEY` (the name the Java
   repository uses). Blank counts as none.
2. The saved key.

A pure function `resolve_auth_key(env, saved) -> Option<(String, KeySource)>` decides, so it
is tested with no environment. `KeySource` is `Environment` or `Settings`.

`.env` loading. `load_env_file()` in the desktop `main` is compiled only in debug builds
(`cfg(debug_assertions)`), so `cargo tauri dev` keeps using the repository `.env` and an
installed build never reads a `.env` from its working folder or a parent. (`ureq` also reads
`ALL_PROXY` and `HTTPS_PROXY` from the environment, so a stray `.env` could otherwise reroute
sync traffic.) The CLI keeps loading `.env`. `.env.example` and `desktop/README.md` say so.

### Commands

All run through `run_blocking` because they touch the disk.

| Command | Returns | Behavior |
|---|---|---|
| `auth_key_status_cmd` | `KeyStatus` | Reports the state. |
| `save_auth_key_cmd(key)` | `KeyStatus` | Validates, writes, reports. |
| `clear_auth_key_cmd` | `KeyStatus` | Removes the saved key, reports. |

`KeyStatus { configured: bool, saved: bool, source: "settings" | "environment" | "none" }`.
It never contains the key. If both exist, `source` is `environment` and `saved` is true, so
the page can still offer Remove.

Validation (`save_auth_key_cmd`): trim; reject empty; reject any whitespace or control
character inside the key; reject more than 256 bytes. The real format of an abuse.ch key is
not documented here, so nothing else is rejected. Error texts are fixed strings and never
contain the input.

`do_sync` resolves the key through `resolve_auth_key`, reading the settings file each time
(a small file, and a save takes effect at once). `do_sync_with(state, key)` keeps its shape
for tests.

The settings struct has a hand-written `Debug` that hides the key, and the key is never
passed to `eprintln!`, `format!` or an error. The existing URL redaction still covers every
network error.

### Page

A `<details id="key-section">` under the header, summary "abuse.ch Auth-Key (needed for
Sync)". It is open when no key is configured and closed otherwise. Inside:

- one line of text saying the key is free and where to get it (plain text, no link, because
  the content security policy allows only the app's own content);
- a password input (`autocomplete="off"`, `spellcheck="false"`), Save, and Remove (hidden
  unless `saved`);
- a status line from `ScanView.keyStatusText(status)`: "No key set", "Key saved", "Key from
  the environment (the saved key is not used)", and so on.

The input is cleared after Save, whatever the result. The key controls are disabled while a
sync runs, joining the existing `refreshControls` rule. Everything from the commands is set
with `textContent`.

## Testing

Tests first: write the test, watch it fail for the right reason, then write the code, and
mutate once to confirm each test can fail.

PR A (core): cooldown blocks a second call under 300 s and allows it at 300 s (fake `now`);
a throttled call makes no request (a local listener that counts connections, as the existing
tests do); no key records nothing; a future `last_attempt_at` waits at most 300 s; the
attempt is recorded even when the request fails; an existing database gains the table;
`retry_after_secs` round-trips through serde and defaults when absent; the missing-key
message still contains "Auth-Key".

PR B (desktop): save then status reports `settings`; environment wins; blank environment
falls back to the saved key; `ABUSECH_AUTH_KEY` is accepted; validation cases; clear removes
the file's key; a corrupt file is an error and is left untouched; save writes through the
temporary file and leaves no `.tmp`; mode 0600 on Unix; the serialized `KeyStatus` and every
error contain no part of the key; `Debug` hides the key. Node: `syncText` with
`retry_after_secs`, `keyStatusText` for each state. The page itself is a short manual
checklist: save, restart, Sync works, Remove, environment override, a sync in progress
disables the key controls.

Gates are the usual four, plus `cargo +1.93 check --workspace --locked` and the Node checks.

## Not in this work

The OS credential store, an in-app link to the abuse.ch site, splitting fetch from persist in
`do_sync` (the database lock is still held during the fetch), a settings screen for anything
else, and unknown-field preservation in `settings.json`.

## Risks and checks

| Risk | Handling |
|---|---|
| `std::fs::rename` replacing an existing file on Windows | Test it by hand on the Windows machine. The CI Windows job covers core and helper only, and `settings.rs` is in the desktop crate, which CI tests on Linux |
| The 256-byte limit rejects a real key | It is a guess. If a real key is longer, raise the limit; nothing else depends on it |
| A refused Save on a corrupt file leaves the user stuck | The message names the path and says to delete the file. Revisit when the file holds more than the key |
| Two writers (two app windows) | Last write wins, and the rename keeps the file whole |
