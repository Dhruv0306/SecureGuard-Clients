# Phase 3: Desktop Shell — Detailed Plan

Branch: `phase3-desktop-shell`.

## Scope boundary

A Tauri desktop app wrapping `secureguard-core` directly, in-process, no HTTP, no
backend. Scan a file, see the verdict, see scan history, trigger a signature sync. No
privileged operations of any kind (Phase 4), no release packaging (Phase 5).

## What's already there to build on

Confirmed against current source, not assumed:

```rust
scan_file(path: &Path, signatures: &SignatureSet, rules: &RuleSet) -> io::Result<ScanResult>
storage::open(path: &str) -> SqliteResult<Connection>
storage::record_scan(conn: &Connection, result: &ScanResult) -> SqliteResult<()>
storage::recent_scans(conn: &Connection, limit: i64) -> SqliteResult<Vec<ScanResult>>
signature_sync::sync_signatures(feed_urls: &[&str], conn: &Connection) -> Result<SyncResult>
SignatureSet::load_from_cache(conn: &Connection) -> Result<SignatureSet>
```

Everything Phase 3 needs already exists as library functions. This phase is UI plus a
thin Tauri command layer, not new detection or storage logic.

## The gap this phase needs to close, not just add to

**`record_scan` is never called anywhere except its own unit test.** The CLI's `scan`
subcommand scans and prints a result but never persists it. History has been buildable
since Phase 1's schema but nothing has ever written to it in a real code path. Phase 3
should fix this in the CLI too, not only in the new desktop command, otherwise the CLI
and the desktop app quietly diverge in behavior for no good reason.

## Architecture

```
desktop/
├── src-tauri/
│   ├── Cargo.toml       # depends on secureguard-core via path = "../../core"
│   ├── tauri.conf.json
│   └── src/
│       ├── main.rs
│       └── commands.rs  # #[tauri::command] wrappers
└── src/                 # frontend, plain HTML/CSS/JS, see "Frontend" below
    ├── index.html
    ├── main.js
    └── style.css
```

At the repo root, alongside `core/`, matching the layout the original repo-split plan
specified.

## State management: open once, not per command

The CLI reopens the DB and recompiles the YARA-X rule set on every single invocation,
fine for a short-lived process, wasteful for a long-running desktop app. Tauri commands
should share state initialized once at startup:

```rust
struct AppState {
    conn: Mutex<Connection>,
    rules: RuleSet,
    signatures: Mutex<SignatureSet>,
}
```

Initialized in Tauri's `.setup()` hook, registered via `.manage()`. `signatures` is a
`Mutex` specifically because `sync` needs to replace it in place after a successful
sync, a scan taken right after a sync must see the newly-learned hashes without
restarting the app. `conn` is a `Mutex` because `rusqlite::Connection` isn't `Sync`.

## Tauri commands

| Command | Wraps | Notes |
|---|---|---|
| `scan_file_cmd(path: String)` | `scan_file` + `storage::record_scan` | Persists the result, closing the gap above |
| `recent_scans_cmd(limit: i64)` | `storage::recent_scans` | Backs the history view |
| `sync_signatures_cmd()` | `signature_sync::sync_signatures` | Uses `DEFAULT_FEED_URL`; after success, reloads `state.signatures` via `SignatureSet::load_from_cache` so the change is visible immediately, not just on next restart |

## Frontend: plain HTML/CSS/JS, not a framework

The repo-split plan already decided against reusing the old React frontend. The actual
UI surface here is small: a file picker, a verdict display, a history list, a sync
button. Pulling in React/Vue/Svelte and a build step for that surface is more tooling
than the UI warrants. Plain HTML/CSS calling `invoke()` from Tauri's JS API is enough,
and if the UI grows significantly in a later phase, migrating a small vanilla app to a
framework is a contained, low-risk refactor, not a redesign.

File selection uses Tauri's dialog plugin (`tauri-plugin-dialog`) rather than a raw
`<input type="file">`, since Tauri's webview file inputs don't reliably expose a real
filesystem path back to Rust on all platforms, the dialog plugin does.

## Lessons carried over from the earlier (abandoned) Tauri attempt

The original desktop-shell work in the main repo hit a real bug worth not repeating:
`beforeDevCommand`/`beforeBuildCommand` in `tauri.conf.json` resolve relative to the
directory containing `package.json` (where the `tauri` CLI is invoked from), not
relative to `tauri.conf.json` itself. That attempt also doesn't directly apply here
structurally (this repo's frontend lives inside `desktop/`, not needing to reach across
into a separate top-level `frontend/`), but the underlying lesson, verify path
assumptions against Tauri's actual working-directory behavior rather than the intuitive
guess, still applies to whatever hooks this `tauri.conf.json` ends up needing.

## Test gate (from the original plan doc)

"Manual scan against the same corpus produces matching verdicts through the UI." Manual
verification can't be fully automated away, but two things reduce how much has to be
eyeballed:

1. **Command-level Rust tests**: call the `#[tauri::command]` handler functions
   directly (they're plain Rust functions under the macro, callable without a running
   webview) against the same corpus fixtures Phase 1's `corpus_test.rs` uses. This
   automates the "does the command layer produce the right verdict" question, leaving
   only "does the UI display it correctly" for actual manual checking.
2. **Documented manual checklist**: open the app, scan the EICAR string (saved as a
   local file), scan a known-good file, confirm the displayed verdict matches, confirm
   both appear in the history view, run sync, confirm the signature count updates.

## Explicit non-goals for Phase 3

- No privileged operations, hosts file, firewall, DNS (Phase 4).
- No release packaging or code signing (Phase 5).
- No automatic/background sync scheduling, the sync button is manual, matching Phase
  2's explicit no-daemon decision, a desktop app choosing to call `sync_signatures` on
  its own timer is a reasonable future enhancement, not required to close this phase.

## Implementation notes (post-planning)

- Tauri command return types must implement `serde::Serialize` to cross the IPC
  boundary. `SyncResult` didn't (only `Debug`/`Default`), fixed as its own small commit
  in `core/`.
- Rather than constructing `tauri::State` manually in tests (not a supported pattern,
  Tauri's real test infrastructure is a heavier mock-runtime/IPC-payload setup), the
  command layer is split into plain functions (`do_scan`, `do_recent_scans`, `do_sync`)
  holding the actual logic, with thin `#[tauri::command]` wrappers delegating to them.
  Tests call the plain functions directly, never touching `tauri::State` or Tauri's IPC
  layer at all.
- The desktop app resolves its database path via Tauri's `app.path().app_data_dir()`
  (OS-appropriate: `%APPDATA%`/`~/Library/Application Support`/`~/.local/share`),
  distinct from the CLI's `secureguard.db`-in-cwd default, a desktop app can't assume a
  predictable working directory the way a CLI invocation can.
- No `beforeDevCommand`/`beforeBuildCommand` needed at all: since the frontend is plain
  static HTML/JS/CSS with no build step, `tauri.conf.json` only needs `frontendDist`,
  which sidesteps the whole class of cwd-relative-path bug from the earlier attempt
  by construction, not by being more careful about the same hook.
- Tauri v2's permissions/capabilities system needs an explicit `capabilities/default.json`
  granting `core:default` and `dialog:default`, otherwise the frontend's calls to the
  dialog plugin fail at runtime even with everything wired up correctly on the Rust side.
