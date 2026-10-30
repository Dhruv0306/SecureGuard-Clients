# SecureGuard Desktop

Tauri shell wrapping `secureguard-core` directly, in-process. No HTTP, no backend
server, no privileged operations (that's Phase 4).

## Architecture

- `src-tauri/src/commands.rs`: plain functions (`do_scan`, `do_recent_scans`, `do_sync`)
  holding the actual logic, unit-tested directly without touching Tauri's IPC layer,
  plus thin `#[tauri::command]` wrappers around them.
- `src-tauri/src/main.rs`: app startup, resolves an OS-appropriate data directory
  (`%APPDATA%`/`~/Library/Application Support`/`~/.local/share`) for the signature
  database, distinct from the CLI's `secureguard.db`-in-cwd default.
- `src/`: plain HTML/CSS/JS frontend, no framework, no bundler. `window.__TAURI__` is
  injected globally (`withGlobalTauri: true` in `tauri.conf.json`), so there's nothing
  to `npm install` for the frontend itself, only the Tauri CLI.

## Scanning

The **Scan** section scans a folder you choose (with or without subfolders), the places
malware usually lands first (**Quick scan**: Downloads, Desktop, Documents, temp and startup
folders) or every drive (**Full scan**, which asks first). Neither has a time limit and
**Cancel** stops a scan at any time, keeping what it found.

- Findings appear while the scan runs. "Likely malicious" files are listed first; "Worth a
  look" files are in a collapsed group, because they are not confirmed threats.
- Each finding lists why it was flagged in plain language. Hover a reason to see the
  engine's own wording and points.
- Only non-clean results are saved to the history list.
- SecureGuard reports files. It does not quarantine or delete them yet.
- A scan and a signature sync do not run together. Closing the window during a scan asks
  first.

## Signature sync

**Sync signatures** needs the free abuse.ch Auth-Key (<https://auth.abuse.ch/>) in
`ABUSE_CH_AUTH_KEY`, in the environment or in a `.env` file (copy `.env.example`). With
`cargo tauri dev` the repository's `.env` is found. Without a key the status says what to
do. There is no key field in the app yet, so an installed build needs the variable set in
the environment.

## Requirements

Rust toolchain (same as `core/`), plus Tauri's OS-level prerequisites: WebView2 on
Windows (usually already present), Xcode command line tools on macOS, `webkit2gtk` and
friends on Linux. See the [Tauri v2 prerequisites guide](https://v2.tauri.app/start/prerequisites/).

## Build and run

```bash
cd desktop
npm install
npm run dev
```

`npm run dev` opens a native window running the app directly against `src/`, no dev
server, no build step, since the frontend is plain static files.

## Testing

```bash
cd src-tauri
cargo test
```

The scan screen's wording, sorting and formatting (`src/scan-view.js`) is checked under
Node, with no install step:

```bash
node --test desktop/tests/scan-view.test.js
```

Covers the command layer's actual logic (`do_scan`, `do_recent_scans`, `do_sync`)
directly, this is the automatable half of Phase 3's test gate. The other half, "does
the UI display it correctly", is a manual checklist, see
`docs/phase3-desktop-shell-plan.md`.
