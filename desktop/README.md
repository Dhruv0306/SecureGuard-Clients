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

## Requirements

Rust toolchain (same as `core/`), plus Tauri's OS-level prerequisites: WebView2 on
Windows (usually already present), Xcode command line tools on macOS, `webkit2gtk` and
friends on Linux. See the [Tauri v2 prerequisites guide](https://v2.tauri.app/start/prerequisites/).

## Build and run

```bash
cd desktop
npm install
npx tauri icon path/to/a/logo.png   # one-time, only needed before `npm run build`
npm run dev
```

`npm run dev` opens a native window running the app directly against `src/`, no dev
server, no build step, since the frontend is plain static files.

## Testing

```bash
cd src-tauri
cargo test
```

Covers the command layer's actual logic (`do_scan`, `do_recent_scans`, `do_sync`)
directly, this is the automatable half of Phase 3's test gate. The other half, "does
the UI display it correctly", is a manual checklist, see
`docs/phase3-desktop-shell-plan.md`.
