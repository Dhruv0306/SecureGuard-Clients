# Phase 5.3 spike: results and decisions

Date: 11/10/2026. Branch: `phase5.3-net-crate-spike` (throwaway, not merged).

Before building Phase 5.2 (directory and system scan) and Phase 5.3 (network scan),
the [plan](phase5-1-to-5-3-scan-ui-plan.md) rested on five unverified assumptions.
This spike checked each one with a real build or a real run. Everything below was
measured, not assumed, except where a limitation is stated.

## Results

| # | Question | Answer | Evidence |
|---|---|---|---|
| 1 | Do the abuse.ch feeds need an Auth-Key? | No, not today | HTTP 200 with and without a key for both the Feodo recommended list and the MalwareBazaar recent SHA256 export, run from Windows PowerShell with a `ureq`-style User-Agent |
| 2 | Do the network crates build and work on every release OS? | Yes | `net_probe` passed in CI on ubuntu, windows and macos (`--locked`, stable). It binds a loopback listener, connects to it, and asserts that `listeners`, `netstat2` and `if-addrs` each see it |
| 3 | What Rust version does the locked tree really need? | 1.93 | Cargo on 1.85.1 reports `yara-x`, `wasmtime`, `cranelift-*` and `pulley-*` as requiring 1.93.0; Cargo 1.74 cannot parse edition 2024 manifests. `cargo check --locked -p secureguard-core` passed in CI on 1.93 and stable |
| 4 | Does `core:default` allow event listen and emit? | Yes | The generated ACL manifest for tauri 2.11.6 lists `allow-listen`, `allow-unlisten`, `allow-emit`, `allow-emit-to` under `core:event:default`; at runtime a listen and emit round trip returned its payload (branch lockfile: tauri 2.12.1) |
| 5 | Do async Tauri commands keep the app responsive and cancellable? | Yes | See the measurements below |

### Feed details

- Feodo recommended list at the time: 1 IP (11 lines, 10 of them comments), no IPv6.
- MalwareBazaar recent SHA256 export: 1,303 hashes.

### Command responsiveness (Windows, `cargo tauri dev`, tauri 2.12.1)

Each probe runs about 10 seconds. While it runs, a trivial plain command
(`recent_scans_cmd`) is timed.

| Probe | Other-command latency | Tick gap | Result |
|---|---|---|---|
| plain `fn` (control) | 8534 ms | 1004 ms | Blocked: the second command waited for the probe to finish |
| `#[tauri::command(async)]` | 3 ms | 1005 ms | Responsive |
| `async fn` + `spawn_blocking` | 3 ms | 1005 ms | Responsive |
| 3 parallel `spawn_blocking` | 7 ms | 1005 ms | Responsive |
| cancel, either async shape | n/a | n/a | Stopped 87 to 94 ms after the cancel call, at step 26 of 100 |

Two things that did not behave as first assumed:

- A plain `fn` command does block every other command: the control proved that
  commands run on the main thread and queue behind it.
- It did not delay `probe-tick` events (gap stayed about 1 s) or page timers
  (about 111 ms). Only the second-command latency exposed the stall. Any future
  responsiveness test must measure command latency, not timers or event arrival.

## Decisions

### Phase 5.2

1. Long-running commands (directory and system scan) are `async fn` commands that
   run their blocking work in `tauri::async_runtime::spawn_blocking`.
2. Progress is reported with `AppHandle::emit`; cancel is a shared `AtomicBool` in
   managed state, set by a separate async command and checked per directory entry
   and per file.
3. All six existing desktop commands were plain `fn`, so they ran on the main
   thread. That included `sync_signatures_cmd`, which does network I/O, and
   `signature_sync::fetch_feed_text` set no timeout. **Done:** all six are now
   `async fn` commands through one `run_blocking` helper, not only the two slow
   ones. Converting just `sync_signatures_cmd` and `scan_file_cmd` would not have
   been enough: `do_sync` holds the database lock for the whole network fetch, so
   any command left on the main thread that touches the database would still
   freeze the window behind a sync. The feed fetcher now has a 30 s timeout and a
   named User-Agent.
   Still open: `do_sync` holds that database lock during the fetch, so a scan
   waits to record its history until a running sync finishes. Fix by splitting
   fetch from persist in `signature_sync`.
4. Bulk scan history records non-clean results only for now, with no schema
   migration. This is a deliberate shortcut; revisit with a `PRAGMA user_version`
   migrator when per-scan detail is needed.

### Phase 5.3a (local network scan)

1. Use `listeners` 0.6, `netstat2` 0.11 and `if-addrs` 0.15, behind a socket-source
   trait so the findings logic is testable with fakes.
2. The findings engine is a pure function over observations. Severity starts from
   the Java port tables and is lowered one level for loopback-only listeners.
3. Do not port the Java service's simulated suspicious-IP result or its
   flag-based firewall and web-protection booleans. Do not actively probe ports.
4. A row with no resolved process name is shown as "unknown", never hidden.

### Phase 5.3b (threat-intel connection matching)

1. Start with the Feodo list: fetch, cache in SQLite, match established connections
   locally. Tests use a fixture list, because the live list is tiny.
2. Keyless by default. Support an optional `Auth-Key` header from configuration and
   report a 401 or 403 clearly. abuse.ch has announced mandatory authentication
   for its APIs; it is not enforced on these two URLs today.
3. Show how old the cached list is. A stale list gives false confidence.
4. Add a request timeout and a User-Agent to the shared feed fetcher. (Both are
   already in place; see the Phase 5.2 note above.)

### Toolchain

Raise the declared `rust-version` from 1.74 to 1.93 in `core`, `helper` and
`desktop`, and keep a permanent CI job that runs `cargo check --workspace --locked`
on exactly 1.93. The floor is set by YARA-X and wasmtime and will rise with them.

## What the spike did not establish

- Elevated versus normal behavior. Two local Windows runs resolved a process name
  for every listener and an owning PID for every TCP socket (140 of 140, 103 of 103
  in one run). Whether either run was elevated was not confirmed.
- Linux and macOS behavior when unprivileged and other users' sockets are present.
  CI only shows that each OS can see its own process.
- Firewall status, which needs per-OS commands and may need the privileged helper.
  Out of scope for 5.3.
- The `msrv-probe` CI job checked `secureguard-core` only; the permanent job in
  the toolchain PR covers the whole workspace.

## Clean-up

The spike branch holds throwaway probes (a `spike-probes` cargo feature, an
example binary and a CI workflow). It is not merged. Real code lands through fresh
pull requests from `main`.
