# Phase 5.3 spike: how to run each check

Throwaway branch `phase5.3-net-crate-spike`. Delete `spike_probes.rs`, the
`spike-probes` feature, the cfg blocks in `main.rs`, `net_probe.rs`, the three
dev-dependencies, `net-spike.yml` and `scripts/spike/` once the spike is decided.

## Test 1: does the abuse.ch feed need an Auth-Key?

    # PowerShell
    .\scripts\spike\check-feeds.ps1
    $env:ABUSE_CH_AUTH_KEY = "your-key"; .\scripts\spike\check-feeds.ps1

    # bash / Git Bash
    scripts/spike/check-feeds.sh
    ABUSE_CH_AUTH_KEY=your-key scripts/spike/check-feeds.sh

200 means usable. 401 or 403 means a key is required. 429 means rate limited.
An HTML or JSON body means the plain-text parser would misread it. Check the
`data-with-colon` count: above zero means the feed contains IPv6 entries.

## Test 2: crates and MSRV

    cargo run --locked -p secureguard-core --example net_probe

Must end with `RESULT: PASS`. Run it once normally and once elevated
(Administrator or sudo), and compare the two counters it prints: listening
sockets with a resolved process name, and TCP sockets with an owning pid. Push the branch to run
the three-OS matrix and the MSRV matrix in `.github/workflows/net-spike.yml`.

Known before this spike: the committed `Cargo.lock` already needs Rust 1.93
(`yara-x-parser 1.20.0`), so the 1.74 and 1.85 MSRV jobs are expected to fail.
The open question is whether the new crates build on 1.93 on every OS.

## Test 3: does `core:default` allow event listening?

    cd desktop/src-tauri
    cargo build --locked
    # then open gen/schemas/acl-manifests.json and search for "core:event"

Behavioral check, from the devtools console of `cargo tauri dev`:

    const { listen, emit } = window.__TAURI__.event;
    await listen('probe', e => console.log('got', e.payload));
    await emit('probe', 42);

Pass: the console prints `got 42`. Negative control: remove `core:default` from
`capabilities/default.json`, restart, repeat, expect a "not allowed" error, then
restore the file.

## Test 4: does `command(async)` keep the UI responsive?

Start the app with the probes, open devtools (right-click in the window, then
Inspect, Console tab), and paste the whole of `scripts/spike/tauri-console-checks.js`:

    cd desktop/src-tauri
    cargo tauri dev --features spike-probes

The script runs Test 3 (event listen and emit) and Test 4 in about a minute and
prints a PASS/FAIL table plus JSON. The control step freezes the window for
about 10 seconds on purpose. While it runs, try dragging the window: the
control should be unresponsive and the async probes should not be.

It measures two things that do not depend on how the web view is scheduled:
how late a trivial second command (`recent_scans_cmd`) is answered while a
probe runs, and when the `probe-tick` events reach the page. A page timer gap
is printed for information only. On Windows the web view renders out of
process, so a JavaScript timer can keep ticking while the app's main thread is
blocked. That is why timer gaps alone are not used to decide.

Expected: the control (`probe_blocking`) shows a stall, and `probe_async` and
`probe_spawn_blocking` do not. Both async shapes must cancel within about a
second of `probe_cancel`. `probe_async` sleeps on an async runtime worker,
which is fine for one probe but is why the real scan should use the
`probe_spawn_blocking` shape.
