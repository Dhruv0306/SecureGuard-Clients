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
(Administrator or sudo), and compare the process names. Push the branch to run
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

    cd desktop/src-tauri
    cargo tauri dev --features spike-probes

Install the heartbeat once in the devtools console:

    window.__hb = { last: performance.now(), stalls: [] };
    setInterval(() => {
      const now = performance.now(), gap = now - window.__hb.last;
      if (gap > 250) { window.__hb.stalls.push(Math.round(gap)); console.warn('UI stall', Math.round(gap), 'ms'); }
      window.__hb.last = now;
    }, 100);
    const { invoke } = window.__TAURI__.core;
    await window.__TAURI__.event.listen('probe-tick', e => console.log('tick', e.payload));

Each probe runs about 10 seconds and returns the number of 100 ms steps it
completed (100 means it ran to the end).

| Probe | Run | Expected |
|---|---|---|
| Control | `await invoke('probe_blocking')` | one stall of several seconds, window may show Not responding |
| Async | `await invoke('probe_async')` | no stall warnings, window drags smoothly |
| Recommended | `await invoke('probe_spawn_blocking')` | no stall warnings |

Interleaving: start a probe without `await`, then time a normal command.

    invoke('probe_async');
    console.time('other'); await invoke('recent_scans_cmd', { limit: 1 }); console.timeEnd('other');

It should return in milliseconds. With `probe_blocking` it waits behind the probe.

Cancel:

    const p = invoke('probe_spawn_blocking');
    setTimeout(() => invoke('probe_cancel'), 2000);
    console.log('steps completed', await p);   // expect roughly 20, not 100

Parallel load: start `probe_spawn_blocking` three times without `await` and
confirm the heartbeat still reports no stalls.

Note that `probe_async` sleeps on an async runtime worker. That is fine for one
probe but is why the real scan should use the `probe_spawn_blocking` shape.
