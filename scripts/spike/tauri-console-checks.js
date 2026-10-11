// Phase 5.3 spike: Tests 3 and 4 in one paste. Run in the devtools console of
//   cargo tauri dev --features spike-probes
// (right-click in the app window, Inspect, Console tab; paste this whole file).
//
// The run takes about a minute. Do not touch the app. The control step
// (probe_blocking) is EXPECTED to freeze the window for about 10 seconds: that
// is the measurement, not a hang.
//
// Why these metrics: on Windows the web view renders out of process, so a
// JavaScript timer can keep ticking even while the app's own main thread is
// blocked. Timer gaps alone can therefore look healthy for a frozen app. The
// two decisive signals are (a) how late a trivial second command is answered
// while a probe runs and (b) when the probe-tick events reach the page. The
// timer gap is still printed, for information only.
(async () => {
  const { invoke } = window.__TAURI__.core;
  const { listen, emit } = window.__TAURI__.event;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const rows = [];
  const add = (test, pass, detail) => rows.push({ test, result: pass ? 'PASS' : 'FAIL', detail });
  const LATENCY_LIMIT_MS = 500; // a healthy trivial command answers in single-digit ms
  const TICK_GAP_LIMIT_MS = 1600; // ticks are sent about once per second

  // ---- Test 3: is the event API permitted and working? ----
  try {
    let got = null;
    const unlisten = await listen('probe', (e) => { got = e.payload; });
    await emit('probe', 42);
    await sleep(300);
    unlisten();
    add('T3 listen + emit round trip', got === 42, 'payload=' + got);
  } catch (e) {
    add('T3 listen + emit round trip', false, String(e));
  }

  // ---- Test 4 helper: run one probe and measure how the app behaved ----
  async function measure(name, cmd, { concurrent = 1, cancelAfterMs = null } = {}) {
    const ticks = [];
    const unlisten = await listen('probe-tick', () => ticks.push(performance.now()));
    let hbLast = performance.now();
    let hbMax = 0;
    const hb = setInterval(() => {
      const now = performance.now();
      hbMax = Math.max(hbMax, now - hbLast);
      hbLast = now;
    }, 100);

    const t0 = performance.now();
    const runs = [];
    for (let i = 0; i < concurrent; i++) runs.push(invoke(cmd));
    await sleep(1500); // let the probe(s) get going

    const latencies = [];
    let cancelledAt = null;
    const cancelTimer = cancelAfterMs === null ? null : setTimeout(() => {
      cancelledAt = performance.now();
      invoke('probe_cancel');
    }, Math.max(0, cancelAfterMs - 1500));

    // Ask a trivial command repeatedly while the probe is still running.
    const probeDone = Promise.all(runs);
    let finished = false;
    probeDone.then(() => { finished = true; });
    while (!finished && latencies.length < 3) {
      const s = performance.now();
      await invoke('recent_scans_cmd', { limit: 1 });
      latencies.push(Math.round(performance.now() - s));
      await sleep(300);
    }

    const steps = (await probeDone)[0];
    const total = performance.now() - t0;
    clearInterval(hb);
    if (cancelTimer) clearTimeout(cancelTimer);
    unlisten();

    // Longest silence between tick events, counting from the start of the run.
    let maxTickGap = ticks.length ? ticks[0] - t0 : total;
    for (let i = 1; i < ticks.length; i++) maxTickGap = Math.max(maxTickGap, ticks[i] - ticks[i - 1]);
    const maxLatency = Math.max(...latencies, 0);
    return { name, steps, total, ticks: ticks.length, maxTickGap, maxLatency, latencies, hbMax, cancelledAt, t0 };
  }

  const fmt = (n) => Math.round(n);

  // Control: expected to FAIL the responsiveness bar. That failure is the proof
  // that the measurement can detect a blocked main thread.
  {
    const r = await measure('control: plain fn', 'probe_blocking');
    const blocked = r.maxLatency > LATENCY_LIMIT_MS || r.maxTickGap > TICK_GAP_LIMIT_MS;
    add('T4 control (probe_blocking) shows a stall', blocked,
      `expected a stall: max other-command latency ${fmt(r.maxLatency)} ms, max tick gap ${fmt(r.maxTickGap)} ms, page timer gap ${fmt(r.hbMax)} ms (info only), steps ${r.steps}`);
  }

  for (const [label, cmd] of [['command(async)', 'probe_async'], ['async + spawn_blocking', 'probe_spawn_blocking']]) {
    const r = await measure(label, cmd);
    const ok = r.maxLatency <= LATENCY_LIMIT_MS && r.maxTickGap <= TICK_GAP_LIMIT_MS && r.steps === 100 && r.ticks === 10;
    add(`T4 ${label} stays responsive`, ok,
      `max other-command latency ${fmt(r.maxLatency)} ms, max tick gap ${fmt(r.maxTickGap)} ms, ticks ${r.ticks}/10, steps ${r.steps}, page timer gap ${fmt(r.hbMax)} ms (info only)`);
  }

  for (const [label, cmd] of [['command(async)', 'probe_async'], ['async + spawn_blocking', 'probe_spawn_blocking']]) {
    const r = await measure(label + ' cancel', cmd, { cancelAfterMs: 2500 });
    const elapsedAfterCancel = r.cancelledAt === null ? Infinity : (r.t0 + r.total) - r.cancelledAt;
    const ok = r.steps > 0 && r.steps < 60 && elapsedAfterCancel < 1000;
    add(`T4 ${label} can be cancelled`, ok,
      `steps completed ${r.steps} of 100 (expect about 25), stopped ${fmt(elapsedAfterCancel)} ms after cancel`);
  }

  {
    const r = await measure('3 parallel spawn_blocking', 'probe_spawn_blocking', { concurrent: 3 });
    const ok = r.maxLatency <= LATENCY_LIMIT_MS && r.maxTickGap <= TICK_GAP_LIMIT_MS;
    add('T4 three parallel spawn_blocking probes stay responsive', ok,
      `max other-command latency ${fmt(r.maxLatency)} ms, max tick gap ${fmt(r.maxTickGap)} ms (note: the three share one cancel flag and one tick stream, so tick count is not checked)`);
  }

  console.table(rows);
  const all = rows.every((r) => r.result === 'PASS');
  console.log(all ? 'ALL CHECKS PASSED' : 'SOME CHECKS FAILED, copy the JSON below into the chat');
  console.log(JSON.stringify(rows, null, 2));
  window.__spikeResults = rows;
  return rows;
})();
