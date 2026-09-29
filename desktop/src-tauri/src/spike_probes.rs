//! Throwaway Phase 5.3 spike probes. Compiled only with
//! `--features spike-probes`, so a normal build carries none of this.
//!
//! Purpose: settle, with evidence, how Tauri 2.11.6 schedules commands, before
//! the real directory/system scan (Phase 5.2) is built on an assumption.
//!
//!   probe_blocking        plain `fn`            (control: expected to stall the UI)
//!   probe_async           `command(async)` fn   (runs on the async runtime)
//!   probe_spawn_blocking  `async fn` + spawn_blocking (the pattern the real scan should use)
//!   probe_cancel          sets a shared flag, every probe checks it every 100 ms
//!
//! Each probe works for about 10 s in 100 ms steps, emits a `probe-tick` event
//! once per second, and returns how many steps it completed (so a cancel shows
//! up as a number below 100). See docs/spikes/phase5-3-spike.md for the
//! console snippets that drive these.
//!
//! Delete this file, the `spike-probes` feature and the cfg blocks in main.rs
//! once the spike is decided.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager};

#[derive(Default)]
pub struct ProbeCancel(pub AtomicBool);

const STEPS: u32 = 100; // 100 steps x 100 ms = 10 s

fn run_probe(app: &AppHandle) -> Result<u32, String> {
    let cancel = app.state::<ProbeCancel>();
    cancel.0.store(false, Ordering::SeqCst);

    for step in 0..STEPS {
        if cancel.0.load(Ordering::SeqCst) {
            return Ok(step);
        }
        std::thread::sleep(Duration::from_millis(100));
        if step % 10 == 9 {
            app.emit("probe-tick", step + 1).map_err(|e| e.to_string())?;
        }
    }
    Ok(STEPS)
}

/// Control. A plain `fn` command runs on the main thread in Tauri 2, so this
/// is expected to freeze the window for the full 10 s.
#[tauri::command]
pub fn probe_blocking(app: AppHandle) -> Result<u32, String> {
    run_probe(&app)
}

/// `#[tauri::command(async)]` moves a sync fn onto the async runtime.
#[tauri::command(async)]
pub fn probe_async(app: AppHandle) -> Result<u32, String> {
    run_probe(&app)
}

/// The recommended shape for long blocking work (file walking, hashing): an
/// async command that hands the blocking part to a dedicated blocking thread.
#[tauri::command]
pub async fn probe_spawn_blocking(app: AppHandle) -> Result<u32, String> {
    tauri::async_runtime::spawn_blocking(move || run_probe(&app))
        .await
        .map_err(|e| e.to_string())?
}

/// Async so it never depends on the main thread being free.
#[tauri::command(async)]
pub fn probe_cancel(app: AppHandle) {
    app.state::<ProbeCancel>().0.store(true, Ordering::SeqCst);
}
