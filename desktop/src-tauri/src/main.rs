mod commands;
mod helper_client;
#[cfg(feature = "spike-probes")]
mod spike_probes;

use commands::AppState;
use tauri::Manager;

fn main() {
    let builder = tauri::Builder
        ::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // Unlike the CLI, which defaults to a "secureguard.db" file in
            // the current working directory (fine for a short-lived command
            // invoked from wherever), a desktop app needs a real,
            // OS-appropriate persistent location: %APPDATA% on Windows,
            // ~/Library/Application Support on macOS, ~/.local/share on
            // Linux, resolved via Tauri's own path resolver rather than
            // hand-rolling per-OS logic.
            let data_dir = app.path().app_data_dir().expect("failed to resolve app data directory");
            std::fs::create_dir_all(&data_dir).expect("failed to create app data directory");
            let db_path = data_dir.join("secureguard.db");

            let state = AppState::new(&db_path.to_string_lossy()).expect(
                "failed to initialize application state"
            );
            app.manage(state);

            #[cfg(feature = "spike-probes")]
            app.manage(spike_probes::ProbeCancel::default());

            Ok(())
        });

    // Two handler lists on purpose: the spike commands exist only when the
    // throwaway `spike-probes` feature is on. Collapse back to one list when
    // the spike is removed.
    #[cfg(not(feature = "spike-probes"))]
    let builder = builder.invoke_handler(
        tauri::generate_handler![
            commands::scan_file_cmd,
            commands::recent_scans_cmd,
            commands::sync_signatures_cmd,
            commands::block_domain_cmd,
            commands::unblock_domain_cmd,
            commands::list_blocked_domains_cmd
        ]
    );

    #[cfg(feature = "spike-probes")]
    let builder = builder.invoke_handler(
        tauri::generate_handler![
            commands::scan_file_cmd,
            commands::recent_scans_cmd,
            commands::sync_signatures_cmd,
            commands::block_domain_cmd,
            commands::unblock_domain_cmd,
            commands::list_blocked_domains_cmd,
            spike_probes::probe_blocking,
            spike_probes::probe_async,
            spike_probes::probe_spawn_blocking,
            spike_probes::probe_cancel
        ]
    );

    builder
        .run(tauri::generate_context!())
        .expect("error while running SecureGuard desktop shell");
}
