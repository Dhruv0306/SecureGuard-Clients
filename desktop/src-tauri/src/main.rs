mod commands;
mod helper_client;
mod scan_control;

use commands::AppState;
use tauri::{ Emitter, Manager };

fn main() {
    // The abuse.ch Auth-Key can live in a .env file (see .env.example).
    // `cargo tauri dev` runs in desktop/src-tauri, so the repository's .env
    // is found in a parent folder.
    secureguard_core::signature_sync::load_env_file();

    tauri::Builder
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

            Ok(())
        })
        .on_window_event(|window, event| {
            // While a scan runs, closing the window asks first: the page shows
            // "Cancel the scan and exit?" and calls cancel_scan_cmd and
            // exit_app_cmd if the user agrees. (macOS Cmd+Q does not go
            // through this path; the scan ends with the process.)
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if commands::close_is_blocked(&window.state::<AppState>()) {
                    api.prevent_close();
                    let _ = window.emit("close-blocked-by-scan", ());
                }
            }
        })
        .invoke_handler(
            tauri::generate_handler![
                commands::scan_file_cmd,
                commands::scan_folder_cmd,
                commands::scan_quick_cmd,
                commands::scan_full_cmd,
                commands::cancel_scan_cmd,
                commands::exit_app_cmd,
                commands::recent_scans_cmd,
                commands::sync_signatures_cmd,
                commands::block_domain_cmd,
                commands::unblock_domain_cmd,
                commands::list_blocked_domains_cmd
            ]
        )
        .run(tauri::generate_context!())
        .expect("error while running SecureGuard desktop shell");
}
