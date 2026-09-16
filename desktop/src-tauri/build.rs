// Keeps tauri.conf.json's "version" field in lockstep with the workspace
// version (CARGO_PKG_VERSION, sourced from [workspace.package].version via
// this crate's `version.workspace = true`). Tauri's own CLI (`tauri build`/
// `tauri dev`) does this sync automatically, but a plain `cargo build`
// doesn't, a known, commonly hit gap (other real Tauri projects hand-roll
// exactly this same build.rs fix). Without it, tauri.conf.json could
// silently drift from the version this release workflow actually tags and
// builds, done before tauri_build::build() runs so it reads the freshly
// synced value.
fn main() {
    sync_tauri_conf_version();
    tauri_build::build()
}

fn sync_tauri_conf_version() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR not set, cargo invokes build scripts with it");
    let conf_path = std::path::Path::new(&manifest_dir).join("tauri.conf.json");

    let cargo_version = std::env::var("CARGO_PKG_VERSION")
        .expect("CARGO_PKG_VERSION not set, cargo invokes build scripts with it");

    let contents = std::fs::read_to_string(&conf_path)
        .expect("failed to read tauri.conf.json for version sync");

    let needle = format!("\"version\": \"{cargo_version}\"");
    if contents.contains(&needle) {
        return; // already in sync, avoid dirtying the working tree needlessly
    }

    // Simple, deliberately non-clever replacement: match the exact
    // `"version": "...anything..."` line and swap in the current value.
    // A full JSON parse-and-rewrite would risk reformatting the rest of the
    // file (key order, whitespace); this touches only the one field.
    let updated = {
        let re_start = contents.find("\"version\": \"").expect(
            "tauri.conf.json must have a top-level \"version\" field for this sync to update",
        );
        let value_start = re_start + "\"version\": \"".len();
        let value_end = contents[value_start..]
            .find('"')
            .map(|i| value_start + i)
            .expect("malformed version field in tauri.conf.json");
        format!(
            "{}{}{}",
            &contents[..value_start],
            cargo_version,
            &contents[value_end..]
        )
    };

    std::fs::write(&conf_path, updated).expect("failed to write synced tauri.conf.json");

    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:warning=synced tauri.conf.json version to {cargo_version}");
}
