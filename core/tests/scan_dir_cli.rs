//! End-to-end checks of `scg-scan scan-dir`: real process, real folder, real
//! database. Known-bad content is recognized through a seeded signature hash,
//! never a raw EICAR file (Windows Defender blocks those).

use secureguard_core::hash_match::sha256_hex;
use secureguard_core::{ rusqlite, storage };
use std::fs;
use std::path::Path;
use std::process::{ Command, Output };

const BAD: &[u8] = b"known-bad-bytes-for-the-cli-test";

fn scg(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_scg-scan"))
        .args(args)
        .output()
        .expect("failed to run scg-scan")
}

fn seed_signature(db: &Path, content: &[u8]) {
    let conn = storage::open(&db.to_string_lossy()).unwrap();
    conn.execute(
        "INSERT INTO signature_cache (sha256, source, added_at) VALUES (?1, 'test', 0)",
        rusqlite::params![sha256_hex(content)]
    ).unwrap();
}

#[test]
fn reports_json_and_exits_zero_for_a_clean_folder() {
    let dir = tempfile::tempdir().unwrap();
    let scan_root = dir.path().join("tree");
    fs::create_dir_all(scan_root.join("sub")).unwrap();
    fs::write(scan_root.join("a.txt"), b"hello").unwrap();
    fs::write(scan_root.join("sub/b.txt"), b"world").unwrap();
    let db = dir.path().join("test.db");

    let out = scg(&["scan-dir", &scan_root.to_string_lossy(), "--recursive", "--json", "--db", &db.to_string_lossy()]);

    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["scanned"], 2);
    assert_eq!(report["stop_reason"], "completed");
    assert!(report["findings"].as_array().unwrap().is_empty());
}

#[test]
fn flags_a_known_bad_file_and_records_it_to_history() {
    let dir = tempfile::tempdir().unwrap();
    let scan_root = dir.path().join("tree");
    fs::create_dir_all(&scan_root).unwrap();
    fs::write(scan_root.join("bad.bin"), BAD).unwrap();
    fs::write(scan_root.join("ok.txt"), b"fine").unwrap();
    let db = dir.path().join("test.db");
    seed_signature(&db, BAD);

    let out = scg(&["scan-dir", &scan_root.to_string_lossy(), "--json", "--db", &db.to_string_lossy()]);

    assert!(out.status.success(), "a finding is not an error: {}", String::from_utf8_lossy(&out.stderr));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["malicious"], 1);
    assert_eq!(report["findings"][0]["result"]["verdict"], "Malicious");

    let conn = storage::open(&db.to_string_lossy()).unwrap();
    let history = storage::recent_scans(&conn, 10).unwrap();
    assert_eq!(history.len(), 1, "only the non-clean result is recorded");
    assert_eq!(history[0].file_name, "bad.bin");
}

#[test]
fn prints_a_readable_summary_without_json() {
    let dir = tempfile::tempdir().unwrap();
    let scan_root = dir.path().join("tree");
    fs::create_dir_all(&scan_root).unwrap();
    fs::write(scan_root.join("bad.bin"), BAD).unwrap();
    let db = dir.path().join("test.db");
    seed_signature(&db, BAD);

    let out = scg(&["scan-dir", &scan_root.to_string_lossy(), "--db", &db.to_string_lossy()]);

    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(text.contains("Scanned 1 files"), "{text}");
    assert!(text.contains("Findings:"), "{text}");
    assert!(text.contains("bad.bin"), "{text}");
}

#[test]
fn a_missing_folder_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope");
    let db = dir.path().join("test.db");

    let out = scg(&["scan-dir", &missing.to_string_lossy(), "--db", &db.to_string_lossy()]);

    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("is not a folder"));
}

#[test]
fn a_path_or_system_is_required_but_not_both() {
    assert_eq!(scg(&["scan-dir"]).status.code(), Some(2));
    assert_eq!(scg(&["scan-dir", "somewhere", "--system"]).status.code(), Some(2));
}

#[test]
fn the_number_of_workers_does_not_change_the_report() {
    let dir = tempfile::tempdir().unwrap();
    let scan_root = dir.path().join("tree");
    for folder in 0..5 {
        fs::create_dir_all(scan_root.join(format!("f{folder}"))).unwrap();
        for file in 0..10 {
            fs::write(scan_root.join(format!("f{folder}/file{file}.txt")), format!("content {folder} {file}")).unwrap();
        }
        fs::write(scan_root.join(format!("f{folder}/bad{folder}.bin")), format!("bad-{folder}")).unwrap();
    }
    let db = dir.path().join("test.db");
    for folder in 0..5 {
        seed_signature(&db, format!("bad-{folder}").as_bytes());
    }

    let run = |workers: &str| {
        let out = scg(&[
            "scan-dir", &scan_root.to_string_lossy(), "--recursive", "--json",
            "--workers", workers, "--db", &db.to_string_lossy(),
        ]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let mut report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        // Timing and the reuse count legitimately differ.
        report.as_object_mut().unwrap().remove("elapsed_ms");
        report.as_object_mut().unwrap().remove("reused_results");
        report
    };

    let single = run("1");
    assert_eq!(single["malicious"], 5);
    assert_eq!(run("4"), single);
}

#[test]
fn quick_full_system_and_a_path_are_mutually_exclusive() {
    assert_eq!(scg(&["scan-dir", "--quick", "--system"]).status.code(), Some(2));
    assert_eq!(scg(&["scan-dir", "--quick", "--full"]).status.code(), Some(2));
    assert_eq!(scg(&["scan-dir", "--full", "somewhere"]).status.code(), Some(2));
    assert_eq!(scg(&["scan-dir", "--quick", "somewhere"]).status.code(), Some(2));
}

#[test]
fn quick_scan_checks_the_standard_folders_under_the_home_directory() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(home.join("Downloads")).unwrap();
    fs::write(home.join("Downloads").join("bad.bin"), BAD).unwrap();
    fs::write(home.join("Downloads").join("ok.txt"), b"fine").unwrap();
    // Folders that would otherwise be real ones on the machine running the test.
    let nowhere = dir.path().join("nowhere");
    let db = dir.path().join("test.db");
    seed_signature(&db, BAD);

    let out = Command::new(env!("CARGO_BIN_EXE_scg-scan"))
        .args(["scan-dir", "--quick", "--json", "--db", &db.to_string_lossy()])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("TMPDIR", &nowhere)
        .env("TEMP", &nowhere)
        .env("TMP", &nowhere)
        .env("LOCALAPPDATA", &nowhere)
        .env("APPDATA", &nowhere)
        .env("PROGRAMDATA", &nowhere)
        .output()
        .expect("failed to run scg-scan");

    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["scanned"], 2);
    assert_eq!(report["malicious"], 1);
}

#[test]
fn quick_scan_with_no_standard_folders_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let nowhere = dir.path().join("nowhere");
    let db = dir.path().join("test.db");

    let out = Command::new(env!("CARGO_BIN_EXE_scg-scan"))
        .args(["scan-dir", "--quick", "--db", &db.to_string_lossy()])
        .env("HOME", &nowhere)
        .env("USERPROFILE", &nowhere)
        .env("TMPDIR", &nowhere)
        .env("TEMP", &nowhere)
        .env("TMP", &nowhere)
        .env("LOCALAPPDATA", &nowhere)
        .env("APPDATA", &nowhere)
        .env("PROGRAMDATA", &nowhere)
        .output()
        .expect("failed to run scg-scan");

    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("standard folders"));
}
