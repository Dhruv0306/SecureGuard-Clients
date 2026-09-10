use zip::ZipArchive;

/// Ported from SecurityServiceImpl: contribution per suspicious entry found
/// inside an archive (by extension or header bytes), not a full malicious
/// verdict on its own.
pub const SCORE_ZIP_SUSPICIOUS_ENTRY: i32 = 15;

/// Ratio and absolute-size limits used to flag zip bombs before fully
/// decompressing an archive. A zip bomb is reported as SUSPICIOUS rather
/// than scored against the malware engine, since the archive can't safely
/// be fully read to extract further signals.
const MAX_COMPRESSION_RATIO: u64 = 100;
const MAX_UNCOMPRESSED_BYTES: u64 = 500 * 1024 * 1024; // 500 MB

pub const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    "exe", "dll", "scr", "bat", "cmd", "com", "vbs", "js", "jar", "ps1",
];

#[derive(Debug)]
pub enum ZipCheck {
    /// Compression ratio or total size indicates a zip bomb; caller should
    /// flag SUSPICIOUS and stop, not attempt full extraction.
    LikelyZipBomb,
    /// Archive read normally; contains a score contribution from any
    /// suspicious entries found, and may be zero.
    Scored(i32),
    /// Not a valid zip, or another read error; treated as no contribution
    /// rather than a false positive on a corrupt-but-harmless file.
    NotAZip,
}

pub fn scan_zip(data: &[u8]) -> ZipCheck {
    let cursor = std::io::Cursor::new(data);
    let mut archive = match ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => return ZipCheck::NotAZip,
    };

    let compressed_size = data.len() as u64;
    let mut total_uncompressed: u64 = 0;
    let mut score = 0;

    for i in 0..archive.len() {
        let entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(_) => continue,
        };
        total_uncompressed += entry.size();

        if total_uncompressed > MAX_UNCOMPRESSED_BYTES
            || (compressed_size > 0 && total_uncompressed / compressed_size.max(1) > MAX_COMPRESSION_RATIO)
        {
            return ZipCheck::LikelyZipBomb;
        }

        if entry_is_suspicious(entry.name()) {
            score += SCORE_ZIP_SUSPICIOUS_ENTRY;
        }
    }

    ZipCheck::Scored(score)
}

fn entry_is_suspicious(name: &str) -> bool {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    SUSPICIOUS_EXTENSIONS.contains(&ext.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::FileOptions;

    fn build_test_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut writer = zip::ZipWriter::new(cursor);
            let options = FileOptions::<()>::default();
            for (name, content) in entries {
                writer.start_file(*name, options).unwrap();
                writer.write_all(content).unwrap();
            }
            writer.finish().unwrap();
        }
        buf
    }

    #[test]
    fn not_a_zip_for_garbage_bytes() {
        assert!(matches!(scan_zip(b"not a zip file at all"), ZipCheck::NotAZip));
    }

    #[test]
    fn clean_archive_scores_zero() {
        let data = build_test_zip(&[("readme.txt", b"hello world")]);
        match scan_zip(&data) {
            ZipCheck::Scored(score) => assert_eq!(score, 0),
            other => panic!("expected Scored(0), got {other:?}"),
        }
    }

    #[test]
    fn suspicious_entry_is_scored() {
        let data = build_test_zip(&[("payload.exe", b"MZ fake pe header")]);
        match scan_zip(&data) {
            ZipCheck::Scored(score) => assert_eq!(score, SCORE_ZIP_SUSPICIOUS_ENTRY),
            other => panic!("expected Scored({SCORE_ZIP_SUSPICIOUS_ENTRY}), got {other:?}"),
        }
    }

    #[test]
    fn multiple_suspicious_entries_accumulate_score() {
        let data = build_test_zip(&[
            ("a.exe", b"one"),
            ("b.dll", b"two"),
            ("c.txt", b"clean"),
        ]);
        match scan_zip(&data) {
            ZipCheck::Scored(score) => assert_eq!(score, SCORE_ZIP_SUSPICIOUS_ENTRY * 2),
            other => panic!("expected accumulated score, got {other:?}"),
        }
    }
}
