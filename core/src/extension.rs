/// Ported verbatim from SecurityServiceImpl.SUSPICIOUS_EXTENSIONS. Used for
/// three distinct purposes there (zip-entry scoring, extension-masquerade
/// gating, and entropy-scoring gating), kept as one shared set here for the
/// same reason: it's one list in the Java source, not three.
pub const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".scr",
    ".js",
    ".vbs",
    ".hta",
    ".sys",
    ".bin",
    ".com",
    ".msi",
    ".pif",
    ".gadget",
    ".msp",
    ".cpl",
    ".msc",
    ".jar",
    ".ps1",
    ".psm1",
    ".vbe",
    ".ws",
    ".wsf",
    ".wsh",
    ".sct",
    ".shb",
    ".tmp",
];

/// Ported verbatim from SecurityServiceImpl.RANSOMWARE_EXTENSIONS.
pub const RANSOMWARE_EXTENSIONS: &[&str] = &[
    ".encrypted",
    ".crypto",
    ".locked",
    ".crypted",
    ".crypt",
    ".vault",
    ".petya",
    ".wannacry",
    ".wcry",
    ".wncry",
    ".locky",
    ".zepto",
    ".thor",
    ".aesir",
    ".zzzzz",
];

/// Ported verbatim from SecurityServiceImpl.COMMON_EXTENSIONS, used only by
/// the ransomware directory-behavior heuristic to decide which sibling-file
/// extensions are unremarkable versus suspiciously novel.
pub const COMMON_EXTENSIONS: &[&str] = &[
    ".txt",
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".java",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".py",
    ".c",
    ".cpp",
    ".h",
    ".css",
    ".html",
    ".htm",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".svg",
    ".ico",
    ".mp3",
    ".mp4",
    ".wav",
    ".avi",
    ".mov",
    ".mkv",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".csv",
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".properties",
    ".gitignore",
    ".env",
    ".log",
    ".sql",
    ".sh",
    ".bat",
    ".ini",
    ".conf",
    ".lock",
    ".toml",
    ".class",
    ".jar",
    ".exe",
    ".dll",
];

/// Ported verbatim from SecurityServiceImpl.TROJAN_NAME_SIGNATURES. Deliberately
/// narrow, high-signal terms, per the Java source's own comment: broad terms
/// like "inject"/"payload"/"downloader" were removed there as too noisy.
pub const TROJAN_NAME_SIGNATURES: &[&str] = &[
    "backdoor",
    "rootkit",
    "trojan",
    "remote_access",
    "stealer",
    "reverse_shell",
    "wscript.shell",
];

/// Matches SecurityServiceImpl.getFileExtension: substring from the last
/// '.', lowercased, including the dot. Empty string if there is no '.'.
pub fn get_file_extension(name: &str) -> String {
    match name.rfind('.') {
        Some(idx) => name[idx..].to_lowercase(),
        None => String::new(),
    }
}

/// Ported verbatim from SecurityServiceImpl.containsSuspiciousBytes: MZ (PE)
/// or ELF magic bytes. Deliberately not used to flag files with executable
/// extensions, only meaningful when the extension claims the file is
/// something else, see check_extension_masquerade.
pub fn contains_suspicious_bytes(header: &[u8]) -> bool {
    if header.len() >= 4 {
        if header[0] == 0x4d && header[1] == 0x5a {
            return true; // "MZ"
        }
        if header[0] == 0x7f && header[1] == 0x45 && header[2] == 0x4c && header[3] == 0x46 {
            return true; // ELF
        }
    }
    false
}

/// Ported verbatim from SecurityServiceImpl.SCORE_EXTENSION_MASQUERADE logic:
/// flags a file only when it is disguised, an executable header hiding
/// behind a non-executable, non-suspicious extension. A .exe legitimately
/// having an MZ header is expected and not scored.
pub fn check_extension_masquerade(extension: &str, header: &[u8]) -> i32 {
    if extension.is_empty() || SUSPICIOUS_EXTENSIONS.contains(&extension) {
        return 0;
    }
    if contains_suspicious_bytes(header) {
        crate::scoring::SCORE_EXTENSION_MASQUERADE
    } else {
        0
    }
}

/// Formats that are compressed by design, so their entropy says nothing about
/// packing. Both are on SUSPICIOUS_EXTENSIONS (a .jar can be run, an .msi
/// installs software), which in the Java engine switched entropy scoring on
/// and flagged every jar and installer package on a machine. Deliberate
/// departure from the Java engine; see docs/java-engine-false-positive-fixes.md.
pub const COMPRESSED_CONTAINER_EXTENSIONS: &[&str] = &[".jar", ".msi"];

/// Adapted from SecurityServiceImpl.isExecutableLikeForEntropy: gates entropy
/// scoring to files that already look executable (by extension or real header
/// bytes), so an ordinary .zip/.jpg/encrypted backup isn't penalized just for
/// being naturally high-entropy. Unlike the Java engine, a compressed
/// container (.jar, .msi) is not "executable-like" by extension alone: it is
/// still checked if its header is really a Windows or Linux executable.
pub fn is_executable_like_for_entropy(extension: &str, header: &[u8]) -> bool {
    if contains_suspicious_bytes(header) {
        return true;
    }
    SUSPICIOUS_EXTENSIONS.contains(&extension) && !COMPRESSED_CONTAINER_EXTENSIONS.contains(&extension)
}

/// True for a native library whose header is exactly what its name promises:
/// an ELF file named .so, .ko, .o or .node (or a versioned .so.1.2), or a
/// Windows executable named .pyd or .node. These are not disguised; flagging
/// them as extension masquerade made every Linux library bundled inside a
/// Windows program (debugpy ships several) look malicious. Deliberate
/// departure from the Java engine. `file_name_lower` is the lowercased name.
pub fn is_expected_native_library(file_name_lower: &str, header: &[u8]) -> bool {
    let is_elf = header.len() >= 4 && header[..4] == [0x7f, b'E', b'L', b'F'];
    let is_pe = header.len() >= 2 && header[..2] == *b"MZ";
    let extension = get_file_extension(file_name_lower);
    let elf_name =
        extension == ".so" ||
        extension == ".ko" ||
        extension == ".o" ||
        extension == ".node" ||
        file_name_lower.contains(".so.");
    let pe_name = extension == ".pyd" || extension == ".node";
    (is_elf && elf_name) || (is_pe && pe_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_extension_with_dot_lowercased() {
        assert_eq!(get_file_extension("Invoice.PDF"), ".pdf");
        assert_eq!(get_file_extension("archive.tar.gz"), ".gz");
        assert_eq!(get_file_extension("noextension"), "");
    }

    #[test]
    fn detects_mz_and_elf_magic_bytes() {
        assert!(contains_suspicious_bytes(b"MZ\x90\x00rest"));
        assert!(contains_suspicious_bytes(b"\x7FELFrest"));
        assert!(!contains_suspicious_bytes(b"PDF-1.4 not executable"));
        assert!(!contains_suspicious_bytes(b"MZ")); // too short, needs 4 bytes
    }

    #[test]
    fn masquerade_requires_non_suspicious_extension_and_real_header() {
        // .txt claiming to be a PE binary: masquerade.
        assert!(check_extension_masquerade(".txt", b"MZ\x90\x00") > 0);
        // .exe with an MZ header: expected, not masquerade.
        assert_eq!(check_extension_masquerade(".exe", b"MZ\x90\x00"), 0);
        // .txt with ordinary content: no masquerade.
        assert_eq!(check_extension_masquerade(".txt", b"just text"), 0);
    }

    #[test]
    fn entropy_gate_matches_suspicious_extension_or_real_header() {
        assert!(is_executable_like_for_entropy(".bin", b"anything"));
        assert!(is_executable_like_for_entropy(".txt", b"MZ\x90\x00"));
        assert!(!is_executable_like_for_entropy(".txt", b"just text"));
    }

    #[test]
    fn compressed_containers_are_not_executable_like_unless_the_header_says_so() {
        let text = b"PK\x03\x04 not an exe";
        assert!(!is_executable_like_for_entropy(".jar", text));
        assert!(!is_executable_like_for_entropy(".msi", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"));
        // Still gated on when the bytes really are a Windows or Linux executable.
        assert!(is_executable_like_for_entropy(".jar", b"MZ\x90\x00"));
        assert!(is_executable_like_for_entropy(".jar", b"\x7fELF\x02\x01\x01\x00"));
        // Other executable-looking extensions are unchanged.
        assert!(is_executable_like_for_entropy(".exe", b"anything"));
        assert!(is_executable_like_for_entropy(".dll", b"anything"));
        assert!(!is_executable_like_for_entropy(".dat", b"anything"));
    }

    #[test]
    fn native_libraries_with_a_matching_header_are_expected() {
        let elf = b"\x7fELF\x02\x01\x01\x00";
        for name in ["libfoo.so", "libfoo.so.1", "libfoo.so.1.2.3", "mod.ko", "x.o", "addon.node"] {
            assert!(is_expected_native_library(name, elf), "{name} with an ELF header");
        }
        assert!(is_expected_native_library("module.pyd", b"MZ\x90\x00"));
        assert!(is_expected_native_library("addon.node", b"MZ\x90\x00"));
    }

    #[test]
    fn a_disguised_executable_is_still_not_expected() {
        let elf = b"\x7fELF\x02\x01\x01\x00";
        let pe = b"MZ\x90\x00\x03\x00\x00\x00";
        assert!(!is_expected_native_library("report.pdf", elf));
        assert!(!is_expected_native_library("photo.jpg", pe));
        assert!(!is_expected_native_library("libfoo.so", pe), "a Windows executable named .so");
        assert!(!is_expected_native_library("module.pyd", elf), "a Linux executable named .pyd");
        assert!(!is_expected_native_library("libfoo.so", b"plain text"));
    }
}
