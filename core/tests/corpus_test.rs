//! Validates the Rust core against the same shared corpus the Java backend's
//! own pressure tests use, per docs/standalone-native-clients-plan.md's
//! "Test corpus sync" design: fetched directly from raw.githubusercontent.com
//! at a pinned commit in the main Antivirus repo, not vendored as a git
//! submodule. Tests fail loudly if the fetch breaks or the pin goes stale,
//! that's an accepted, visible tradeoff for a solo maintainer over the
//! heavier submodule-sync alternative.
//!
//! Three corpus categories, each mirroring how the Java backend's own tests
//! already validate the same claims (see ScanEvasionIT.java and
//! known-good-samples/PROVENANCE.md in the main repo):
//!
//! 1. Known-malware IOC hashes (WannaCry, NotPetya): the project holds no
//!    live malware, per its own "hash-only IOC data" policy, so this is a
//!    lookup-mechanism test, not a file-scan test, exactly matching how the
//!    Java side's `seedSignature`/`isKnownMalicious` test works.
//! 2. Known-good real-world archives (jq, ripgrep, shellcheck source tarballs):
//!    fetched and integrity-checked against their published SHA-256, then
//!    scored. Asserts verdict != Malicious, not verdict == Clean: entropy
//!    scoring is gated to files that already look executable (by extension
//!    or MZ/ELF header bytes, see extension::is_executable_like_for_entropy),
//!    and .tar.gz qualifies for neither, so these archives are expected to
//!    come back fully CLEAN under this engine. The weaker assertion is kept
//!    anyway to match the Java test's actual documented guarantee
//!    (`knownGoodOpenSourceArchivesAreNeverFlaggedAsMalicious`) rather than a
//!    stronger claim this crate's own corpus test happens to also satisfy.
//! 3. EICAR: the standard test string, in-memory only (not written to disk
//!    in this test, avoiding the same Windows-Defender interaction the
//!    disk-based unit test in lib.rs already documents).

use secureguard_core::hash_match::SignatureSet;
use secureguard_core::scoring::score_file;
use secureguard_core::types::Verdict;
use secureguard_core::yara_scan::RuleSet;
use secureguard_core::DEFAULT_RULES;
use sha2::{Digest, Sha256};
use std::io::Read;

/// Pinned commit in Dhruv0306/Antivirus. Update deliberately when the corpus
/// changes upstream, a stale pin fails loudly (404) rather than silently
/// drifting.
const PINNED_MAIN_REPO_COMMIT: &str = "e8239283fea0a3988bba66e89899ec22bbcc81c2";

struct KnownGoodSample {
    path: &'static str,
    expected_sha256: &'static str,
}

/// Mirrors known-good-samples/PROVENANCE.md in the main repo exactly, same
/// files, same published hashes.
const KNOWN_GOOD_SAMPLES: &[KnownGoodSample] = &[
    KnownGoodSample {
        path: "jq-1.7.1.tar.gz",
        expected_sha256: "fc75b1824aba7a954ef0886371d951c3bf4b6e0a921d1aefc553f309702d6ed1",
    },
    KnownGoodSample {
        path: "ripgrep-14.1.0.tar.gz",
        expected_sha256: "33c6169596a6bbfdc81415910008f26e0809422fda2d849562637996553b2ab6",
    },
    KnownGoodSample {
        path: "shellcheck-0.10.0.tar.gz",
        expected_sha256: "149ef8f90c0ccb8a5a9e64d2b8cdd079ac29f7d2f5a263ba64087093e9135050",
    },
];

/// Mirrors ScanEvasionIT.java's KNOWN_MALWARE_IOCS exactly.
const KNOWN_MALWARE_IOCS: &[(&str, &str)] = &[
    (
        "WannaCry",
        "6cf273e91bb4a2455f08604ed402d151d39ab528ef9901738c45770097b35ebb",
    ),
    (
        "NotPetya",
        "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
    ),
];

fn fetch_known_good_sample(path: &str) -> Vec<u8> {
    let url = format!(
        "https://raw.githubusercontent.com/Dhruv0306/Antivirus/{PINNED_MAIN_REPO_COMMIT}/src/test/resources/known-good-samples/{path}"
    );

    let response = ureq::get(&url)
        .call()
        .unwrap_or_else(|e| panic!("failed to fetch corpus file {path} from {url}: {e}"));

    let mut bytes = Vec::new();

    response
        .into_body()
        .into_reader()
        .read_to_end(&mut bytes)
        .unwrap_or_else(|e| panic!("failed to read corpus file {path}: {e}"));

    bytes
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[test]
fn known_malware_iocs_are_recognized_by_the_lookup_mechanism() {
    // Not a file-scan test, this project holds no live malware. Mirrors the
    // Java side's own seedSignature/isKnownMalicious lookup-mechanism test
    // exactly, same published hashes, same "was it recognized" question.
    let hashes: Vec<String> = KNOWN_MALWARE_IOCS
        .iter()
        .map(|(_, hash)| hash.to_string())
        .collect();

    let signatures = SignatureSet::from_hashes(hashes);

    for (family, hash) in KNOWN_MALWARE_IOCS {
        assert!(
            signatures.contains(hash),
            "expected the real, published {family} IOC hash to be recognized once seeded, \
             matching the same lookup mechanism ScanEvasionIT validates on the Java side"
        );
    }
}

#[test]
fn known_good_archives_are_never_flagged_as_malicious() {
    let rules = RuleSet::compile(DEFAULT_RULES).expect("default rule set should compile");

    for sample in KNOWN_GOOD_SAMPLES {
        let bytes = fetch_known_good_sample(sample.path);

        let actual_hash = sha256_hex(&bytes);

        assert_eq!(
            actual_hash, sample.expected_sha256,
            "integrity check failed for {}: fetched content doesn't match the pinned SHA-256 \
             in the main repo's PROVENANCE.md, don't trust this fixture until that's resolved",
            sample.path
        );

        let result = score_file(
            sample.path,
            &bytes,
            &SignatureSet::new(),
            &rules,
            None,
        );

        // Matches the Java test's actual guarantee, not a stronger one: a
        // gzip archive is inherently high-entropy, SUSPICIOUS from entropy
        // alone is expected and tolerated in both engines. What must never
        // happen is MALICIOUS on a genuinely clean, real-world archive.
        assert_ne!(
            result.verdict,
            Verdict::Malicious,
            "known-good archive {} was flagged MALICIOUS (score {}), this is a false positive \
             on real, unmodified open-source content, matching the false-positive-resistance \
             guarantee the Java backend's ScanEvasionIT already enforces",
            sample.path,
            result.score
        );
    }
}

#[test]
fn eicar_is_detected_matching_the_java_engines_verdict() {
    let rules = RuleSet::compile(DEFAULT_RULES).expect("default rule set should compile");

    let eicar = secureguard_core::hash_match::EICAR_TEST_STRING.as_bytes();

    let result = score_file(
        "eicar.com",
        eicar,
        &SignatureSet::new(),
        &rules,
        None,
    );

    assert_eq!(
        result.verdict,
        Verdict::Malicious,
        "EICAR should be MALICIOUS, matching ScanAccuracyIT's documented expectation on the \
         Java side (score = 100 via known-hash match there; this engine's own known-hash/EICAR \
         short-circuit produces the same tier, not necessarily the same numeric score)"
    );
}
