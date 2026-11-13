//! Validates the Rust core against the same shared corpus the Java backend's
//! own pressure tests use, per docs/standalone-native-clients-plan.md's
//! "Test corpus sync" design: fetched directly from raw.githubusercontent.com
//! at a pinned commit in the main Antivirus repo, not vendored as a git
//! submodule. Tests fail loudly if the fetch breaks or the pin goes stale,
//! that's an accepted, visible tradeoff for a solo maintainer over the
//! heavier submodule-sync alternative.
//!
//! A download is retried (a reset connection is common on a slow or filtered
//! network), each attempt has a time limit so a stalled one cannot hang the
//! run, and a copy that matches the pinned SHA-256 is kept under `target/` so
//! the next run on the same machine does not download it again. Only content
//! that matches the pinned hash is ever kept or accepted, so none of this
//! weakens the integrity check; a fresh CI checkout still downloads everything.
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
use sha2::{ Digest, Sha256 };
use std::io::Read;
use std::path::Path;
use std::time::Duration;

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
    ("WannaCry", "6cf273e91bb4a2455f08604ed402d151d39ab528ef9901738c45770097b35ebb"),
    ("NotPetya", "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745"),
];

/// Pauses between attempts to download one file: it is tried once, then once
/// after each pause (three attempts in all).
const RETRY_PAUSES: [Duration; 2] = [Duration::from_secs(2), Duration::from_secs(5)];

/// One attempt may take this long in total, so a stalled download turns into a
/// retry instead of waiting for the network to give up.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(40);

/// One attempt to download a corpus file.
fn fetch_known_good_sample(path: &str) -> Result<Vec<u8>, String> {
    let url = format!(
        "https://raw.githubusercontent.com/Dhruv0306/Antivirus/{PINNED_MAIN_REPO_COMMIT}/src/test/resources/known-good-samples/{path}"
    );

    let config = ureq::Agent::config_builder().timeout_global(Some(ATTEMPT_TIMEOUT)).build();
    let agent: ureq::Agent = config.into();

    let response = agent.get(&url).call().map_err(|e| format!("fetching {url}: {e}"))?;

    let mut bytes = Vec::new();
    response
        .into_body()
        .into_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| format!("reading {url}: {e}"))?;

    Ok(bytes)
}

/// Accepts the downloaded content only if it is exactly the pinned file. A
/// download that stops early gives other bytes, so it fails here and is retried.
fn verify_sample(path: &str, bytes: Vec<u8>, expected_sha256: &str) -> Result<Vec<u8>, String> {
    let actual = sha256_hex(&bytes);
    if actual == expected_sha256 {
        Ok(bytes)
    } else {
        Err(
            format!(
                "integrity check failed for {path}: fetched content has SHA-256 {actual} but the pinned \
                 SHA-256 in the main repo's PROVENANCE.md is {expected_sha256}, don't trust this fixture \
                 until that's resolved"
            )
        )
    }
}

/// Runs `fetch` until it works, pausing between attempts as `pauses` says and
/// not after the last one. `sleep` is passed in so tests need not wait.
fn fetch_with_retries(
    mut fetch: impl FnMut() -> Result<Vec<u8>, String>,
    pauses: &[Duration],
    mut sleep: impl FnMut(Duration)
) -> Result<Vec<u8>, String> {
    let attempts = pauses.len() + 1;
    let mut last_error = String::new();
    for attempt in 0..attempts {
        match fetch() {
            Ok(bytes) => {
                return Ok(bytes);
            }
            Err(e) => {
                last_error = e;
                if let Some(pause) = pauses.get(attempt) {
                    sleep(*pause);
                }
            }
        }
    }
    Err(format!("failed after {attempts} attempts, last error: {last_error}"))
}

/// Returns the file from `cache_dir` if a copy with the pinned hash is there,
/// otherwise `fetch`es it and keeps a copy, but only if the copy has the pinned
/// hash. The copy is written under a temporary name and renamed, so an
/// interrupted run never leaves a half file under the real name. Failing to
/// write the cache is not an error: the cache only saves time.
fn cached_or_fetched(
    cache_dir: &Path,
    name: &str,
    expected_sha256: &str,
    fetch: impl FnOnce() -> Result<Vec<u8>, String>
) -> Result<Vec<u8>, String> {
    let cached = cache_dir.join(name);
    if let Ok(bytes) = std::fs::read(&cached) {
        if sha256_hex(&bytes) == expected_sha256 {
            return Ok(bytes);
        }
    }

    let bytes = fetch()?;
    if sha256_hex(&bytes) == expected_sha256 {
        let temporary = cache_dir.join(format!(".{name}.{}.part", std::process::id()));
        let stored = std::fs
            ::create_dir_all(cache_dir)
            .and_then(|()| std::fs::write(&temporary, &bytes))
            .and_then(|()| std::fs::rename(&temporary, &cached));
        if let Err(e) = stored {
            eprintln!("could not cache {name}: {e}");
            let _ = std::fs::remove_file(&temporary);
        }
    }
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

// ---- the download helpers: no network, so they run anywhere ----

#[cfg(test)]
mod download_helpers {
    use super::*;
    use std::cell::{ Cell, RefCell };

    fn temp_cache() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn hash_of(bytes: &[u8]) -> String {
        sha256_hex(bytes)
    }

    // fetch_with_retries

    #[test]
    fn a_fetch_that_works_is_not_repeated_and_never_sleeps() {
        let calls = Cell::new(0);
        let result = fetch_with_retries(
            || {
                calls.set(calls.get() + 1);
                Ok(b"data".to_vec())
            },
            &RETRY_PAUSES,
            |_| panic!("must not sleep")
        );
        assert_eq!(result, Ok(b"data".to_vec()));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn a_fetch_that_fails_once_is_retried_after_the_first_pause() {
        let calls = Cell::new(0);
        let slept = RefCell::new(Vec::new());
        let result = fetch_with_retries(
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 1 { Err("connection reset".to_string()) } else { Ok(b"data".to_vec()) }
            },
            &RETRY_PAUSES,
            |d| slept.borrow_mut().push(d)
        );
        assert_eq!(result, Ok(b"data".to_vec()));
        assert_eq!(calls.get(), 2);
        assert_eq!(*slept.borrow(), vec![RETRY_PAUSES[0]]);
    }

    #[test]
    fn a_fetch_that_keeps_failing_gives_up_with_every_attempt_counted_and_the_last_error() {
        let calls = Cell::new(0);
        let slept = RefCell::new(Vec::new());
        let result = fetch_with_retries(
            || {
                calls.set(calls.get() + 1);
                Err(format!("reset number {}", calls.get()))
            },
            &RETRY_PAUSES,
            |d| slept.borrow_mut().push(d)
        );
        let message = result.unwrap_err();
        assert_eq!(calls.get() as usize, RETRY_PAUSES.len() + 1);
        assert!(message.contains(&format!("{} attempts", RETRY_PAUSES.len() + 1)), "{message}");
        assert!(message.contains("reset number 3"), "the last error is the one shown: {message}");
        assert_eq!(*slept.borrow(), RETRY_PAUSES.to_vec(), "pauses between attempts only, none after the last");
    }

    #[test]
    fn with_no_pauses_there_is_exactly_one_attempt() {
        let calls = Cell::new(0);
        let result = fetch_with_retries(
            || {
                calls.set(calls.get() + 1);
                Err("no".to_string())
            },
            &[],
            |_| panic!("must not sleep")
        );
        assert!(result.is_err());
        assert_eq!(calls.get(), 1);
    }

    // verify_sample

    #[test]
    fn content_with_the_pinned_hash_is_accepted_as_it_is() {
        let bytes = b"real archive".to_vec();
        assert_eq!(verify_sample("a.tar.gz", bytes.clone(), &hash_of(&bytes)), Ok(bytes));
    }

    #[test]
    fn content_with_another_hash_is_refused_and_both_hashes_are_shown() {
        let bytes = b"truncated".to_vec();
        let pinned = hash_of(b"the real one");
        let message = verify_sample("a.tar.gz", bytes.clone(), &pinned).unwrap_err();
        assert!(message.contains("integrity check failed for a.tar.gz"), "{message}");
        assert!(message.contains(&pinned) && message.contains(&hash_of(&bytes)), "{message}");
        assert!(message.contains("don't trust this fixture"), "{message}");
    }

    // cached_or_fetched

    #[test]
    fn a_copy_in_the_cache_with_the_right_hash_is_used_without_fetching() {
        let cache = temp_cache();
        let bytes = b"cached archive".to_vec();
        std::fs::write(cache.path().join("a.tar.gz"), &bytes).unwrap();

        let result = cached_or_fetched(cache.path(), "a.tar.gz", &hash_of(&bytes), || {
            panic!("must not fetch")
        });

        assert_eq!(result, Ok(bytes));
    }

    #[test]
    fn a_copy_in_the_cache_with_the_wrong_hash_is_ignored_and_replaced() {
        let cache = temp_cache();
        let good = b"the real archive".to_vec();
        std::fs::write(cache.path().join("a.tar.gz"), b"half a downl").unwrap();

        let result = cached_or_fetched(cache.path(), "a.tar.gz", &hash_of(&good), || Ok(good.clone()));

        assert_eq!(result, Ok(good.clone()));
        assert_eq!(std::fs::read(cache.path().join("a.tar.gz")).unwrap(), good);
    }

    #[test]
    fn a_fetched_file_is_cached_so_the_next_call_does_not_fetch() {
        let cache = temp_cache().keep();
        let nested = cache.join("corpus").join("commit"); // the folder need not exist yet
        let bytes = b"fresh archive".to_vec();
        let fetches = Cell::new(0);

        for _ in 0..2 {
            let result = cached_or_fetched(&nested, "a.tar.gz", &hash_of(&bytes), || {
                fetches.set(fetches.get() + 1);
                Ok(bytes.clone())
            });
            assert_eq!(result, Ok(bytes.clone()));
        }

        assert_eq!(fetches.get(), 1);
        std::fs::remove_dir_all(cache).ok();
    }

    #[test]
    fn a_failed_fetch_caches_nothing() {
        let cache = temp_cache();
        let result = cached_or_fetched(cache.path(), "a.tar.gz", &hash_of(b"x"), || Err("reset".to_string()));

        assert_eq!(result, Err("reset".to_string()));
        assert_eq!(std::fs::read_dir(cache.path()).unwrap().count(), 0);
    }

    #[test]
    fn content_with_the_wrong_hash_is_never_written_to_the_cache() {
        let cache = temp_cache();
        let result = cached_or_fetched(cache.path(), "a.tar.gz", &hash_of(b"right"), || {
            verify_sample("a.tar.gz", b"wrong".to_vec(), &hash_of(b"right"))
        });

        assert!(result.is_err());
        assert_eq!(std::fs::read_dir(cache.path()).unwrap().count(), 0);
    }

    #[test]
    fn wrong_bytes_that_a_fetch_reports_as_fine_are_returned_but_not_cached() {
        let cache = temp_cache();
        let wrong = b"not the pinned file".to_vec();

        let result = cached_or_fetched(cache.path(), "a.tar.gz", &hash_of(b"right"), || Ok(wrong.clone()));

        assert_eq!(result, Ok(wrong), "the caller's own integrity check still sees what came back");
        assert_eq!(std::fs::read_dir(cache.path()).unwrap().count(), 0, "but it is never kept");
    }

    #[test]
    fn a_successful_cache_write_leaves_only_the_file_itself() {
        let cache = temp_cache();
        let bytes = b"archive".to_vec();
        cached_or_fetched(cache.path(), "a.tar.gz", &hash_of(&bytes), || Ok(bytes.clone())).unwrap();

        let names: Vec<String> = std::fs::read_dir(cache.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["a.tar.gz".to_string()], "no temporary file may be left behind");
    }
}

#[test]
fn known_malware_iocs_are_recognized_by_the_lookup_mechanism() {
    // Not a file-scan test, this project holds no live malware. Mirrors the
    // Java side's own seedSignature/isKnownMalicious lookup-mechanism test
    // exactly, same published hashes, same "was it recognized" question.
    let hashes: Vec<String> = KNOWN_MALWARE_IOCS.iter()
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

    let cache = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("corpus-cache")
        .join(PINNED_MAIN_REPO_COMMIT);

    for sample in KNOWN_GOOD_SAMPLES {
        let bytes = cached_or_fetched(&cache, sample.path, sample.expected_sha256, || {
            fetch_with_retries(
                || {
                    fetch_known_good_sample(sample.path).and_then(|bytes|
                        verify_sample(sample.path, bytes, sample.expected_sha256)
                    )
                },
                &RETRY_PAUSES,
                std::thread::sleep
            )
        }).unwrap_or_else(|e| panic!("failed to get corpus file {}: {e}", sample.path));

        // Checked again on purpose, whatever the helpers did.
        let actual_hash = sha256_hex(&bytes);

        assert_eq!(
            actual_hash,
            sample.expected_sha256,
            "integrity check failed for {}: fetched content doesn't match the pinned SHA-256 \
             in the main repo's PROVENANCE.md, don't trust this fixture until that's resolved",
            sample.path
        );

        let result = score_file(sample.path, &bytes, &SignatureSet::new(), &rules, None);

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

    let result = score_file("eicar.com", eicar, &SignatureSet::new(), &rules, None);

    assert_eq!(
        result.verdict,
        Verdict::Malicious,
        "EICAR should be MALICIOUS, matching ScanAccuracyIT's documented expectation on the \
         Java side (score = 100 via known-hash match there; this engine's own known-hash/EICAR \
         short-circuit produces the same tier, not necessarily the same numeric score)"
    );
}
