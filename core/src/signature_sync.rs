//! Ported from ThreatIntelSignatureService.java. Two behaviors carried over
//! deliberately exactly:
//!
//! 1. **Persists the full accumulated signature set, not just the new
//!    fetch.** MalwareBazaar's "recent" export is a rolling window; a hash
//!    learned on an earlier sync can drop out of a later response. Storing
//!    only the latest fetch would silently lose previously-learned
//!    signatures. Insert-or-ignore into the persisted `signature_cache`
//!    table gives this property without needing Java's full-file-rewrite
//!    approach, the table already only grows.
//! 2. **A bad feed never aborts the others.** Each feed URL is fetched and
//!    parsed independently; a timeout, non-2xx response, or unparseable
//!    body is recorded as an error for that URL and the sync continues.
//!
//! What's deliberately different from Java: no background daemon thread.
//! Nothing in this crate runs continuously yet (Phase 3's desktop shell
//! doesn't exist), so `sync_signatures` is a plain, callable, one-shot
//! function, meant to be invoked by the OS's own scheduler (cron, Task
//! Scheduler) via a CLI flag, or later by the desktop app on its own
//! schedule. See docs/phase2-threat-intel-sync-plan.md for the full
//! reasoning.

use regex::Regex;
use rusqlite::{ params, Connection };
use std::collections::HashSet;
use std::sync::OnceLock;
use std::time::{ Duration, SystemTime, UNIX_EPOCH };

/// Ported verbatim from ThreatIntelSignatureService.EICAR_SHA256: seeded
/// unconditionally by SignatureSet::load_from_cache, whether or not any
/// sync has ever succeeded.
pub const EICAR_SIGNATURE_SHA256: &str =
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

/// Where the abuse.ch Auth-Key is read from: an environment variable, which
/// the CLI and the desktop app can also fill from a `.env` file.
pub const AUTH_KEY_ENV: &str = "ABUSE_CH_AUTH_KEY";

/// abuse.ch made its exports require a free Auth-Key (the old keyless
/// `/export/txt/sha256/recent/` URL now answers 410). The documented form
/// puts the key in the path of the CSV export, which lists the hashes added
/// in the last 48 hours and is refreshed every 5 minutes.
const MALWAREBAZAAR_EXPORT_BASE: &str = "https://mb-api.abuse.ch/v2/files/exports";

fn missing_key_message() -> String {
    format!(
        "MalwareBazaar needs a free Auth-Key. Get one at https://auth.abuse.ch/ and set {AUTH_KEY_ENV}."
    )
}

/// Trims the key and treats an empty or blank value as no key.
pub fn auth_key_from(value: Option<String>) -> Option<String> {
    value
        .map(|key| key.trim().to_string())
        .filter(|key| !key.is_empty())
}

pub fn auth_key_from_env() -> Option<String> {
    auth_key_from(std::env::var(AUTH_KEY_ENV).ok())
}

/// Everything except letters, digits and `-._~` is percent-encoded, so a key
/// can never add a path segment, a query or a fragment to the URL.
fn percent_encode_unreserved(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The MalwareBazaar "recent" export URL for this key. The URL contains the
/// key, so it must never be shown or stored as it is: see [`redact_feed_url`].
pub fn malwarebazaar_feed_url(auth_key: &str) -> Result<String, String> {
    let key = auth_key.trim();
    if key.is_empty() {
        return Err("the Auth-Key is empty".to_string());
    }
    Ok(format!("{MALWAREBAZAAR_EXPORT_BASE}/{}/recent.csv", percent_encode_unreserved(key)))
}

/// The URL with any Auth-Key hidden: the path segment after `/exports/` (when
/// more path follows it) and the value of an `auth-key=` query parameter.
/// Used for every error and for the `source` stored with each signature.
pub fn redact_feed_url(url: &str) -> String {
    let mut out = url.to_string();
    if let Some(at) = out.find("/exports/") {
        let start = at + "/exports/".len();
        if let Some(slash) = out[start..].find('/') {
            out.replace_range(start..start + slash, "***");
        }
    }
    let lower = out.to_ascii_lowercase();
    if let Some(at) = lower.find("auth-key=") {
        let start = at + "auth-key=".len();
        let end = out[start..].find(['&', '#']).map_or(out.len(), |offset| start + offset);
        out.replace_range(start..end, "***");
    }
    out
}

fn sha256_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    // Ported verbatim from ThreatIntelSignatureService: a loose regex over
    // raw response text rather than strict line parsing, tolerant of
    // whatever formatting quirks the feed export has.
    PATTERN.get_or_init(|| Regex::new(r"\b[a-fA-F0-9]{64}\b").expect("sha256 pattern must compile"))
}

/// Ported from ThreatIntelSignatureService's hash-extraction logic.
pub fn extract_sha256_signatures(text: &str) -> HashSet<String> {
    sha256_pattern()
        .find_iter(text)
        .map(|m| m.as_str().to_lowercase())
        .collect()
}

#[derive(Debug, Default, serde::Serialize)]
pub struct SyncResult {
    /// Count of hashes newly inserted this sync (already-known hashes are
    /// not counted again).
    pub new_signatures: usize,
    /// Total row count in signature_cache after this sync.
    pub total_signatures: usize,
    /// One entry per feed URL that failed, empty on full success. A
    /// non-empty list does not mean the whole sync failed, only that some
    /// feeds did not contribute this round, matching Java's
    /// one-bad-feed-never-aborts-the-others behavior.
    pub feed_errors: Vec<String>,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Upper bound for one whole feed request: connecting, sending, waiting and
/// reading the body. Without a bound, a feed that accepts the connection and
/// then goes quiet would hang the sync, and with it any caller waiting on it.
pub const FEED_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Identifies this client to feed operators. Some reject or rate-limit
/// anonymous library defaults, and a named agent makes our traffic easy for
/// them to recognize.
const FEED_USER_AGENT: &str = concat!(
    "SecureGuard-Clients/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/Dhruv0306/SecureGuard-Clients)"
);

fn fetch_feed_text(url: &str) -> Result<String, String> {
    fetch_feed_text_with(url, FEED_REQUEST_TIMEOUT)
}

fn fetch_feed_text_with(url: &str, timeout: Duration) -> Result<String, String> {
    use std::io::Read;

    let config = ureq::Agent
        ::config_builder()
        .timeout_global(Some(timeout))
        .user_agent(FEED_USER_AGENT)
        .build();
    let agent: ureq::Agent = config.into();

    // The URL can contain the Auth-Key, so only this form is ever shown.
    let shown = redact_feed_url(url);

    let response = agent
        .get(url)
        .call()
        .map_err(|e| {
            let message = match e {
                // abuse.ch requires an Auth-Key; say so plainly instead of
                // leaving a bare status code.
                ureq::Error::StatusCode(code @ (401 | 403)) =>
                    format!(
                        "request to {shown} was not accepted (HTTP {code}); check the Auth-Key in {AUTH_KEY_ENV}"
                    ),
                other => format!("request to {shown} failed: {other}"),
            };
            // Whatever the library put in its own error text.
            message.replace(url, &shown)
        })?;

    let mut text = String::new();
    response
        .into_body()
        .into_reader()
        .read_to_string(&mut text)
        .map_err(|e| format!("failed to read response body from {shown}: {e}").replace(url, &shown))?;
    Ok(text)
}

/// One fetch-persist pass over every feed URL. Never panics on a bad feed,
/// records the failure in `feed_errors` and continues to the next URL.
pub fn sync_signatures(feed_urls: &[&str], conn: &Connection) -> rusqlite::Result<SyncResult> {
    let mut result = SyncResult::default();

    for &url in feed_urls {
        match fetch_feed_text(url) {
            Ok(text) => {
                let hashes = extract_sha256_signatures(&text);
                let added_at = now_unix();
                for hash in hashes {
                    let inserted = conn.execute(
                        "INSERT OR IGNORE INTO signature_cache (sha256, source, added_at) \
                         VALUES (?1, ?2, ?3)",
                        params![hash, redact_feed_url(url), added_at]
                    )?;
                    if inserted > 0 {
                        result.new_signatures += 1;
                    }
                }
            }
            Err(e) => {
                result.feed_errors.push(e);
            }
        }
    }

    result.total_signatures = conn.query_row("SELECT COUNT(*) FROM signature_cache", [], |row|
        row.get::<_, i64>(0)
    )? as usize;

    Ok(result)
}

/// The default feed, MalwareBazaar's recent export, which needs an Auth-Key.
/// With no key it makes no request and says what to do; what was learned
/// before stays in the cache either way.
pub fn sync_default_feeds(conn: &Connection, auth_key: Option<&str>) -> rusqlite::Result<SyncResult> {
    let Some(key) = auth_key_from(auth_key.map(str::to_string)) else {
        let mut result = sync_signatures(&[], conn)?;
        result.feed_errors.push(missing_key_message());
        return Ok(result);
    };
    match malwarebazaar_feed_url(&key) {
        Ok(url) => sync_signatures(&[&url], conn),
        Err(_) => {
            let mut result = sync_signatures(&[], conn)?;
            result.feed_errors.push(missing_key_message());
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage;
    use std::io::{ BufRead, BufReader, Write };
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn extracts_sha256_hashes_from_loosely_formatted_text() {
        let text =
            "\
            # some comment line\n\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
            not-a-hash-at-all\n\
            BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB, trailing text\n";
        let hashes = extract_sha256_signatures(text);
        assert_eq!(hashes.len(), 2);
        assert!(
            hashes.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert!(
            hashes.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
    }

    /// Minimal single-request test HTTP server: accepts one connection,
    /// writes a fixed response, closes. No mocking framework needed, ureq
    /// can hit 127.0.0.1 directly, matching the plan doc's stated approach.
    fn spawn_single_response_server(body: &'static str, status_line: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind test server");
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // Drain the request line/headers, don't need to parse them.
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                let response = format!(
                    "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{addr}/")
    }

    /// Accepts one connection and then says nothing, like a feed that has
    /// stalled. Holds the socket open well past any test timeout.
    fn spawn_silent_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                thread::sleep(Duration::from_secs(5));
                drop(stream);
            }
        });
        format!("http://{addr}/")
    }

    /// Like spawn_single_response_server, but also hands back the raw request
    /// headers so a test can inspect what the client sent.
    fn spawn_capturing_server() -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                let mut line = String::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    request.push_str(&line);
                }
                let _ = tx.send(request);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
            }
        });
        (format!("http://{addr}/"), rx)
    }

    #[test]
    fn a_stalled_feed_times_out_instead_of_hanging() {
        let url = spawn_silent_server();
        let started = std::time::Instant::now();

        let result = fetch_feed_text_with(&url, Duration::from_millis(300));

        assert!(result.is_err(), "a feed that never answers must be an error");
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "timeout did not fire promptly, took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn feed_requests_identify_themselves_with_a_user_agent() {
        let (url, requests) = spawn_capturing_server();

        fetch_feed_text(&url).unwrap();

        let request = requests.recv_timeout(Duration::from_secs(5)).unwrap().to_lowercase();
        assert!(
            request.contains("user-agent: secureguard-clients/"),
            "expected a SecureGuard-Clients user agent, request was:\n{request}"
        );
    }

    #[test]
    fn a_rejected_feed_error_mentions_the_auth_key() {
        let url = spawn_single_response_server("", "HTTP/1.1 403 Forbidden");

        let error = fetch_feed_text(&url).unwrap_err();

        assert!(error.contains("403"), "error should carry the status code: {error}");
        assert!(error.contains("Auth-Key"), "error should explain the likely cause: {error}");
    }

    #[test]
    fn syncs_new_signatures_from_a_local_feed() {
        let conn = storage::open_in_memory().unwrap();
        let hash = "c".repeat(64);
        let url = spawn_single_response_server(hash.leak(), "HTTP/1.1 200 OK");

        let result = sync_signatures(&[&url], &conn).unwrap();

        assert_eq!(result.new_signatures, 1);
        assert_eq!(result.total_signatures, 1);
        assert!(result.feed_errors.is_empty());
    }

    #[test]
    fn stale_cache_survives_a_fetch_that_returns_nothing_new() {
        let conn = storage::open_in_memory().unwrap();
        let existing = "d".repeat(64);
        conn.execute(
            "INSERT INTO signature_cache (sha256, source, added_at) VALUES (?1, 'seed', 0)",
            params![existing]
        ).unwrap();

        // Feed responds successfully but with no hashes in the body.
        let url = spawn_single_response_server("no signatures here", "HTTP/1.1 200 OK");
        let result = sync_signatures(&[&url], &conn).unwrap();

        assert_eq!(result.new_signatures, 0);
        assert_eq!(
            result.total_signatures,
            1,
            "a previously-learned signature must survive an empty fetch, not be lost"
        );
    }

    #[test]
    fn one_bad_feed_does_not_abort_or_affect_a_good_one() {
        let conn = storage::open_in_memory().unwrap();
        let good_hash = "e".repeat(64);

        let bad_url = spawn_single_response_server("", "HTTP/1.1 500 Internal Server Error");
        let good_url = spawn_single_response_server(good_hash.leak(), "HTTP/1.1 200 OK");

        let result = sync_signatures(&[&bad_url, &good_url], &conn).unwrap();

        assert_eq!(result.feed_errors.len(), 1, "the bad feed should be recorded as an error");
        assert_eq!(
            result.new_signatures,
            1,
            "the good feed should still contribute despite the other feed failing"
        );
    }

    #[test]
    fn unreachable_feed_is_recorded_as_an_error_not_a_panic() {
        let conn = storage::open_in_memory().unwrap();
        // Port 1 is reserved/unlikely to have a listener; connection should
        // simply fail rather than hang or panic.
        let result = sync_signatures(&["http://127.0.0.1:1/"], &conn).unwrap();
        assert_eq!(result.feed_errors.len(), 1);
        assert_eq!(result.new_signatures, 0);
    }

    // --- Auth-Key handling (abuse.ch made the export require one) ---

    const KEY: &str = "SECRETKEY123";

    /// A feed URL shaped like abuse.ch's, with the key in the path, but
    /// served by a local test server.
    fn keyed_local_url(base: &str) -> String {
        format!("{base}v2/files/exports/{KEY}/recent.csv")
    }

    #[test]
    fn the_feed_url_puts_the_key_where_abuse_ch_documents_it() {
        assert_eq!(
            malwarebazaar_feed_url("abc-123_XYZ").unwrap(),
            "https://mb-api.abuse.ch/v2/files/exports/abc-123_XYZ/recent.csv"
        );
    }

    #[test]
    fn a_key_cannot_change_the_rest_of_the_url() {
        let url = malwarebazaar_feed_url("a/b?c#d e").unwrap();
        assert_eq!(
            url,
            "https://mb-api.abuse.ch/v2/files/exports/a%2Fb%3Fc%23d%20e/recent.csv"
        );
        assert!(malwarebazaar_feed_url("").is_err());
        assert!(malwarebazaar_feed_url("   ").is_err());
    }

    #[test]
    fn redaction_hides_the_key_in_the_path_and_in_a_query_and_leaves_other_urls_alone() {
        assert_eq!(
            redact_feed_url("https://mb-api.abuse.ch/v2/files/exports/SECRETKEY123/recent.csv"),
            "https://mb-api.abuse.ch/v2/files/exports/***/recent.csv"
        );
        assert_eq!(
            redact_feed_url("https://example.org/feed.txt?auth-key=SECRETKEY123&x=1"),
            "https://example.org/feed.txt?auth-key=***&x=1"
        );
        assert_eq!(redact_feed_url("http://127.0.0.1:8080/feed.txt"), "http://127.0.0.1:8080/feed.txt");
    }

    #[test]
    fn an_empty_or_blank_key_counts_as_no_key() {
        assert_eq!(auth_key_from(None), None);
        assert_eq!(auth_key_from(Some("".to_string())), None);
        assert_eq!(auth_key_from(Some("  \t".to_string())), None);
        assert_eq!(auth_key_from(Some("  abc \n".to_string())), Some("abc".to_string()));
    }

    #[test]
    fn without_a_key_the_sync_says_what_to_do_and_keeps_what_it_has() {
        let conn = storage::open_in_memory().unwrap();
        conn.execute(
            "INSERT INTO signature_cache (sha256, source, added_at) VALUES (?1, 'seed', 0)",
            params!["d".repeat(64)]
        ).unwrap();

        for key in [None, Some("   ")] {
            let result = sync_default_feeds(&conn, key).unwrap();
            assert_eq!(result.new_signatures, 0);
            assert_eq!(result.total_signatures, 1, "what was learned before must stay");
            assert_eq!(result.feed_errors.len(), 1);
            let message = &result.feed_errors[0];
            assert!(message.contains("Auth-Key"), "{message}");
            assert!(message.contains("auth.abuse.ch"), "{message}");
            assert!(message.contains(AUTH_KEY_ENV), "{message}");
        }
    }

    #[test]
    fn an_error_never_contains_the_key_whatever_went_wrong() {
        let rejected = keyed_local_url(&spawn_single_response_server("", "HTTP/1.1 403 Forbidden"));
        let broken = keyed_local_url(&spawn_single_response_server("", "HTTP/1.1 500 Internal Server Error"));
        let gone = keyed_local_url(&spawn_single_response_server("", "HTTP/1.1 410 Gone"));
        let unreachable = format!("http://127.0.0.1:1/v2/files/exports/{KEY}/recent.csv");

        for url in [rejected, broken, gone, unreachable] {
            let error = fetch_feed_text(&url).unwrap_err();
            assert!(!error.contains(KEY), "the key leaked into: {error}");
            assert!(error.contains("***"), "expected the redacted URL in: {error}");
        }
    }

    #[test]
    fn a_rejected_key_is_reported_as_not_accepted() {
        let url = keyed_local_url(&spawn_single_response_server("", "HTTP/1.1 401 Unauthorized"));
        let error = fetch_feed_text(&url).unwrap_err();
        assert!(error.contains("401"), "{error}");
        assert!(error.contains("not accepted"), "{error}");
        assert!(error.contains(AUTH_KEY_ENV), "{error}");
    }

    #[test]
    fn the_stored_source_and_the_sync_result_never_contain_the_key() {
        let conn = storage::open_in_memory().unwrap();
        let hash = "a".repeat(64);
        let good = keyed_local_url(&spawn_single_response_server(hash.leak(), "HTTP/1.1 200 OK"));
        let bad = keyed_local_url(&spawn_single_response_server("", "HTTP/1.1 403 Forbidden"));

        let result = sync_signatures(&[&good, &bad], &conn).unwrap();

        assert_eq!(result.new_signatures, 1);
        let source: String = conn
            .query_row("SELECT source FROM signature_cache", [], |row| row.get(0))
            .unwrap();
        assert!(!source.contains(KEY), "the key was stored in source: {source}");
        assert!(source.contains("/exports/***/"), "{source}");
        for error in &result.feed_errors {
            assert!(!error.contains(KEY), "{error}");
        }
    }

    #[test]
    fn hashes_are_found_in_the_quoted_columns_of_a_csv_and_other_hash_kinds_are_not() {
        let sha256 = "ab".repeat(32);
        let md5 = "cd".repeat(16);
        let sha1 = "ef".repeat(20);
        let sha3_384 = "12".repeat(48);
        let csv = format!(
            "################\n# MalwareBazaar recent malware samples (CSV)\n#\n\
             \"2026-10-30 08:50:00\",\"{sha256}\",\"{md5}\",\"{sha1}\",\"{sha3_384}\",\"a.exe\"\n"
        );
        let found = extract_sha256_signatures(&csv);
        assert_eq!(found.len(), 1);
        assert!(found.contains(&sha256));
    }
}
