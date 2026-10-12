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

/// Ported from ThreatIntelSignatureService's default
/// app.threat-intel.urls value.
pub const DEFAULT_FEED_URL: &str = "https://bazaar.abuse.ch/export/txt/sha256/recent/";

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

    let response = agent
        .get(url)
        .call()
        .map_err(|e| match e {
            // abuse.ch has announced mandatory authentication for its APIs;
            // say so plainly instead of leaving a bare status code.
            ureq::Error::StatusCode(code @ (401 | 403)) =>
                format!(
                    "request to {url} was rejected (HTTP {code}); the feed may now require an Auth-Key"
                ),
            other => format!("request to {url} failed: {other}"),
        })?;

    let mut text = String::new();
    response
        .into_body()
        .into_reader()
        .read_to_string(&mut text)
        .map_err(|e| format!("failed to read response body from {url}: {e}"))?;
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
                        params![hash, url, added_at]
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
}
