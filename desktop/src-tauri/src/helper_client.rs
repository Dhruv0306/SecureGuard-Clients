//! Desktop-side client for the helper's IPC protocol. See
//! helper/src/main.rs and secureguard_core::helper_protocol for the
//! server side and shared types.
//!
//! Same verification caveat as the helper itself: this `interprocess`
//! usage is written against the crate's documented API, not compiled
//! against here.

use interprocess::local_socket::{ prelude::*, GenericNamespaced, Stream, ToNsName };
use secureguard_core::helper_protocol::{ HelperRequest, HelperResponse, HELPER_SOCKET_NAME };
use std::io::{ BufRead, BufReader, ErrorKind, Write };
use std::sync::mpsc;
use std::time::Duration;

/// Why a request did not get an answer from the helper.
#[derive(Debug)]
pub enum HelperError {
    /// Nothing is listening on the helper's pipe or socket: the helper is not
    /// running. The page turns this into a plain explanation.
    Unreachable(String),
    /// Anything else (a refused connection, a broken exchange, a reply that
    /// could not be read). The text is shown as it is.
    Other(String),
}

/// Starts the error text of a block or unblock that failed because the helper
/// is not running, so the page can recognize it without matching on the
/// operating system's wording. Keep in step with `HELPER_UNREACHABLE` in
/// desktop/src/scan-view.js.
pub const HELPER_UNREACHABLE: &str = "helper-unreachable:";

/// A missing pipe or socket (`NotFound` on Windows, `ConnectionRefused` or
/// `NotFound` on Unix) means no helper is listening. Any other connect error,
/// such as `PermissionDenied`, means something is there that this user cannot
/// use, which is a different problem from "not running".
fn means_not_running(kind: ErrorKind) -> bool {
    matches!(kind, ErrorKind::NotFound | ErrorKind::ConnectionRefused)
}

pub fn send_domain_list(active_domains: &[String]) -> Result<HelperResponse, HelperError> {
    send_domain_list_to(HELPER_SOCKET_NAME, active_domains)
}

/// Same as `send_domain_list` for a chosen socket name, so a test can point it
/// at a name nobody listens on.
pub fn send_domain_list_to(
    socket_name: &str,
    active_domains: &[String]
) -> Result<HelperResponse, HelperError> {
    exchange(socket_name, &(HelperRequest::SetDomains { active_domains: active_domains.to_vec() }))
}

/// Whether anything is listening on the socket. Connects and leaves without
/// sending a line; the helper ignores such a connection and does not count it
/// as activity.
pub fn helper_reachable_at(socket_name: &str) -> bool {
    match socket_name.to_ns_name::<GenericNamespaced>() {
        Ok(name) => Stream::connect(name).is_ok(),
        Err(_) => false,
    }
}

/// Asks the helper to answer and exit. The text of an error is the same as
/// for a block request (see `helper_outcome`), so an unreachable helper starts
/// with `HELPER_UNREACHABLE`.
pub fn quit_helper_at(socket_name: &str) -> Result<(), String> {
    helper_outcome(exchange(socket_name, &(HelperRequest::Quit { quit: true })))
}

/// `quit_helper_at` that gives up after `timeout`. The request runs on its own
/// thread, so a helper that never answers cannot hold up the caller; the thread
/// is left behind and ends when the process does.
pub fn quit_helper_within(socket_name: &str, timeout: Duration) -> Result<(), String> {
    let (sender, receiver) = mpsc::channel();
    let name = socket_name.to_string();
    std::thread::spawn(move || {
        let _ = sender.send(quit_helper_at(&name));
    });
    receiver
        .recv_timeout(timeout)
        .unwrap_or_else(|_| Err("the privileged helper did not answer the quit request in time".to_string()))
}

/// One request, one response, over a fresh connection.
fn exchange(socket_name: &str, request: &HelperRequest) -> Result<HelperResponse, HelperError> {
    let name = socket_name.to_ns_name::<GenericNamespaced>().map_err(|e|
        HelperError::Other(format!("invalid helper socket name: {e}"))
    )?;

    let mut conn = Stream::connect(name).map_err(|e| {
        let text = format!("failed to connect to the privileged helper: {e}");
        if means_not_running(e.kind()) {
            HelperError::Unreachable(text)
        } else {
            HelperError::Other(text)
        }
    })?;

    let mut request_json = serde_json
        ::to_string(request)
        .map_err(|e| HelperError::Other(format!("failed to build request: {e}")))?;
    request_json.push('\n');

    conn
        .write_all(request_json.as_bytes())
        .map_err(|e| HelperError::Other(format!("failed to send request to helper: {e}")))?;

    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| HelperError::Other(format!("failed to read helper response: {e}")))?;

    serde_json
        ::from_str(&line)
        .map_err(|e| HelperError::Other(format!("malformed helper response: {e}")))
}

/// Turns the result of one request into what the block and unblock commands
/// return: `Ok` when the helper did it, otherwise the text for the page. An
/// unreachable helper gets `HELPER_UNREACHABLE` first. The caller rolls its
/// database change back on any `Err`.
pub fn helper_outcome(result: Result<HelperResponse, HelperError>) -> Result<(), String> {
    match result {
        Ok(response) if response.success => Ok(()),
        Ok(response) => Err(response.error.unwrap_or_else(|| "helper reported failure".to_string())),
        Err(HelperError::Unreachable(text)) => Err(format!("{HELPER_UNREACHABLE} {text}")),
        Err(HelperError::Other(text)) => Err(text),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::ErrorKind;

    fn response(success: bool, error: Option<&str>) -> HelperResponse {
        HelperResponse { success, error: error.map(str::to_string) }
    }

    #[test]
    fn a_socket_nobody_listens_on_is_reported_as_unreachable() {
        let name = format!("secureguard-helper-test-nobody-{}", std::process::id());

        let result = send_domain_list_to(&name, &["a.example".to_string()]);

        assert!(matches!(result, Err(HelperError::Unreachable(_))), "got {result:?}");
    }

    #[test]
    fn only_a_missing_or_refused_connection_means_the_helper_is_not_running() {
        assert!(means_not_running(ErrorKind::NotFound));
        assert!(means_not_running(ErrorKind::ConnectionRefused));
        // A helper that is there but refuses this user is a different problem,
        // and the page must not claim it is "not running".
        assert!(!means_not_running(ErrorKind::PermissionDenied));
        assert!(!means_not_running(ErrorKind::TimedOut));
        assert!(!means_not_running(ErrorKind::Other));
    }

    #[test]
    fn a_successful_response_is_ok() {
        assert_eq!(helper_outcome(Ok(response(true, None))), Ok(()));
    }

    #[test]
    fn a_response_that_says_no_keeps_the_helpers_own_text_and_has_no_marker() {
        let result = helper_outcome(Ok(response(false, Some("rejected request: bad name"))));
        assert_eq!(result, Err("rejected request: bad name".to_string()));

        let result = helper_outcome(Ok(response(false, None)));
        assert_eq!(result, Err("helper reported failure".to_string()));
    }

    #[test]
    fn an_unreachable_helper_gets_the_marker_at_the_start_of_the_text() {
        let text = helper_outcome(
            Err(HelperError::Unreachable("failed to connect (os error 2)".to_string()))
        ).unwrap_err();

        assert!(text.starts_with(HELPER_UNREACHABLE), "{text}");
        assert!(text.contains("failed to connect (os error 2)"), "{text}");
        assert_eq!(HELPER_UNREACHABLE, "helper-unreachable:");
    }

    #[test]
    fn any_other_failure_has_no_marker() {
        let text = helper_outcome(Err(HelperError::Other("failed to send request".to_string()))).unwrap_err();

        assert_eq!(text, "failed to send request");
        assert!(!text.contains(HELPER_UNREACHABLE));
    }

    // ---- probing and quitting, against a fake helper on a real local socket ----

    use interprocess::local_socket::ListenerOptions;
    use std::sync::{ Arc, Mutex };
    use std::time::{ Duration, Instant };

    pub(crate) fn unique_name(tag: &str) -> String {
        format!("secureguard-test-{}-{}", std::process::id(), tag)
    }

    /// Listens on `name`, records every line it receives, and answers each with
    /// `reply` (an empty reply means: hold the connection open and say nothing).
    pub(crate) fn fake_helper(name: &str, reply: &'static str) -> Arc<Mutex<Vec<String>>> {
        let listener = ListenerOptions::new()
            .name(name.to_ns_name::<GenericNamespaced>().unwrap())
            .create_sync()
            .expect("the fake helper should bind");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for conn in listener.incoming().flatten() {
                let mut reader = BufReader::new(conn);
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    continue; // a probe: connected and left
                }
                recorded.lock().unwrap().push(line.trim_end().to_string());
                if reply.is_empty() {
                    held.push(reader); // never answers, never closes
                } else {
                    let _ = reader.get_mut().write_all(reply.as_bytes());
                }
            }
        });
        seen
    }

    #[test]
    fn a_helper_that_listens_is_reachable_and_nothing_is_not() {
        let name = unique_name("reach");
        assert!(!helper_reachable_at(&name));

        let _seen = fake_helper(&name, "");
        assert!(helper_reachable_at(&name));
    }

    #[test]
    fn a_quit_sends_exactly_the_quit_line_and_succeeds_on_a_success_reply() {
        let name = unique_name("quit-ok");
        let seen = fake_helper(&name, "{\"success\":true,\"error\":null}\n");

        assert_eq!(quit_helper_at(&name), Ok(()));
        assert_eq!(*seen.lock().unwrap(), vec!["{\"quit\":true}".to_string()]);
    }

    #[test]
    fn a_quit_the_helper_refuses_returns_the_helpers_text() {
        let name = unique_name("quit-no");
        let _seen = fake_helper(&name, "{\"success\":false,\"error\":\"rejected request: nope\"}\n");

        assert_eq!(quit_helper_at(&name), Err("rejected request: nope".to_string()));
    }

    #[test]
    fn a_quit_with_no_helper_running_carries_the_unreachable_marker() {
        let text = quit_helper_at(&unique_name("quit-none")).unwrap_err();
        assert!(text.starts_with(HELPER_UNREACHABLE), "{text}");
    }

    #[test]
    fn a_quit_to_a_helper_that_never_answers_gives_up_at_the_time_limit() {
        let name = unique_name("quit-slow");
        let _seen = fake_helper(&name, "");

        let started = Instant::now();
        let result = quit_helper_within(&name, Duration::from_millis(400));

        assert!(started.elapsed() < Duration::from_secs(3), "took {:?}", started.elapsed());
        assert!(result.unwrap_err().contains("did not answer"));
    }
}
