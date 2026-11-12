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

/// Whom the app will talk to. A Unix socket has no access list (on Linux it is
/// an abstract socket anyone can bind), so another local user could bind the
/// helper's name first and wait for requests. On Unix the app therefore talks
/// only to a socket whose owner is root; nothing is sent otherwise. Windows
/// pipes are protected by the helper's first-instance flag and access list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerTrust {
    Anyone,
    /// The socket must belong to this user.
    Uid(u32),
}

impl ServerTrust {
    pub fn for_platform() -> Self {
        if cfg!(unix) { ServerTrust::Uid(0) } else { ServerTrust::Anyone }
    }

    /// `owner` is the user id behind the socket, or None when it cannot be read.
    pub fn accepts(&self, owner: Option<u32>) -> bool {
        match self {
            ServerTrust::Anyone => true,
            ServerTrust::Uid(expected) => owner == Some(*expected),
        }
    }
}

/// The user id of the process behind the socket we connected to.
#[cfg(unix)]
fn owner_euid(conn: &Stream) -> Option<u32> {
    use interprocess::local_socket::traits::StreamCommon;
    conn.peer_creds().ok().and_then(|creds| creds.euid())
}

#[cfg(not(unix))]
fn owner_euid(_conn: &Stream) -> Option<u32> {
    None
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
    send_domain_list_to(HELPER_SOCKET_NAME, ServerTrust::for_platform(), active_domains)
}

/// Same as `send_domain_list` for a chosen socket name, so a test can point it
/// at a name nobody listens on.
pub fn send_domain_list_to(
    socket_name: &str,
    trust: ServerTrust,
    active_domains: &[String]
) -> Result<HelperResponse, HelperError> {
    exchange(
        socket_name,
        trust,
        &(HelperRequest::SetDomains { active_domains: active_domains.to_vec() })
    )
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
pub fn quit_helper_at(socket_name: &str, trust: ServerTrust) -> Result<(), String> {
    helper_outcome(exchange(socket_name, trust, &(HelperRequest::Quit { quit: true })))
}

/// `quit_helper_at` that gives up after `timeout`. The request runs on its own
/// thread, so a helper that never answers cannot hold up the caller; the thread
/// is left behind and ends when the process does.
pub fn quit_helper_within(
    socket_name: &str,
    trust: ServerTrust,
    timeout: Duration
) -> Result<(), String> {
    let (sender, receiver) = mpsc::channel();
    let name = socket_name.to_string();
    std::thread::spawn(move || {
        let _ = sender.send(quit_helper_at(&name, trust));
    });
    receiver
        .recv_timeout(timeout)
        .unwrap_or_else(|_| Err("the privileged helper did not answer the quit request in time".to_string()))
}

/// One request, one response, over a fresh connection. Nothing is sent until
/// the socket's owner passes `trust`.
fn exchange(
    socket_name: &str,
    trust: ServerTrust,
    request: &HelperRequest
) -> Result<HelperResponse, HelperError> {
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

    if !trust.accepts(owner_euid(&conn)) {
        return Err(
            HelperError::Other(
                "the privileged helper socket is not owned by the expected user, so nothing was sent to it".to_string()
            )
        );
    }

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

        let result = send_domain_list_to(&name, ServerTrust::Anyone, &["a.example".to_string()]);

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

        assert_eq!(quit_helper_at(&name, ServerTrust::Anyone), Ok(()));
        assert_eq!(*seen.lock().unwrap(), vec!["{\"quit\":true}".to_string()]);
    }

    #[test]
    fn a_quit_the_helper_refuses_returns_the_helpers_text() {
        let name = unique_name("quit-no");
        let _seen = fake_helper(&name, "{\"success\":false,\"error\":\"rejected request: nope\"}\n");

        assert_eq!(quit_helper_at(&name, ServerTrust::Anyone), Err("rejected request: nope".to_string()));
    }

    #[test]
    fn a_quit_with_no_helper_running_carries_the_unreachable_marker() {
        let text = quit_helper_at(&unique_name("quit-none"), ServerTrust::Anyone).unwrap_err();
        assert!(text.starts_with(HELPER_UNREACHABLE), "{text}");
    }

    #[test]
    fn a_quit_to_a_helper_that_never_answers_gives_up_at_the_time_limit() {
        let name = unique_name("quit-slow");
        let _seen = fake_helper(&name, "");

        let started = Instant::now();
        let result = quit_helper_within(&name, ServerTrust::Anyone, Duration::from_millis(400));

        assert!(started.elapsed() < Duration::from_secs(3), "took {:?}", started.elapsed());
        assert!(result.unwrap_err().contains("did not answer"));
    }

    // ---- not talking to an impostor ----

    #[test]
    fn the_platform_trusts_root_on_unix_and_anyone_on_windows() {
        if cfg!(unix) {
            assert_eq!(ServerTrust::for_platform(), ServerTrust::Uid(0));
        } else {
            assert_eq!(ServerTrust::for_platform(), ServerTrust::Anyone);
        }
    }

    #[test]
    fn trust_in_a_user_means_exactly_that_user() {
        assert!(ServerTrust::Anyone.accepts(None));
        assert!(ServerTrust::Anyone.accepts(Some(1000)));
        assert!(ServerTrust::Uid(0).accepts(Some(0)));
        assert!(!ServerTrust::Uid(0).accepts(Some(1000)));
        assert!(!ServerTrust::Uid(0).accepts(None), "a socket whose owner cannot be read is not trusted");
    }

    /// The user the fake helper (this process) runs as, as a client sees it.
    #[cfg(unix)]
    fn my_euid(name: &str) -> u32 {
        use interprocess::local_socket::traits::StreamCommon;
        let conn = Stream::connect(name.to_ns_name::<GenericNamespaced>().unwrap()).unwrap();
        conn.peer_creds().unwrap().euid().expect("this platform reports the peer user")
    }

    #[cfg(unix)]
    #[test]
    fn a_helper_run_by_the_expected_user_is_talked_to() {
        let name = unique_name("trust-ok");
        let seen = fake_helper(&name, "{\"success\":true,\"error\":null}\n");
        let me = my_euid(&name);

        let result = send_domain_list_to(&name, ServerTrust::Uid(me), &["a.example".to_string()]);

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_socket_owned_by_someone_else_is_refused_and_is_sent_nothing() {
        let name = unique_name("trust-no");
        let seen = fake_helper(&name, "{\"success\":true,\"error\":null}\n");
        let someone_else = my_euid(&name).wrapping_add(1);

        let result = send_domain_list_to(&name, ServerTrust::Uid(someone_else), &["a.example".to_string()]);

        match result {
            Err(HelperError::Other(text)) => assert!(text.contains("not owned by the expected user"), "{text}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        std::thread::sleep(Duration::from_millis(200));
        assert!(seen.lock().unwrap().is_empty(), "the domain list must not reach an impostor");
    }

    #[cfg(unix)]
    #[test]
    fn a_quit_is_not_sent_to_an_impostor_either() {
        let name = unique_name("trust-quit");
        let seen = fake_helper(&name, "{\"success\":true,\"error\":null}\n");
        let someone_else = my_euid(&name).wrapping_add(1);

        let text = quit_helper_at(&name, ServerTrust::Uid(someone_else)).unwrap_err();

        assert!(text.contains("not owned by the expected user"), "{text}");
        assert!(!text.starts_with(HELPER_UNREACHABLE), "a squatted socket is not a missing helper");
        std::thread::sleep(Duration::from_millis(200));
        assert!(seen.lock().unwrap().is_empty());
    }
}
