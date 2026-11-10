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

    let request = HelperRequest::SetDomains {
        active_domains: active_domains.to_vec(),
    };
    let mut request_json = serde_json
        ::to_string(&request)
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
mod tests {
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
}
