//! Shared between the `helper` process and the desktop app's IPC client.
//! Kept in `core` rather than duplicated in both, so a protocol change
//! can't silently drift out of sync between the two sides.
//!
//! Protocol: one request, one response, connection closes. No persistent
//! session, no polling, matching the design decision in
//! docs/phase4-desktop-privileged-helper-plan.md: the desktop app sends
//! the full active domain list every time it changes, the helper always
//! writes the complete set, not a delta.

use serde::{ Deserialize, Serialize };

/// Name the helper listens on. Not a filesystem path, `interprocess`
/// resolves this per-platform (a named pipe name on Windows, a socket
/// path on Unix).
pub const HELPER_SOCKET_NAME: &str = "secureguard-helper";

/// What the desktop app can ask of the helper. Two shapes on the wire, told
/// apart by their field alone (`untagged`):
///
/// - `{"active_domains":[...]}` sets the complete list of blocked domains. This
///   is the exact shape every earlier version sent, so it must not change.
/// - `{"quit":true}` asks the helper to answer and then exit. It never touches
///   the hosts file.
///
/// `deny_unknown_fields` makes a mixed shape (both fields, or any extra one) a
/// parse error, so a request can never be read two ways. An older helper has no
/// `quit` shape and rejects it as a missing `active_domains`, so it can never
/// mistake a quit for an empty list that clears every entry.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged, deny_unknown_fields)]
pub enum HelperRequest {
    SetDomains {
        active_domains: Vec<String>,
    },
    /// Only `true` means quit. The helper rejects `false` as a bad request.
    Quit {
        quit: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HelperResponse {
    pub success: bool,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Result<HelperRequest, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[test]
    fn a_set_domains_request_keeps_its_exact_wire_format() {
        let request = HelperRequest::SetDomains { active_domains: vec!["a.example".to_string()] };
        assert_eq!(serde_json::to_string(&request).unwrap(), r#"{"active_domains":["a.example"]}"#);
    }

    #[test]
    fn the_request_an_older_desktop_sends_still_parses() {
        let request = parse(r#"{"active_domains":["a.example","b.example"]}"#).unwrap();
        assert_eq!(
            request,
            HelperRequest::SetDomains {
                active_domains: vec!["a.example".to_string(), "b.example".to_string()],
            }
        );
        assert_eq!(parse(r#"{"active_domains":[]}"#).unwrap(), HelperRequest::SetDomains {
            active_domains: vec![],
        });
    }

    #[test]
    fn a_quit_request_has_its_own_shape() {
        assert_eq!(serde_json::to_string(&HelperRequest::Quit { quit: true }).unwrap(), r#"{"quit":true}"#);
        assert_eq!(parse(r#"{"quit":true}"#).unwrap(), HelperRequest::Quit { quit: true });
        assert_eq!(parse(r#"{"quit":false}"#).unwrap(), HelperRequest::Quit { quit: false });
    }

    #[test]
    fn a_mixed_or_empty_or_extended_request_is_an_error() {
        for bad in [
            r#"{"active_domains":[],"quit":true}"#,
            r#"{"active_domains":["a.example"],"quit":false}"#,
            r#"{}"#,
            r#"{"quit":"yes"}"#,
            r#"{"active_domains":["a.example"],"extra":1}"#,
            r#"{"quit":true,"extra":1}"#,
        ] {
            assert!(parse(bad).is_err(), "must reject {bad}");
        }
    }
}
