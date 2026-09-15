//! Shared between the `helper` process and the desktop app's IPC client.
//! Kept in `core` rather than duplicated in both, so a protocol change
//! can't silently drift out of sync between the two sides.
//!
//! Protocol: one request, one response, connection closes. No persistent
//! session, no polling, matching the design decision in
//! docs/phase4-desktop-privileged-helper-plan.md: the desktop app sends
//! the full active domain list every time it changes, the helper always
//! writes the complete set, not a delta.

use serde::{Deserialize, Serialize};

/// Name the helper listens on. Not a filesystem path, `interprocess`
/// resolves this per-platform (a named pipe name on Windows, a socket
/// path on Unix).
pub const HELPER_SOCKET_NAME: &str = "secureguard-helper";

#[derive(Debug, Serialize, Deserialize)]
pub struct HelperRequest {
    pub active_domains: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HelperResponse {
    pub success: bool,
    pub error: Option<String>,
}
