//! Desktop-side client for the helper's IPC protocol. See
//! helper/src/main.rs and secureguard_core::helper_protocol for the
//! server side and shared types.
//!
//! Same verification caveat as the helper itself: this `interprocess`
//! usage is written against the crate's documented API, not compiled
//! against here.

use interprocess::local_socket::{prelude::*, GenericNamespaced, Stream, ToNsName};
use secureguard_core::helper_protocol::{HelperRequest, HelperResponse, HELPER_SOCKET_NAME};
use std::io::{BufRead, BufReader, Write};

pub fn send_domain_list(active_domains: &[String]) -> Result<HelperResponse, String> {
    let name = HELPER_SOCKET_NAME
        .to_ns_name::<GenericNamespaced>()
        .map_err(|e| format!("invalid helper socket name: {e}"))?;

    let mut conn = Stream::connect(name).map_err(|e| {
        format!(
            "failed to connect to the privileged helper (is it installed and running?): {e}"
        )
    })?;

    let request = HelperRequest {
        active_domains: active_domains.to_vec(),
    };
    let mut request_json =
        serde_json::to_string(&request).map_err(|e| format!("failed to build request: {e}"))?;
    request_json.push('\n');

    conn.write_all(request_json.as_bytes())
        .map_err(|e| format!("failed to send request to helper: {e}"))?;

    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("failed to read helper response: {e}"))?;

    serde_json::from_str(&line).map_err(|e| format!("malformed helper response: {e}"))
}
