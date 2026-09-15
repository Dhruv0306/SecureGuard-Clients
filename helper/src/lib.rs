//! The privileged helper's actual logic, split into a library so it's
//! testable (integration tests can only link a crate's lib target, not its
//! bin), with a thin main.rs binary wrapper. Same verification caveat as
//! before: the `interprocess` API usage here is written against that
//! crate's documented API, not compiled against here.

use interprocess::local_socket::{
    prelude::*, GenericNamespaced, ListenerOptions, ToNsName,
};
use secureguard_core::helper_protocol::{HelperRequest, HelperResponse};
use secureguard_core::hosts_writer::HostsFileWriter;
use std::io::{BufRead, BufReader, Write};

/// Binds the given socket name and serves requests forever, one connection
/// at a time. Blocking, meant to be the entire body of `main()`.
pub fn run_helper_server(socket_name: &str, writer: HostsFileWriter) -> ! {
    let name = socket_name
        .to_ns_name::<GenericNamespaced>()
        .unwrap_or_else(|e| {
            eprintln!("failed to construct socket name: {e}");
            std::process::exit(1);
        });

    let listener = ListenerOptions::new().name(name).create_sync().unwrap_or_else(|e| {
        eprintln!(
            "failed to bind helper socket (already running elsewhere, or a \
             permissions problem): {e}"
        );
        std::process::exit(1);
    });

    eprintln!("secureguard-helper listening on '{socket_name}'");

    for connection in listener.incoming() {
        match connection {
            Ok(conn) => handle_connection(conn, &writer),
            Err(e) => eprintln!("failed to accept a connection: {e}"),
        }
    }

    // listener.incoming() only yields None if the listener itself is
    // dropped, which never happens here, but the type system doesn't know
    // that, satisfy the `-> !` return type explicitly.
    unreachable!("local socket listener's incoming() ended unexpectedly")
}

/// Handles exactly one request-response exchange on an already-accepted
/// connection, then returns (the connection closes when dropped). Public so
/// integration tests can drive it directly against a real local socket
/// without needing the full accept loop.
pub fn handle_connection(conn: impl std::io::Read + std::io::Write, writer: &HostsFileWriter) {
    let mut reader = BufReader::new(conn);
    let mut line = String::new();

    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return; // client disconnected without sending anything
    }

    let response = match serde_json::from_str::<HelperRequest>(&line) {
        Ok(request) => match writer.write(&request.active_domains) {
            Ok(()) => HelperResponse { success: true, error: None },
            Err(e) => HelperResponse {
                success: false,
                error: Some(format!("failed to write hosts file: {e}")),
            },
        },
        Err(e) => HelperResponse {
            success: false,
            error: Some(format!("malformed request: {e}")),
        },
    };

    let Ok(mut response_json) = serde_json::to_string(&response) else {
        eprintln!("failed to serialize response, dropping connection");
        return;
    };
    response_json.push('\n');

    let mut stream = reader.into_inner();
    if let Err(e) = stream.write_all(response_json.as_bytes()) {
        eprintln!("failed to write response to client: {e}");
    }
}
