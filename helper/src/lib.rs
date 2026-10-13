//! The privileged helper's actual logic, split into a library so it's
//! testable (integration tests can only link a crate's lib target, not its
//! bin), with a thin main.rs binary wrapper. Same verification caveat as
//! before: the `interprocess` API usage here is written against that
//! crate's documented API, not compiled against here.

use interprocess::local_socket::{ prelude::*, GenericNamespaced, Listener, ListenerOptions, ToNsName };
use secureguard_core::blocked_domain::parse_domain_list;
use secureguard_core::helper_protocol::{ HelperRequest, HelperResponse };
use secureguard_core::hosts_writer::HostsFileWriter;
use std::io::{ BufRead, BufReader };

/// Who may open the helper's named pipe on Windows, as a security descriptor
/// string. Without an explicit one, a pipe created by an elevated process lets
/// only SYSTEM, administrators and its creator write to it, so an ordinary
/// (non-elevated) desktop app is refused with "Access is denied".
///
/// - `SY` SYSTEM and `BA` administrators: full control (they can already edit
///   the hosts file themselves).
/// - `IU` the interactive user, who runs the desktop app: generic read and
///   write, enough to connect, send a request and read the reply.
///
/// Everyone else, including services and network logons, is denied. The
/// client opens the pipe with generic read and write, so the right to add
/// pipe instances comes with it; see docs/helper-security-model.md for what
/// that does and does not allow. Every request is validated regardless of who
/// sent it.
#[cfg(windows)]
const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// Creates the helper's listener. The first pipe instance is created with
/// the "first instance" flag, so if another process already owns this pipe
/// name the call fails instead of the helper silently sharing it.
pub fn bind_listener(socket_name: &str) -> std::io::Result<Listener> {
    let name = socket_name.to_ns_name::<GenericNamespaced>()?;
    let options = ListenerOptions::new().name(name);

    #[cfg(windows)]
    let options = {
        use interprocess::os::windows::local_socket::ListenerOptionsExt;
        use interprocess::os::windows::security_descriptor::SecurityDescriptor;

        let sddl = widestring::U16CString::from_str(PIPE_SDDL).map_err(|e|
            std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
        )?;
        options.security_descriptor(SecurityDescriptor::deserialize(&sddl)?)
    };

    options.create_sync()
}

/// Binds the given socket name and serves requests forever, one connection
/// at a time. Blocking, meant to be the entire body of `main()`.
pub fn run_helper_server(socket_name: &str, writer: HostsFileWriter) -> ! {
    let listener = bind_listener(socket_name).unwrap_or_else(|e| {
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
        // The helper is the trust boundary: it checks every name itself and
        // rejects the whole request, untouched file included, if any is bad.
        Ok(request) =>
            match parse_domain_list(&request.active_domains) {
                Err(e) =>
                    HelperResponse {
                        success: false,
                        error: Some(format!("rejected request: {e}")),
                    },
                Ok(domains) =>
                    match writer.write(&domains) {
                        Ok(()) => HelperResponse { success: true, error: None },
                        Err(e) =>
                            HelperResponse {
                                success: false,
                                error: Some(format!("failed to write hosts file: {e}")),
                            },
                    }
            }
        Err(e) =>
            HelperResponse {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{ Cursor, Read, Write };

    /// An in-memory connection: reads the request from `input`, collects the
    /// reply in `output`. Lets the request handling be tested without sockets.
    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const ORIGINAL_HOSTS: &str = "127.0.0.1 localhost\n";

    fn hosts_file() -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), ORIGINAL_HOSTS).unwrap();
        file
    }

    fn send(domains: Vec<String>, hosts: &tempfile::NamedTempFile) -> HelperResponse {
        let request = HelperRequest { active_domains: domains };
        let mut line = serde_json::to_string(&request).unwrap();
        line.push('\n');

        let mut conn = Duplex { input: Cursor::new(line.into_bytes()), output: Vec::new() };
        handle_connection(&mut conn, &HostsFileWriter::new(hosts.path()));
        serde_json::from_slice(&conn.output).unwrap()
    }

    #[test]
    fn a_valid_request_is_written() {
        let hosts = hosts_file();
        let response = send(vec!["Malware.Example.com".to_string()], &hosts);

        assert!(response.success, "{:?}", response.error);
        let content = std::fs::read_to_string(hosts.path()).unwrap();
        assert!(content.contains("127.0.0.1 malware.example.com # SECUREGUARD_BLOCKED_DOMAIN"));
    }

    #[test]
    fn a_newline_injection_is_rejected_and_the_file_is_untouched() {
        let hosts = hosts_file();
        let response = send(vec!["ok.example.com\n93.184.216.34 bank.example".to_string()], &hosts);

        assert!(!response.success);
        assert!(response.error.unwrap().starts_with("rejected request:"));
        assert_eq!(std::fs::read_to_string(hosts.path()).unwrap(), ORIGINAL_HOSTS);
    }

    #[test]
    fn one_bad_entry_rejects_the_whole_request_with_no_partial_write() {
        let hosts = hosts_file();
        let response = send(vec!["good.example.com".to_string(), "bad domain.example.com".to_string()], &hosts);

        assert!(!response.success);
        assert_eq!(std::fs::read_to_string(hosts.path()).unwrap(), ORIGINAL_HOSTS);
    }

    #[test]
    fn a_comment_marker_and_a_carriage_return_are_rejected() {
        for bad in ["evil.example.com # trick", "evil.example.com\r\n1.2.3.4 x.example"] {
            let hosts = hosts_file();
            let response = send(vec![bad.to_string()], &hosts);
            assert!(!response.success, "must reject {bad:?}");
            assert_eq!(std::fs::read_to_string(hosts.path()).unwrap(), ORIGINAL_HOSTS);
        }
    }

    #[test]
    fn an_oversized_list_is_rejected() {
        let hosts = hosts_file();
        let many = (0..=secureguard_core::blocked_domain::MAX_BLOCKED_DOMAINS)
            .map(|i| format!("d{i}.example.com"))
            .collect();
        let response = send(many, &hosts);

        assert!(!response.success);
        assert_eq!(std::fs::read_to_string(hosts.path()).unwrap(), ORIGINAL_HOSTS);
    }

    #[test]
    fn an_empty_list_clears_our_entries_but_keeps_system_ones() {
        let hosts = hosts_file();
        send(vec!["blocked.example.com".to_string()], &hosts);
        let response = send(vec![], &hosts);

        assert!(response.success);
        let content = std::fs::read_to_string(hosts.path()).unwrap();
        assert!(content.contains("127.0.0.1 localhost"));
        assert!(!content.contains("SECUREGUARD_BLOCKED_DOMAIN"));
    }
}
