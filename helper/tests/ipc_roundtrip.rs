//! The one genuinely novel, unverified-by-me piece of Phase 4 is the
//! `interprocess` local-socket API usage. This test exercises it for real:
//! a real socket bind, a real client connect, a real request/response
//! round-trip, just pointed at a temp file instead of the OS hosts file, so
//! it's safe to run in CI without touching real system state.

use interprocess::local_socket::{ prelude::*, GenericNamespaced, Stream, ToNsName };
use secureguard_core::helper_protocol::{ HelperRequest, HelperResponse };
use secureguard_core::hosts_writer::HostsFileWriter;
use std::io::{ BufRead, BufReader, Write };
use std::thread;

fn unique_socket_name(test_name: &str) -> String {
    // Distinct per test (and per process, via PID) so parallel test runs
    // don't collide on the same socket name.
    format!("secureguard-helper-test-{test_name}-{}", std::process::id())
}

fn send_request(socket_name: &str, active_domains: Vec<String>) -> HelperResponse {
    let name = socket_name.to_ns_name::<GenericNamespaced>().expect("valid socket name");

    // The server side binds asynchronously in a spawned thread; give it a
    // moment to be ready. A fixed sleep is not ideal, but this crate has no
    // "ready" signal to wait on more precisely, and a flaky-if-too-short
    // sleep is a known, accepted tradeoff here, not a hidden one.
    thread::sleep(std::time::Duration::from_millis(100));

    let mut conn = Stream::connect(name).expect("client should connect to the test server");

    let request = HelperRequest { active_domains };
    let mut request_json = serde_json::to_string(&request).unwrap();
    request_json.push('\n');
    conn.write_all(request_json.as_bytes()).unwrap();

    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

#[test]
fn round_trips_a_successful_domain_block_request() {
    let hosts_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(hosts_file.path(), "127.0.0.1 localhost\n").unwrap();
    let hosts_path = hosts_file.path().to_path_buf();

    let socket_name = unique_socket_name("success");
    let server_socket_name = socket_name.clone();

    let server = thread::spawn(move || {
        let name = server_socket_name.to_ns_name::<GenericNamespaced>().expect("valid socket name");
        let listener = interprocess::local_socket::ListenerOptions
            ::new()
            .name(name)
            .create_sync()
            .expect("test server should bind");
        let conn = listener
            .incoming()
            .next()
            .expect("should receive one connection")
            .expect("connection should be accepted cleanly");
        let writer = HostsFileWriter::new(hosts_path);
        secureguard_helper::handle_connection(conn, &writer);
    });

    let response = send_request(&socket_name, vec!["malware.example.com".to_string()]);
    server.join().unwrap();

    assert!(response.success, "expected success, got error: {:?}", response.error);
    assert!(response.error.is_none());

    let final_content = std::fs::read_to_string(hosts_file.path()).unwrap();
    assert!(final_content.contains("malware.example.com"));
}

#[test]
fn round_trips_a_malformed_request_as_a_reported_error_not_a_crash() {
    let hosts_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(hosts_file.path(), "127.0.0.1 localhost\n").unwrap();
    let hosts_path = hosts_file.path().to_path_buf();

    let socket_name = unique_socket_name("malformed");
    let server_socket_name = socket_name.clone();

    let server = thread::spawn(move || {
        let name = server_socket_name.to_ns_name::<GenericNamespaced>().expect("valid socket name");
        let listener = interprocess::local_socket::ListenerOptions
            ::new()
            .name(name)
            .create_sync()
            .expect("test server should bind");
        let conn = listener
            .incoming()
            .next()
            .expect("should receive one connection")
            .expect("connection should be accepted cleanly");
        let writer = HostsFileWriter::new(hosts_path);
        secureguard_helper::handle_connection(conn, &writer);
    });

    thread::sleep(std::time::Duration::from_millis(100));
    let name = socket_name.to_ns_name::<GenericNamespaced>().unwrap();
    let mut conn = Stream::connect(name).unwrap();
    conn.write_all(b"not valid json at all\n").unwrap();
    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let response: HelperResponse = serde_json::from_str(&line).unwrap();

    server.join().unwrap();

    assert!(!response.success);
    assert!(response.error.is_some());
}
