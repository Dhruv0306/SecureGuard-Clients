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

    let request = HelperRequest::SetDomains { active_domains };
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
        // The same constructor the real helper uses, so on Windows these
        // tests also prove the pipe's security descriptor is accepted and
        // that a client in this session can still connect.
        let listener = secureguard_helper::bind_listener(&server_socket_name).expect(
            "test server should bind"
        );
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
        // The same constructor the real helper uses, so on Windows these
        // tests also prove the pipe's security descriptor is accepted and
        // that a client in this session can still connect.
        let listener = secureguard_helper::bind_listener(&server_socket_name).expect(
            "test server should bind"
        );
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

// ---- serve: quit, idle exit, and clients that say nothing ----

use secureguard_helper::{ Access, ExitReason, ServeOptions };
use std::time::{ Duration, Instant };

/// Runs a test body on its own thread and fails the test if it does not finish,
/// so a helper that stops answering fails fast instead of hanging the run.
fn within<T: Send + 'static>(seconds: u64, body: impl FnOnce() -> T + Send + 'static) -> T {
    let (done, result) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let _ = done.send(body());
    });
    result
        .recv_timeout(Duration::from_secs(seconds))
        .unwrap_or_else(|_| panic!("the test did not finish within {seconds} s (the helper stopped answering)"))
}

fn options(idle_limit_ms: u64) -> ServeOptions {
    ServeOptions {
        idle_limit: Duration::from_millis(idle_limit_ms),
        poll: Duration::from_millis(20),
        access: Access::Anyone,
    }
}

fn hosts() -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), "127.0.0.1 localhost\n").unwrap();
    file
}

/// Starts the real accept loop on a real socket. The listener is bound here,
/// before the thread starts, so a client can connect at once.
fn start_serve(
    test_name: &str,
    hosts: &tempfile::NamedTempFile,
    options: ServeOptions
) -> (String, thread::JoinHandle<std::io::Result<ExitReason>>) {
    let socket_name = unique_socket_name(test_name);
    let listener = secureguard_helper::bind_listener(&socket_name).expect("test server should bind");
    let hosts_path = hosts.path().to_path_buf();
    let handle = thread::spawn(move || {
        secureguard_helper::serve(&listener, &HostsFileWriter::new(hosts_path), &options)
    });
    (socket_name, handle)
}

fn connect(socket_name: &str) -> Stream {
    Stream::connect(socket_name.to_ns_name::<GenericNamespaced>().unwrap()).expect("client should connect")
}

fn request_on(conn: Stream, line: &str) -> HelperResponse {
    let mut conn = conn;
    conn.write_all(line.as_bytes()).unwrap();
    let mut reader = BufReader::new(conn);
    let mut reply = String::new();
    reader.read_line(&mut reply).unwrap();
    serde_json::from_str(&reply).unwrap()
}

#[test]
fn serve_handles_a_domain_request_and_then_a_quit_request() {
    let hosts = hosts();
    let (socket_name, server) = start_serve("serve-end-to-end", &hosts, options(60_000));

    let response = request_on(connect(&socket_name), "{\"active_domains\":[\"malware.example.com\"]}\n");
    assert!(response.success, "{:?}", response.error);
    assert!(std::fs::read_to_string(hosts.path()).unwrap().contains("malware.example.com"));

    let before = std::fs::read(hosts.path()).unwrap();
    let response = request_on(connect(&socket_name), "{\"quit\":true}\n");
    assert!(response.success, "{:?}", response.error);
    assert_eq!(server.join().unwrap().unwrap(), ExitReason::Quit);
    assert_eq!(std::fs::read(hosts.path()).unwrap(), before, "quit must not change the hosts file");
}

#[test]
fn serve_exits_when_idle_and_not_before_the_limit() {
    let hosts = hosts();
    let started = Instant::now();
    let (_socket_name, server) = start_serve("serve-idle", &hosts, options(1_500));

    assert_eq!(server.join().unwrap().unwrap(), ExitReason::Idle);
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(1_500), "left after only {elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
}

#[test]
fn a_request_restarts_the_idle_timer() {
    let hosts = hosts();
    let started = Instant::now();
    let (socket_name, server) = start_serve("serve-idle-reset", &hosts, options(1_500));

    thread::sleep(Duration::from_millis(500));
    // Sent no earlier than 500 ms in, so the limit now runs out no earlier than 2,000 ms.
    let response = request_on(connect(&socket_name), "{\"active_domains\":[]}\n");
    assert!(response.success);

    thread::sleep(Duration::from_millis(1_200));
    assert!(!server.is_finished(), "the helper left although a request arrived less than the limit ago");

    assert_eq!(server.join().unwrap().unwrap(), ExitReason::Idle);
    assert!(started.elapsed() >= Duration::from_millis(2_000), "left after only {:?}", started.elapsed());
}

#[test]
fn a_rejected_request_also_restarts_the_idle_timer() {
    let hosts = hosts();
    let started = Instant::now();
    let (socket_name, server) = start_serve("serve-idle-reset-bad", &hosts, options(1_500));

    thread::sleep(Duration::from_millis(500));
    let response = request_on(connect(&socket_name), "not json\n");
    assert!(!response.success);

    assert_eq!(server.join().unwrap().unwrap(), ExitReason::Idle);
    assert!(started.elapsed() >= Duration::from_millis(2_000), "left after only {:?}", started.elapsed());
}

#[test]
fn a_client_that_connects_and_says_nothing_does_not_block_a_quit_request() {
    within(20, move || {
        let hosts = hosts();
        let (socket_name, server) = start_serve("serve-silent-quit", &hosts, options(60_000));

        let _silent = connect(&socket_name); // never writes, never closes
        thread::sleep(Duration::from_millis(200));

        let response = request_on(connect(&socket_name), "{\"quit\":true}\n");
        assert!(response.success, "{:?}", response.error);
        assert_eq!(server.join().unwrap().unwrap(), ExitReason::Quit);
    });
}

#[test]
fn a_client_that_connects_and_says_nothing_does_not_keep_the_helper_alive() {
    within(20, move || {
        let hosts = hosts();
        let (socket_name, server) = start_serve("serve-silent-idle", &hosts, options(1_000));

        let _silent = connect(&socket_name);

        assert_eq!(server.join().unwrap().unwrap(), ExitReason::Idle);
    });
}

#[test]
fn connections_beyond_the_reader_limit_are_closed_and_service_resumes_when_clients_leave() {
    within(20, move || {
        let hosts = hosts();
        let (socket_name, server) = start_serve("serve-reader-cap", &hosts, options(60_000));

        let silent: Vec<Stream> = (0..secureguard_helper::MAX_READERS).map(|_| connect(&socket_name)).collect();
        thread::sleep(Duration::from_millis(500)); // let the loop accept and start a reader for each

        // One more is closed by the helper: it gets no reply.
        let mut extra = BufReader::new(connect(&socket_name));
        thread::sleep(Duration::from_millis(300));
        extra.get_mut().write_all(b"{\"active_domains\":[]}\n").ok();
        let mut reply = String::new();
        assert!(
            matches!(extra.read_line(&mut reply), Ok(0) | Err(_)),
            "a connection over the limit must not be answered, got {reply:?}"
        );
        drop(extra);

        // When the silent clients leave, their readers end and requests are served again.
        drop(silent);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut conn = connect(&socket_name);
            let sent = conn.write_all(b"{\"quit\":true}\n").is_ok();
            let mut reader = BufReader::new(conn);
            let mut reply = String::new();
            if sent && matches!(reader.read_line(&mut reply), Ok(n) if n > 0) {
                assert!(reply.contains("\"success\":true"), "{reply}");
                break;
            }
            assert!(Instant::now() < deadline, "service did not resume after the silent clients left");
            thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(server.join().unwrap().unwrap(), ExitReason::Quit);
    });
}

// ---- who may connect (Unix): the check uses the peer's real user id ----

#[cfg(unix)]
mod access {
    use super::*;
    use interprocess::local_socket::traits::StreamCommon;
    use std::os::unix::process::CommandExt;

    const CLIENT_SOCKET_ENV: &str = "SCG_TEST_CLIENT_SOCKET";
    /// "nobody", a user that exists on Linux and macOS.
    const OTHER_USER: u32 = 65534;

    /// The user id this test process runs as, as the helper would see it: ask
    /// a listener of our own about the peer that connects to it.
    fn my_euid() -> u32 {
        let name = unique_socket_name("whoami");
        let listener = secureguard_helper::bind_listener(&name).unwrap();
        let client = connect(&name);
        let server_side = listener.accept().unwrap();
        drop(client);
        server_side.peer_creds().unwrap().euid().expect("this platform reports the peer user")
    }

    fn serve_with(
        test_name: &str,
        hosts: &tempfile::NamedTempFile,
        access: Access,
        idle_limit_ms: u64
    ) -> (String, thread::JoinHandle<std::io::Result<ExitReason>>) {
        let mut opts = options(idle_limit_ms);
        opts.access = access;
        start_serve(test_name, hosts, opts)
    }

    /// What a client got back: the reply's success flag, or None when the
    /// helper closed the connection without answering.
    fn client_in_process(socket_name: &str) -> Option<bool> {
        let mut conn = connect(socket_name);
        if conn.write_all(b"{\"active_domains\":[]}\n").is_err() {
            return None;
        }
        let mut reader = BufReader::new(conn);
        let mut reply = String::new();
        match reader.read_line(&mut reply) {
            Ok(n) if n > 0 => Some(serde_json::from_str::<HelperResponse>(&reply).unwrap().success),
            _ => None,
        }
    }

    /// The same client in a copy of this test program that runs as another
    /// user. Only possible when this process is root.
    fn client_as_other_user(socket_name: &str) -> Option<bool> {
        let output = std::process::Command
            ::new(std::env::current_exe().unwrap())
            .args(["--exact", "access::client_entry", "--nocapture", "--test-threads=1"])
            .env(CLIENT_SOCKET_ENV, socket_name)
            .uid(OTHER_USER)
            .output()
            .expect("the test program should start as another user");
        let text = String::from_utf8_lossy(&output.stdout).to_string();
        // The test harness prints "test name ... " before what the test prints.
        let line = text
            .lines()
            .find_map(|l| l.find("RESULT:").map(|at| l[at..].trim()))
            .unwrap_or_else(|| panic!("the child printed no result: {text}\n{}", String::from_utf8_lossy(&output.stderr)));
        match line {
            "RESULT:ok" => Some(true),
            "RESULT:refused" => Some(false),
            "RESULT:none" => None,
            other => panic!("unexpected result {other}"),
        }
    }

    /// Not a test of its own: when started by `client_as_other_user` it plays
    /// the client and prints what happened. Run normally it does nothing.
    #[test]
    fn client_entry() {
        let Ok(socket_name) = std::env::var(CLIENT_SOCKET_ENV) else {
            return;
        };
        let result = match client_in_process(&socket_name) {
            Some(true) => "ok",
            Some(false) => "refused",
            None => "none",
        };
        println!("RESULT:{result}");
    }

    /// A client of the named kind: as `OTHER_USER` when this test runs as root
    /// (the only way to be another user), otherwise as ourselves.
    fn client(socket_name: &str, as_other_user: bool) -> Option<bool> {
        if as_other_user { client_as_other_user(socket_name) } else { client_in_process(socket_name) }
    }

    #[test]
    fn the_user_the_helper_was_told_about_is_served() {
        within(30, || {
            let me = my_euid();
            let hosts = hosts();
            // As root the other user is a child process; otherwise it is us.
            let (allowed, other) = if me == 0 { (OTHER_USER, true) } else { (me, false) };
            let (socket_name, server) = serve_with("acc-allowed", &hosts, Access::Uid(allowed), 1_000);

            assert_eq!(client(&socket_name, other), Some(true));
            assert_eq!(server.join().unwrap().unwrap(), ExitReason::Idle);
        });
    }

    #[test]
    fn any_other_user_is_closed_without_a_reply_and_the_hosts_file_is_untouched() {
        within(30, || {
            let me = my_euid();
            let hosts = hosts();
            // Name a user that is neither root nor the client.
            let (allowed, other) = if me == 0 { (1000, true) } else { (me.wrapping_add(1), false) };
            let (socket_name, server) = serve_with("acc-refused", &hosts, Access::Uid(allowed), 1_500);

            assert_eq!(client(&socket_name, other), None, "a refused user gets no answer");
            assert_eq!(server.join().unwrap().unwrap(), ExitReason::Idle);
            assert_eq!(
                std::fs::read_to_string(hosts.path()).unwrap(),
                "127.0.0.1 localhost\n",
                "a refused request must not touch the hosts file"
            );
        });
    }

    #[test]
    fn root_is_served_whoever_the_helper_was_told_about() {
        within(30, || {
            if my_euid() != 0 {
                return; // only meaningful as root
            }
            let hosts = hosts();
            let (socket_name, server) = serve_with("acc-root", &hosts, Access::Uid(1000), 1_000);

            assert_eq!(client_in_process(&socket_name), Some(true));
            assert_eq!(server.join().unwrap().unwrap(), ExitReason::Idle);
        });
    }
}
