//! Throwaway spike for Phase 5.3a: proves the candidate network crates
//! compile and can observe this very process.
//!
//! Run:   cargo run -p secureguard-core --example net_probe
//! Exit:  0 = every assertion held, 1 = at least one failed (details printed).
//!
//! It binds a loopback listener, connects to it, then asserts three things.
//! First, `listeners` reports our listening port with our own PID. Second,
//! `netstat2` reports the established connection to that port. Third,
//! `if-addrs` reports at least one interface, including the loopback address.
//!
//! Run it once normally and once elevated (Administrator or sudo) and compare
//! the process-name output: unprivileged runs may not resolve other users'
//! processes, which the UI has to tolerate.

use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;

use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};

fn main() -> ExitCode {
    let mut failures: Vec<String> = Vec::new();
    let my_pid = std::process::id();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener.local_addr().expect("listener addr").port();
    let _client = TcpStream::connect(("127.0.0.1", port)).expect("connect to own listener");
    // Accept so the connection is fully established on both ends.
    let _server_side = listener.accept().expect("accept own connection");

    println!("probe: pid={my_pid} listening on 127.0.0.1:{port}");

    // 1. listening sockets + owning process (listeners crate)
    match listeners::get_all() {
        Ok(all) => {
            println!("listeners: {} listening sockets visible", all.len());
            let mine = all
                .iter()
                .find(|l| l.socket.port() == port && l.process.pid == my_pid);
            match mine {
                Some(l) => println!(
                    "listeners: OK found own listener, process name = {:?}",
                    l.process.name
                ),
                None => failures.push(format!(
                    "listeners: own listener on port {port} with pid {my_pid} not found"
                )),
            }
        }
        Err(e) => failures.push(format!("listeners::get_all failed: {e}")),
    }

    // 2. established connections (netstat2 crate)
    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    match get_sockets_info(af, ProtocolFlags::TCP) {
        Ok(sockets) => {
            let established_to_port = sockets.iter().any(|s| match &s.protocol_socket_info {
                ProtocolSocketInfo::Tcp(t) => {
                    t.state == TcpState::Established
                        && (t.remote_port == port || t.local_port == port)
                }
                _ => false,
            });
            println!("netstat2: {} TCP sockets visible", sockets.len());
            if established_to_port {
                println!("netstat2: OK found established connection involving port {port}");
            } else {
                failures.push(format!(
                    "netstat2: no ESTABLISHED connection involving port {port}"
                ));
            }
        }
        Err(e) => failures.push(format!("netstat2::get_sockets_info failed: {e}")),
    }

    // 3. interfaces (if-addrs crate)
    match if_addrs::get_if_addrs() {
        Ok(ifaces) => {
            println!("if-addrs: {} interface addresses", ifaces.len());
            if ifaces.iter().any(|i| i.ip().is_loopback()) {
                println!("if-addrs: OK loopback present");
            } else {
                failures.push("if-addrs: no loopback address reported".to_string());
            }
        }
        Err(e) => failures.push(format!("if_addrs::get_if_addrs failed: {e}")),
    }

    if failures.is_empty() {
        println!("RESULT: PASS");
        ExitCode::SUCCESS
    } else {
        for f in &failures {
            eprintln!("FAIL: {f}");
        }
        println!("RESULT: FAIL ({} failures)", failures.len());
        ExitCode::FAILURE
    }
}
