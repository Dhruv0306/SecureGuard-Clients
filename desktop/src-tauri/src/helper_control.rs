//! Enable site blocking: report whether the helper is running and may be
//! started, start it with the approval prompt, and quit a helper this app
//! started when the app exits. The logic takes the socket name, the helper
//! path and the platform as arguments so tests can use fakes; `current_*` use
//! the real ones.

use crate::helper_client;
use secureguard_core::helper_launch::{
    check_helper_location,
    enable_with,
    helper_path_beside,
    helper_status,
    Enabled,
    HelperStatus,
    LaunchError,
    HELPER_FILE_NAME,
};
use secureguard_core::helper_protocol::HELPER_SOCKET_NAME;
use std::path::{ Path, PathBuf };
use std::sync::atomic::{ AtomicBool, Ordering };
use std::time::Duration;

/// How long the app waits for a helper it started to answer a quit request
/// before it exits anyway.
const QUIT_TIMEOUT: Duration = Duration::from_secs(2);

/// Shown where the app has no way to start the helper yet.
pub const NOT_AVAILABLE_HERE: &str =
    "Starting the privileged helper from the app is not available on this platform yet.";

/// Whether the helper answers and, if not, whether the app may start it.
/// `enforce_writable` is false in developer builds. `can_start` is false on a
/// platform with no launcher.
fn status_at(
    socket_name: &str,
    helper: &Path,
    enforce_writable: bool,
    can_start: bool
) -> HelperStatus {
    let running = helper_client::helper_reachable_at(socket_name);
    if !running && !can_start {
        return HelperStatus {
            supported: false,
            running: false,
            reason: Some(NOT_AVAILABLE_HERE.to_string()),
        };
    }
    helper_status(running, || check_helper_location(helper, enforce_writable))
}

/// The enable flow against a socket and a helper path, with `launch` and
/// `sleep` passed in. Remembers in `started` that this app started the helper,
/// and only then: a helper that was already running is not the app's to quit.
fn enable_using(
    socket_name: &str,
    helper: &Path,
    enforce_writable: bool,
    started: &AtomicBool,
    launch: impl FnOnce(&Path) -> Result<(), LaunchError>,
    sleep: impl FnMut(Duration)
) -> Result<HelperStatus, String> {
    let outcome = enable_with(
        || helper_client::helper_reachable_at(socket_name),
        || check_helper_location(helper, enforce_writable),
        || launch(helper),
        sleep
    );
    match outcome {
        Ok(Enabled::Started) => started.store(true, Ordering::SeqCst),
        Ok(Enabled::AlreadyRunning) => {}
        Err(e) => {
            return Err(e.message());
        }
    }
    Ok(HelperStatus { supported: true, running: true, reason: None })
}

/// Asks a helper this app started to quit, then clears the mark. Waits at most
/// `timeout`. Does nothing for a helper the app did not start.
fn quit_if_started(started: &AtomicBool, socket_name: &str, timeout: Duration) {
    if started.swap(false, Ordering::SeqCst) {
        if let Err(e) = helper_client::quit_helper_within(socket_name, timeout) {
            eprintln!("could not ask the privileged helper to quit: {e}");
        }
    }
}

fn current_helper_path() -> PathBuf {
    std::env::current_exe()
        .map(|exe| helper_path_beside(&exe))
        .unwrap_or_else(|_| PathBuf::from(HELPER_FILE_NAME))
}

// A developer build runs from `target/debug`, which the user can write by
// design, so only a release build enforces the write checks.
pub fn current_status() -> HelperStatus {
    status_at(HELPER_SOCKET_NAME, &current_helper_path(), !cfg!(debug_assertions), cfg!(windows))
}

pub fn enable_current(started: &AtomicBool) -> Result<HelperStatus, String> {
    if !cfg!(windows) {
        return Err(NOT_AVAILABLE_HERE.to_string());
    }
    enable_using(
        HELPER_SOCKET_NAME,
        &current_helper_path(),
        !cfg!(debug_assertions),
        started,
        platform_launch,
        std::thread::sleep
    )
}

/// Called when the app exits.
pub fn quit_started_helper(started: &AtomicBool) {
    quit_if_started(started, HELPER_SOCKET_NAME, QUIT_TIMEOUT);
}

#[cfg(windows)]
fn platform_launch(helper: &Path) -> Result<(), LaunchError> {
    secureguard_core::helper_launch::launch_elevated(helper)
}

#[cfg(not(windows))]
fn platform_launch(_helper: &Path) -> Result<(), LaunchError> {
    // enable_current returns before this on a platform with no launcher.
    Err(LaunchError::Failed(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper_client::tests::{ fake_helper, unique_name };
    use secureguard_core::helper_launch::{ LaunchError, Refusal };
    use std::cell::Cell;
    use std::sync::atomic::{ AtomicBool, Ordering };
    use std::time::Duration;

    /// A folder with a helper file in it. The test owns the folder, so an
    /// ordinary user could replace the file: it is an unsafe place when the
    /// write checks are enforced.
    fn helper_in_a_user_folder() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("secureguard-helper");
        std::fs::write(&helper, b"x").unwrap();
        (dir, helper)
    }

    fn no_sleep(_: Duration) {}

    // ---- status ----

    #[test]
    fn a_running_helper_is_running_and_supported_even_if_the_file_is_missing() {
        let name = unique_name("st-run");
        let _seen = fake_helper(&name, "");
        let status = status_at(&name, std::path::Path::new("no-such-file"), true, true);
        assert_eq!(status, HelperStatus { supported: true, running: true, reason: None });
    }

    #[test]
    fn a_stopped_helper_in_a_developer_folder_can_be_enabled() {
        let (_dir, helper) = helper_in_a_user_folder();
        let status = status_at(&unique_name("st-dev"), &helper, false, true);
        assert_eq!(status, HelperStatus { supported: true, running: false, reason: None });
    }

    #[test]
    fn a_stopped_helper_in_a_folder_the_user_can_write_is_unsupported() {
        let (_dir, helper) = helper_in_a_user_folder();
        let status = status_at(&unique_name("st-unsafe"), &helper, true, true);
        assert!(!status.supported && !status.running);
        assert_eq!(status.reason.as_deref(), Some(Refusal::FileWritableByUser.message()));
    }

    #[test]
    fn a_missing_helper_is_unsupported_with_the_reason() {
        let status = status_at(&unique_name("st-miss"), std::path::Path::new("no-such-file"), true, true);
        assert!(!status.supported);
        assert_eq!(status.reason.as_deref(), Some(Refusal::NotFound.message()));
    }

    #[test]
    fn a_platform_that_cannot_start_the_helper_says_so() {
        let (_dir, helper) = helper_in_a_user_folder();
        let status = status_at(&unique_name("st-plat"), &helper, false, false);
        assert!(!status.supported && !status.running);
        assert_eq!(status.reason.as_deref(), Some(NOT_AVAILABLE_HERE));
    }

    // ---- enable ----

    #[test]
    fn enabling_a_helper_that_already_runs_launches_nothing_and_claims_nothing() {
        let name = unique_name("en-run");
        let _seen = fake_helper(&name, "");
        let started = AtomicBool::new(false);

        let result = enable_using(
            &name,
            std::path::Path::new("no-such-file"),
            true,
            &started,
            |_| panic!("must not launch"),
            no_sleep
        );

        assert_eq!(result, Ok(HelperStatus { supported: true, running: true, reason: None }));
        assert!(!started.load(Ordering::SeqCst), "the app did not start this helper");
    }

    #[test]
    fn enabling_in_an_unsafe_place_is_refused_without_launching() {
        let (_dir, helper) = helper_in_a_user_folder();
        let started = AtomicBool::new(false);

        let result = enable_using(
            &unique_name("en-unsafe"),
            &helper,
            true,
            &started,
            |_| panic!("must not launch"),
            no_sleep
        );

        assert_eq!(result, Err(Refusal::FileWritableByUser.message().to_string()));
        assert!(!started.load(Ordering::SeqCst));
    }

    #[test]
    fn a_helper_the_app_starts_is_remembered_so_it_can_be_quit_on_exit() {
        let (_dir, helper) = helper_in_a_user_folder();
        let name = unique_name("en-start");
        let started = AtomicBool::new(false);
        let launched = Cell::new(0);

        let result = enable_using(
            &name,
            &helper,
            false,
            &started,
            |path| {
                assert_eq!(path, helper.as_path());
                launched.set(launched.get() + 1);
                let _seen = fake_helper(&name, ""); // "the helper comes up"
                Ok(())
            },
            no_sleep
        );

        assert_eq!(result, Ok(HelperStatus { supported: true, running: true, reason: None }));
        assert_eq!(launched.get(), 1);
        assert!(started.load(Ordering::SeqCst));
    }

    #[test]
    fn declining_the_prompt_gives_the_cancelled_text_and_remembers_nothing() {
        let (_dir, helper) = helper_in_a_user_folder();
        let started = AtomicBool::new(false);

        let result = enable_using(
            &unique_name("en-decl"),
            &helper,
            false,
            &started,
            |_| Err(LaunchError::Declined),
            |_| panic!("must not wait after a decline")
        );

        assert!(result.unwrap_err().contains("cancelled"));
        assert!(!started.load(Ordering::SeqCst));
    }

    #[test]
    fn a_helper_that_never_answers_after_the_prompt_times_out_and_remembers_nothing() {
        let (_dir, helper) = helper_in_a_user_folder();
        let started = AtomicBool::new(false);

        let result = enable_using(&unique_name("en-slow"), &helper, false, &started, |_| Ok(()), no_sleep);

        assert!(result.unwrap_err().contains("10 seconds"));
        assert!(!started.load(Ordering::SeqCst));
    }

    // ---- quit on exit ----

    #[test]
    fn a_helper_the_app_did_not_start_is_left_running_on_exit() {
        let name = unique_name("qx-none");
        let seen = fake_helper(&name, "{\"success\":true,\"error\":null}\n");

        quit_if_started(&AtomicBool::new(false), &name, Duration::from_secs(1));

        assert!(seen.lock().unwrap().is_empty(), "no quit may be sent");
    }

    #[test]
    fn a_helper_the_app_started_is_asked_to_quit_once_and_the_flag_is_cleared() {
        let name = unique_name("qx-sent");
        let seen = fake_helper(&name, "{\"success\":true,\"error\":null}\n");
        let started = AtomicBool::new(true);

        quit_if_started(&started, &name, Duration::from_secs(1));
        quit_if_started(&started, &name, Duration::from_secs(1));

        assert_eq!(*seen.lock().unwrap(), vec!["{\"quit\":true}".to_string()]);
        assert!(!started.load(Ordering::SeqCst));
    }

    #[test]
    fn a_stuck_helper_never_holds_up_the_exit() {
        let name = unique_name("qx-stuck");
        let _seen = fake_helper(&name, "");

        let began = std::time::Instant::now();
        quit_if_started(&AtomicBool::new(true), &name, Duration::from_millis(300));

        assert!(began.elapsed() < Duration::from_secs(3), "took {:?}", began.elapsed());
    }

    #[test]
    fn a_helper_that_is_already_gone_is_not_an_error_on_exit() {
        quit_if_started(&AtomicBool::new(true), &unique_name("qx-gone"), Duration::from_secs(1));
    }

    #[cfg(not(windows))]
    #[test]
    fn enabling_on_a_platform_without_a_launcher_says_so() {
        assert_eq!(enable_current(&AtomicBool::new(false)), Err(NOT_AVAILABLE_HERE.to_string()));
    }
}
