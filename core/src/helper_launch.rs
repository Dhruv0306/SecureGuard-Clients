//! Deciding whether the privileged helper may be started from the app, and
//! waiting for it to answer. The decisions are plain functions so they can be
//! tested anywhere; only the elevated start itself is Windows-only.
//!
//! The rule for starting an elevated program: only start it if an ordinary
//! program running as the current user could not have replaced it. On Windows
//! that means the current user can neither open the helper file for writing nor
//! create a file in its folder (an all-users install under Program Files).
//! Parent folders are not checked: that would refuse a valid install on a drive
//! where the user can create folders, such as `D:\Program Files`. The risk that
//! leaves is recorded in docs/helper-security-model.md.

use serde::Serialize;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::path::{ Path, PathBuf };
use std::time::Duration;

/// The helper's file name, next to the app's own executable.
pub const HELPER_FILE_NAME: &str = if cfg!(windows) { "secureguard-helper.exe" } else { "secureguard-helper" };

/// How long to wait for the helper to answer after the user approves the prompt.
pub const WAIT_TIMEOUT: Duration = Duration::from_secs(10);

/// How often to look while waiting.
pub const WAIT_STEP: Duration = Duration::from_millis(250);

/// Why the helper may not be started from the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NotFound,
    FileWritableByUser,
    FolderWritableByUser,
}

impl Refusal {
    /// Plain text for the page. Every case says what to do.
    pub fn message(&self) -> &'static str {
        match self {
            Refusal::NotFound =>
                "The privileged helper was not found next to SecureGuard. Reinstall SecureGuard.",
            Refusal::FileWritableByUser | Refusal::FolderWritableByUser =>
                "Site blocking needs SecureGuard installed for all users, because an ordinary program could change this copy. Reinstall SecureGuard for all users.",
        }
    }
}

/// The decision, from three facts about the helper file. A missing helper is
/// reported first; then a file the user can write; then a folder the user can
/// create files in.
pub fn check_location(
    file_exists: bool,
    file_writable: bool,
    folder_writable: bool
) -> Result<(), Refusal> {
    if !file_exists {
        Err(Refusal::NotFound)
    } else if file_writable {
        Err(Refusal::FileWritableByUser)
    } else if folder_writable {
        Err(Refusal::FolderWritableByUser)
    } else {
        Ok(())
    }
}

/// Whether the current user can open the file for writing. Opens it without
/// creating or truncating, so the file is never changed.
pub fn can_write_file(path: &Path) -> bool {
    OpenOptions::new().write(true).open(path).is_ok()
}

/// Whether the current user can create a file in the folder. Creates a probe
/// file and removes it at once. A probe left by an earlier run counts as yes:
/// creating it needed the same access.
pub fn can_create_in(dir: &Path) -> bool {
    let probe = dir.join(format!(".secureguard-write-probe-{}", std::process::id()));
    match OpenOptions::new().write(true).create_new(true).open(&probe) {
        Ok(file) => {
            drop(file);
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(e) => e.kind() == ErrorKind::AlreadyExists,
    }
}

/// Looks at the real file system. With `enforce_writable` false (a developer
/// build, where `target/debug` is writable by design) only the existence of the
/// helper is checked. The write probes run only when the file exists, so a
/// missing helper never causes a file to be created.
pub fn check_helper_location(helper: &Path, enforce_writable: bool) -> Result<(), Refusal> {
    let exists = helper.is_file();
    if !enforce_writable {
        return if exists { Ok(()) } else { Err(Refusal::NotFound) };
    }
    let folder = helper.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    check_location(exists, exists && can_write_file(helper), exists && can_create_in(folder))
}

/// Where the helper is expected: in the same folder as the app's executable.
pub fn helper_path_beside(app_exe: &Path) -> PathBuf {
    app_exe.parent().unwrap_or(Path::new("")).join(HELPER_FILE_NAME)
}

/// What the page needs to know about site blocking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HelperStatus {
    /// The app may start the helper (or it already runs). False when the
    /// install does not allow it; `reason` then says why.
    pub supported: bool,
    pub running: bool,
    pub reason: Option<String>,
}

/// The status from whether the helper answers now. The location is looked at
/// only when the helper is not running: a running exe cannot be opened for
/// writing even when its permissions allow it, which would read as "safe".
pub fn helper_status(
    running: bool,
    location: impl FnOnce() -> Result<(), Refusal>
) -> HelperStatus {
    if running {
        return HelperStatus { supported: true, running: true, reason: None };
    }
    match location() {
        Ok(()) => HelperStatus { supported: true, running: false, reason: None },
        Err(refusal) =>
            HelperStatus {
                supported: false,
                running: false,
                reason: Some(refusal.message().to_string()),
            },
    }
}

/// Tries `probe` now, then after each `step` until `timeout` has been slept in
/// total, with a last try at the end. Time is counted from the sleeps, so tests
/// need no clock. The probe's own run time is not counted, so the real wait can
/// be a little longer than `timeout`.
pub fn wait_until(
    mut probe: impl FnMut() -> bool,
    timeout: Duration,
    step: Duration,
    mut sleep: impl FnMut(Duration)
) -> bool {
    let mut slept = Duration::ZERO;
    loop {
        if probe() {
            return true;
        }
        if slept >= timeout {
            return false;
        }
        let next = step.min(timeout - slept);
        sleep(next);
        slept += next;
    }
}

/// Why starting the helper failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchError {
    /// The user said no to the approval prompt.
    Declined,
    /// Windows could not start it; the number is the Windows error code.
    Failed(u32),
}

/// UTF-16 units with the terminating zero the Windows calls expect.
pub fn wide_with_nul(units: impl IntoIterator<Item = u16>) -> Vec<u16> {
    units.into_iter().chain(std::iter::once(0)).collect()
}

// FFI-BEGIN
/// Starts the program at `file` (UTF-16, zero-terminated) with the "runas"
/// verb, which makes Windows show its approval prompt. Returns once the prompt
/// has been answered and the program started; it does not wait for the program.
#[cfg(windows)]
fn shell_execute_runas(file: &[u16]) -> Result<(), LaunchError> {
    use windows_sys::Win32::Foundation::{ ERROR_CANCELLED, GetLastError };
    use windows_sys::Win32::UI::Shell::{ ShellExecuteExW, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    debug_assert_eq!(file.last(), Some(&0), "the path must be zero-terminated");
    let verb = wide_with_nul("runas".encode_utf16());

    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        // The call may return before the shell has finished; this asks it to
        // finish first, because this thread may end right after.
        fMask: SEE_MASK_NOASYNC,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        nShow: SW_HIDE,
        ..Default::default()
    };

    // SAFETY: `info` is a fully initialized SHELLEXECUTEINFOW with its size set,
    // and `verb` and `file` are zero-terminated and outlive the call.
    let started = unsafe { ShellExecuteExW(&mut info) };
    if started != 0 {
        return Ok(());
    }
    // SAFETY: GetLastError has no preconditions.
    let code = unsafe { GetLastError() };
    if code == ERROR_CANCELLED { Err(LaunchError::Declined) } else { Err(LaunchError::Failed(code)) }
}
// FFI-END

/// Starts the helper at `path` elevated: Windows asks the user to approve, and
/// `Declined` means they said no.
#[cfg(windows)]
pub fn launch_elevated(path: &Path) -> Result<(), LaunchError> {
    use std::os::windows::ffi::OsStrExt;
    shell_execute_runas(&wide_with_nul(path.as_os_str().encode_wide()))
}

/// What `enable_with` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enabled {
    AlreadyRunning,
    Started,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnableError {
    Refused(Refusal),
    Declined,
    LaunchFailed(u32),
    TimedOut,
}

impl EnableError {
    pub fn message(&self) -> String {
        match self {
            EnableError::Refused(refusal) => refusal.message().to_string(),
            EnableError::Declined =>
                "Approval was cancelled, so site blocking was not turned on.".to_string(),
            EnableError::LaunchFailed(code) =>
                format!("Windows could not start the privileged helper (error {code})."),
            EnableError::TimedOut =>
                format!(
                    "The privileged helper was started but did not answer within {} seconds.",
                    WAIT_TIMEOUT.as_secs()
                ),
        }
    }
}

/// The whole "Enable site blocking" flow with the outside world passed in:
/// does the helper answer, is the location safe, start it (the approval
/// prompt), and sleep. Nothing is started unless the location is safe, and
/// nothing is waited for if the user declined.
pub fn enable_with(
    mut is_running: impl FnMut() -> bool,
    location: impl FnOnce() -> Result<(), Refusal>,
    launch: impl FnOnce() -> Result<(), LaunchError>,
    sleep: impl FnMut(Duration)
) -> Result<Enabled, EnableError> {
    if is_running() {
        return Ok(Enabled::AlreadyRunning);
    }
    location().map_err(EnableError::Refused)?;
    launch().map_err(|e| match e {
        LaunchError::Declined => EnableError::Declined,
        LaunchError::Failed(code) => EnableError::LaunchFailed(code),
    })?;
    if wait_until(&mut is_running, WAIT_TIMEOUT, WAIT_STEP, sleep) {
        Ok(Enabled::Started)
    } else {
        Err(EnableError::TimedOut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{ Cell, RefCell };
    use std::time::Duration;

    // ---- check_location ----

    #[test]
    fn a_missing_helper_is_refused_before_anything_else() {
        assert_eq!(check_location(false, true, true), Err(Refusal::NotFound));
    }

    #[test]
    fn a_helper_file_the_user_can_write_is_refused() {
        assert_eq!(check_location(true, true, false), Err(Refusal::FileWritableByUser));
    }

    #[test]
    fn a_folder_the_user_can_create_files_in_is_refused() {
        assert_eq!(check_location(true, false, true), Err(Refusal::FolderWritableByUser));
        assert_eq!(check_location(true, true, true), Err(Refusal::FileWritableByUser));
    }

    #[test]
    fn a_helper_the_user_cannot_modify_is_accepted() {
        assert_eq!(check_location(true, false, false), Ok(()));
    }

    #[test]
    fn every_refusal_says_what_to_do() {
        for refusal in [Refusal::NotFound, Refusal::FileWritableByUser, Refusal::FolderWritableByUser] {
            let text = refusal.message();
            assert!(text.ends_with('.'), "{text}");
            assert!(text.to_lowercase().contains("reinstall"), "{text}");
        }
        assert!(Refusal::FolderWritableByUser.message().contains("all users"));
    }

    // ---- helper_status ----

    #[test]
    fn a_running_helper_is_supported_and_the_location_is_not_looked_at() {
        let looked = Cell::new(false);
        let status = helper_status(true, || {
            looked.set(true);
            Err(Refusal::FileWritableByUser)
        });
        assert_eq!(status, HelperStatus { supported: true, running: true, reason: None });
        assert!(!looked.get(), "a running exe cannot be probed for write access, so do not");
    }

    #[test]
    fn a_stopped_helper_in_a_safe_place_can_be_enabled() {
        let status = helper_status(false, || Ok(()));
        assert_eq!(status, HelperStatus { supported: true, running: false, reason: None });
    }

    #[test]
    fn a_stopped_helper_in_an_unsafe_place_is_unsupported_with_the_reason() {
        let status = helper_status(false, || Err(Refusal::FolderWritableByUser));
        assert!(!status.supported);
        assert!(!status.running);
        assert_eq!(status.reason.as_deref(), Some(Refusal::FolderWritableByUser.message()));
    }

    // ---- wait_until ----

    fn second(n: u64) -> Duration { Duration::from_secs(n) }

    #[test]
    fn waiting_stops_as_soon_as_the_probe_succeeds_and_sleeps_between_tries() {
        let probes = Cell::new(0);
        let slept = RefCell::new(Vec::new());
        let ok = wait_until(
            || {
                probes.set(probes.get() + 1);
                probes.get() == 3
            },
            second(10),
            second(1),
            |d| slept.borrow_mut().push(d)
        );
        assert!(ok);
        assert_eq!(probes.get(), 3);
        assert_eq!(*slept.borrow(), vec![second(1), second(1)]);
    }

    #[test]
    fn a_probe_that_succeeds_at_once_never_sleeps() {
        let slept = RefCell::new(Vec::new());
        assert!(wait_until(|| true, second(10), second(1), |d| slept.borrow_mut().push(d)));
        assert!(slept.borrow().is_empty());
    }

    #[test]
    fn waiting_gives_up_after_exactly_the_timeout_with_a_last_try_at_the_end() {
        let probes = Cell::new(0);
        let slept = RefCell::new(Vec::new());
        let ok = wait_until(
            || {
                probes.set(probes.get() + 1);
                false
            },
            Duration::from_millis(1000),
            Duration::from_millis(300),
            |d| slept.borrow_mut().push(d)
        );
        assert!(!ok);
        let total: Duration = slept.borrow().iter().sum();
        assert_eq!(total, Duration::from_millis(1000), "never sleeps past the timeout");
        assert_eq!(slept.borrow().last(), Some(&Duration::from_millis(100)), "the last step is shortened");
        assert_eq!(probes.get(), 5, "tries at 0, 300, 600, 900 and 1000 ms");
    }

    #[test]
    fn a_zero_timeout_tries_once_and_does_not_sleep() {
        let probes = Cell::new(0);
        let ok = wait_until(
            || {
                probes.set(probes.get() + 1);
                false
            },
            Duration::ZERO,
            second(1),
            |_| panic!("must not sleep")
        );
        assert!(!ok);
        assert_eq!(probes.get(), 1);
    }

    // ---- enable_with ----

    fn never_called<T>() -> impl FnOnce() -> T {
        || panic!("must not be called")
    }

    #[test]
    fn enabling_when_the_helper_already_runs_does_nothing() {
        let result = enable_with(
            || true,
            never_called::<Result<(), Refusal>>(),
            never_called::<Result<(), LaunchError>>(),
            |_| panic!("must not sleep")
        );
        assert_eq!(result, Ok(Enabled::AlreadyRunning));
    }

    #[test]
    fn enabling_in_an_unsafe_place_is_refused_and_starts_nothing() {
        let result = enable_with(
            || false,
            || Err(Refusal::FolderWritableByUser),
            never_called::<Result<(), LaunchError>>(),
            |_| panic!("must not sleep")
        );
        assert_eq!(result, Err(EnableError::Refused(Refusal::FolderWritableByUser)));
    }

    #[test]
    fn declining_the_prompt_is_its_own_error_and_waits_for_nothing() {
        let result = enable_with(
            || false,
            || Ok(()),
            || Err(LaunchError::Declined),
            |_| panic!("must not sleep")
        );
        assert_eq!(result, Err(EnableError::Declined));
    }

    #[test]
    fn a_failed_start_carries_the_windows_error_code() {
        let result = enable_with(|| false, || Ok(()), || Err(LaunchError::Failed(5)), |_| {});
        assert_eq!(result, Err(EnableError::LaunchFailed(5)));
        assert!(EnableError::LaunchFailed(5).message().contains('5'));
    }

    #[test]
    fn a_started_helper_that_answers_late_is_a_success() {
        let polls = Cell::new(0);
        let launched = Cell::new(false);
        let result = enable_with(
            || {
                polls.set(polls.get() + 1);
                launched.get() && polls.get() >= 4
            },
            || Ok(()),
            || {
                launched.set(true);
                Ok(())
            },
            |_| {}
        );
        assert_eq!(result, Ok(Enabled::Started));
    }

    #[test]
    fn a_started_helper_that_never_answers_times_out_after_the_limit() {
        let slept = RefCell::new(Duration::ZERO);
        let result = enable_with(|| false, || Ok(()), || Ok(()), |d| {
            *slept.borrow_mut() += d;
        });
        assert_eq!(result, Err(EnableError::TimedOut));
        assert_eq!(*slept.borrow(), WAIT_TIMEOUT);
        assert!(EnableError::TimedOut.message().contains("10 seconds"));
    }

    #[test]
    fn the_other_errors_have_plain_messages() {
        assert!(EnableError::Declined.message().contains("cancelled"));
        assert_eq!(
            EnableError::Refused(Refusal::NotFound).message(),
            Refusal::NotFound.message()
        );
    }

    // ---- the file probes and the path ----

    #[test]
    fn a_file_the_user_owns_is_writable_and_the_probe_leaves_it_alone() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"keep me").unwrap();

        assert!(can_write_file(file.path()));
        assert_eq!(std::fs::read(file.path()).unwrap(), b"keep me", "the probe must not truncate");
    }

    #[test]
    fn a_file_that_does_not_exist_is_not_writable_and_is_not_created() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nothing.exe");

        assert!(!can_write_file(&missing));
        assert!(!missing.exists(), "the probe must not create the file");
    }

    #[test]
    fn a_folder_the_user_owns_allows_creating_and_the_probe_cleans_up() {
        let dir = tempfile::tempdir().unwrap();

        assert!(can_create_in(dir.path()));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0, "no probe file left behind");
    }

    #[test]
    fn a_folder_that_does_not_exist_does_not_allow_creating() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!can_create_in(&dir.path().join("missing")));
    }

    #[cfg(unix)]
    #[test]
    fn a_read_only_file_and_folder_are_reported_as_not_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("helper");
        std::fs::write(&file, b"x").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o444)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();

        let (writable, creatable) = (can_write_file(&file), can_create_in(dir.path()));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        if writable {
            return; // running as a privileged user: permissions do not apply, nothing to check
        }
        assert!(!writable && !creatable);
    }

    #[test]
    fn check_helper_location_reads_the_real_file_system() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("secureguard-helper");
        assert_eq!(check_helper_location(&missing, true), Err(Refusal::NotFound));
        assert_eq!(check_helper_location(&missing, false), Err(Refusal::NotFound));

        std::fs::write(&missing, b"x").unwrap();
        // The test owns this folder, so an ordinary user could replace the file.
        assert_eq!(check_helper_location(&missing, true), Err(Refusal::FileWritableByUser));
        // A developer build skips the write checks but still needs the file.
        assert_eq!(check_helper_location(&missing, false), Ok(()));
    }

    #[test]
    fn a_wide_string_gets_exactly_one_terminating_zero() {
        assert_eq!(wide_with_nul("ab".encode_utf16()), vec![97, 98, 0]);
        assert_eq!(wide_with_nul(std::iter::empty()), vec![0]);
    }

    #[test]
    fn the_helper_is_looked_for_next_to_the_app() {
        let app = std::path::Path::new("app-folder").join("secureguard-desktop");
        let helper = helper_path_beside(&app);

        assert_eq!(helper.parent(), app.parent());
        let name = helper.file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(name, HELPER_FILE_NAME);
        assert!(name.starts_with("secureguard-helper"));
    }
}
