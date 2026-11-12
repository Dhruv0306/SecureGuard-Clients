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
    /// Windows: the current user could write the helper file.
    FileWritableByUser,
    /// Windows: the current user could create files next to the helper.
    FolderWritableByUser,
    /// Unix: the helper or its folder is not owned by root.
    NotRootOwned,
    /// Unix: group or others could write the helper or its folder.
    WritableByOthers,
    /// Running from an AppImage, which cannot hold a root-owned helper.
    AppImage,
}

impl Refusal {
    /// Plain text for the page. Every case says what to do.
    pub fn message(&self) -> &'static str {
        match self {
            Refusal::NotFound =>
                "The privileged helper was not found next to SecureGuard. Reinstall SecureGuard.",
            Refusal::FileWritableByUser | Refusal::FolderWritableByUser =>
                "Site blocking needs SecureGuard installed for all users, because an ordinary program could change this copy. Reinstall SecureGuard for all users.",
            Refusal::NotRootOwned =>
                "Site blocking needs SecureGuard installed from the .deb package, because only an administrator should be able to change the helper. Reinstall SecureGuard from the .deb package.",
            Refusal::WritableByOthers =>
                "Site blocking needs the helper to be changeable only by an administrator, and it is not. Reinstall SecureGuard from the .deb package.",
            Refusal::AppImage =>
                "Site blocking is not available in the AppImage. Install the SecureGuard .deb package instead.",
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

/// The Windows rule on the real file system: a missing helper, a helper file
/// the current user can open for writing, or a folder the current user can
/// create files in. The write probes run only when the file exists, so a
/// missing helper never causes a file to be created.
pub fn check_writable_location(helper: &Path) -> Result<(), Refusal> {
    let exists = helper.is_file();
    let folder = helper.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    check_location(exists, exists && can_write_file(helper), exists && can_create_in(folder))
}

/// Owner and permission bits of a file or folder, as `stat` reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerMode {
    pub uid: u32,
    pub mode: u32,
}

/// The Unix rule, from the helper's and its folder's owner and mode: both owned
/// by root, and neither writable by group or others. Owned by root is required
/// even when the mode forbids writing, because the owner can change the mode
/// back. `None` for the file means it does not exist. File type bits in `mode`
/// are ignored.
pub fn check_unix_location(file: Option<OwnerMode>, folder: OwnerMode) -> Result<(), Refusal> {
    let Some(file) = file else {
        return Err(Refusal::NotFound);
    };
    if file.uid != 0 || folder.uid != 0 {
        return Err(Refusal::NotRootOwned);
    }
    const GROUP_OR_OTHER_WRITE: u32 = 0o022;
    if (file.mode | folder.mode) & GROUP_OR_OTHER_WRITE != 0 {
        return Err(Refusal::WritableByOthers);
    }
    Ok(())
}

/// The Unix rule on the real file system. Symlinks are resolved first, so a
/// link in a root-owned folder to a file elsewhere is judged by that file and
/// the folder that file is in.
#[cfg(unix)]
fn check_unix_location_on_disk(helper: &Path) -> Result<(), Refusal> {
    use std::os::unix::fs::MetadataExt;
    let Ok(real) = helper.canonicalize() else {
        return Err(Refusal::NotFound);
    };
    let Ok(file) = std::fs::metadata(&real) else {
        return Err(Refusal::NotFound);
    };
    if !file.is_file() {
        return Err(Refusal::NotFound);
    }
    let Some(folder_path) = real.parent() else {
        return Err(Refusal::NotFound);
    };
    let Ok(folder) = std::fs::metadata(folder_path) else {
        return Err(Refusal::NotFound);
    };
    check_unix_location(
        Some(OwnerMode { uid: file.uid(), mode: file.mode() }),
        OwnerMode { uid: folder.uid(), mode: folder.mode() }
    )
}

/// Looks at the real file system with this platform's rule. With
/// `enforce_safe_install` false (a developer build, where `target/debug` is
/// owned by the developer by design) only the existence of the helper is
/// checked.
pub fn check_helper_location(helper: &Path, enforce_safe_install: bool) -> Result<(), Refusal> {
    if !enforce_safe_install {
        return if helper.is_file() { Ok(()) } else { Err(Refusal::NotFound) };
    }
    #[cfg(unix)]
    {
        check_unix_location_on_disk(helper)
    }
    #[cfg(not(unix))]
    {
        check_writable_location(helper)
    }
}

/// `Some(AppImage)` when the app runs from an AppImage (the `APPIMAGE`
/// variable is set and not empty): its files are unpacked for the user, so the
/// helper cannot be root-owned.
pub fn appimage_refusal(appimage_variable: Option<&str>) -> Option<Refusal> {
    match appimage_variable {
        Some(value) if !value.is_empty() => Some(Refusal::AppImage),
        _ => None,
    }
}

/// Whether the helper may be started from this install: not from an AppImage
/// (even in a developer build, where it could never work), then the platform's
/// location rule.
pub fn check_install(
    helper: &Path,
    enforce_safe_install: bool,
    appimage_variable: Option<&str>
) -> Result<(), Refusal> {
    if let Some(refusal) = appimage_refusal(appimage_variable) {
        return Err(refusal);
    }
    check_helper_location(helper, enforce_safe_install)
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
    /// The system could not start it; the number is the error code (a Windows
    /// error code, or the launcher's exit status).
    Failed(u32),
    /// The program that asks for approval (`pkexec` on Linux) is not installed.
    MissingLauncher,
}

/// A started launcher: how long to wait for the helper to answer, and a watch
/// that is asked each time the wait looks and says whether the launcher failed
/// in the meantime. Windows asks for approval before it returns, so it waits
/// 10 seconds with a watch that never fails. On Linux the prompt is still open
/// while the wait runs, so it waits longer and the watch reports the launcher
/// exiting.
pub struct Launch {
    pub timeout: Duration,
    pub watch: Box<dyn FnMut() -> Option<LaunchError>>,
}

impl Launch {
    pub fn standard() -> Self {
        Self::with_watch(WAIT_TIMEOUT, || None)
    }

    pub fn with_watch(timeout: Duration, watch: impl FnMut() -> Option<LaunchError> + 'static) -> Self {
        Self { timeout, watch: Box::new(watch) }
    }
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
    MissingLauncher,
    /// The helper was started but did not answer within this long.
    TimedOut(Duration),
}

impl EnableError {
    pub fn message(&self) -> String {
        match self {
            EnableError::Refused(refusal) => refusal.message().to_string(),
            EnableError::Declined =>
                "Approval was cancelled, so site blocking was not turned on.".to_string(),
            EnableError::LaunchFailed(code) =>
                format!("The privileged helper could not be started (error {code})."),
            EnableError::MissingLauncher =>
                "Starting the privileged helper needs pkexec (polkit), which was not found. Install polkit, or start the helper by hand.".to_string(),
            EnableError::TimedOut(waited) =>
                format!(
                    "The privileged helper was started but did not answer within {} seconds.",
                    waited.as_secs()
                ),
        }
    }
}

fn launch_error(error: LaunchError) -> EnableError {
    match error {
        LaunchError::Declined => EnableError::Declined,
        LaunchError::Failed(code) => EnableError::LaunchFailed(code),
        LaunchError::MissingLauncher => EnableError::MissingLauncher,
    }
}

/// The whole "Enable site blocking" flow with the outside world passed in:
/// does the helper answer, is the location safe, start it (the approval
/// prompt), and sleep. Nothing is started unless the location is safe. While
/// waiting for the helper, a failure reported by the launcher's watch ends the
/// wait at once, but a helper that answers in the same look wins.
pub fn enable_with(
    mut is_running: impl FnMut() -> bool,
    location: impl FnOnce() -> Result<(), Refusal>,
    launch: impl FnOnce() -> Result<Launch, LaunchError>,
    sleep: impl FnMut(Duration)
) -> Result<Enabled, EnableError> {
    if is_running() {
        return Ok(Enabled::AlreadyRunning);
    }
    location().map_err(EnableError::Refused)?;
    let Launch { timeout, mut watch } = launch().map_err(launch_error)?;

    let mut failure = None;
    let answered = wait_until(
        || {
            if is_running() {
                return true;
            }
            if let Some(error) = watch() {
                failure = Some(error);
                return true; // stop waiting; the failure is reported below
            }
            false
        },
        timeout,
        WAIT_STEP,
        sleep
    );

    match (failure, answered) {
        (Some(error), _) => Err(launch_error(error)),
        (None, true) => Ok(Enabled::Started),
        (None, false) => Err(EnableError::TimedOut(timeout)),
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
        for refusal in [
            Refusal::NotFound,
            Refusal::FileWritableByUser,
            Refusal::FolderWritableByUser,
            Refusal::NotRootOwned,
            Refusal::WritableByOthers,
            Refusal::AppImage,
        ] {
            let text = refusal.message();
            assert!(text.ends_with('.'), "{text}");
            assert!(text.to_lowercase().contains("install"), "{text}");
        }
        assert!(Refusal::FolderWritableByUser.message().contains("all users"));
        assert!(Refusal::AppImage.message().contains(".deb"));
        assert!(Refusal::NotRootOwned.message().contains(".deb"));
    }

    // ---- check_unix_location ----

    fn root(mode: u32) -> OwnerMode { OwnerMode { uid: 0, mode } }
    fn user(mode: u32) -> OwnerMode { OwnerMode { uid: 1000, mode } }

    #[test]
    fn a_root_owned_helper_in_a_root_owned_folder_nobody_else_can_write_is_accepted() {
        assert_eq!(check_unix_location(Some(root(0o755)), root(0o755)), Ok(()));
        assert_eq!(check_unix_location(Some(root(0o555)), root(0o555)), Ok(()));
        // The mode from a real stat has the file type in its high bits.
        assert_eq!(check_unix_location(Some(root(0o100755)), root(0o040755)), Ok(()));
    }

    #[test]
    fn a_missing_helper_is_refused_before_anything_else_on_unix_too() {
        assert_eq!(check_unix_location(None, user(0o777)), Err(Refusal::NotFound));
    }

    #[test]
    fn a_helper_or_folder_owned_by_anyone_but_root_is_refused() {
        assert_eq!(check_unix_location(Some(user(0o755)), root(0o755)), Err(Refusal::NotRootOwned));
        assert_eq!(check_unix_location(Some(root(0o755)), user(0o755)), Err(Refusal::NotRootOwned));
        // Mode 555 does not help: the owner can change the mode back.
        assert_eq!(check_unix_location(Some(user(0o555)), user(0o555)), Err(Refusal::NotRootOwned));
    }

    #[test]
    fn a_helper_or_folder_that_group_or_others_can_write_is_refused() {
        for mode in [0o775, 0o757, 0o777, 0o666, 0o100775, 0o100757] {
            assert_eq!(
                check_unix_location(Some(root(mode)), root(0o755)),
                Err(Refusal::WritableByOthers),
                "file mode {mode:o}"
            );
        }
        for mode in [0o775, 0o757, 0o777, 0o041777, 0o040775] {
            assert_eq!(
                check_unix_location(Some(root(0o755)), root(mode)),
                Err(Refusal::WritableByOthers),
                "folder mode {mode:o}"
            );
        }
    }

    #[test]
    fn ownership_is_reported_before_writability() {
        assert_eq!(check_unix_location(Some(user(0o777)), root(0o755)), Err(Refusal::NotRootOwned));
    }

    // ---- AppImage and the whole install check ----

    #[test]
    fn an_appimage_is_recognized_by_its_environment_variable() {
        assert_eq!(appimage_refusal(None), None);
        assert_eq!(appimage_refusal(Some("")), None);
        assert_eq!(appimage_refusal(Some("/tmp/SecureGuard.AppImage")), Some(Refusal::AppImage));
    }

    #[test]
    fn an_appimage_is_refused_even_in_a_developer_build_and_even_if_the_file_is_missing() {
        let missing = std::path::Path::new("no-such-dir").join(HELPER_FILE_NAME);
        assert_eq!(check_install(&missing, false, Some("/x.AppImage")), Err(Refusal::AppImage));
        assert_eq!(check_install(&missing, true, Some("/x.AppImage")), Err(Refusal::AppImage));
    }

    #[test]
    fn without_an_appimage_the_install_check_is_the_location_check() {
        let missing = std::path::Path::new("no-such-dir").join(HELPER_FILE_NAME);
        assert_eq!(check_install(&missing, false, None), Err(Refusal::NotFound));
        assert_eq!(check_install(&missing, true, Some("")), Err(Refusal::NotFound));
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
            never_called::<Result<Launch, LaunchError>>(),
            |_| panic!("must not sleep")
        );
        assert_eq!(result, Ok(Enabled::AlreadyRunning));
    }

    #[test]
    fn enabling_in_an_unsafe_place_is_refused_and_starts_nothing() {
        let result = enable_with(
            || false,
            || Err(Refusal::FolderWritableByUser),
            never_called::<Result<Launch, LaunchError>>(),
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
    fn a_failed_start_carries_the_error_code() {
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
                Ok(Launch::standard())
            },
            |_| {}
        );
        assert_eq!(result, Ok(Enabled::Started));
    }

    #[test]
    fn a_started_helper_that_never_answers_times_out_after_the_limit() {
        let slept = RefCell::new(Duration::ZERO);
        let result = enable_with(|| false, || Ok(()), || Ok(Launch::standard()), |d| {
            *slept.borrow_mut() += d;
        });
        assert_eq!(result, Err(EnableError::TimedOut(WAIT_TIMEOUT)));
        assert_eq!(*slept.borrow(), WAIT_TIMEOUT);
        assert!(EnableError::TimedOut(WAIT_TIMEOUT).message().contains("10 seconds"));
    }

    // ---- a launcher that sets its own wait and can fail early ----

    #[test]
    fn the_standard_launch_waits_ten_seconds_and_never_fails_early() {
        let mut launch = Launch::standard();
        assert_eq!(launch.timeout, WAIT_TIMEOUT);
        assert_eq!((launch.watch)(), None);
    }

    #[test]
    fn the_launcher_sets_how_long_to_wait() {
        let slept = RefCell::new(Duration::ZERO);
        let result = enable_with(
            || false,
            || Ok(()),
            || Ok(Launch::with_watch(Duration::from_secs(120), || None)),
            |d| {
                *slept.borrow_mut() += d;
            }
        );
        assert_eq!(result, Err(EnableError::TimedOut(Duration::from_secs(120))));
        assert_eq!(*slept.borrow(), Duration::from_secs(120));
        assert!(EnableError::TimedOut(Duration::from_secs(120)).message().contains("120 seconds"));
    }

    #[test]
    fn a_launcher_that_reports_a_decline_ends_the_wait_at_once() {
        let slept = RefCell::new(Duration::ZERO);
        let looks = Cell::new(0);
        let result = enable_with(
            || false,
            || Ok(()),
            || {
                Ok(
                    Launch::with_watch(Duration::from_secs(120), move || {
                        looks.set(looks.get() + 1);
                        if looks.get() >= 3 { Some(LaunchError::Declined) } else { None }
                    })
                )
            },
            |d| {
                *slept.borrow_mut() += d;
            }
        );
        assert_eq!(result, Err(EnableError::Declined));
        assert_eq!(*slept.borrow(), WAIT_STEP * 2, "two sleeps between three looks, then it stops");
    }

    #[test]
    fn a_launcher_that_exited_with_an_error_carries_its_code() {
        let result = enable_with(
            || false,
            || Ok(()),
            || Ok(Launch::with_watch(Duration::from_secs(120), || Some(LaunchError::Failed(127)))),
            |_| panic!("must not sleep after a failure")
        );
        assert_eq!(result, Err(EnableError::LaunchFailed(127)));
    }

    #[test]
    fn a_helper_that_comes_up_wins_over_a_failure_reported_at_the_same_moment() {
        let polls = Cell::new(0);
        let result = enable_with(
            || {
                polls.set(polls.get() + 1);
                polls.get() >= 2
            },
            || Ok(()),
            || Ok(Launch::with_watch(Duration::from_secs(120), || Some(LaunchError::Failed(1)))),
            |_| {}
        );
        assert_eq!(result, Ok(Enabled::Started));
    }

    #[test]
    fn a_missing_launcher_is_its_own_error_with_a_plain_message() {
        let result = enable_with(|| false, || Ok(()), || Err(LaunchError::MissingLauncher), |_| {});
        assert_eq!(result, Err(EnableError::MissingLauncher));
        let text = EnableError::MissingLauncher.message();
        assert!(text.contains("pkexec"), "{text}");
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
    fn the_write_probes_read_the_real_file_system() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("secureguard-helper");
        assert_eq!(check_writable_location(&missing), Err(Refusal::NotFound));

        std::fs::write(&missing, b"x").unwrap();
        // The test owns this folder, so an ordinary user could replace the file.
        assert_eq!(check_writable_location(&missing), Err(Refusal::FileWritableByUser));
    }

    #[test]
    fn a_developer_build_skips_the_checks_but_still_needs_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("secureguard-helper");
        assert_eq!(check_helper_location(&helper, false), Err(Refusal::NotFound));

        std::fs::write(&helper, b"x").unwrap();
        // A place the rule refuses on every platform and for every user.
        #[cfg(unix)]
        {
            set_mode(&helper, 0o777);
            set_mode(dir.path(), 0o777);
            assert!(check_helper_location(&helper, true).is_err());
        }
        assert_eq!(check_helper_location(&helper, false), Ok(()));
    }

    #[cfg(not(unix))]
    #[test]
    fn on_windows_the_platform_rule_is_the_write_probes() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("secureguard-helper.exe");
        std::fs::write(&helper, b"x").unwrap();
        assert_eq!(check_helper_location(&helper, true), Err(Refusal::FileWritableByUser));
    }

    /// Whether this test process owns what it creates as root would, which
    /// decides what the real file system tests can say.
    #[cfg(unix)]
    fn running_as_root(dir: &std::path::Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(dir).unwrap().uid() == 0
    }

    #[cfg(unix)]
    fn set_mode(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn on_unix_the_platform_rule_reads_the_real_owner_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("bin");
        std::fs::create_dir(&folder).unwrap();
        let helper = folder.join("secureguard-helper");
        std::fs::write(&helper, b"x").unwrap();
        set_mode(&helper, 0o755);
        set_mode(&folder, 0o755);

        if !running_as_root(dir.path()) {
            // Everything this process creates belongs to a normal user.
            assert_eq!(check_helper_location(&helper, true), Err(Refusal::NotRootOwned));
            return;
        }
        assert_eq!(check_helper_location(&helper, true), Ok(()));

        set_mode(&helper, 0o775);
        assert_eq!(check_helper_location(&helper, true), Err(Refusal::WritableByOthers));
        set_mode(&helper, 0o755);

        set_mode(&folder, 0o777);
        assert_eq!(check_helper_location(&helper, true), Err(Refusal::WritableByOthers));
        set_mode(&folder, 0o755);

        std::os::unix::fs::chown(&helper, Some(65534), None).unwrap();
        assert_eq!(check_helper_location(&helper, true), Err(Refusal::NotRootOwned));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_a_file_someone_else_owns_is_judged_by_the_file_it_points_to() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("secureguard-helper");
        std::fs::write(&target, b"x").unwrap();
        set_mode(&target, 0o755);
        set_mode(dir.path(), 0o755);
        std::os::unix::fs::symlink(&target, &link).unwrap();

        if running_as_root(dir.path()) {
            std::os::unix::fs::chown(&target, Some(65534), None).unwrap();
        }
        assert_eq!(check_helper_location(&link, true), Err(Refusal::NotRootOwned));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_is_judged_by_the_folder_of_the_file_it_points_to() {
        let dir = tempfile::tempdir().unwrap();
        if !running_as_root(dir.path()) {
            return; // everything made here is user-owned, so folders cannot be told apart
        }
        let safe = dir.path().join("safe");
        let open = dir.path().join("open");
        std::fs::create_dir(&safe).unwrap();
        std::fs::create_dir(&open).unwrap();
        set_mode(&safe, 0o755);
        set_mode(&open, 0o777); // anyone could replace the file inside
        let target = open.join("secureguard-helper");
        std::fs::write(&target, b"x").unwrap();
        set_mode(&target, 0o755);
        let link = safe.join("secureguard-helper");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert_eq!(check_helper_location(&link, true), Err(Refusal::WritableByOthers));
    }

    #[cfg(unix)]
    #[test]
    fn on_unix_a_missing_helper_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            check_helper_location(&dir.path().join("secureguard-helper"), true),
            Err(Refusal::NotFound)
        );
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
