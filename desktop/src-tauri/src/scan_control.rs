//! One scan at a time, with a cancel flag the scan polls.
//!
//! The session lives in `AppState`, not in the window, so a page reload
//! cannot lose track of a running scan. The lock here is held only for a
//! few instructions and never together with any other lock or across a scan
//! (see the lock rule on `AppState`).

use std::sync::atomic::{ AtomicBool, Ordering };
use std::sync::{ Arc, Mutex, PoisonError };

#[derive(Default)]
pub struct ScanControl {
    /// The cancel flag of the scan that is running, if there is one.
    session: Mutex<Option<Arc<AtomicBool>>>,
}

impl ScanControl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Claims the one scan slot. The returned guard frees it when dropped, so
    /// a normal end, an error and a panic all clear the session.
    pub fn start(&self) -> Result<ScanGuard<'_>, String> {
        let mut session = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        if session.is_some() {
            return Err("A scan is already running.".to_string());
        }
        let cancel = Arc::new(AtomicBool::new(false));
        *session = Some(Arc::clone(&cancel));
        Ok(ScanGuard { control: self, cancel })
    }

    /// Asks the running scan to stop. True if a scan was running.
    pub fn cancel(&self) -> bool {
        let session = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        match session.as_ref() {
            Some(flag) => {
                flag.store(true, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    // Test-only until the close-window handler uses it (next commit).
    #[cfg(test)]
    pub fn is_running(&self) -> bool {
        self.session.lock().unwrap_or_else(PoisonError::into_inner).is_some()
    }
}

pub struct ScanGuard<'a> {
    control: &'a ScanControl,
    cancel: Arc<AtomicBool>,
}

impl ScanGuard<'_> {
    pub fn cancel_flag(&self) -> &AtomicBool {
        &self.cancel
    }
}

impl Drop for ScanGuard<'_> {
    fn drop(&mut self) {
        *self.control.session.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn a_second_scan_is_refused_while_one_is_running() {
        let control = ScanControl::new();
        let _first = control.start().unwrap();
        let error = control.start().err().unwrap();
        assert_eq!(error, "A scan is already running.");
    }

    #[test]
    fn cancel_reports_whether_a_scan_was_running_and_sets_its_flag() {
        let control = ScanControl::new();
        assert!(!control.cancel(), "nothing is running yet");

        let guard = control.start().unwrap();
        assert!(!guard.cancel_flag().load(Ordering::Relaxed));
        assert!(control.cancel());
        assert!(guard.cancel_flag().load(Ordering::Relaxed));
    }

    #[test]
    fn the_session_is_cleared_after_a_scan_ends_and_a_new_one_can_start() {
        let control = ScanControl::new();
        {
            let _guard = control.start().unwrap();
            assert!(control.is_running());
        }
        assert!(!control.is_running());
        assert!(!control.cancel(), "a finished scan cannot be cancelled");

        let second = control.start().unwrap();
        assert!(
            !second.cancel_flag().load(Ordering::Relaxed),
            "a new scan must not inherit the old scan's cancel flag"
        );
    }

    #[test]
    fn the_session_is_cleared_when_a_scan_panics() {
        let control = ScanControl::new();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = control.start().unwrap();
            panic!("scan blew up");
        }));
        assert!(outcome.is_err());
        assert!(!control.is_running());
        assert!(control.start().is_ok());
    }
}
