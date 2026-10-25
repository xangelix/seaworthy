//! The failure dialog on macOS. A program LaunchServices starts (from the
//! Finder, the Dock, `open`) has no terminal: its stderr goes nowhere a user
//! looks. So when the launcher itself fails — no build this Mac can run, a
//! damaged install, a core that won't load — it also shows what it printed
//! in an alert (CoreFoundation's `CFUserNotificationDisplayAlert`: no
//! AppKit, no Objective-C). A failure of the core is the core's to report.

/// Whether the launcher's failure goes into a dialog: on macOS, when stderr
/// isn't a terminal and LaunchServices started the program — it puts
/// `__CFBundleIdentifier` in the environment of every app it launches. A
/// LaunchDaemon, a script and a test harness have no such variable; a
/// command run in Terminal inherits Terminal's, but has a terminal.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn wanted(stderr_is_terminal: bool, launched_by_launch_services: bool) -> bool {
    cfg!(target_os = "macos") && !stderr_is_terminal && launched_by_launch_services
}

/// Whether this process was started the way [`wanted`] asks about.
pub(crate) fn launch_services_without_terminal() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: isatty takes a descriptor number and only queries it.
        #[allow(unsafe_code, reason = "FFI: isatty")]
        let terminal = unsafe { libc::isatty(libc::STDERR_FILENO) } == 1;
        // LaunchServices' launch marker, read only to decide whether to show
        // a dialog.
        let launched = std::env::var_os("__CFBundleIdentifier").is_some();
        wanted(terminal, launched)
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Shows `message` under the heading `title` and waits for the user to
/// dismiss it. Elsewhere than macOS, nothing.
pub(crate) fn show(title: &str, message: &str) {
    #[cfg(target_os = "macos")]
    macos::alert(title, message);
    #[cfg(not(target_os = "macos"))]
    let _ = (title, message);
}

#[cfg(target_os = "macos")]
mod macos {
    //! CoreFoundation's alert, through three C functions.

    use core::ffi::c_void;

    type CFStringRef = *const c_void;
    type CFOptionFlags = usize;

    /// `kCFStringEncodingUTF8`.
    const UTF8: u32 = 0x0800_0100;
    /// `kCFUserNotificationStopAlertLevel`.
    const STOP_ALERT: CFOptionFlags = 0;

    // SAFETY: the signatures are CoreFoundation's (CFString.h, CFBase.h,
    // CFUserNotification.h) on 64-bit macOS: `CFIndex` is `isize`,
    // `CFOptionFlags` `usize`, `CFStringEncoding` `u32`, `Boolean` `u8`,
    // `SInt32` `i32`, every reference a pointer.
    #[allow(unsafe_code, reason = "FFI: CoreFoundation declarations")]
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithBytes(
            alloc: *const c_void,
            bytes: *const u8,
            num_bytes: isize,
            encoding: u32,
            is_external_representation: u8,
        ) -> CFStringRef;
        fn CFRelease(cf: *const c_void);
        fn CFUserNotificationDisplayAlert(
            timeout: f64,
            flags: CFOptionFlags,
            icon_url: *const c_void,
            sound_url: *const c_void,
            localization_url: *const c_void,
            alert_header: CFStringRef,
            alert_message: CFStringRef,
            default_button_title: CFStringRef,
            alternate_button_title: CFStringRef,
            other_button_title: CFStringRef,
            response_flags: *mut CFOptionFlags,
        ) -> i32;
    }

    /// A CFString of `text` (null when CoreFoundation refuses it).
    fn cf_string(text: &str) -> CFStringRef {
        let Ok(len) = isize::try_from(text.len()) else {
            return core::ptr::null();
        };
        // SAFETY: `text` is valid UTF-8 of `len` bytes; the default
        // allocator (null); the result is released by the caller.
        #[allow(unsafe_code, reason = "FFI: CFStringCreateWithBytes")]
        let string =
            unsafe { CFStringCreateWithBytes(core::ptr::null(), text.as_ptr(), len, UTF8, 0) };
        string
    }

    pub(super) fn alert(title: &str, message: &str) {
        let header = cf_string(title);
        let body = cf_string(message);
        if !header.is_null() && !body.is_null() {
            let mut response: CFOptionFlags = 0;
            // SAFETY: two live CFStrings, nulls for every optional argument
            // (default icon, sound, button), a response slot; a zero
            // timeout waits until the user dismisses the alert.
            #[allow(unsafe_code, reason = "FFI: CFUserNotificationDisplayAlert")]
            unsafe {
                CFUserNotificationDisplayAlert(
                    0.0,
                    STOP_ALERT,
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    header,
                    body,
                    core::ptr::null(),
                    core::ptr::null(),
                    core::ptr::null(),
                    &raw mut response,
                );
            }
        }
        for string in [header, body] {
            if !string.is_null() {
                // SAFETY: a CFString this module created and still owns.
                #[allow(unsafe_code, reason = "FFI: CFRelease")]
                unsafe {
                    CFRelease(string);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_launch_services_start_without_a_terminal_gets_a_dialog() {
        assert_eq!(wanted(false, true), cfg!(target_os = "macos"));
        assert!(!wanted(true, true), "a terminal sees stderr");
        assert!(
            !wanted(false, false),
            "a daemon or a script has no one to show it to"
        );
        assert!(!wanted(true, false));
    }
}
