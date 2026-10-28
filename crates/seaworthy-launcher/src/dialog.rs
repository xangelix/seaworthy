//! The failure dialog. A desktop program started from the Finder, the Dock,
//! Explorer or a shortcut has no terminal: its stderr goes nowhere a user
//! looks, and a launcher that can't run a core (no build this machine can
//! run, a damaged install, a core that won't load) would seem to do nothing
//! at all. So the launcher also shows what it printed in a dialog, when
//! someone can see one and nothing else would show them the text:
//!
//! - **macOS**: LaunchServices started the program and stderr isn't a
//!   terminal. CoreFoundation's `CFUserNotificationDisplayAlert` (no AppKit,
//!   no Objective-C).
//! - **Windows**: the launcher is a GUI-subsystem program
//!   (`windows_subsystem = "windows"`, read from its own PE header), stderr
//!   isn't a console, the process isn't in session 0 (services), and its
//!   window station is interactive (`WSF_VISIBLE`: not a service's, a
//!   scheduled task's without a logged-on user, or an SSH session's).
//!   `MessageBoxW`, from `user32.dll` loaded out of System32 only when every
//!   other condition holds: the launcher doesn't import it, so its import
//!   table is what it was.
//! - **Never** with [`crate::ENV_NO_DIALOG`] set (anything but empty or
//!   `0`), or with `CI` set (anything but empty, `0` or `false`): a CI
//!   runner's desktop session can be interactive, and a dialog there would
//!   hold the job until it times out.
//!
//! A failure of the core is the core's to report. The exit code and stderr
//! are the same either way; a dialog only adds a copy of the text, already
//! made display-safe, at most [`MAX_LINES`] lines and [`MAX_CHARS`]
//! characters.

use std::ffi::OsStr;

/// The most lines a dialog shows (a damaged install lists one per core).
pub(crate) const MAX_LINES: usize = 40;
/// The most characters a dialog shows.
pub(crate) const MAX_CHARS: usize = 4000;

/// The PE optional header's `Subsystem` of a GUI program
/// (`IMAGE_SUBSYSTEM_WINDOWS_GUI`).
pub(crate) const SUBSYSTEM_GUI: u16 = 2;

/// Whether a failure goes into a dialog, and if not, why not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Show it.
    Show,
    /// [`crate::ENV_NO_DIALOG`] is set.
    OptedOut,
    /// `CI` is set.
    Ci,
    /// stderr is a terminal (a console on Windows): someone reads it there.
    Terminal,
    /// macOS: LaunchServices didn't start the program (a script, a
    /// LaunchDaemon, a test harness).
    NotLaunchServices,
    /// Windows: a console program, whose failures belong in its console.
    ConsoleProgram,
    /// Windows: session 0, where services run and no one sees a window.
    ServiceSession,
    /// Windows: the window station isn't interactive.
    HiddenStation,
    /// Something the decision needs couldn't be read (the program's own
    /// header, its session, its window station, user32): no dialog.
    Unknown,
    /// Neither macOS nor Windows.
    #[cfg_attr(any(target_os = "macos", windows), allow(dead_code))]
    Unsupported,
}

impl Decision {
    /// The decision as the launcher's debug output reports it
    /// (`SEAWORTHY_LAUNCHER_DEBUG=1`).
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::Show => "showing this failure in a dialog",
            Self::OptedOut => "no dialog: SEAWORTHY_LAUNCHER_NO_DIALOG is set",
            Self::Ci => "no dialog: CI is set",
            Self::Terminal => "no dialog: stderr is a terminal",
            Self::NotLaunchServices => "no dialog: LaunchServices did not start the program",
            Self::ConsoleProgram => "no dialog: a console program",
            Self::ServiceSession => "no dialog: session 0, where no one sees a window",
            // Asked last: every other condition called for a dialog.
            Self::HiddenStation => {
                "no dialog: the window station is not interactive (a dialog was called for otherwise)"
            }
            Self::Unknown => "no dialog: whether anyone could see one is unknown",
            Self::Unsupported => "no dialog on this platform",
        }
    }
}

/// [`crate::ENV_NO_DIALOG`]'s value turns the dialog off: anything but
/// unset, empty or `0`.
pub(crate) fn opted_out(value: Option<&OsStr>) -> bool {
    value.is_some_and(|value| !value.is_empty() && value != "0")
}

/// `CI`'s value says a CI job runs this: anything but unset, empty, `0` or
/// `false` (any case).
pub(crate) fn in_ci(value: Option<&OsStr>) -> bool {
    value.is_some_and(|value| {
        !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
    })
}

/// The decision on macOS. LaunchServices puts `__CFBundleIdentifier` in
/// the environment of every app it launches: a LaunchDaemon, a script and a
/// test harness have no such variable; a command run in Terminal inherits
/// Terminal's, but has a terminal.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn macos(
    opted_out: bool,
    ci: bool,
    stderr_terminal: bool,
    launch_services: bool,
) -> Decision {
    if opted_out {
        Decision::OptedOut
    } else if ci {
        Decision::Ci
    } else if stderr_terminal {
        Decision::Terminal
    } else if !launch_services {
        Decision::NotLaunchServices
    } else {
        Decision::Show
    }
}

/// The decision on Windows, from the program's PE `subsystem`, whether
/// stderr is a console, the process's `session` and — asked last, and only
/// when everything else calls for a dialog, because it loads user32 —
/// whether its window station is visible. `None` is an input that couldn't
/// be read.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn windows(
    opted_out: bool,
    ci: bool,
    subsystem: Option<u16>,
    stderr_terminal: bool,
    session: Option<u32>,
    station_visible: impl FnOnce() -> Option<bool>,
) -> Decision {
    if opted_out {
        return Decision::OptedOut;
    }
    if ci {
        return Decision::Ci;
    }
    match subsystem {
        Some(SUBSYSTEM_GUI) => {}
        Some(_) => return Decision::ConsoleProgram,
        None => return Decision::Unknown,
    }
    if stderr_terminal {
        return Decision::Terminal;
    }
    match session {
        Some(0) => return Decision::ServiceSession,
        Some(_) => {}
        None => return Decision::Unknown,
    }
    match station_visible() {
        Some(true) => Decision::Show,
        Some(false) => Decision::HiddenStation,
        None => Decision::Unknown,
    }
}

/// The `Subsystem` field of a PE image whose headers start `headers`: the
/// DOS header's `e_lfanew`, the `PE\0\0` signature, a PE32 or PE32+
/// optional header (the field is at the same offset in both). `None` for
/// anything else.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn pe_subsystem(headers: &[u8]) -> Option<u16> {
    const OPTIONAL_HEADER: usize = 4 + 20;
    const SUBSYSTEM: usize = 68;
    let le16 = |at: usize| -> Option<u16> {
        let bytes = headers.get(at..at.checked_add(2)?)?;
        Some(u16::from_le_bytes(bytes.try_into().ok()?))
    };
    if headers.get(..2)? != b"MZ" {
        return None;
    }
    let lfanew = usize::try_from(u32::from_le_bytes(
        headers.get(0x3c..0x40)?.try_into().ok()?,
    ))
    .ok()?;
    if headers.get(lfanew..lfanew.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let optional = lfanew.checked_add(OPTIONAL_HEADER)?;
    if !matches!(le16(optional)?, 0x10b | 0x20b) {
        return None;
    }
    le16(optional.checked_add(SUBSYSTEM)?)
}

/// The dialog's text: the launcher's lines, at most [`MAX_LINES`] lines and
/// [`MAX_CHARS`] characters (line breaks included), with a last line saying
/// so when it's cut.
pub(crate) fn text(lines: &[String]) -> String {
    let mut out = String::new();
    let mut left = MAX_CHARS;
    let mut cut = lines.len() > MAX_LINES;
    for (i, line) in lines.iter().take(MAX_LINES).enumerate() {
        if i > 0 {
            if left == 0 {
                cut = true;
                break;
            }
            out.push('\n');
            left = left.saturating_sub(1);
        }
        let count = line.chars().count();
        if count > left {
            out.extend(line.chars().take(left));
            cut = true;
            break;
        }
        out.push_str(line);
        left = left.saturating_sub(count);
    }
    if cut {
        out.push_str("\n\u{2026} (cut short)");
    }
    out
}

/// The decision for this process (see the module docs).
pub(crate) fn decide() -> Decision {
    let opted_out = opted_out(std::env::var_os(crate::ENV_NO_DIALOG).as_deref());
    let ci = in_ci(std::env::var_os("CI").as_deref());
    #[cfg(any(target_os = "macos", windows))]
    let stderr_terminal = std::io::IsTerminal::is_terminal(&std::io::stderr());
    #[cfg(target_os = "macos")]
    {
        // LaunchServices' launch marker, read only to decide whether to
        // show a dialog.
        let launched = std::env::var_os("__CFBundleIdentifier").is_some();
        macos(opted_out, ci, stderr_terminal, launched)
    }
    #[cfg(windows)]
    {
        windows(
            opted_out,
            ci,
            win::own_subsystem(),
            stderr_terminal,
            win::session(),
            win::station_visible,
        )
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = (opted_out, ci);
        Decision::Unsupported
    }
}

/// Shows `message` under the heading `title` and waits for the user to
/// dismiss it. Elsewhere than macOS and Windows, nothing.
pub(crate) fn show(title: &str, message: &str) {
    #[cfg(target_os = "macos")]
    macos_alert::alert(title, message);
    #[cfg(windows)]
    win::message_box(title, message);
    #[cfg(not(any(target_os = "macos", windows)))]
    let _ = (title, message);
}

#[cfg(target_os = "macos")]
mod macos_alert {
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

#[cfg(windows)]
mod win {
    //! The process's own PE header, its session and window station, and
    //! the message box. user32 isn't imported: it is loaded from System32
    //! once everything else calls for a dialog, and its three functions are
    //! looked up by name.

    use core::ffi::c_void;

    use windows_sys::Win32::Foundation::HMODULE;
    use windows_sys::Win32::System::LibraryLoader::{
        GetModuleHandleW, GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
    };
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows_sys::Win32::System::StationsAndDesktops::{HWINSTA, UOI_FLAGS, USEROBJECTFLAGS};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MB_ICONERROR, MB_OK, MB_SETFOREGROUND, MB_TOPMOST, WSF_VISIBLE,
    };

    /// How much of the image's start is read for its header: one page,
    /// the least the loader maps for an image's headers (4 KiB pages on
    /// every Windows architecture).
    const HEADER_PAGE: usize = 4096;

    /// `GetProcessWindowStation`.
    type GetProcessWindowStationFn = unsafe extern "system" fn() -> HWINSTA;
    /// `GetUserObjectInformationW`.
    type GetUserObjectInformationWFn =
        unsafe extern "system" fn(*mut c_void, i32, *mut c_void, u32, *mut u32) -> i32;
    /// `MessageBoxW`.
    type MessageBoxWFn = unsafe extern "system" fn(*mut c_void, *const u16, *const u16, u32) -> i32;

    /// The `Subsystem` this process's executable was built with.
    pub(super) fn own_subsystem() -> Option<u16> {
        // SAFETY: GetModuleHandleW(NULL) returns the base address of the
        // executable the process was started from; it has no
        // preconditions.
        #[allow(unsafe_code, reason = "FFI: GetModuleHandleW(NULL)")]
        let base = unsafe { GetModuleHandleW(core::ptr::null()) };
        if base.is_null() {
            return None;
        }
        // SAFETY: the loader maps an executable's headers at its base,
        // readable for the life of the process, in at least one whole
        // page; the slice is only read, and nothing writes the headers.
        #[allow(unsafe_code, reason = "reads the executable's own mapped headers")]
        let headers =
            unsafe { core::slice::from_raw_parts(base.cast::<u8>().cast_const(), HEADER_PAGE) };
        super::pe_subsystem(headers)
    }

    /// This process's session (0: services).
    pub(super) fn session() -> Option<u32> {
        let mut session = 0u32;
        // SAFETY: this process's id and a valid out pointer.
        #[allow(unsafe_code, reason = "FFI: ProcessIdToSessionId")]
        let done = unsafe { ProcessIdToSessionId(std::process::id(), &raw mut session) };
        (done != 0).then_some(session)
    }

    /// user32's three functions, from System32 only.
    struct User32 {
        get_process_window_station: GetProcessWindowStationFn,
        get_user_object_information: GetUserObjectInformationWFn,
        message_box: MessageBoxWFn,
    }

    /// The address of `name` (NUL-terminated) in `module`.
    fn proc(
        module: HMODULE,
        name: &core::ffi::CStr,
    ) -> Option<unsafe extern "system" fn() -> isize> {
        // SAFETY: a module handle LoadLibraryExW returned (never freed) and
        // a NUL-terminated name.
        #[allow(unsafe_code, reason = "FFI: GetProcAddress")]
        let address = unsafe { GetProcAddress(module, name.as_ptr().cast()) };
        address
    }

    fn user32() -> Option<User32> {
        let name = wide("user32.dll");
        // SAFETY: a NUL-terminated name, no file handle, and a search of
        // System32 alone: no other directory can supply the library.
        #[allow(unsafe_code, reason = "FFI: LoadLibraryExW of user32 from System32")]
        let module = unsafe {
            LoadLibraryExW(
                name.as_ptr(),
                core::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return None;
        }
        let station = proc(module, c"GetProcessWindowStation")?;
        let information = proc(module, c"GetUserObjectInformationW")?;
        let message_box = proc(module, c"MessageBoxW")?;
        // SAFETY: user32's GetProcessWindowStation: `HWINSTA (void)`, in
        // the "system" ABI every user32 export uses.
        #[allow(unsafe_code, reason = "a GetProcAddress address to its function type")]
        let get_process_window_station = unsafe {
            core::mem::transmute::<unsafe extern "system" fn() -> isize, GetProcessWindowStationFn>(
                station,
            )
        };
        // SAFETY: user32's GetUserObjectInformationW: `BOOL (HANDLE, int,
        // PVOID, DWORD, LPDWORD)`.
        #[allow(unsafe_code, reason = "a GetProcAddress address to its function type")]
        let get_user_object_information = unsafe {
            core::mem::transmute::<unsafe extern "system" fn() -> isize, GetUserObjectInformationWFn>(
                information,
            )
        };
        // SAFETY: user32's MessageBoxW: `int (HWND, LPCWSTR, LPCWSTR,
        // UINT)`.
        #[allow(unsafe_code, reason = "a GetProcAddress address to its function type")]
        let message_box = unsafe {
            core::mem::transmute::<unsafe extern "system" fn() -> isize, MessageBoxWFn>(message_box)
        };
        Some(User32 {
            get_process_window_station,
            get_user_object_information,
            message_box,
        })
    }

    /// Whether this process's window station is interactive (`WSF_VISIBLE`:
    /// only an interactive logon's `WinSta0` is).
    pub(super) fn station_visible() -> Option<bool> {
        let user32 = user32()?;
        // SAFETY: GetProcessWindowStation takes no arguments; the handle it
        // returns is the process's own and must not be closed.
        #[allow(unsafe_code, reason = "FFI: GetProcessWindowStation")]
        let station = unsafe { (user32.get_process_window_station)() };
        if station.is_null() {
            return None;
        }
        let mut flags = USEROBJECTFLAGS::default();
        let size = u32::try_from(core::mem::size_of::<USEROBJECTFLAGS>()).ok()?;
        let mut needed = 0u32;
        // SAFETY: the window station handle just returned, UOI_FLAGS, and a
        // USEROBJECTFLAGS of `size` bytes to fill.
        #[allow(unsafe_code, reason = "FFI: GetUserObjectInformationW(UOI_FLAGS)")]
        let done = unsafe {
            (user32.get_user_object_information)(
                station,
                UOI_FLAGS,
                (&raw mut flags).cast(),
                size,
                &raw mut needed,
            )
        };
        if done == 0 {
            return None;
        }
        Some(flags.dwFlags & WSF_VISIBLE.cast_unsigned() != 0)
    }

    /// `text` as a NUL-terminated UTF-16 string.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    /// An error message box, in front, until the user dismisses it.
    pub(super) fn message_box(title: &str, message: &str) {
        let Some(user32) = user32() else {
            return;
        };
        let (title, message) = (wide(title), wide(message));
        // SAFETY: no owner window, two NUL-terminated UTF-16 strings that
        // outlive the call, and a style of documented flags.
        #[allow(unsafe_code, reason = "FFI: MessageBoxW")]
        unsafe {
            (user32.message_box)(
                core::ptr::null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST,
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use std::cell::Cell;
    use std::ffi::OsString;

    use super::*;

    #[test]
    fn the_opt_out_takes_anything_but_empty_or_zero() {
        assert!(!opted_out(None));
        for off in ["", "0"] {
            assert!(!opted_out(Some(OsStr::new(off))), "{off:?}");
        }
        for on in ["1", "yes", "true"] {
            assert!(opted_out(Some(OsStr::new(on))), "{on:?}");
        }
    }

    #[test]
    fn ci_is_anything_but_empty_zero_or_false() {
        assert!(!in_ci(None));
        for off in ["", "0", "false", "False", "FALSE"] {
            assert!(!in_ci(Some(OsStr::new(off))), "{off:?}");
        }
        for on in ["true", "1", "yes"] {
            assert!(in_ci(Some(OsStr::new(on))), "{on:?}");
        }
        assert!(in_ci(Some(&OsString::from("TRUE"))));
    }

    #[test]
    fn macos_shows_a_dialog_only_for_a_launch_services_start_without_a_terminal() {
        assert_eq!(macos(false, false, false, true), Decision::Show);
        assert_eq!(macos(false, false, true, true), Decision::Terminal);
        assert_eq!(
            macos(false, false, false, false),
            Decision::NotLaunchServices
        );
        assert_eq!(macos(true, false, false, true), Decision::OptedOut);
        assert_eq!(macos(false, true, false, true), Decision::Ci);
    }

    /// The Windows decision's inputs: opted out, CI, subsystem, stderr a
    /// console, session, window station visible.
    type Inputs = (bool, bool, Option<u16>, bool, Option<u32>, Option<bool>);
    /// One input changed.
    type Change = fn(&mut Inputs);

    /// The Windows decision with every input calling for a dialog, but
    /// `change`'s; whether the window station was asked.
    fn windows_with(change: impl FnOnce(&mut Inputs)) -> (Decision, bool) {
        let mut inputs: Inputs = (
            false,
            false,
            Some(SUBSYSTEM_GUI),
            false,
            Some(1),
            Some(true),
        );
        change(&mut inputs);
        let (opted_out, ci, subsystem, terminal, session, station) = inputs;
        let asked = Cell::new(false);
        let decision = windows(opted_out, ci, subsystem, terminal, session, || {
            asked.set(true);
            station
        });
        (decision, asked.get())
    }

    #[test]
    fn windows_shows_a_dialog_only_for_a_gui_program_someone_can_see() {
        assert_eq!(windows_with(|_| {}), (Decision::Show, true));
        assert_eq!(
            windows_with(|i| i.5 = Some(false)),
            (Decision::HiddenStation, true)
        );
        assert_eq!(windows_with(|i| i.5 = None), (Decision::Unknown, true));
    }

    #[test]
    fn windows_asks_the_window_station_only_when_everything_else_calls_for_a_dialog() {
        // Each of these decides before user32 would be loaded.
        let cases: [(Change, Decision); 7] = [
            (|i| i.0 = true, Decision::OptedOut),
            (|i| i.1 = true, Decision::Ci),
            // IMAGE_SUBSYSTEM_WINDOWS_CUI: a console program.
            (|i| i.2 = Some(3), Decision::ConsoleProgram),
            (|i| i.2 = None, Decision::Unknown),
            (|i| i.3 = true, Decision::Terminal),
            (|i| i.4 = Some(0), Decision::ServiceSession),
            (|i| i.4 = None, Decision::Unknown),
        ];
        for (change, expected) in cases {
            assert_eq!(windows_with(change), (expected, false), "{expected:?}");
        }
        // The opt-out wins over everything, even a console program's.
        assert_eq!(
            windows_with(|i| {
                i.0 = true;
                i.2 = Some(3);
            }),
            (Decision::OptedOut, false)
        );
    }

    #[test]
    fn every_decision_has_a_debug_line() {
        for decision in [
            Decision::Show,
            Decision::OptedOut,
            Decision::Ci,
            Decision::Terminal,
            Decision::NotLaunchServices,
            Decision::ConsoleProgram,
            Decision::ServiceSession,
            Decision::HiddenStation,
            Decision::Unknown,
            Decision::Unsupported,
        ] {
            let line = decision.describe();
            assert!(line.is_ascii() && !line.contains('\n'), "{line}");
            assert_eq!(
                line.starts_with("no dialog"),
                decision != Decision::Show,
                "{line}"
            );
        }
    }

    /// The first bytes of a PE image: the DOS header pointing at `lfanew`,
    /// the signature, a COFF header and an optional header of `magic`
    /// carrying `subsystem`.
    fn headers(lfanew: u32, magic: u16, subsystem: u16) -> Vec<u8> {
        let mut out = vec![0u8; 512];
        out[..2].copy_from_slice(b"MZ");
        out[0x3c..0x40].copy_from_slice(&lfanew.to_le_bytes());
        let at = lfanew as usize;
        out[at..at + 4].copy_from_slice(b"PE\0\0");
        out[at + 24..at + 26].copy_from_slice(&magic.to_le_bytes());
        out[at + 24 + 68..at + 24 + 70].copy_from_slice(&subsystem.to_le_bytes());
        out
    }

    #[test]
    fn the_subsystem_is_read_from_a_pe32_or_pe32_plus_header() {
        assert_eq!(pe_subsystem(&headers(0x80, 0x20b, 2)), Some(SUBSYSTEM_GUI));
        assert_eq!(pe_subsystem(&headers(0x80, 0x20b, 3)), Some(3));
        assert_eq!(pe_subsystem(&headers(0xf8, 0x10b, 2)), Some(2));
    }

    #[test]
    fn a_header_that_is_not_a_pe_image_has_no_subsystem() {
        let good = headers(0x80, 0x20b, 2);
        let mut not_mz = good.clone();
        not_mz[0] = b'X';
        assert_eq!(pe_subsystem(&not_mz), None);
        let mut not_pe = good.clone();
        not_pe[0x80] = b'X';
        assert_eq!(pe_subsystem(&not_pe), None);
        // An optional header that's neither PE32 nor PE32+ (a ROM image).
        assert_eq!(pe_subsystem(&headers(0x80, 0x107, 2)), None);
        // e_lfanew past the bytes, and at the edge of the address space.
        for lfanew in [0x1000, u32::MAX - 1, u32::MAX] {
            let mut far = good.clone();
            far[0x3c..0x40].copy_from_slice(&lfanew.to_le_bytes());
            assert_eq!(pe_subsystem(&far), None, "{lfanew:#x}");
        }
        // Truncated anywhere.
        for len in [0, 1, 2, 0x3c, 0x40, 0x84, 0x80 + 25, 0x80 + 24 + 69] {
            assert_eq!(pe_subsystem(&good[..len]), None, "{len}");
        }
    }

    #[test]
    fn the_dialog_text_is_the_lines_capped() {
        let lines = |n: usize, len: usize| -> Vec<String> {
            (0..n)
                .map(|i| format!("{i:03}{}", "x".repeat(len)))
                .collect()
        };
        assert_eq!(text(&[]), "");
        assert_eq!(
            text(&["one".to_owned(), "two".to_owned()]),
            "one\ntwo",
            "short text is kept as it is"
        );
        let many = text(&lines(MAX_LINES + 5, 4));
        assert_eq!(many.lines().count(), MAX_LINES + 1);
        assert!(many.ends_with("\u{2026} (cut short)"), "{many}");
        let long = text(&lines(3, MAX_CHARS));
        let body = long.strip_suffix("\n\u{2026} (cut short)").expect("marked");
        assert_eq!(body.chars().count(), MAX_CHARS);
        assert_eq!(body.lines().count(), 1);
        // Exactly full: nothing is cut.
        let exact = text(&["y".repeat(MAX_CHARS)]);
        assert_eq!(exact.chars().count(), MAX_CHARS);
        // Cut on a character boundary, whatever the script.
        let wide = text(&["\u{8a66}".repeat(MAX_CHARS + 1)]);
        assert!(
            wide.starts_with(&"\u{8a66}".repeat(MAX_CHARS)),
            "kept whole characters"
        );
        assert!(wide.ends_with("(cut short)"));
    }

    #[cfg(windows)]
    #[test]
    fn this_test_program_is_a_console_program_in_a_session() {
        // The test harness is a console-subsystem executable.
        assert_eq!(win::own_subsystem(), Some(3));
        assert!(win::session().is_some());
        // user32 loads from System32 and the station reads, whatever it is.
        assert!(win::station_visible().is_some());
    }
}
