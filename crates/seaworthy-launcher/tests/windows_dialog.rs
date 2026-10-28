//! The failure dialog on real Windows: `examples/desktop_launcher.rs` (a
//! GUI-subsystem launcher, `windows_subsystem = "windows"`), copied alone
//! into a directory of its own, finds no core and exits 74. Every run is
//! bounded: a launcher that blocks is killed and the test fails.
//!
//! - Opted out (`SEAWORTHY_LAUNCHER_NO_DIALOG=1`) or in CI (`CI=true`): no
//!   dialog, whatever the session.
//! - Started on a window station of its own (which, not being an interactive
//!   logon's `WinSta0`, is never visible): no dialog, though everything else
//!   calls for one.
//! - In an interactive session (a desktop; a CI runner's logged-on session):
//!   the dialog shows the launcher's lines, titled with its name, and once
//!   dismissed the launcher exits 74. Run from a service's session instead,
//!   the launcher must not show one there either.
//!
//! With `SEAWORTHY_LAUNCHER_DEBUG=1` the launcher reports its decision on
//! stderr, unless the process is elevated (CI runners' are), where it
//! ignores the variable and says so: the checks of the decision line apply
//! to a non-elevated run.
//!
//! `cargo test` builds the example; run alone, build it first
//! (`cargo build -p seaworthy-launcher --example desktop_launcher`).

#![cfg(windows)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::ffi::OsString;
use std::io::Read as _;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use seaworthy_launcher::{ENV_DEBUG, ENV_NO_DIALOG, EXIT_DAMAGED_INSTALL};
use windows_sys::Win32::Foundation::{
    GENERIC_ALL, HANDLE_FLAG_INHERIT, HWND, LPARAM, SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, CloseWindowStation, CreateDesktopW, CreateWindowStationW,
    GetProcessWindowStation, GetUserObjectInformationW, SetProcessWindowStation, UOI_FLAGS,
    USEROBJECTFLAGS,
};
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessW, GetExitCodeProcess, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CWF_CREATE_ONLY, EnumWindows, GetClassNameW, GetDlgItemTextW, GetWindowTextW,
    GetWindowThreadProcessId, IDOK, PostMessageW, WINSTA_ALL_ACCESS, WM_COMMAND, WSF_VISIBLE,
};

/// How long a launcher may take to exit (or to show its dialog).
const LIMIT: Duration = Duration::from_secs(60);

/// The launcher's lines for a directory with no core (exit 74).
const DAMAGED: &str = "no build of this program that this CPU can run was found";
const REPAIR: &str = "repair or reinstall it";

/// What an elevated launcher says when it ignores `SEAWORTHY_LAUNCHER_DEBUG`.
const ELEVATED: &str = "are ignored in an elevated or root process";

/// One test at a time: they start processes with inherited handles and
/// change this process's window station for a moment.
static SERIAL: Mutex<()> = Mutex::new(());

/// The desktop example, copied alone into a directory of its own.
struct Launcher {
    dir: PathBuf,
    path: PathBuf,
}

impl Launcher {
    fn new(test: &str) -> Self {
        // target/<profile>/deps/<test>.exe -> target/<profile>/examples/
        let built = std::env::current_exe()
            .unwrap()
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .join("examples")
            .join("desktop_launcher.exe");
        assert!(
            built.is_file(),
            "{} is missing: `cargo test` builds the examples; run alone, build it first (cargo build -p seaworthy-launcher --example desktop_launcher)",
            built.display()
        );
        let dir =
            std::env::temp_dir().join(format!("seaworthy-launcher-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("desktop_launcher.exe");
        std::fs::copy(&built, &path).unwrap();
        // It is the program the tests mean to run: a GUI-subsystem image.
        let header = std::fs::read(&path).unwrap();
        let lfanew = u32::from_le_bytes(header[0x3c..0x40].try_into().unwrap()) as usize;
        let subsystem = u16::from_le_bytes(
            header[lfanew + 24 + 68..lfanew + 24 + 70]
                .try_into()
                .unwrap(),
        );
        assert_eq!(subsystem, 2, "the example isn't a GUI-subsystem program");
        Self { dir, path }
    }

    /// The launcher with `CI`, the opt-out and the debug switch unset,
    /// then `env`; stdin closed, stdout and stderr piped.
    fn command(&self, env: &[(&str, &str)]) -> Command {
        let mut command = Command::new(&self.path);
        for name in ["CI", ENV_NO_DIALOG, ENV_DEBUG] {
            command.env_remove(name);
        }
        for (name, value) in env {
            command.env(name, value);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

impl Drop for Launcher {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// `child`'s exit status within `limit`, or `None` after killing it.
fn wait(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Runs `command` to its end within [`LIMIT`]: the exit code and stderr.
fn run(mut command: Command) -> (i32, String) {
    let mut child = command.spawn().unwrap();
    let status = wait(&mut child, LIMIT);
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let status = status.unwrap_or_else(|| {
        panic!("the launcher didn't exit within {LIMIT:?} (a dialog nobody can answer?); stderr:\n{stderr}")
    });
    (status.code().unwrap(), stderr)
}

/// The launcher's usual failure: exit 74 and its lines on stderr.
fn assert_damaged(code: i32, stderr: &str) {
    assert_eq!(code, EXIT_DAMAGED_INSTALL, "{stderr}");
    assert!(stderr.contains(DAMAGED), "{stderr}");
    assert!(
        stderr.contains(&format!("desktop_launcher: {REPAIR}")),
        "{stderr}"
    );
}

/// The debug decision line is in `stderr`, unless the launcher ran
/// elevated and ignored the debug switch (and said so).
fn assert_decision(stderr: &str, line: &str) {
    if stderr.contains(ELEVATED) {
        eprintln!("note: the launcher ran elevated, so it reported no decision (expected: {line})");
    } else {
        assert!(
            stderr.contains(&format!("desktop_launcher: {line}")),
            "expected {line:?} in:\n{stderr}"
        );
    }
}

#[test]
fn opted_out_or_in_ci_a_gui_launcher_shows_no_dialog() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let launcher = Launcher::new("opt-out");
    for (env, line) in [
        (
            [(ENV_NO_DIALOG, "1"), (ENV_DEBUG, "1")],
            "no dialog: SEAWORTHY_LAUNCHER_NO_DIALOG is set",
        ),
        ([("CI", "true"), (ENV_DEBUG, "1")], "no dialog: CI is set"),
    ] {
        let (code, stderr) = run(launcher.command(&env));
        assert_damaged(code, &stderr);
        assert_decision(&stderr, line);
    }
    // Without the debug switch, stderr is the launcher's lines alone.
    let (code, stderr) = run(launcher.command(&[(ENV_NO_DIALOG, "1")]));
    assert_damaged(code, &stderr);
    assert!(
        !stderr.contains("no dialog") && !stderr.contains("in a dialog"),
        "{stderr}"
    );
}

/// `text` as a NUL-terminated UTF-16 string.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// Runs the launcher on `<station>\Default`, a window station and desktop
/// made for the run, with this process's environment minus `CI` and the
/// opt-out, plus the debug switch: the exit code and stderr.
fn run_on_hidden_station(launcher: &Launcher) -> (i32, String) {
    let station_name = wide(&format!("seaworthy-dialog-{}", std::process::id()));
    // SAFETY: GetProcessWindowStation takes no arguments; the handle is the
    // process's own and is never closed.
    #[allow(unsafe_code, reason = "FFI: GetProcessWindowStation")]
    let original = unsafe { GetProcessWindowStation() };
    assert!(!original.is_null(), "this process has no window station");
    // SAFETY: a NUL-terminated name, create-only, full access, the
    // creator's default security.
    #[allow(unsafe_code, reason = "FFI: CreateWindowStationW")]
    let station = unsafe {
        CreateWindowStationW(
            station_name.as_ptr(),
            CWF_CREATE_ONLY,
            WINSTA_ALL_ACCESS.cast_unsigned(),
            core::ptr::null(),
        )
    };
    assert!(
        !station.is_null(),
        "CreateWindowStationW: {}",
        std::io::Error::last_os_error()
    );
    // A desktop is made in the process's current window station: switch
    // to the new one for the call, then back.
    // SAFETY: a window station handle just created.
    #[allow(unsafe_code, reason = "FFI: SetProcessWindowStation")]
    let switched = unsafe { SetProcessWindowStation(station) };
    assert_ne!(switched, 0, "{}", std::io::Error::last_os_error());
    let desktop_name = wide("Default");
    // SAFETY: a NUL-terminated name, no device or mode, no flags, full
    // access, the creator's default security.
    #[allow(unsafe_code, reason = "FFI: CreateDesktopW")]
    let desktop = unsafe {
        CreateDesktopW(
            desktop_name.as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            0,
            GENERIC_ALL,
            core::ptr::null(),
        )
    };
    let desktop_error = std::io::Error::last_os_error();
    // SAFETY: the process's original window station handle.
    #[allow(unsafe_code, reason = "FFI: SetProcessWindowStation")]
    let restored = unsafe { SetProcessWindowStation(original) };
    assert_ne!(restored, 0, "{}", std::io::Error::last_os_error());
    assert!(!desktop.is_null(), "CreateDesktopW: {desktop_error}");

    // The child's environment block: sorted `name=value` strings.
    let mut env: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(name, _)| {
            !name.eq_ignore_ascii_case("CI") && !name.eq_ignore_ascii_case(ENV_NO_DIALOG)
        })
        .filter(|(name, _)| !name.eq_ignore_ascii_case(ENV_DEBUG))
        .collect();
    env.push((ENV_DEBUG.into(), "1".into()));
    env.sort_by_key(|(name, _)| name.to_ascii_uppercase());
    let mut block: Vec<u16> = Vec::new();
    for (name, value) in &env {
        block.extend(name.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);

    // stderr (and stdout) through a pipe whose write end alone is inherited.
    let (mut reader, writer) = std::io::pipe().unwrap();
    // SAFETY: the pipe's write end, open for this call.
    #[allow(unsafe_code, reason = "FFI: SetHandleInformation")]
    let inheritable = unsafe {
        SetHandleInformation(
            writer.as_raw_handle(),
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    };
    assert_ne!(inheritable, 0, "{}", std::io::Error::last_os_error());

    let mut desktop_path = wide(&format!("seaworthy-dialog-{}\\Default", std::process::id()));
    let application = wide(&launcher.path.to_string_lossy());
    let mut command_line = wide(&format!("\"{}\"", launcher.path.display()));
    let startup = STARTUPINFOW {
        cb: u32::try_from(core::mem::size_of::<STARTUPINFOW>()).unwrap(),
        lpDesktop: desktop_path.as_mut_ptr(),
        dwFlags: STARTF_USESTDHANDLES,
        hStdInput: core::ptr::null_mut(),
        hStdOutput: writer.as_raw_handle(),
        hStdError: writer.as_raw_handle(),
        ..STARTUPINFOW::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: NUL-terminated application name and (writable) command line,
    // inheritable handles (the pipe's write end alone is), a Unicode
    // environment block ending in two NULs, the startup information naming
    // the new desktop and the pipe, and an out structure.
    #[allow(unsafe_code, reason = "FFI: CreateProcessW")]
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            1,
            CREATE_UNICODE_ENVIRONMENT,
            block.as_ptr().cast(),
            core::ptr::null(),
            &startup,
            &mut info,
        )
    };
    let create_error = std::io::Error::last_os_error();
    drop(writer);
    assert_ne!(created, 0, "CreateProcessW: {create_error}");
    // SAFETY: the process handle CreateProcessW just returned, open and
    // closed by nothing else.
    #[allow(unsafe_code, reason = "takes ownership of the process handle")]
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    // SAFETY: the thread handle CreateProcessW just returned, open and
    // closed by nothing else.
    #[allow(unsafe_code, reason = "takes ownership of the thread handle")]
    let _thread = unsafe { OwnedHandle::from_raw_handle(info.hThread) };

    let limit = u32::try_from(LIMIT.as_millis()).unwrap();
    // SAFETY: an open process handle.
    #[allow(unsafe_code, reason = "FFI: WaitForSingleObject")]
    let waited = unsafe { WaitForSingleObject(process.as_raw_handle(), limit) };
    if waited != WAIT_OBJECT_0 {
        // SAFETY: an open process handle.
        #[allow(unsafe_code, reason = "FFI: TerminateProcess")]
        unsafe {
            TerminateProcess(process.as_raw_handle(), 1);
        }
    }
    let mut code = 0u32;
    // SAFETY: an open process handle and an out value.
    #[allow(unsafe_code, reason = "FFI: GetExitCodeProcess")]
    let got = unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) };
    assert_ne!(got, 0, "{}", std::io::Error::last_os_error());
    let mut stderr = String::new();
    reader.read_to_string(&mut stderr).unwrap();

    // SAFETY: the desktop handle CreateDesktopW returned, no longer used.
    #[allow(unsafe_code, reason = "FFI: CloseDesktop")]
    unsafe {
        CloseDesktop(desktop);
    }
    // SAFETY: the window station handle CreateWindowStationW returned, not
    // this process's own any more.
    #[allow(unsafe_code, reason = "FFI: CloseWindowStation")]
    unsafe {
        CloseWindowStation(station);
    }
    assert_eq!(
        waited, WAIT_OBJECT_0,
        "the launcher didn't exit within {LIMIT:?} on a hidden window station; stderr:\n{stderr}"
    );
    (i32::try_from(code).unwrap(), stderr)
}

#[test]
fn on_a_window_station_no_one_sees_a_gui_launcher_shows_no_dialog() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let launcher = Launcher::new("hidden");
    let (code, stderr) = run_on_hidden_station(&launcher);
    assert_damaged(code, &stderr);
    // The window station is asked last: everything else called for a
    // dialog.
    assert_decision(
        &stderr,
        "no dialog: the window station is not interactive (a dialog was called for otherwise)",
    );
}

/// Whether this test process runs where a dialog would be seen: outside
/// session 0, on a visible window station.
fn interactive() -> bool {
    let mut session = 0u32;
    // SAFETY: this process's id and an out value.
    #[allow(unsafe_code, reason = "FFI: ProcessIdToSessionId")]
    let got = unsafe { ProcessIdToSessionId(std::process::id(), &mut session) };
    assert_ne!(got, 0, "{}", std::io::Error::last_os_error());
    // SAFETY: GetProcessWindowStation takes no arguments; the handle is the
    // process's own and is never closed.
    #[allow(unsafe_code, reason = "FFI: GetProcessWindowStation")]
    let station = unsafe { GetProcessWindowStation() };
    let mut flags = USEROBJECTFLAGS::default();
    let mut needed = 0u32;
    // SAFETY: the process's window station, UOI_FLAGS and a
    // USEROBJECTFLAGS to fill, of its own size.
    #[allow(unsafe_code, reason = "FFI: GetUserObjectInformationW")]
    let read = unsafe {
        GetUserObjectInformationW(
            station,
            UOI_FLAGS,
            (&raw mut flags).cast(),
            u32::try_from(core::mem::size_of::<USEROBJECTFLAGS>()).unwrap(),
            &mut needed,
        )
    };
    assert_ne!(read, 0, "{}", std::io::Error::last_os_error());
    session != 0 && flags.dwFlags & WSF_VISIBLE.cast_unsigned() != 0
}

/// A window's text through `read` (a window's title, a dialog item's
/// text).
fn text_of(read: impl FnOnce(*mut u16, i32) -> i32) -> String {
    let mut buffer = vec![0u16; 8192];
    let len = read(buffer.as_mut_ptr(), i32::try_from(buffer.len()).unwrap());
    String::from_utf16_lossy(&buffer[..usize::try_from(len.max(0)).unwrap()])
}

/// What [`collect`] looks for and what it found.
struct Search {
    pid: u32,
    found: Vec<HWND>,
}

/// EnumWindows' callback: keeps `search.pid`'s dialog boxes (class
/// `#32770`, a message box's).
extern "system" fn collect(window: HWND, search: LPARAM) -> i32 {
    // SAFETY: `search` is the `&mut Search` `dialogs_of` passed to
    // EnumWindows, alive for the whole enumeration and used by nothing
    // else meanwhile.
    #[allow(unsafe_code, reason = "EnumWindows' context pointer")]
    let search = unsafe { &mut *(search as *mut Search) };
    let mut pid = 0u32;
    // SAFETY: a window EnumWindows passed and an out value.
    #[allow(unsafe_code, reason = "FFI: GetWindowThreadProcessId")]
    unsafe {
        GetWindowThreadProcessId(window, &mut pid);
    }
    let class = text_of(|buffer, len| {
        // SAFETY: a window EnumWindows passed and a buffer of `len` units.
        #[allow(unsafe_code, reason = "FFI: GetClassNameW")]
        let n = unsafe { GetClassNameW(window, buffer, len) };
        n
    });
    if pid == search.pid && class == "#32770" {
        search.found.push(window);
    }
    1
}

/// The dialog boxes process `pid` has open on this desktop.
fn dialogs_of(pid: u32) -> Vec<HWND> {
    let mut search = Search {
        pid,
        found: Vec::new(),
    };
    // SAFETY: a callback of EnumWindows' type and a pointer to `search`,
    // which outlives the call.
    #[allow(unsafe_code, reason = "FFI: EnumWindows")]
    unsafe {
        EnumWindows(Some(collect), (&raw mut search) as LPARAM);
    }
    search.found
}

#[test]
fn in_an_interactive_session_a_gui_launcher_shows_its_failure_until_dismissed() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let launcher = Launcher::new("interactive");
    let mut child = launcher.command(&[(ENV_DEBUG, "1")]).spawn().unwrap();
    if !interactive() {
        // A service's session (some CI runners'): the launcher must not
        // show its dialog where no one sees it, so it exits at once.
        eprintln!(
            "note: this test runs outside an interactive session: checking that no dialog blocks"
        );
        let status = wait(&mut child, LIMIT);
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        let status = status.unwrap_or_else(|| panic!("the launcher blocked:\n{stderr}"));
        assert_damaged(status.code().unwrap(), &stderr);
        return;
    }
    // The message box appears, titled with the program's name and holding
    // the launcher's lines; dismissing it lets the launcher exit 74.
    let deadline = Instant::now() + LIMIT;
    let dialog = loop {
        if let Some(window) = dialogs_of(child.id()).into_iter().next() {
            break window;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!(
                "the launcher exited ({status}) without showing a dialog in an interactive session:\n{stderr}"
            );
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("no dialog appeared within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    // The text may be set a moment after the window exists.
    let mut message = String::new();
    while message.is_empty() && Instant::now() < deadline {
        message = text_of(|buffer, len| {
            // SAFETY: a dialog box of the child's, the message box's text
            // item (0xFFFF) and a buffer of `len` units.
            #[allow(unsafe_code, reason = "FFI: GetDlgItemTextW")]
            let n = unsafe { GetDlgItemTextW(dialog, 0xFFFF, buffer, len) };
            i32::try_from(n).unwrap()
        });
        std::thread::sleep(Duration::from_millis(50));
    }
    let title = text_of(|buffer, len| {
        // SAFETY: a dialog box of the child's and a buffer of `len` units.
        #[allow(unsafe_code, reason = "FFI: GetWindowTextW")]
        let n = unsafe { GetWindowTextW(dialog, buffer, len) };
        n
    });
    // SAFETY: a window of the child's, and the OK button's command.
    #[allow(unsafe_code, reason = "FFI: PostMessageW")]
    let posted = unsafe { PostMessageW(dialog, WM_COMMAND, IDOK.cast_unsigned() as usize, 0) };
    assert_ne!(posted, 0, "{}", std::io::Error::last_os_error());
    let status = wait(&mut child, LIMIT);
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let status = status.unwrap_or_else(|| {
        panic!("the launcher didn't exit after its dialog was dismissed:\n{stderr}")
    });
    assert_damaged(status.code().unwrap(), &stderr);
    assert_eq!(title, "desktop_launcher");
    assert!(message.contains(DAMAGED), "{message}");
    assert!(message.contains(REPAIR), "{message}");
    assert_decision(&stderr, "showing this failure in a dialog");
}
