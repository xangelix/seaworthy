//! The fixture's core: reports which build runs, then does what its first
//! argument asks — `exit <n>`, `panic`, `args`, `partial-line` (a last line
//! with no newline, left in stdout's buffer), `hypot` (libm's `hypot` and
//! `hypotf`, which `core_main!` binds to glibc's baseline versions), `serve`
//! (run until stopped: a service lane's service; under the Windows SCM it
//! answers the SCM until told to stop), or nothing.

fn main() -> i32 {
    println!("core={}", seaworthy_launcher::this_core());
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("exit") => args.get(2).and_then(|code| code.parse().ok()).unwrap_or(2),
        Some("panic") => panic!("the core panicked on request"),
        Some("args") => {
            println!("args={}", args.get(1..).unwrap_or_default().join(" "));
            0
        }
        Some("partial-line") => {
            print!("no newline at the end");
            0
        }
        Some("hypot") => {
            // black_box: computed at run time, through libm, not folded.
            let (x, y) = std::hint::black_box((3.0_f64, 4.0_f64));
            let (xf, yf) = std::hint::black_box((5.0_f32, 12.0_f32));
            let huge = std::hint::black_box(f64::MAX);
            println!(
                "hypot={} hypotf={} overflow={}",
                x.hypot(y),
                xf.hypot(yf),
                huge.hypot(huge)
            );
            0
        }
        Some("serve") => serve(),
        _ => 0,
    }
}

/// A service's main process: stopped by its manager's signal.
#[cfg(not(windows))]
fn serve() -> i32 {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// Under the SCM, the dispatcher: `Running` until STOP or SHUTDOWN, then
/// `Stopped` (exit 0). The SCM kills a service process that never connects
/// within 30 s, and a Windows Installer upgrade stops the service through
/// it. Started from a console (1063), it runs until killed, as on unix.
#[cfg(windows)]
fn serve() -> i32 {
    scm::serve()
}

#[cfg(windows)]
mod scm {
    #![allow(unsafe_code, reason = "the SCM's dispatcher and status calls")]

    use std::ffi::c_void;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};

    use windows_sys::Win32::Foundation::{
        ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, GetLastError, NO_ERROR,
    };
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
        SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
        SERVICE_RUNNING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE,
        SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
        SetServiceStatus, StartServiceCtrlDispatcherW,
    };

    /// The status handle, as an integer (a raw pointer isn't `Sync`).
    static HANDLE: AtomicUsize = AtomicUsize::new(0);
    static STOP: Mutex<bool> = Mutex::new(false);
    static STOPPING: Condvar = Condvar::new();

    pub(super) fn serve() -> i32 {
        // An own-process service: the SCM ignores the name (it may be empty).
        let mut name = [0u16];
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: name.as_mut_ptr(),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: std::ptr::null_mut(),
                lpServiceProc: None,
            },
        ];
        // SAFETY: a NULL-terminated table whose name outlives the call,
        // which returns once the service stopped.
        if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } != 0 {
            return 0;
        }
        // SAFETY: reads the calling thread's last-error value.
        if unsafe { GetLastError() } == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        eprintln!(
            "StartServiceCtrlDispatcherW: {}",
            std::io::Error::last_os_error()
        );
        1
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let name = [0u16];
        // SAFETY: an own-process service's name isn't checked; the handler
        // is a plain function.
        let handle = unsafe {
            RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(handler), std::ptr::null_mut())
        };
        if handle.is_null() {
            return;
        }
        HANDLE.store(handle as usize, Ordering::SeqCst);
        report(
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        );
        let mut stop = STOP
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*stop {
            stop = STOPPING
                .wait(stop)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        drop(stop);
        report(SERVICE_STOPPED, 0);
    }

    unsafe extern "system" fn handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut c_void,
        _context: *mut c_void,
    ) -> u32 {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                report(SERVICE_STOP_PENDING, 0);
                *STOP
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
                STOPPING.notify_all();
                NO_ERROR
            }
            SERVICE_CONTROL_INTERROGATE => NO_ERROR,
            _ => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }

    fn report(state: SERVICE_STATUS_CURRENT_STATE, accepted: u32) {
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: accepted,
            dwWin32ExitCode: NO_ERROR,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: if state == SERVICE_STOP_PENDING {
                5000
            } else {
                0
            },
        };
        // SAFETY: the handle RegisterServiceCtrlHandlerExW returned.
        unsafe {
            SetServiceStatus(
                HANDLE.load(Ordering::SeqCst) as SERVICE_STATUS_HANDLE,
                &status,
            );
        }
    }
}

seaworthy_launcher::core_main!(main);
