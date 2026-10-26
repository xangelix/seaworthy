//! Loading the chosen core and calling its entry point, plus the platform
//! checks the launcher needs (secure-execution mode on Linux and macOS and
//! its trust rule for the core's path, and the AMX permission).

use std::path::{Path, PathBuf};

use seaworthy_fsguard::mode::Owners;

/// The core's entry point: `seaworthy_core_main(abi) -> exit code`.
pub(crate) type CoreMain = unsafe extern "C" fn(u32) -> i32;

/// The exported symbol `core_main!` generates.
pub(crate) const ENTRY_SYMBOL: &str = "seaworthy_core_main";

/// Why a core could not be called.
#[derive(Debug)]
pub(crate) enum LoadError {
    /// The OS refused to load the library (its message).
    Load(String),
    /// The library loaded but has no `seaworthy_core_main` (not a core).
    NoEntryPoint(String),
}

/// Loads the core at `path` (absolute) and calls its entry point with
/// `abi`, returning its exit code. The library is never unloaded: the
/// process exits when the core returns.
pub(crate) fn call_core(path: &Path, abi: u32) -> Result<i32, LoadError> {
    let entry = platform::load(path)?;
    // SAFETY: `entry` is the `seaworthy_core_main` symbol `core_main!` exports —
    // `extern "C" fn(u32) -> i32` — resolved from the core just loaded, which
    // stays loaded for the rest of the process. The core contains the panic
    // boundary, so no unwind crosses this call.
    #[allow(unsafe_code, reason = "FFI: calls the loaded core's entry point")]
    let code = unsafe { entry(abi) };
    Ok(code)
}

#[cfg(unix)]
mod platform {
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use super::{CoreMain, ENTRY_SYMBOL, LoadError};

    fn last_dl_error() -> String {
        // SAFETY: dlerror takes no arguments and only reads this thread's
        // dynamic-loader error state.
        #[allow(unsafe_code, reason = "FFI: dlerror")]
        let message = unsafe { libc::dlerror() };
        if message.is_null() {
            return "unknown dynamic-loader error".to_owned();
        }
        // SAFETY: dlerror returned a non-null, NUL-terminated string owned by
        // the dynamic loader, valid until the next dl* call on this thread;
        // none happens before it is copied out here.
        #[allow(unsafe_code, reason = "reads dlerror's C string")]
        let text = unsafe { CStr::from_ptr(message) };
        text.to_string_lossy().into_owned()
    }

    pub(super) fn load(path: &Path) -> Result<CoreMain, LoadError> {
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| LoadError::Load("the path contains a NUL byte".to_owned()))?;
        // SAFETY: dlopen with a valid NUL-terminated absolute path. RTLD_NOW
        // resolves every symbol now (a missing one fails here, not mid-run);
        // RTLD_LOCAL keeps the core's symbols out of the global namespace.
        // Loading runs the core's initializers: the launcher has already
        // checked that this CPU supports every feature the core was built
        // with.
        #[allow(unsafe_code, reason = "FFI: dlopen of the chosen core")]
        let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            return Err(LoadError::Load(last_dl_error()));
        }
        let symbol =
            CString::new(ENTRY_SYMBOL).map_err(|_| LoadError::NoEntryPoint(String::new()))?;
        // SAFETY: a lookup of a NUL-terminated name in the handle dlopen just
        // returned (non-null, never closed).
        #[allow(unsafe_code, reason = "FFI: dlsym of the entry point")]
        let address = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
        if address.is_null() {
            return Err(LoadError::NoEntryPoint(last_dl_error()));
        }
        // SAFETY: the symbol is `core_main!`'s `extern "C" fn(u32) -> i32`;
        // a non-null data pointer from dlsym converts to that function type
        // on every Unix the launcher supports (Linux, macOS: POSIX requires
        // dlsym's result to be convertible to a function pointer).
        #[allow(unsafe_code, reason = "a dlsym address to its function type")]
        let entry = unsafe { std::mem::transmute::<*mut libc::c_void, CoreMain>(address) };
        Ok(entry)
    }
}

#[cfg(windows)]
mod platform {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
        LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW, SetDefaultDllDirectories,
    };

    use super::{CoreMain, LoadError};

    pub(super) fn restrict_dll_search() -> Result<(), String> {
        // SAFETY: SetDefaultDllDirectories takes a flag set and changes
        // only this process's DLL search order.
        #[allow(unsafe_code, reason = "FFI: SetDefaultDllDirectories")]
        let done = unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) };
        if done == 0 {
            Err(std::io::Error::last_os_error().to_string())
        } else {
            Ok(())
        }
    }

    pub(super) fn load(path: &Path) -> Result<CoreMain, LoadError> {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: LoadLibraryExW with a NUL-terminated absolute path. The
        // search flags resolve the core's own imports (the FIPS module DLL
        // pair) from the core's directory and System32 only — never the
        // working directory or PATH. Loading runs the core's initializers:
        // the launcher has already checked that this CPU supports every
        // feature the core was built with.
        #[allow(unsafe_code, reason = "FFI: LoadLibraryExW of the chosen core")]
        let module = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(LoadError::Load(std::io::Error::last_os_error().to_string()));
        }
        // SAFETY: a lookup of a NUL-terminated name in the module
        // LoadLibraryExW just returned (non-null, never freed).
        #[allow(unsafe_code, reason = "FFI: GetProcAddress of the entry point")]
        let address = unsafe { GetProcAddress(module, c"seaworthy_core_main".as_ptr().cast()) };
        let Some(address) = address else {
            return Err(LoadError::NoEntryPoint(
                std::io::Error::last_os_error().to_string(),
            ));
        };
        // SAFETY: the export is `core_main!`'s `extern "C" fn(u32) -> i32`; on
        // x86-64 Windows the "C" and "system" ABIs are the same.
        #[allow(unsafe_code, reason = "a GetProcAddress address to its function type")]
        let entry = unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, CoreMain>(address)
        };
        Ok(entry)
    }
}

/// The core's real path, if root controls every step of it — the rule for
/// loading code in secure-execution mode (Linux and macOS).
///
/// A set-user-ID (or file-capability) launcher finds its cores beside its
/// own path, and that path is whatever the caller exec'd: a hardlink in the
/// caller's own directory (`fs.protected_hardlinks=0`), or a launcher copied
/// with its capabilities intact by a careless installer, would otherwise
/// load the caller's code with raised privileges. So the core path is
/// resolved (symlinks included) and the file and every directory up to `/`
/// must be owned by root and not writable by group or others; the core must
/// be a regular file. The resolved path is what gets loaded, so nothing an
/// unprivileged user controls lies between this check and the load.
pub(crate) fn trusted_path(path: &Path) -> Result<PathBuf, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let real = std::fs::canonicalize(path)
            .map_err(|e| format!("cannot resolve {}: {e}", path.display()))?;
        check_chain(&real, |step| {
            std::fs::metadata(step)
                .map(|meta| Owner {
                    uid: meta.uid(),
                    mode: meta.mode(),
                    regular_file: meta.is_file(),
                })
                .map_err(|e| format!("cannot inspect {}: {e}", step.display()))
        })?;
        Ok(real)
    }
    #[cfg(not(unix))]
    {
        Ok(path.to_path_buf())
    }
}

/// Opens `path` for reading the way secure-execution mode reads a core:
/// never through a symlink (`O_NOFOLLOW`), never blocking on a FIFO or a
/// device (`O_NONBLOCK`), and only if the open file is a regular file
/// (`fstat` on the descriptor, so what was checked is what is read).
pub(crate) fn open_regular(path: &Path) -> Result<std::fs::File, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        let metadata = file
            .metadata()
            .map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
        if !metadata.is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        std::fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))
    }
}

/// What [`check_chain`] needs to know about one step of a path.
#[cfg_attr(not(unix), allow(dead_code))]
struct Owner {
    uid: u32,
    mode: u32,
    regular_file: bool,
}

/// The trust rule over a resolved path, given each step's owner and mode:
/// the file is a regular file, and it and every directory above it are
/// owned by root and not writable by group or others. Separate from the
/// file system so every branch is unit-tested.
#[cfg_attr(not(unix), allow(dead_code))]
fn check_chain(real: &Path, stat: impl Fn(&Path) -> Result<Owner, String>) -> Result<(), String> {
    let file = stat(real)?;
    if !file.regular_file {
        return Err(format!("{} is not a regular file", real.display()));
    }
    root_controlled(real, &file)?;
    for dir in real.ancestors().skip(1) {
        root_controlled(dir, &stat(dir)?)?;
    }
    Ok(())
}

/// One step of [`check_chain`]: owned by root, not group/other-writable.
#[cfg_attr(not(unix), allow(dead_code))]
fn root_controlled(step: &Path, owner: &Owner) -> Result<(), String> {
    let what = step.display().to_string();
    match seaworthy_fsguard::mode::untrusted(&what, owner.uid, owner.mode, false, Owners::Root) {
        Some(why) => Err(why),
        None => Ok(()),
    }
}

/// Secure-execution mode — Linux's `AT_SECURE` (set-user-ID, set-group-ID
/// or file capabilities), macOS's `issetugid()` (set-user-ID or
/// set-group-ID): developer overrides from the environment are ignored, and
/// the core must pass [`trusted_path`].
pub(crate) fn secure_execution() -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: getauxval reads the process's auxiliary vector; it has no
        // preconditions.
        #[allow(unsafe_code, reason = "FFI: getauxval(AT_SECURE)")]
        let secure = unsafe { libc::getauxval(libc::AT_SECURE) };
        secure != 0
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: issetugid takes no arguments and only reads the process's
        // credentials-changed flag.
        #[allow(unsafe_code, reason = "FFI: issetugid")]
        let tainted = unsafe { libc::issetugid() };
        tainted != 0
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Whether this process runs with administrator rights it may not have
/// been started with by whoever set its environment: root on Unix (`euid`
/// 0 — `sudo`, a root shell, a root service), an elevated token on Windows
/// (an administrator's elevated console, LocalSystem, the service
/// accounts). The launcher then ignores its environment overrides.
/// Unknown (a token that can't be read) counts as elevated.
pub(crate) fn elevated() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid takes no arguments and can't fail.
        #[allow(unsafe_code, reason = "FFI: geteuid")]
        let euid = unsafe { libc::geteuid() };
        euid == 0
    }
    #[cfg(windows)]
    {
        seaworthy_fsguard::windows::process_elevated().unwrap_or(true)
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Windows: `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)` —
/// from here on, a `LoadLibrary` anywhere in the process searches the
/// launcher's directory, System32 and `AddDllDirectory` directories only,
/// never the working directory or `PATH` (`Launcher::legacy_dll_search`).
/// Elsewhere, nothing.
pub(crate) fn restrict_dll_search() -> Result<(), String> {
    #[cfg(windows)]
    {
        platform::restrict_dll_search()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

/// Requests the per-process permission Linux requires before a process may
/// use AMX tile data (`arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA)`).
/// Elsewhere AMX needs no request.
pub(crate) fn request_amx() -> Result<(), String> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        const ARCH_REQ_XCOMP_PERM: libc::c_long = 0x1023;
        const XFEATURE_XTILEDATA: libc::c_long = 18;
        // SAFETY: arch_prctl with an integer request and argument; it only
        // changes this process's permitted extended-state set.
        #[allow(unsafe_code, reason = "FFI: arch_prctl(ARCH_REQ_XCOMP_PERM)")]
        let rc = unsafe {
            libc::syscall(
                libc::SYS_arch_prctl,
                ARCH_REQ_XCOMP_PERM,
                XFEATURE_XTILEDATA,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(format!(
                "the kernel refused AMX tile state ({})",
                std::io::Error::last_os_error()
            ))
        }
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const CORE: &str = "/opt/acme/tool/lib/libacme_core_x86-64-v3.so";

    /// A file system where every step is root-owned 0755 (the core 0644)
    /// unless `overrides` says otherwise.
    fn stat_with(overrides: &[(&str, Owner)]) -> impl Fn(&Path) -> Result<Owner, String> {
        let overrides: HashMap<String, (u32, u32, bool)> = overrides
            .iter()
            .map(|(path, o)| ((*path).to_owned(), (o.uid, o.mode, o.regular_file)))
            .collect();
        move |step: &Path| {
            let key = step.to_string_lossy().into_owned();
            let (uid, mode, regular_file) =
                overrides.get(&key).copied().unwrap_or(if key == CORE {
                    (0, 0o100_644, true)
                } else {
                    (0, 0o040_755, false)
                });
            Ok(Owner {
                uid,
                mode,
                regular_file,
            })
        }
    }

    fn owner(uid: u32, mode: u32, regular_file: bool) -> Owner {
        Owner {
            uid,
            mode,
            regular_file,
        }
    }

    #[test]
    fn a_root_controlled_chain_is_trusted() {
        assert_eq!(check_chain(Path::new(CORE), stat_with(&[])), Ok(()));
    }

    #[test]
    fn a_core_owned_by_a_user_is_refused() {
        let refusal = check_chain(
            Path::new(CORE),
            stat_with(&[(CORE, owner(1000, 0o100_644, true))]),
        )
        .expect_err("refused");
        assert_eq!(refusal, format!("{CORE} is owned by uid 1000, not root"));
    }

    #[test]
    fn a_group_or_world_writable_core_is_refused() {
        for mode in [0o100_664, 0o100_646] {
            let refusal = check_chain(Path::new(CORE), stat_with(&[(CORE, owner(0, mode, true))]))
                .expect_err("refused");
            assert!(
                refusal.starts_with(&format!("{CORE} is writable by group or others")),
                "{refusal}"
            );
        }
    }

    #[test]
    fn every_directory_up_to_the_root_is_checked() {
        // A user's directory anywhere above — the hardlinked-launcher case.
        let refusal = check_chain(
            Path::new(CORE),
            stat_with(&[("/opt/acme", owner(1000, 0o040_755, false))]),
        )
        .expect_err("refused");
        assert_eq!(refusal, "/opt/acme is owned by uid 1000, not root");
        // A world-writable directory, even root's (a /tmp-like parent).
        let refusal = check_chain(
            Path::new(CORE),
            stat_with(&[("/opt", owner(0, 0o041_777, false))]),
        )
        .expect_err("refused");
        assert!(
            refusal.starts_with("/opt is writable by group or others"),
            "{refusal}"
        );
        let refusal = check_chain(
            Path::new(CORE),
            stat_with(&[("/", owner(0, 0o040_775, false))]),
        )
        .expect_err("refused");
        assert!(
            refusal.starts_with("/ is writable by group or others"),
            "{refusal}"
        );
    }

    #[test]
    fn a_core_that_is_not_a_regular_file_is_refused() {
        let refusal = check_chain(
            Path::new(CORE),
            stat_with(&[(CORE, owner(0, 0o020_644, false))]),
        )
        .expect_err("refused");
        assert_eq!(refusal, format!("{CORE} is not a regular file"));
    }

    #[test]
    fn a_step_that_cannot_be_inspected_is_refused() {
        let refusal = check_chain(Path::new(CORE), |step: &Path| {
            if step == Path::new("/opt") {
                Err("cannot inspect /opt: permission denied".to_owned())
            } else {
                stat_with(&[])(step)
            }
        })
        .expect_err("refused");
        assert_eq!(refusal, "cannot inspect /opt: permission denied");
    }

    #[cfg(unix)]
    #[test]
    fn secure_reads_open_only_regular_files_and_never_follow_a_symlink() {
        let dir =
            std::env::temp_dir().join(format!("seaworthy_launcher_open_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch");
        let file = dir.join("core.so");
        std::fs::write(&file, b"not a core").expect("write");
        assert!(open_regular(&file).is_ok());
        // A symlink to it is refused (O_NOFOLLOW), not read through.
        let link = dir.join("link.so");
        std::os::unix::fs::symlink(&file, &link).expect("symlink");
        let refusal = open_regular(&link).expect_err("a symlink");
        assert!(refusal.starts_with("cannot open"), "{refusal}");
        // A FIFO neither blocks the open (O_NONBLOCK) nor passes.
        let fifo = dir.join("fifo.so");
        let c_fifo = std::ffi::CString::new(fifo.to_str().expect("utf-8")).expect("no NUL");
        // SAFETY: mkfifo with a NUL-terminated path and a mode.
        #[allow(unsafe_code, reason = "FFI: mkfifo for the test")]
        let made = unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) };
        assert_eq!(made, 0, "mkfifo");
        let refusal = open_regular(&fifo).expect_err("a FIFO");
        assert!(refusal.ends_with("is not a regular file"), "{refusal}");
        // A directory.
        assert!(open_regular(&dir).is_err());
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn the_real_file_system_is_read_through_symlinks() {
        // /bin/sh (or what it links to) is root-owned and not group/other
        // writable on every Linux distribution, as is every directory above.
        let real = trusted_path(Path::new("/bin/sh")).expect("trusted");
        assert!(real.is_absolute());
        assert_eq!(real, std::fs::canonicalize("/bin/sh").expect("resolves"));
        let refusal = trusted_path(Path::new("/usr")).expect_err("a directory");
        assert!(refusal.contains("not a regular file"), "{refusal}");
        let refusal = trusted_path(Path::new("/nonexistent/acme/core.so")).expect_err("missing");
        assert!(
            refusal.starts_with("cannot resolve /nonexistent/acme/core.so"),
            "{refusal}"
        );
    }
}
