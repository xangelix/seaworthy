//! The Unix calls, through libc.

/// This process's effective uid.
#[must_use]
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments and can't fail.
    #[allow(unsafe_code, reason = "FFI: geteuid")]
    let euid = unsafe { libc::geteuid() };
    euid
}
