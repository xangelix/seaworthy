//! Real-SCM integration tests for the Windows backend: the half of the
//! Windows SCM end-to-end lane that asserts on the crate's TYPED results
//! (`ServiceError` variants, `status()` answers), which is cleaner in Rust
//! than parsing CLI output. The process-level behaviors (the MSI-installed
//! service running under the SCM, failure actions, a version mismatch
//! keeping it running) live in `scripts/windows-scm-e2e.ps1`. The crate
//! installs nothing (a product's MSI does), so what's left here is the
//! lifecycle's answers for a service the SCM doesn't know.
//!
//! Double-gated like the rest of the lane's Rust half: every test is
//! `#[ignore]`d AND returns early unless `SEAWORTHY_WINDOWS_SCM_E2E=1`.
//! The lane runs them as an administrator on a Windows machine with a real
//! SCM (a GitHub-hosted `windows-2025` runner):
//!
//! ```text
//! SEAWORTHY_WINDOWS_SCM_E2E=1 cargo test -p seaworthy-service \
//!     --features runtime --test windows_scm -- --ignored --test-threads 1
//! ```
//!
//! (A Wine lane never runs them: Wine's service manager is not
//! authoritative, and they are ignored there anyway.)

#![cfg(windows)]

use std::time::Duration;

use seaworthy_service::{ServiceBackend, ServiceError, backend::windows::WindowsBackend};

const GATE: &str = "SEAWORTHY_WINDOWS_SCM_E2E";

/// The env half of the double gate.
fn enabled(test: &str) -> bool {
    let on = std::env::var(GATE).as_deref() == Ok("1");
    if !on {
        eprintln!("{test}: skipped ({GATE} != 1) — runs in the Windows SCM lane (--ignored)");
    }
    on
}

/// Every lifecycle operation on a service that does not exist answers the
/// typed `DoesNotExist` (status: `None`) — never a raw platform error.
#[test]
#[ignore = "asks the Service Control Manager; see the module docs"]
fn lifecycle_operations_on_a_missing_service_are_typed() {
    if !enabled("lifecycle_operations_on_a_missing_service_are_typed") {
        return;
    }
    let name = format!("acme-e2e-rs-missing-{}", std::process::id());
    let backend = WindowsBackend::new(&name)
        .with_poll_timing(Duration::from_millis(100), Duration::from_secs(30));
    assert!(matches!(backend.status(), Ok(None)));
    assert!(matches!(backend.start(), Err(ServiceError::DoesNotExist)));
    assert!(matches!(backend.stop(), Err(ServiceError::DoesNotExist)));
}
