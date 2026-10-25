//! Windows SCM backend: the lifecycle of a service a product's MSI
//! registered (`start`, `stop`, `status`).
//!
//! Products install as MSIs (the seaworthy CLI), which lay out the
//! launcher, its cores and their DLLs and register the service
//! declaratively: its account, failure actions and DACLs
//! ([`render::windows`](crate::render::windows)). The crate installs
//! nothing itself.
//!
//! # Critical Windows "gotchas" (the Code 5 & 1053 graveyard)
//!
//! * **The missing-DLL trap (Code 1053 — timeout):** if the SCM launches an
//!   executable whose required DLLs (e.g. `aws_lc_fips.dll`) can't be found,
//!   the process dies with `STATUS_DLL_NOT_FOUND` before `main()` runs and
//!   the SCM reports a start timeout. The package must lay every DLL a
//!   program imports (a FIPS product's module DLL included) beside it.
//! * **Names are validated first:** every operation checks the name
//!   (`validate_service_name`) before it opens the SCM, so a bad name is
//!   the typed [`ServiceError::InvalidName`], never a raw OS error.

use std::{
    thread::sleep,
    time::{Duration, Instant},
};

use windows_service::{
    service::{ServiceAccess, ServiceState as WinServiceState},
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use crate::{
    ServiceError,
    backend::{DEFAULT_CLOCK_INTERVAL, DEFAULT_TRANSITION_TIMEOUT, ServiceBackend, ServiceState},
    render::is_safe_service_name,
};

// ---------------------------------------------------------------------------

/// Drives a Windows service through the local Service Control Manager.
#[derive(Debug, Clone)]
pub struct WindowsBackend {
    name: String,
    clock_interval: Duration,
    timeout: Duration,
}

impl WindowsBackend {
    /// Backend for the service named `name` (the SCM machine name).
    ///
    /// The name is NOT validated here (mirroring `SystemdBackend::new`);
    /// every operation validates it first with
    /// [`ServiceError::InvalidName`] before any SCM call — see
    /// `validate_service_name`.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            clock_interval: DEFAULT_CLOCK_INTERVAL,
            timeout: DEFAULT_TRANSITION_TIMEOUT,
        }
    }

    /// Override the poll interval / total timeout used by `start` and
    /// `stop`.
    #[must_use]
    pub fn with_poll_timing(mut self, clock_interval: Duration, timeout: Duration) -> Self {
        self.clock_interval = clock_interval;
        self.timeout = timeout;
        self
    }

    fn service_manager(access: ServiceManagerAccess) -> Result<ServiceManager, ServiceError> {
        Ok(ServiceManager::local_computer(None::<&str>, access)?)
    }
}

impl ServiceBackend for WindowsBackend {
    fn start(&self) -> Result<(), ServiceError> {
        validate_service_name(&self.name)?;
        let service_manager = Self::service_manager(ServiceManagerAccess::CONNECT)?;
        let service = service_manager.open_service(
            &self.name,
            ServiceAccess::QUERY_STATUS | ServiceAccess::START,
        )?;

        service.start::<&str>(&[])?;

        sleep(self.clock_interval);
        let start = Instant::now();
        while start.elapsed() < self.timeout {
            if self.status()? == Some(ServiceState::Running) {
                return Ok(());
            }
            sleep(self.clock_interval);
        }
        Err(ServiceError::StartTimeout)
    }

    fn stop(&self) -> Result<(), ServiceError> {
        validate_service_name(&self.name)?;
        let service_manager = Self::service_manager(ServiceManagerAccess::CONNECT)?;
        let service = service_manager.open_service(
            &self.name,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
        )?;

        service.stop()?;

        sleep(self.clock_interval);
        let start = Instant::now();
        while start.elapsed() < self.timeout {
            if self.status()? == Some(ServiceState::Stopped) {
                return Ok(());
            }
            sleep(self.clock_interval);
        }
        Err(ServiceError::StopTimeout)
    }

    fn status(&self) -> Result<Option<ServiceState>, ServiceError> {
        validate_service_name(&self.name)?;
        let service_manager = Self::service_manager(ServiceManagerAccess::CONNECT)?;
        match service_manager.open_service(&self.name, ServiceAccess::QUERY_STATUS) {
            Ok(service) => Ok(Some(map_state(service.query_status()?.current_state))),
            Err(e) => {
                let error = ServiceError::from(e);
                if matches!(error, ServiceError::DoesNotExist) {
                    Ok(None)
                } else {
                    Err(error)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------

/// The SCM forbids `/` and `\` in service names. Validate with the
/// crate's shared name rule (which also rejects whitespace/control
/// characters and `%`) at the top of every operation, before the SCM is
/// asked anything.
fn validate_service_name(name: &str) -> Result<(), ServiceError> {
    if is_safe_service_name(name) {
        return Ok(());
    }
    Err(ServiceError::InvalidName(format!(
        "{name:?} is not a valid SCM service name (the SCM forbids '/' and '\\'; must start with an ASCII letter or digit; no whitespace, control characters, '%', or leading '-')"
    )))
}

fn map_state(state: WinServiceState) -> ServiceState {
    match state {
        WinServiceState::Running => ServiceState::Running,
        WinServiceState::Stopped => ServiceState::Stopped,
        WinServiceState::Paused => ServiceState::Paused,
        WinServiceState::StartPending => ServiceState::StartPending,
        WinServiceState::StopPending => ServiceState::StopPending,
        WinServiceState::PausePending => ServiceState::PausePending,
        WinServiceState::ContinuePending => ServiceState::ContinuePending,
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_names_are_rejected_before_any_scm_call() {
        for bad in ["a/b", "a\\b", "a\nb", "a\rb", "", "-x", ".hidden", "éclair"] {
            let backend = WindowsBackend::new(bad);
            assert!(matches!(
                backend.status(),
                Err(ServiceError::InvalidName(_))
            ));
            assert!(matches!(backend.start(), Err(ServiceError::InvalidName(_))));
            assert!(matches!(backend.stop(), Err(ServiceError::InvalidName(_))));
        }
    }
}
