//! Service declaration data shared by every backend.
//!
//! [`ServiceSpec`] is deliberately plain data: the same declaration feeds the
//! Windows service record, the systemd unit renderer, and the launchd plist.
//! Keeping it backend-agnostic forces the platform quirks into the backends,
//! where they belong.

use std::{ffi::OsString, fmt, path::PathBuf, time::Duration};

// ---------------------------------------------------------------------------

/// The `LimitNOFILE=` a unit gets when [`ServiceSpec::open_files_limit`] is
/// `None`: 65536 — enough for tens of thousands of sockets per node (see
/// the field docs for the reasoning).
pub const DEFAULT_OPEN_FILES_LIMIT: u64 = 65_536;

/// The smallest [`ServiceSpec::open_files_limit`] accepted: below 64 a
/// process cannot even hold its standard streams, a runtime, a listener,
/// and a database pool — a value that small is a typo, refused loudly.
pub const MIN_OPEN_FILES_LIMIT: u64 = 64;

// ---------------------------------------------------------------------------

/// Everything a service manager needs to register the daemon: the input
/// of the renderers ([`crate::render`]), whose output packages carry (the
/// systemd unit, the LaunchDaemon plist, the MSI's service record).
///
/// `program` is the service's executable: the path the unit's `ExecStart=`
/// and the SCM record name, where the package installs it (the crate
/// installs nothing: a package lays out the program and registers the
/// service).
///
/// Every rendered text field is validated before anything is rendered
/// (`ServiceError::InvalidSpec` /
/// `InvalidName`): control characters (NUL, CR, LF included) are REFUSED,
/// never flattened — systemd's unit parser treats NUL as an end of line
/// just like `\n`, so a flattening guard that misses one byte is a
/// directive-injection hole.
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    /// Machine name: the SCM service name / systemd unit basename.
    ///
    /// Must be a valid service name on every targeted platform (no path
    /// separators, no whitespace, no `%` specifiers); the renderers and
    /// every backend operation enforce it, rejecting unusable names with
    /// `ServiceError::InvalidName` before `systemctl`, `launchctl` or the
    /// SCM is asked.
    pub name: String,
    /// Human-readable name shown in service management UIs. No control
    /// characters.
    pub display_name: String,
    /// One-line description (SCM description / systemd `Description=`).
    /// No control characters and no trailing `\` (a trailing backslash is
    /// a line continuation in unit files — it would swallow the next
    /// directive); `%` is escaped for you.
    pub description: String,
    /// The installed executable: where the package puts it.
    ///
    /// Must be an absolute, UTF-8, `/`-leading path on systemd (validated
    /// by the renderer with `ServiceError::InvalidSpec`): the `ExecStart`
    /// first word must not carry a modifier prefix (`+` would run the
    /// service with FULL PRIVILEGES ignoring the sandbox's
    /// `User=`/`Group=`). On Windows it must be absolute,
    /// control-character-free, and `%`-free (the SCM expands `%VAR%` in
    /// `ImagePath`).
    ///
    /// The package owns the program's directory: root-owned 0755 under
    /// `/opt/<vendor>/<app>` from a deb, rpm or pacman, and a protected
    /// admin-only DACL with the service account read + execute under
    /// `%ProgramFiles%\<vendor>\<app>` from the MSI (a service is only as
    /// trustworthy as whoever can replace its binary).
    pub program: PathBuf,
    /// Launch arguments for the service.
    ///
    /// ALWAYS passed to the service manager separately from `program`,
    /// never formatted into the executable path — on Windows, folding
    /// arguments into `binPath` is the classic Code 5 (Access Denied) trap.
    /// No control characters on either platform, and no `%` on Windows
    /// (the SCM stores the command line as `REG_EXPAND_SZ` and expands
    /// `%VAR%` with the service account's environment at every start —
    /// there is no escape syntax).
    ///
    /// **NEVER pass secrets here**: arguments land in a world-readable
    /// (0644) unit file on systemd and stay visible in
    /// `/proc/<pid>/cmdline` on Linux (and in the SCM's registry config on
    /// Windows). Credentials belong in a 0600 config file or an
    /// `EnvironmentFile=` with tight permissions.
    pub arguments: Vec<OsString>,
    /// systemd `EnvironmentFile=` lines (one per path, rendered under
    /// `[Service]`), opt-in (empty renders nothing). This is where
    /// credentials belong — the arguments docs above explain why they can
    /// never ride `arguments`. Each entry must be an absolute path over the
    /// conservative alphabet `[A-Za-z0-9._/@+-]` (the directive is
    /// word-split, C-unescaped, and specifier-expanded — a quote, a
    /// backslash, or a `%` would silently change what systemd reads).
    ///
    /// **systemd reads the file as ROOT, before the `User=` switch** — that
    /// is why a `root:root 0600` file works for an unprivileged unit, and
    /// it is the right custody shape. Because root feeds its contents
    /// (`LD_PRELOAD` and friends included) into the service, the file must
    /// be root's and not group/other-writable, under directories that are
    /// too: a package that ships one sets that up. systemd-only;
    /// the Windows record ignores the field.
    pub environment_files: Vec<PathBuf>,
    /// systemd `LimitNOFILE=` — the service's open-file-descriptor limit
    /// (soft = hard). `None` renders [`DEFAULT_OPEN_FILES_LIMIT`] (65536);
    /// `Some(n)` renders `n` (at least [`MIN_OPEN_FILES_LIMIT`], else
    /// `ServiceError::InvalidSpec`).
    ///
    /// Why a default at all: every live connection of a websocket or HTTP
    /// server costs one descriptor, and systemd hands services a SOFT limit
    /// of 1024 (the `select()`-compatibility default; the hard limit is
    /// 524288 on systemd ≥ 240). A node meant to hold thousands of
    /// connections would silently top out near a thousand — `accept`
    /// failing with `EMFILE` — so the unit raises the soft limit itself.
    /// 65536 covers tens of thousands of connections plus database pools
    /// and files; the kernel allocates per OPEN descriptor, not per limit,
    /// so a high ceiling costs nothing idle. tokio never uses `select()`,
    /// so the old reason for a 1024 soft limit does not apply. Values above
    /// the kernel's `fs.nr_open` (1048576 by default) make the unit fail to
    /// start. User units are additionally bounded by the user manager's own
    /// hard limit. systemd-only; the
    /// Windows backend ignores the field (Windows has no per-process
    /// descriptor limit of this kind).
    pub open_files_limit: Option<u64>,
    /// What the supervisor should do when the process fails.
    pub failure_policy: FailurePolicy,
    /// systemd identity + capability sandbox, opt-in (`None` = the unit
    /// runs as root with every capability — the "raw host access" escape
    /// hatch; [`ServiceSpec::systemd_hardening`] still applies). Honored by
    /// the systemd backend only.
    pub sandbox: Option<SystemdSandbox>,
    /// The systemd hardening directive set, ON by default with a per-knob
    /// opt-out. Honored by the systemd backend only.
    pub systemd_hardening: SystemdHardening,
    /// The Windows account the SCM runs the service under. The default is
    /// the per-service virtual account `NT SERVICE\<name>`;
    /// `LocalSystem` is an explicit opt-in. Windows-only;
    /// the systemd backend ignores it.
    pub windows_account: WindowsServiceAccount,
    /// systemd `StateDirectory=`: a directory under `/var/lib` (a user
    /// unit's under `~/.local/state`) that systemd creates, owns to the
    /// service's user, and keeps writable under `ProtectSystem=strict`.
    /// `None` renders nothing.
    ///
    /// A relative path of one or more segments over `[A-Za-z0-9._@+-]`,
    /// separated by `/` (for example `acme/collector`): no leading or
    /// trailing `/`, no empty, `.` or `..` segment. It renders with
    /// `StateDirectoryMode=0700`, since a service keeps its keys and
    /// enrollment there. The update helper's request file lives in it
    /// ([`render::systemd::update_path_unit`](crate::render::systemd::update_path_unit)).
    /// systemd-only; the Windows backend ignores the field.
    pub state_directory: Option<String>,
}

impl Default for ServiceSpec {
    /// A base for struct-update syntax, so a caller's literal survives new
    /// fields: `ServiceSpec { name, program, ..ServiceSpec::default() }`.
    /// `name`, `display_name`, `description` and `program` are empty and
    /// must be set (every renderer refuses them empty). Everything else is
    /// the documented default: no arguments or environment files, the
    /// default open-files limit and failure policy, no sandbox, full
    /// hardening, the virtual account, no state directory.
    fn default() -> Self {
        Self {
            name: String::new(),
            display_name: String::new(),
            description: String::new(),
            program: PathBuf::new(),
            arguments: Vec::new(),
            environment_files: Vec::new(),
            open_files_limit: None,
            failure_policy: FailurePolicy::default(),
            sandbox: None,
            systemd_hardening: SystemdHardening::default(),
            windows_account: WindowsServiceAccount::default(),
            state_directory: None,
        }
    }
}

// ---------------------------------------------------------------------------

/// systemd identity and capability sandbox for one service: `User=` /
/// `Group=` plus the `CapabilityBoundingSet=` / `AmbientCapabilities=`
/// pair. The directive hardening set lives in [`SystemdHardening`] and
/// applies to every unit, sandboxed or not.
///
/// The values are validated with the same strictness as the unit name
/// (no whitespace/control/path characters, no `%` specifiers, no leading
/// `-`; capability names must match `[A-Za-z0-9_]+`) and rejected with
/// `ServiceError::InvalidName` before the filesystem or `systemctl` is
/// touched. Three `user`/`group` rules go further than the name rule:
/// `%` is rejected outright (`"%u"` expands to ROOT for a system unit),
/// bare all-digit values are rejected (`"0"` IS root), and `user = "root"`
/// is refused unless
/// [`SystemdSandbox::allow_root`] opts in — a "sandbox" running as root
/// with every capability is not least privilege.
///
/// Aimed at system units: `User=`/`Group=` are system-unit settings (a
/// `systemctl --user` manager already runs as that user and rejects
/// re-targeting it), so the renderer skips them for user units; the
/// capability lines render there unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdSandbox {
    /// The user the service runs as (`User=`). The package creates it
    /// (the `sysusers.d` file [`render::systemd::sysusers`](crate::render::systemd::sysusers)
    /// renders).
    pub user: String,
    /// The group the service runs as (`Group=`).
    pub group: String,
    /// Capability allowlist (`CapabilityBoundingSet=` ceiling +
    /// `AmbientCapabilities=` grant, space-separated in the unit). **Empty
    /// means NO capabilities**: it renders an empty `CapabilityBoundingSet=`
    /// (never "no line", which would be the full bounding set). The ambient
    /// half is load-bearing: after `User=` drops to a non-root user the
    /// kernel clears effective/permitted capabilities across `execve`, and
    /// only ambient (or file) capabilities restore them — a bounding set
    /// alone grants nothing. Each entry must match `[A-Za-z0-9_]+`.
    pub capabilities: Vec<String>,
    /// Explicit opt-in to `user = "root"` (a root identity with a bounded
    /// capability set). Off by default; the renderer refuses a root
    /// identity otherwise.
    pub allow_root: bool,
}

// ---------------------------------------------------------------------------

/// The standard systemd hardening directive set, rendered into every unit
/// (sandboxed or not). [`Default`] turns every knob ON: the rendered
/// sandboxed unit scores at the "OK" end of
/// `systemd-analyze security` instead of "EXPOSED". Each `bool` renders
/// exactly one directive, so an app that needs one relaxed (a JIT needs
/// `memory_deny_write_execute: false`, a netlink user adds
/// `extra_address_families`) opts out of exactly that knob.
/// [`SystemdHardening::none`] is the explicit all-off shape for daemons
/// that genuinely need raw host access.
///
/// User units: `ProtectHome` renders `read-only` (the program itself
/// usually lives under `$HOME`), and the mount-namespace settings need
/// unprivileged user namespaces on the host — opt out per knob where
/// they are disabled.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // one bool per directive IS the API
pub struct SystemdHardening {
    /// `NoNewPrivileges=true`.
    pub no_new_privileges: bool,
    /// `ProtectSystem=strict` (the whole hierarchy read-only except
    /// [`SystemdHardening::read_write_paths`] and the state directory).
    pub protect_system_strict: bool,
    /// `ProtectHome=true` (`read-only` for user units).
    pub protect_home: bool,
    /// `PrivateTmp=true`.
    pub private_tmp: bool,
    /// `PrivateDevices=true`.
    pub private_devices: bool,
    /// `ProtectKernelTunables=true`.
    pub protect_kernel_tunables: bool,
    /// `ProtectKernelModules=true`.
    pub protect_kernel_modules: bool,
    /// `ProtectKernelLogs=true`.
    pub protect_kernel_logs: bool,
    /// `ProtectControlGroups=true`.
    pub protect_control_groups: bool,
    /// `ProtectClock=true`.
    pub protect_clock: bool,
    /// `ProtectHostname=true`.
    pub protect_hostname: bool,
    /// `ProtectProc=invisible` + `ProcSubset=pid`.
    pub protect_proc: bool,
    /// `RestrictNamespaces=true`.
    pub restrict_namespaces: bool,
    /// `RestrictRealtime=true`.
    pub restrict_realtime: bool,
    /// `RestrictSUIDSGID=true`.
    pub restrict_suid_sgid: bool,
    /// `LockPersonality=true`.
    pub lock_personality: bool,
    /// `MemoryDenyWriteExecute=true` (turn off for JIT runtimes).
    pub memory_deny_write_execute: bool,
    /// `RemoveIPC=true`.
    pub remove_ipc: bool,
    /// `SystemCallArchitectures=native`.
    pub system_call_architectures_native: bool,
    /// `SystemCallFilter=@system-service` + `SystemCallFilter=~@privileged
    /// @resources` + `SystemCallErrorNumber=EPERM`.
    pub system_call_filter: bool,
    /// `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` plus
    /// [`SystemdHardening::extra_address_families`].
    pub restrict_address_families: bool,
    /// `UMask=0077`.
    pub umask_0077: bool,
    /// `DevicePolicy=closed`.
    pub device_policy_closed: bool,
    /// Extra `AF_*` families appended to `RestrictAddressFamilies=` (e.g.
    /// `AF_NETLINK`). Each must match `AF_[A-Z0-9_]+`.
    pub extra_address_families: Vec<String>,
    /// Paths that stay writable under `ProtectSystem=strict`, rendered as
    /// one space-separated `ReadWritePaths=` line. Each entry must be an
    /// absolute path over `[A-Za-z0-9._/@+-]` — the value is word-split,
    /// C-unescaped and specifier-expanded, and systemd drops the WHOLE line
    /// on one stray quote, which would leave every listed path read-only
    /// (writes fail with EROFS).
    pub read_write_paths: Vec<PathBuf>,
}

impl Default for SystemdHardening {
    /// Every knob on, no extra address families, no extra writable paths.
    fn default() -> Self {
        Self {
            no_new_privileges: true,
            protect_system_strict: true,
            protect_home: true,
            private_tmp: true,
            private_devices: true,
            protect_kernel_tunables: true,
            protect_kernel_modules: true,
            protect_kernel_logs: true,
            protect_control_groups: true,
            protect_clock: true,
            protect_hostname: true,
            protect_proc: true,
            restrict_namespaces: true,
            restrict_realtime: true,
            restrict_suid_sgid: true,
            lock_personality: true,
            memory_deny_write_execute: true,
            remove_ipc: true,
            system_call_architectures_native: true,
            system_call_filter: true,
            restrict_address_families: true,
            umask_0077: true,
            device_policy_closed: true,
            extra_address_families: Vec::new(),
            read_write_paths: Vec::new(),
        }
    }
}

impl SystemdHardening {
    /// Every knob off: the explicit shape for a daemon that genuinely needs
    /// raw host access. Prefer turning off individual knobs.
    pub fn none() -> Self {
        Self {
            no_new_privileges: false,
            protect_system_strict: false,
            protect_home: false,
            private_tmp: false,
            private_devices: false,
            protect_kernel_tunables: false,
            protect_kernel_modules: false,
            protect_kernel_logs: false,
            protect_control_groups: false,
            protect_clock: false,
            protect_hostname: false,
            protect_proc: false,
            restrict_namespaces: false,
            restrict_realtime: false,
            restrict_suid_sgid: false,
            lock_personality: false,
            memory_deny_write_execute: false,
            remove_ipc: false,
            system_call_architectures_native: false,
            system_call_filter: false,
            restrict_address_families: false,
            umask_0077: false,
            device_policy_closed: false,
            extra_address_families: Vec::new(),
            read_write_paths: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------

/// The account a Windows service runs under ([`ServiceSpec::windows_account`]).
/// Honored by the Windows SCM backend only; the systemd backend ignores it.
///
/// The default is [`WindowsServiceAccount::Virtual`] — `NT SERVICE\<name>`:
/// passwordless, a per-service SID, least privilege, and the identity the
/// MSI's protected program-directory DACL grants read + execute (never
/// Modify: the service never writes its own program directory).
/// `LocalSystem` — the most privileged
/// account on the host, with `SeDebugPrivilege`/`SeImpersonatePrivilege`
/// and access to every protected secret, so a daemon RCE is total host
/// compromise — is only ever an explicit opt-in
/// ([`WindowsServiceAccount::LocalSystem`]); spelling it through
/// [`WindowsServiceAccount::Named`] is refused.
///
/// The account behaviors (virtual-account SIDs under the DACL, profile
/// temp directories) are exercised against a real SCM on a Windows runner
/// (`scripts/windows-scm-e2e.ps1`);
/// [`render::windows::virtual_account_sid`](crate::render::windows::virtual_account_sid)
/// computes the SID the same way Windows does, for packages.
#[derive(Clone, Default)]
pub enum WindowsServiceAccount {
    /// `NT SERVICE\<service name>` — the default.
    #[default]
    Virtual,
    /// `NT AUTHORITY\LocalService`.
    LocalService,
    /// `NT AUTHORITY\NetworkService` (the machine's network identity).
    NetworkService,
    /// `LocalSystem` — root-equivalent. Explicit opt-in only.
    LocalSystem,
    /// A named account: `DOMAIN\user`, `.\user`, `user@domain`, or another
    /// `NT SERVICE\…` / `NT AUTHORITY\…` spelling. Validated by the renderer:
    /// non-empty, no control characters, no leading/trailing whitespace, at
    /// most one `\` (interior spaces are fine — every `NT …` account has
    /// one); a LocalSystem spelling is refused (use the explicit variant).
    Named {
        /// The account name.
        account_name: String,
        /// The password (domain/local user accounts only — `NT SERVICE` /
        /// `NT AUTHORITY` accounts are passwordless and MUST leave this
        /// `None`). Zeroized on drop; **excluded from `Debug`**; never
        /// rendered into any file this crate writes.
        account_password: Option<zeroize::Zeroizing<String>>,
    },
}

impl fmt::Debug for WindowsServiceAccount {
    /// Hand-rolled: the derived form would print the password
    /// (`Zeroizing`'s own `Debug` is a plain derive), so the password is
    /// redacted by hand.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Virtual => f.write_str("Virtual"),
            Self::LocalService => f.write_str("LocalService"),
            Self::NetworkService => f.write_str("NetworkService"),
            Self::LocalSystem => f.write_str("LocalSystem"),
            Self::Named {
                account_name,
                account_password,
            } => f
                .debug_struct("Named")
                .field("account_name", account_name)
                .field(
                    "account_password",
                    &account_password.as_ref().map(|_| "<redacted>"),
                )
                .finish(),
        }
    }
}

// ---------------------------------------------------------------------------

/// Supervisor restart policy: escalating delays between automatic restarts,
/// and (Windows) a window after which the escalation resets.
///
/// **Retry forever, never fail-stop.** Both platforms keep
/// restarting a failing daemon at the capped delay — a fleet of headless
/// devices must never park itself permanently down behind a start-limit
/// budget that only a reboot or a hand-run `reset-failed` clears:
///
/// * **Windows SCM** takes one Restart action per delay and repeats the
///   LAST action for every further failure; the failure count resets after
///   `reset_period` of stable uptime.
/// * **systemd** renders `RestartSec=` = the first delay,
///   `RestartMaxDelaySec=` = the last, `RestartSteps=` = `len - 1`
///   (systemd interpolates exponentially between them — the default
///   15 s → 15 min policy lands at ≈15 s / 1 min / 4 min / 15 min), and
///   `StartLimitIntervalSec=0` (no start limit). `RestartSteps=` /
///   `RestartMaxDelaySec=` need **systemd ≥ 254**; older managers ignore
///   the unknown keys (a logged warning) and restart forever at the first
///   delay — a safe degradation. `reset_period`
///   has no systemd rendering: the step counter resets when the unit is
///   started by hand or `reset-failed`.
///
/// An empty `restart_delays` on systemd means "never restart after a
/// failure". The Windows record REFUSES an empty list
/// (`ServiceError::InvalidSpec`): the SCM's failure actions are a Windows
/// service's only recovery, and a service is always restarted.
///
/// Escalation exits (a supervisor's `RunError::TaskFailed`) and fatal exits
/// consume this policy like crashes: each one restarts at the next (capped)
/// delay.
///
/// The systemd renderer rejects a first delay below 1 s and a last delay
/// shorter than the first with `ServiceError::InvalidSpec` (a
/// sub-second value truncates to `RestartSec=0` — a hot restart loop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailurePolicy {
    /// Windows: window of stable uptime after which the failure count (and
    /// thus the escalation step) resets to zero. No systemd rendering.
    pub reset_period: Duration,
    /// Delay before the Nth automatic restart; the last delay repeats
    /// forever. Empty = never restart after a failure (systemd; refused on
    /// Windows — see above). Must be non-decreasing on systemd (first ≥ 1s).
    pub restart_delays: Vec<Duration>,
}

impl Default for FailurePolicy {
    /// The production-tested escalation: restart after
    /// 15s, then 1min, 5min, 15min; reset the escalation after 24h stable.
    fn default() -> Self {
        Self {
            reset_period: Duration::from_secs(24 * 60 * 60),
            restart_delays: vec![
                Duration::from_secs(15),
                Duration::from_secs(60),
                Duration::from_secs(5 * 60),
                Duration::from_secs(15 * 60),
            ],
        }
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_policy_default_is_the_reference_escalation() {
        let policy = FailurePolicy::default();
        assert_eq!(policy.reset_period, Duration::from_secs(24 * 60 * 60));
        assert_eq!(
            policy.restart_delays,
            vec![
                Duration::from_secs(15),
                Duration::from_secs(60),
                Duration::from_secs(300),
                Duration::from_secs(900),
            ]
        );
    }
}
