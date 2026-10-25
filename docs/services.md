# Services

How `seaworthy-service` describes a service, what it renders for each platform's service
manager, the least-privilege defaults it applies, and how a service binary runs under the
supervisor. The crate's README has the short version and the examples.

The crate installs nothing. A package (MSI, deb, rpm, pacman package, macOS pkg) lays out the
program and registers the service from what the renderers produce; the optional runtime then
starts, stops and queries the installed service, and runs the service's own main loop.

| Part | Feature | What it is |
|---|---|---|
| `ServiceSpec` and friends | always | The backend-agnostic description |
| `render::systemd` | always | Service unit, update helper units and polkit rule, `sysusers.d` entry |
| `render::windows` | always | MSI service record, failure actions, account and SID, SDDLs |
| `render::launchd` | always | LaunchDaemon plists, the `launchctl print` state mapping |
| `backend` | `runtime` | start / stop / status through the SCM, `systemctl`, `launchctl` |
| `run` | `runtime` | `run_service`, the Unix signal loop, the Windows SCM dispatcher |

The pure half has no OS-specific dependency and no tokio, so one Linux build host renders
every platform's files.

## The spec

`ServiceSpec` is plain data. Build it with struct-update syntax so new fields keep working:
`ServiceSpec { name, display_name, description, program, ..ServiceSpec::default() }`.

| Field | Meaning | Rules |
|---|---|---|
| `name` | The SCM service name, systemd unit basename and launchd label | An ASCII letter or digit first; no whitespace, control characters, `/`, `\` or `%`. systemd: `[A-Za-z0-9:_.-]`, no `@` (a template instance), at most 200 bytes. launchd: `[A-Za-z0-9._-]` |
| `display_name` | Shown in service management UIs; the update helper's label; the `sysusers.d` GECOS field | No control characters; for sysusers also no `"`, `:` or `\` |
| `description` | systemd `Description=`, the SCM description | No control characters, no trailing `\` (a unit-file line continuation); `%` is escaped |
| `program` | The installed executable, where the package puts it | Absolute, UTF-8, `/`-leading on systemd and launchd, below a directory, no `\`; no modifier prefix can be represented. Windows: absolute, no control characters, no `%` |
| `arguments` | Launch arguments, always passed separately from `program` | UTF-8, no control characters; no `%` on Windows. Never secrets: they are world-readable |
| `environment_files` | systemd `EnvironmentFile=` lines, where credentials belong | Absolute paths over `[A-Za-z0-9._/@+-]`. systemd reads them as root before the `User=` switch, so `root:root 0600` under root-owned directories is the custody shape. Refused for launchd (a plist is world-readable); ignored on Windows |
| `open_files_limit` | systemd `LimitNOFILE=` (soft = hard); launchd `NumberOfFiles` | `None` renders 65536 on systemd (systemd's soft default of 1024 caps a connection server near a thousand sockets); at least 64. Values above the kernel's `fs.nr_open` keep the unit from starting |
| `failure_policy` | Restart delays and the Windows reset period | See [Failure and restart policy](#failure-and-restart-policy) |
| `sandbox` | `SystemdSandbox`: `User=`/`Group=` and the capability pair; launchd's `UserName`/`GroupName` | See [systemd](#systemd) |
| `systemd_hardening` | `SystemdHardening`: the directive set, every knob on by default | See [systemd](#systemd) |
| `windows_account` | `WindowsServiceAccount`, default the virtual account | See [Windows](#windows) |
| `state_directory` | systemd `StateDirectory=` (`/var/lib/<dir>`, mode 0700); the update request file lives there | Relative segments over `[A-Za-z0-9._@+-]`; no empty, `.` or `..` segment; not under systemd's reserved `private/` |

Every renderer validates first and refuses rather than flattens: a value systemd, sysusers,
launchd or Windows Installer would read differently from what the spec says is an error
(`ServiceError::InvalidName` for names, `ServiceError::InvalidSpec` for content), never a
silently mangled file.

## Failure and restart policy

`FailurePolicy` holds `restart_delays` (the delay before the Nth automatic restart; the last
repeats forever) and `reset_period` (Windows: stable uptime after which the escalation
resets). The default restarts after 15 s, 1 min, 5 min and 15 min, then every 15 min forever,
and resets after 24 h.

- **systemd** renders `Restart=on-failure`, `RestartSec=` (the first delay),
  `RestartSteps=` (`len - 1`), `RestartMaxDelaySec=` (the last delay) and
  `StartLimitIntervalSec=0`. systemd interpolates exponentially between first and last (the
  default lands at about 15 s, 1 min, 4 min, 15 min). The escalation needs systemd 254; older
  managers ignore the keys and restart forever at the first delay. The first delay must be at
  least 1 s (a shorter one truncates to `RestartSec=0`, a hot loop) and the last must not be
  below the first. An empty list renders `Restart=no`. `reset_period` has no systemd form.
- **Windows** gets one Restart action per delay, in milliseconds; the SCM repeats the last
  action for every further failure, and the failure-actions-on-non-crash-failures flag is
  always set, so a fatal exit (`Stopped` with a non-zero code) restarts like a crash. Every
  delay and the reset period must be at least 1 s. An empty list is refused: failure actions
  are a Windows service's only recovery.
- **launchd** gets `KeepAlive` = { `SuccessfulExit` = false } and `ThrottleInterval` = the
  first delay: restarted after a non-zero exit or a crash, never after exit 0. launchd has one
  fixed interval, so there is no escalation. An empty list leaves `KeepAlive` out.

No platform ever fail-stops: a fleet of unattended machines must not park itself down behind
a start-limit budget that only a reboot or a hand-run `reset-failed` clears.

### Known gap: no crash-loop rollback

A freshly installed release that crashes at start is restarted forever at the capped delay. It
stays down on that release until a fix-forward release reaches it; there is no mark-good
sentinel or automatic rollback.

## What render produces

### systemd

- `render::systemd::unit(spec, Scope)`: the service unit. `Scope::User` targets
  `default.target`, skips `User=`/`Group=` (a user manager already runs as that user) and
  renders `ProtectHome=read-only`.
- `render::systemd::update_path_unit(spec)`: `<name>-update.path`, starting
  `<name>-update.service` when the service writes
  `/var/lib/<state_directory>/update-request`. Writing that file is the only thing the service
  can do to ask for an update. No `TriggerLimit*=` beyond systemd's defaults: a tripped limit
  fails the path unit, and nothing would restart it.
- `render::systemd::update_service_unit(spec, helper, cache_directory)`: the update helper, a
  root oneshot with no `[Install]` and no start limit, sandboxed (`ProtectSystem=strict`
  except its 0700 `CacheDirectory=`, no home, devices, kernel tunables, modules, logs or
  control groups, `NoNewPrivileges`, `@system-service`, IPv4/IPv6/Unix sockets only). The
  package manager it starts runs in a transient unit that inherits none of this.
- `render::systemd::desktop_update_service_unit` and `desktop_update_polkit_rule`: for a
  product with no service, the same helper unit and a polkit rule letting the active, local
  session `start` exactly that unit, nothing else.
- `render::systemd::sysusers(spec)`: the sandbox user (and group, as `u user -:group` when it
  differs) for `/usr/lib/sysusers.d`.

The hardening set (`SystemdHardening`, on by default) renders: `NoNewPrivileges=true`,
`ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `PrivateDevices=true`,
`DevicePolicy=closed`, `ProtectKernelTunables=true`, `ProtectKernelModules=true`,
`ProtectKernelLogs=true`, `ProtectControlGroups=true`, `ProtectClock=true`,
`ProtectHostname=true`, `ProtectProc=invisible`, `ProcSubset=pid`, `RestrictNamespaces=true`,
`RestrictRealtime=true`, `RestrictSUIDSGID=true`, `LockPersonality=true`,
`MemoryDenyWriteExecute=true`, `RemoveIPC=true`, `SystemCallArchitectures=native`,
`SystemCallFilter=@system-service`, `SystemCallFilter=~@privileged @resources`,
`SystemCallErrorNumber=EPERM`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` (plus
`extra_address_families`), `UMask=0077`, and `ReadWritePaths=` for the declared paths. Each
`bool` renders one directive, so a service turns off exactly what it needs;
`SystemdHardening::none()` is the explicit all-off shape. User units need unprivileged user
namespaces for the mount-namespace settings.

The sandbox (`SystemdSandbox`) renders `User=`, `Group=`, `CapabilityBoundingSet=` (the
ceiling) and `AmbientCapabilities=` (the grant: after `User=` drops root, only ambient
capabilities survive `execve`). An empty list renders an empty `CapabilityBoundingSet=`: no
capabilities, never the full set. User and group names follow the portable rule
(`[A-Za-z_][A-Za-z0-9_-]{0,30}`); bare numbers (`0` is root), `%` specifiers (`%u` expands to
root in a system unit) and `root` without `allow_root` are refused. With the hardening and a
sandbox, `systemd-analyze security --offline=yes` scores the unit at most 2.0 ("OK"); without
them it is "EXPOSED".

### Windows

- `render::windows::service_record(spec)`: the `ServiceInstall` row and its failure actions:
  name, display name, description, the account as `ServiceInstall.StartName` spells it, its
  SID, the arguments quoted into one command line by the rules MSVC programs parse with, and
  the failure actions. Refused besides the Windows rules: `[` or `]` anywhere (MSI expands
  `[PROPERTY]` in those columns and `[~]` inserts a NUL) and a named account with a password
  (an MSI would carry it in a property).
- `render::windows::virtual_account_sid(name)`: `S-1-5-80-` plus the SHA-1 of the upper-cased
  name in UTF-16LE, as five little-endian 32-bit numbers. Windows derives it from the name
  alone, so an MSI can grant the account access before the service exists. ASCII names only
  (Windows upper-cases with its own table).
- `render::windows::program_dir_sddl(spec)`: the program directory's protected DACL: SYSTEM
  and Administrators full control, the service account read + execute (`0x1200a9`), never
  Modify.
- `render::windows::state_dir_sddl(spec)`: the state directory under
  `%ProgramData%\<Vendor>\<Product>\state`: owner SYSTEM, SYSTEM and Administrators full
  control, OWNER RIGHTS read-control only, the service account Modify (`0x1301bf`: never
  `WRITE_DAC` or `WRITE_OWNER`).
- `render::windows::data_dir_sddl()` and `updates_dir_sddl()`: the `%ProgramData%` parents and
  the update helper's staging directory: owner SYSTEM, SYSTEM and Administrators only, OWNER
  RIGHTS read-control. Any user may create a directory under `%ProgramData%`; the installer
  takes the owner back, and the OWNER RIGHTS entry strips a squatting owner's implicit
  `WRITE_DAC`.
- `render::windows::helper_service_sddl(grantee)`: the update helper service's DACL: SYSTEM and
  Administrators get Windows' default service rights; the grantee (the main service's account
  — `SY`, `LS`, `NS` or a virtual account's SID, never a broad principal — or interactive
  users for a desktop product) may query and **start** it, never stop, reconfigure or delete
  it. The helper takes no input, so starting it can only make the machine install the release
  the product's server names.

Accounts (`WindowsServiceAccount`): `Virtual` (`NT SERVICE\<name>`, the default:
passwordless, a per-service SID, least privilege), `LocalService`, `NetworkService`, the
explicit `LocalSystem` opt-in (root-equivalent: a compromise of the service is a compromise of
the host), or `Named` (a domain or local account; a password is zeroized on drop, redacted from
`Debug` and never rendered). Spelling `LocalSystem` through `Named` is refused.

### launchd

- `render::launchd::plist(spec)`: `/Library/LaunchDaemons/<name>.plist`: `Label`,
  `ProgramArguments` (no shell, nothing re-split), `RunAtLoad`, `KeepAlive` and
  `ThrottleInterval` from the failure policy, `ProcessType` `Standard`, `ExitTimeOut` 20 s
  (the run loop's stop hint plus its shutdown grace), `UserName`/`GroupName` from the sandbox
  (root without one: macOS has no per-service accounts), `NumberOfFiles` limits, `Umask` 0077.
- `render::launchd::daemon_plist(spec, log_file)`: the same, with standard output and error
  appended to a log file (launchd otherwise discards a daemon's output).
- `render::launchd::update_helper_plist(spec, helper, request_file, log_file)`: the update
  helper as root, on demand: no `RunAtLoad`, no `KeepAlive`, `WatchPaths` on the request file.
  The service asks for an update by writing that file, so it never needs the right to start a
  system daemon.
- `render::launchd::state(print_output)`: the service's state from `launchctl print`'s
  top-level `state =` line; anything unknown is `ServiceState::Unknown`, which no wait reads
  as success.

Capabilities, environment files, `root`/`wheel` without `allow_root` and bare numeric IDs are
refused for launchd.

## The runtime

The `runtime` feature adds the backends and the run loop. It builds on Unix and Windows only.

### Backends

`ServiceBackend` (`start`, `stop`, `status`) with `DefaultBackend` aliasing the platform's:

- `SystemdBackend` (system or `--user` units) resolves `systemctl` by absolute path
  (`/usr/bin`, then `/bin`; `with_systemctl` pins another; a `PATH` fallback logs loudly).
  `failed` reads as `Stopped`; an `ActiveState` it doesn't know reads as `Unknown`, never
  `Running`.
- `LaunchdBackend` drives the `system` domain through `/bin/launchctl`: `stop` signals the
  process (`launchctl kill SIGTERM`) and leaves the job loaded; `start` kickstarts a loaded
  job or loads it from its plist.
- `WindowsBackend` talks to the local SCM through `windows-service`.

Every backend validates the name before it asks the service manager anything, and polls at a
configurable interval (default 1 s) up to a timeout (default 30 s).

### The run loop

`run_service(name, init, body)` runs `init` (typically the first server contact, retried until
the server answers), then `body` with a `ShutdownRx` that fires when the supervisor wants the
service gone. Both return an `Outcome`: `Success` or `Fatal`.

- A clean stop returns `ServiceExit::Stopped`: `main` exits 0 (`ServiceExit::exit_process`),
  and the supervisor does not restart it.
- `Fatal` from either phase returns `RunError::Fatal`, a panic in the Windows service main
  `RunError::TaskPanicked`; `main` exits `RunError::exit_code()` (`EXIT_CODE_FATAL`, 1) and the
  supervisor restarts it per the failure policy.
- Init is raced against the stop request. A service still retrying an unreachable server
  stops cleanly (exit 0) instead of waiting for the supervisor's SIGKILL.
- The runtime is shut down with a 5 s grace for blocking work on every path, so a slow DNS
  lookup never keeps the process (and its files) alive after the stop was reported.

On Unix the loop forwards the first SIGTERM or SIGINT into the shutdown channel. A SIGINT
listener that fails to register never reads as a stop.

### The Windows dispatcher contract

The SCM contract has two chained requirements: the process's entry point calls
`StartServiceCtrlDispatcherW`, and only then does the SCM invoke the service main on its own
thread, where the control handler must register and every status report must happen.
`run_windows_service(name, init, body)` implements both halves: call it from `main`. It stashes
the service main (one per process, the SCM's contract), starts the dispatcher, and runs the
state machine on the SCM's thread:

1. `StartPending` while the runtime is built (accepting no controls);
2. `Running` at once, BEFORE init, accepting STOP and SHUTDOWN (an OS shutdown takes the same
   graceful path as a stop). A service held in `StartPending` would answer STOP with 1061 and
   make an MSI's `ServiceControl` fail with 1920 and roll back;
3. init raced against STOP, then the body;
4. a clean stop: `StopPending`, the runtime shut down, `Stopped` with Win32 exit code 0;
5. every failure (a `Fatal` outcome, a panic, a status-report failure): `Stopped` with
   `ERROR_SERVICE_SPECIFIC_ERROR` and service-specific code 1, so the failure actions restart
   it. If even that report fails, the process exits with code 1 and the SCM sees a crash.

Started outside the SCM (a developer console, `cargo run`), the dispatcher answers 1063 and the
same call runs the foreground shape instead: Ctrl-C stops it, no status protocol. Windows
admits one dispatcher call per process, so the process remembers the 1063 and later runs take
the foreground shape directly. `run_service` remains the ServiceMain body for an application
that wires its own dispatcher (the name it registers under must match the installed service).

Two Windows traps the design avoids: arguments never go into the image path (Code 5, Access
Denied), and a missing DLL the program imports reads as an instant start timeout (Code 1053),
so the package lays every DLL beside the program.

## Testing

- Unit tests on every platform cover every renderer (golden units and plists), every
  validation rule, the SCM state machine's exit paths (platform-neutral, so Linux runs them),
  the systemd and launchd backends against stub tools, and, where present,
  `systemd-analyze security` and `verify` on the rendered sandboxed unit and node on the polkit
  rule (`SEAWORTHY_REQUIRE_NODE=1` makes node mandatory).
- `fuzz/` target `service_unit` renders arbitrary specs and checks the unit, the update units
  and the `sysusers.d` text against an independent parser of what systemd reads: no field can
  add a line, a section or a directive, and every value recovers exactly.
- `scripts/windows-scm-e2e.ps1` runs against a real SCM on an elevated Windows machine (a
  GitHub-hosted `windows-2025` runner): it installs a fixture product's MSI and checks the
  virtual account, the DACLs, failure-action restarts after a fatal exit, a panic and a crash,
  a version mismatch that keeps the service running, a stop during init, a clean stop that is
  not restarted, and the uninstall. `tests/windows_scm.rs` adds typed-result checks
  (`SEAWORTHY_WINDOWS_SCM_E2E=1`). An OS shutdown and boot stay a physical or VM check before a
  release.
- `scripts/check-powershell.sh` parses the PowerShell scripts and checks them against Windows
  PowerShell 5.1's syntax.
