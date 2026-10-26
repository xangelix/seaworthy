# seaworthy-service

*One service description, rendered for systemd, the Windows SCM and launchd, with
least-privilege defaults, plus the runtime glue a service binary needs.*

`seaworthy-service` has two halves:

- **Always present, pure.** `ServiceSpec` (and `FailurePolicy`, `UnixIdentity`, `SystemdSandbox`,
  `SystemdHardening`, `WindowsServiceAccount`), validated and rendered by `render` into the
  files an installer needs: systemd units and a `sysusers.d` entry, the update helper's units
  and polkit rule, a Windows service's MSI record and SDDLs, and macOS LaunchDaemon plists. No
  OS-specific dependency and no tokio, so a packaging tool renders every platform's files on
  one Linux host.
- **`runtime` (off by default).** `backend`: start / stop / status of an installed service
  through the Windows SCM, `systemctl` or `launchctl`. `run`: `run_service`, the run loop a
  service binary enters (the Unix signal loop; on Windows the SCM dispatcher, its status
  protocol and a console fallback).

The crate installs nothing. A package (the seaworthy CLI's MSI, deb, rpm, pacman package or
macOS pkg) lays out the program and registers the service from what `render` produced.

```toml
[dependencies]
# Packaging tools: the spec and the renderers only.
seaworthy-service = "0.1"
# A service binary: the run loop and the backends too.
seaworthy-service = { version = "0.1", features = ["runtime"] }
```

## Rendering a service

```rust
use std::path::PathBuf;

use seaworthy_service::{
    ServiceSpec, SystemdSandbox, UnixIdentity,
    render::{self, systemd::Scope},
};

let spec = ServiceSpec {
    name: "acme-agent".into(),
    display_name: "Acme Agent".into(),
    description: "The Acme agent".into(),
    program: PathBuf::from("/opt/acme/agent/bin/acme-agent"),
    arguments: vec!["service".into()],
    state_directory: Some("acme/agent".into()),
    // The Unix account: named, never root by omission (the default,
    // UnixIdentity::Unspecified, is refused by the systemd and launchd
    // renderers).
    unix_identity: UnixIdentity::User(SystemdSandbox {
        user: "acme-agent".into(),
        group: "acme-agent".into(),
        capabilities: vec![],
        allow_root: false,
    }),
    ..ServiceSpec::default()
};

// Linux: the unit, the sandbox user, the update helper's path unit.
let unit = render::systemd::unit(&spec, Scope::System)?;
assert!(unit.contains("\nUser=acme-agent\n") && unit.contains("\nProtectSystem=strict\n"));
let sysusers = render::systemd::sysusers(&spec)?;
assert!(sysusers.is_some());
let _path_unit = render::systemd::update_path_unit(&spec)?;

// Windows: the MSI's ServiceInstall record and the program directory's DACL.
let record = render::windows::service_record(&spec)?;
assert_eq!(record.account, "NT SERVICE\\acme-agent");
let _program_dir = render::windows::program_dir_sddl(&spec)?;

// macOS: the LaunchDaemon.
let _plist = render::launchd::plist(&spec)?;
# Ok::<(), seaworthy_service::ServiceError>(())
```

Every value is validated before anything is rendered, and refused rather than flattened:
systemd, sysusers, launchd and Windows Installer parse these files with administrator rights.

## Running a service

`main` hands `run_service` an `init` future (typically the first server contact, retried until
it works) and a `body` that runs until the supervisor asks it to stop; on Windows it enters
through `run_windows_service`, which starts the SCM dispatcher. The library never exits the
process: `main` turns the disposition into the exit code.

```rust,no_run
# #[cfg(feature = "runtime")]
fn main() {
    use seaworthy_service::{Outcome, ShutdownRx};

    let init = async { Outcome::<(), std::io::Error>::Success(()) };
    let body = |(), mut shutdown: ShutdownRx| async move {
        // Serve until SIGTERM / SIGINT / SCM STOP or SHUTDOWN.
        let _ = shutdown.recv().await;
        Outcome::Success(())
    };
    #[cfg(windows)]
    let result = seaworthy_service::run_windows_service("acme-agent", init, body);
    #[cfg(not(windows))]
    let result = seaworthy_service::run_service("acme-agent", init, body);
    match result {
        // A clean, supervisor-requested stop: exit 0, not restarted.
        Ok(exit) => exit.exit_process(),
        // Every failure exits EXIT_CODE_FATAL (1): the supervisor restarts it.
        Err(error) => std::process::exit(error.exit_code()),
    }
}
# #[cfg(not(feature = "runtime"))]
# fn main() {}
```

## The rules

1. **The supervisor owns the restart, and a service never exits to update.** Clean stops
   (SIGTERM, SIGINT, SCM STOP or SHUTDOWN) exit 0; every failure exits `EXIT_CODE_FATAL` (1).
   On Windows every failure path reports `Stopped` with service-specific code 1, so the SCM's
   failure actions restart the service (the dispatcher returns only once the service reports
   `Stopped`). A version mismatch is not an exit: the service asks the update helper
   (seaworthy-updater) and keeps running, and the package manager restarts it once the new
   release is installed.
2. **Retry forever; never fail-stop.** systemd renders a capped, escalating delay
   (`RestartSteps=`/`RestartMaxDelaySec=`, systemd 254 or later) with no start limit
   (`StartLimitIntervalSec=0`); the SCM repeats its last restart action forever. A fleet never
   parks itself down behind a start-limit budget only a reboot clears.
3. **Init can always be stopped.** The run loop races init against the stop request (on
   Windows it reports `Running` before init), so a service retrying an unreachable server
   stops cleanly, and an MSI can stop it for an upgrade at any time.
4. **Unit text is never an injection vector.** Control characters (NUL, CR and LF included)
   are refused in every rendered field, never flattened; a trailing `\` in `Description=` is
   refused; `ExecStart` tokens are quoted per systemd.syntax with `%` and `$` doubled and a
   lone `;` escaped; the program path must be absolute, below a directory and free of
   modifier prefixes (`+` would run it with full privileges, ignoring the sandbox).
   `EnvironmentFile=` and `ReadWritePaths=` admit only `[A-Za-z0-9._/@+-]`.
5. **What root executes is writable only by administrators.** The package owns the program
   directory: root-owned 0755 under `/opt/<vendor>/<app>` on Linux; on Windows a protected
   DACL with SYSTEM and Administrators full control and the service account read + execute
   (`render::windows::program_dir_sddl`). A service never writes its own program.
6. **Arguments ride beside the program path, never inside it, and never carry secrets.**
   Folding them into a Windows `binPath` is the classic Code 5 (Access Denied) trap; on
   Windows they must not contain `%` (the SCM expands `%VAR%` in the stored command line).
   Arguments are world-readable (the unit file, `/proc/<pid>/cmdline`, the SCM's registry):
   credentials go in a root-only `EnvironmentFile=`.

## Least privilege by default

- **systemd hardening, on.** `SystemdHardening::default()` renders `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
  `DevicePolicy=closed`, `ProtectKernelTunables/Modules/Logs`, `ProtectControlGroups`,
  `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible` + `ProcSubset=pid`,
  `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`,
  `MemoryDenyWriteExecute`, `RemoveIPC`, `SystemCallArchitectures=native`,
  `SystemCallFilter=@system-service` + `~@privileged @resources`,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` and `UMask=0077`. One `bool` per
  directive, so a service opts out of exactly what it needs (a JIT turns off
  `memory_deny_write_execute`). The sandboxed unit scores at the "OK" end of
  `systemd-analyze security` (the crate's tests assert at most 2.0).
- **An explicit identity.** `unix_identity` must name the account:
  `UnixIdentity::User(SystemdSandbox)` renders `User=`/`Group=` and the
  `CapabilityBoundingSet=` + `AmbientCapabilities=` pair (an empty capability list means no
  capabilities; `root`, bare numeric IDs and `%` specifiers are refused unless `allow_root`
  opts in; `render::systemd::sysusers` creates the user), `UnixIdentity::Root` runs as root
  with every capability by choice, and the default, `UnixIdentity::Unspecified`, is refused
  by the systemd (system scope) and launchd renderers: nothing runs as root by omission.
- **Windows: the virtual account.** The default account is `NT SERVICE\<name>`
  (passwordless, a per-service SID that `render::windows::virtual_account_sid` computes at
  packaging time). `LocalSystem` is an explicit opt-in. The state directory grants the account
  Modify, never `WRITE_DAC` or `WRITE_OWNER`; the `%ProgramData%` parents are owned by SYSTEM
  and strip an owner's implicit rights. At run time the service audits its own state directory
  (`run::audit_state_directory`; automatic on Windows for an MSI-installed service) and refuses
  to run on anything it can't trust (the audit is `seaworthy-fsguard`'s).
- **launchd.** A `UnixIdentity::User` maps to `UserName`/`GroupName`, `UnixIdentity::Root`
  to no `UserName`; environment files are refused (a plist is world-readable).

See [docs/services.md](../../docs/services.md) for every field, the failure policy, what each
renderer produces, the runtime and the Windows dispatcher contract.

## Out of scope

- **Crash-loop rollback.** A freshly installed release that crashes at start is restarted
  forever at the capped delay until a fix-forward release reaches it.
- **A supervisor of its own.** `Fatal` exits non-zero and the OS service manager's restart
  policy (your `FailurePolicy`) does the recovery. Two supervisors would fight.
- **Installing services.** Packages do that, from the renderers' output.
- **launchd's escalation and sandbox.** launchd restarts at one fixed `ThrottleInterval` and
  has no counterpart to the systemd hardening set.
- **`setcap`.** Capabilities are granted unit-side (`AmbientCapabilities`), which survives
  package upgrades; file capabilities do not.

## Platform notes

Linux: systemd 254 or later for the restart escalation (older managers ignore the unknown keys
and restart forever at the first delay), 247 or later for `ProtectProc=`. Windows: the SCM,
through `windows-service`. macOS: a LaunchDaemon in the `system` domain, driven by
`launchctl`. The `runtime` feature builds on Unix and Windows only. The run loop runs a tokio
multi-thread runtime.

## Security

The crate has no cryptographic surface beyond computing a Windows virtual account's SID, which
Windows defines as SHA-1 of the service name (an identifier, not an integrity check; through
`seaworthy-crypto`). The systemd renderer is fuzzed (`fuzz/`, target `service_unit`) against
an independent parser of what systemd reads. Report vulnerabilities as described in
[SECURITY.md](../../SECURITY.md).

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or
[MIT license](../../LICENSE-MIT) at your option.
