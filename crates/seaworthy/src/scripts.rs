//! The Linux package scripts, and the systemd preset file they apply.
//!
//! Each format calls its scripts with its own arguments, so each gets its
//! own spelling of one shared lifecycle:
//!
//! | Phase | deb | rpm | pacman (`.INSTALL`) |
//! | --- | --- | --- | --- |
//! | before unpack | `preinst install [<old>]` / `preinst upgrade <old>` | `%pre 1` / `%pre 2` | `pre_install` / `pre_upgrade` |
//! | after unpack | `postinst configure [<old>]` | `%post 1` / `%post 2` | `post_install` / `post_upgrade` |
//! | before removal | `prerm remove` | `%preun 0` | `pre_remove` |
//! | after removal | `postrm remove` / `postrm purge` | `%postun 0` | `post_remove` |
//!
//! Every other call (`prerm upgrade`, `%preun 1`, `postrm upgrade`,
//! `%postun 1`, …) does nothing: the new version's scripts take over.
//! pacman passes package versions, never actions, so its scripts have the
//! action fixed. nFPM puts each pacman script into a bash function of the
//! package's `.INSTALL`.
//!
//! What the lifecycle does, and never more:
//!
//! - **Before unpack (install or upgrade):** note which of the package's
//!   units have no file yet, in `/run/seaworthy/<package>.new-units`.
//!   Those are the units new to this host: on a fresh install every one,
//!   on an upgrade the ones this version adds, and on a deb reinstall
//!   after `apt remove` (dpkg then passes the old version, as for an
//!   upgrade) every one again. On an upgrade, also stop and disable the
//!   update path unit when this version no longer ships it (the helper
//!   was dropped, or this is a downgrade to a version without it).
//! - **After install:** create the sandbox user (`systemd-sysusers`),
//!   reload systemd, apply the preset policy to the update path unit and
//!   the service (`systemctl preset`), and start whichever the policy
//!   enabled, the path unit first, so no early update request is missed.
//! - **After upgrade:** create the sandbox user if missing, reload systemd,
//!   apply presets to the noted new units only, `try-restart` the service
//!   (the new build takes over if it was running), and start the update
//!   path unit if it's enabled (a no-op when it's running; it revives one
//!   stopped by a failure). The update units are **never restarted**: the
//!   helper may be the process running this upgrade.
//! - **Before removal:** stop the update path unit, any running update
//!   helper and the service, then disable the service and the path unit.
//! - **After removal:** reload systemd. The sandbox user and the state
//!   under `/var/lib` stay: they're the administrator's, even on purge.
//!
//! A desktop app's package has one unit, its update helper's oneshot,
//! which the logged-in session starts through the package's polkit rule.
//! Its scripts only reload systemd after an install or upgrade (it learns
//! the new or changed unit) and stop the helper before removal; nothing is
//! enabled, preset or started, and before unpack there is nothing to do.
//!
//! The package ships a vendor preset file (`/usr/lib/systemd/system-preset/
//! 80-<package>.preset`) enabling its units, so a host's own policy decides:
//! a site preset in `/etc/systemd/system-preset` that sorts earlier
//! (`00-site.preset`: `disable *`) keeps them off, and a masked unit is
//! left alone (`systemctl preset` and `enable` both fail on one). Distros
//! that disable everything by default (Fedora's, and Arch's
//! `99-default.preset`) sort after it.
//!
//! Robustness, as distributions' own helpers do it:
//!
//! - A failed `systemctl` call (a unit that won't start, a preset that
//!   fails) prints a warning and the transaction goes on, so one unit can't
//!   leave the package half-configured. `systemd-sysusers` failing does
//!   fail it: the service can't run without its user.
//! - Starts and restarts are queued (`--no-block`): a service ordered after
//!   `network-online.target` must not hold the package manager until the
//!   network comes up, or deadlock an install run before it.
//! - Enablement (presets, `disable`) is applied whenever `systemctl`
//!   exists, even when systemd isn't running (an image build, a chroot): it
//!   only writes symlinks, and the units then start on the image's first
//!   boot. Starting, stopping and reloading need a running systemd
//!   (`/run/systemd/system`) and are skipped without one.
//! - deb: a start is skipped when `/usr/sbin/policy-rc.d` forbids it (exit
//!   101, the container convention), and under dpkg's chrootless mode
//!   (`DPKG_ROOT` set) no `systemctl` runs at all and `systemd-sysusers`
//!   gets `--root`.
//! - The marker is trusted only in a root-owned directory that isn't a
//!   symlink, and only for names in the package's own unit list. `/run` is
//!   root-only and cleared at boot.
//!
//! Every value interpolated into a script was validated as a systemd unit
//! name or a package name first.

use crate::config::Output;

/// What the scripts manage, by name.
#[derive(Debug, Clone, Default)]
pub struct Units {
    /// The service unit (`<name>.service`), if the product is a service.
    pub service: Option<String>,
    /// The update path unit (`<name>-update.path`), if the helper ships.
    pub update_path: Option<String>,
    /// The update helper's oneshot (`<name>-update.service`), if the
    /// helper ships: a desktop app's (`<package>-update.service`) is its
    /// package's only unit.
    pub update_service: Option<String>,
    /// Units an earlier version of this product may have shipped and this
    /// one doesn't (`<name>-update.path` when the helper doesn't ship): an
    /// upgrade or downgrade stops and disables them.
    pub retired: Vec<String>,
    /// The `sysusers.d` file to apply, if the product has a sandbox user.
    pub sysusers: Option<String>,
}

impl Units {
    /// The units the preset file enables, in start order: the update path
    /// unit, then the service.
    #[must_use]
    pub fn enabled(&self) -> Vec<&str> {
        [self.update_path.as_deref(), self.service.as_deref()]
            .into_iter()
            .flatten()
            .collect()
    }
}

/// One format's scripts. `pre_upgrade` and `post_upgrade` are pacman's
/// own functions; deb and rpm decide inside the install scripts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scripts {
    /// Before unpack (`preinst`, `%pre`, `pre_install`).
    pub pre_install: String,
    /// After unpack (`postinst`, `%post`, `post_install`).
    pub post_install: String,
    /// Before removal (`prerm`, `%preun`, `pre_remove`).
    pub pre_remove: String,
    /// After removal (`postrm`, `%postun`, `post_remove`).
    pub post_remove: String,
    /// pacman's `pre_upgrade`.
    pub pre_upgrade: Option<String>,
    /// pacman's `post_upgrade`.
    pub post_upgrade: Option<String>,
}

/// Where the before-unpack script notes the units new to this host.
/// `/run` is root-only and cleared at boot.
pub const MARKER_DIR: &str = "/run/seaworthy";

/// Where vendor presets live.
pub const PRESET_DIR: &str = "/usr/lib/systemd/system-preset";

/// Where vendor units live.
pub const UNIT_DIR: &str = "/usr/lib/systemd/system";

/// Debian's start-policy hook (`invoke-rc.d`'s convention: exit 101 forbids).
pub const POLICY_RC_D: &str = "/usr/sbin/policy-rc.d";

/// The preset file's install path for `package`.
#[must_use]
pub fn preset_path(package: &str) -> String {
    format!("{PRESET_DIR}/80-{package}.preset")
}

/// The preset file enabling `units`, or `None` when there's nothing to
/// enable.
#[must_use]
pub fn preset(units: &Units) -> Option<String> {
    let enabled = units.enabled();
    if enabled.is_empty() {
        return None;
    }
    let mut text = String::from(
        "# Generated by seaworthy: enable this package's units by default.\n\
         # A site preset in /etc/systemd/system-preset that sorts earlier wins.\n",
    );
    for unit in enabled {
        text.push_str(&format!("enable {unit}\n"));
    }
    Some(text)
}

/// A script's phase.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    PreInstall,
    PostInstall,
    PreRemove,
    PostRemove,
}

/// How a script learns its action.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Caller {
    Deb,
    Rpm,
    /// pacman: the action is fixed by the function the script becomes.
    Fixed(&'static str),
}

/// The `case` mapping a format's arguments to `$action`.
fn action(caller: Caller, phase: Phase) -> String {
    let arms = match (caller, phase) {
        (Caller::Fixed(action), _) => return format!("action={action}\n"),
        (Caller::Deb, Phase::PreInstall) => {
            "  install) action=install ;;   # a reinstall after `apt remove` passes the old version\n\
             \x20 upgrade) action=upgrade ;;\n"
        }
        (Caller::Deb, Phase::PostInstall) => {
            "  configure) if [ -n \"${2:-}\" ]; then action=upgrade; else action=install; fi ;;\n\
             \x20 abort-remove) action=install ;;   # prerm remove ran: undo it\n\
             \x20 abort-upgrade|abort-deconfigure) action=restore ;;\n"
        }
        (Caller::Deb, Phase::PreRemove) => "  remove) action=remove ;;\n",
        (Caller::Deb, Phase::PostRemove) => {
            "  remove|purge) action=remove ;;\n  abort-install) action=restore ;;\n"
        }
        (Caller::Rpm, Phase::PreInstall | Phase::PostInstall) => {
            "  1) action=install ;;\n  [2-9]|[1-9][0-9]*) action=upgrade ;;\n"
        }
        (Caller::Rpm, Phase::PreRemove | Phase::PostRemove) => "  0) action=remove ;;\n",
    };
    format!("action=none\ncase \"${{1:-}}\" in\n{arms}esac\n")
}

/// The helper functions a phase uses.
fn helpers(caller: Caller, phase: Phase, package: &str) -> String {
    let deb = caller == Caller::Deb;
    let mut s = String::from("systemd_running() { [ -d /run/systemd/system ]; }\n");
    if deb {
        // dpkg's chrootless mode: never touch the running system.
        s.push_str("has_systemctl() { [ -z \"${DPKG_ROOT:-}\" ] && command -v systemctl >/dev/null 2>&1; }\n");
    } else {
        s.push_str("has_systemctl() { command -v systemctl >/dev/null 2>&1; }\n");
    }
    s.push_str(&format!(
        "try() {{ \"$@\" || echo \"{package}: warning: '$*' failed (exit $?); continuing\" >&2; }}\n"
    ));
    if matches!(phase, Phase::PreInstall | Phase::PostInstall) {
        // `test -O` isn't POSIX, but every /bin/sh these packages run under
        // has it: dash (Debian, Ubuntu), bash (Fedora, RHEL, Arch), busybox.
        s.push_str(&format!(
            "# shellcheck disable=SC3067 # test -O: dash, bash and busybox all have it\n\
             marker_dir_ok() {{ [ -d {MARKER_DIR} ] && [ ! -L {MARKER_DIR} ] && [ -O {MARKER_DIR} ]; }}\n"
        ));
    }
    if phase == Phase::PostInstall {
        s.push_str(
            "masked() {\n\
             \x20 case \"$(systemctl is-enabled \"$1\" 2>/dev/null || true)\" in\n\
             \x20   masked*) return 0 ;;\n\
             \x20 esac\n\
             \x20 return 1\n\
             }\n",
        );
        if deb {
            s.push_str(&format!(
                "may_start() {{\n\
                 \x20 [ -x {POLICY_RC_D} ] || return 0\n\
                 \x20 rc=0\n\
                 \x20 {POLICY_RC_D} \"${{1%.*}}\" start >/dev/null 2>&1 || rc=$?\n\
                 \x20 [ \"$rc\" != 101 ]\n\
                 }}\n"
            ));
        } else {
            s.push_str("may_start() { return 0; }\n");
        }
    }
    s
}

fn script(caller: Caller, phase: Phase, package: &str, units: &Units) -> String {
    let format = match caller {
        Caller::Deb => "deb",
        Caller::Rpm => "rpm",
        Caller::Fixed(_) => "pacman",
    };
    let name = match phase {
        Phase::PreInstall => "before unpack",
        Phase::PostInstall => "after unpack",
        Phase::PreRemove => "before removal",
        Phase::PostRemove => "after removal",
    };
    let mut s = format!(
        "#!/bin/sh\n\
         # Generated by seaworthy: {package}, {format}, {name}. See seaworthy::scripts.\n\
         set -e\n"
    );
    s.push_str(&helpers(caller, phase, package));
    s.push_str(&action(caller, phase));
    let marker = format!("{MARKER_DIR}/{package}.new-units");
    let enabled = units.enabled().join(" ");
    match phase {
        Phase::PreInstall => {
            s.push_str(&format!(
                "if [ \"$action\" = install ] || [ \"$action\" = upgrade ]; then\n\
                 \x20 if [ -d /run ] && {{ [ -e {MARKER_DIR} ] || mkdir -m 0700 {MARKER_DIR}; }} && marker_dir_ok; then\n\
                 \x20   : > {marker}\n\
                 \x20   units=\"{enabled}\"\n\
                 \x20   for unit in $units; do\n\
                 \x20     if [ ! -e {UNIT_DIR}/\"$unit\" ]; then echo \"$unit\" >> {marker}; fi\n\
                 \x20   done\n\
                 \x20 fi\n\
                 fi\n"
            ));
            if !units.retired.is_empty() {
                s.push_str(&format!(
                    "# Units the installed version shipped and this one doesn't.\n\
                     if [ \"$action\" = upgrade ] && has_systemctl; then\n\
                     \x20 retired=\"{}\"\n\
                     \x20 for unit in $retired; do\n\
                     \x20   if [ -e {UNIT_DIR}/\"$unit\" ]; then\n\
                     \x20     if systemd_running; then try systemctl --no-block stop \"$unit\"; fi\n\
                     \x20     try systemctl disable \"$unit\"\n\
                     \x20   fi\n\
                     \x20 done\n\
                     fi\n",
                    units.retired.join(" ")
                ));
            }
        }
        Phase::PostInstall => {
            // Only the package's own units count from the marker.
            let known = units.enabled().join("|");
            s.push_str(&format!(
                "new_units=\n\
                 if [ \"$action\" = install ]; then\n\
                 \x20 new_units=\"{enabled}\"\n\
                 elif [ \"$action\" = upgrade ] && marker_dir_ok && [ -f {marker} ]; then\n\
                 \x20 while IFS= read -r unit; do\n\
                 \x20   case \"$unit\" in {known}) new_units=\"$new_units $unit\" ;; esac\n\
                 \x20 done < {marker}\n\
                 fi\n\
                 is_new() {{ case \" $new_units \" in *\" $1 \"*) return 0 ;; esac; return 1; }}\n"
            ));
            if let Some(sysusers) = &units.sysusers {
                let root = if caller == Caller::Deb {
                    " ${DPKG_ROOT:+--root=\"$DPKG_ROOT\"}"
                } else {
                    ""
                };
                s.push_str(&format!(
                    "if [ \"$action\" != none ] && command -v systemd-sysusers >/dev/null 2>&1; then\n\
                     \x20 systemd-sysusers{root} {sysusers}\n\
                     fi\n"
                ));
            }
            s.push_str(
                "if [ \"$action\" != none ] && has_systemctl; then\n\
                 \x20 if systemd_running; then try systemctl daemon-reload; fi\n\
                 \x20 for unit in $new_units; do\n\
                 \x20   if ! masked \"$unit\"; then try systemctl preset \"$unit\"; fi\n\
                 \x20 done\n\
                 \x20 if systemd_running; then\n\
                 \x20   for unit in $new_units; do\n\
                 \x20     if systemctl is-enabled --quiet \"$unit\" && may_start \"$unit\"; then try systemctl --no-block start \"$unit\"; fi\n\
                 \x20   done\n",
            );
            if let Some(path) = &units.update_path {
                // Never a restart: `start` leaves a running unit alone.
                s.push_str(&format!(
                    "    if [ \"$action\" != install ] && ! is_new {path} && systemctl is-enabled --quiet {path} && may_start {path}; then try systemctl --no-block start {path}; fi\n"
                ));
            }
            if let Some(service) = &units.service {
                s.push_str(&format!(
                    "    if [ \"$action\" != install ] && ! is_new {service} && ! masked {service} && may_start {service}; then try systemctl --no-block try-restart {service}; fi\n"
                ));
            }
            s.push_str("  fi\nfi\n");
            // Last: a configure step retried after a failure still knows
            // which units were new.
            s.push_str(&format!(
                "if [ \"$action\" != none ]; then rm -f {marker}; fi\n"
            ));
        }
        Phase::PreRemove => {
            let stop: Vec<&str> = [
                units.update_path.as_deref(),
                units.update_service.as_deref(),
                units.service.as_deref(),
            ]
            .into_iter()
            .flatten()
            .collect();
            s.push_str(&format!(
                "if [ \"$action\" = remove ] && has_systemctl; then\n\
                 \x20 if systemd_running; then try systemctl stop {}; fi\n\
                 \x20 try systemctl disable {enabled}\n\
                 fi\n",
                stop.join(" ")
            ));
        }
        Phase::PostRemove => {
            // Only on removal: in a deb upgrade the old `postrm upgrade`
            // runs between the new `preinst` (which writes the marker) and
            // the new `postinst` (which reads it).
            s.push_str(&format!(
                "if [ \"$action\" != none ]; then rm -f {marker}; fi\n\
                 if [ \"$action\" = remove ] && has_systemctl && systemd_running; then\n\
                 \x20 try systemctl daemon-reload\n\
                 fi\n"
            ));
        }
    }
    s
}

/// A desktop product's scripts, whose only unit is its update helper's
/// oneshot (`unit`): nothing enables or starts it (the logged-in session
/// does, through the package's polkit rule), so the lifecycle is only
/// systemd learning the unit after an install or upgrade, and the helper
/// stopped before removal. Before unpack there is nothing to do.
fn helper_only_script(caller: Caller, phase: Phase, package: &str, unit: &str) -> String {
    let format = match caller {
        Caller::Deb => "deb",
        Caller::Rpm => "rpm",
        Caller::Fixed(_) => "pacman",
    };
    let name = match phase {
        Phase::PreInstall => "before unpack",
        Phase::PostInstall => "after unpack",
        Phase::PreRemove => "before removal",
        Phase::PostRemove => "after removal",
    };
    let mut s = format!(
        "#!/bin/sh\n\
         # Generated by seaworthy: {package}, {format}, {name}. See seaworthy::scripts.\n\
         # The package's only unit is its update helper's, {unit}: the logged-in\n\
         # session starts it, never these scripts.\n\
         set -e\n"
    );
    if phase == Phase::PreInstall {
        s.push_str(":\n");
        return s;
    }
    s.push_str("systemd_running() { [ -d /run/systemd/system ]; }\n");
    if caller == Caller::Deb {
        s.push_str("has_systemctl() { [ -z \"${DPKG_ROOT:-}\" ] && command -v systemctl >/dev/null 2>&1; }\n");
    } else {
        s.push_str("has_systemctl() { command -v systemctl >/dev/null 2>&1; }\n");
    }
    s.push_str(&format!(
        "try() {{ \"$@\" || echo \"{package}: warning: '$*' failed (exit $?); continuing\" >&2; }}\n"
    ));
    s.push_str(&action(caller, phase));
    match phase {
        Phase::PreInstall => {}
        Phase::PostInstall => s.push_str(
            "if [ \"$action\" != none ] && has_systemctl && systemd_running; then\n\
             \x20 try systemctl daemon-reload\n\
             fi\n",
        ),
        Phase::PreRemove => s.push_str(&format!(
            "if [ \"$action\" = remove ] && has_systemctl && systemd_running; then\n\
             \x20 try systemctl stop {unit}\n\
             fi\n"
        )),
        Phase::PostRemove => s.push_str(
            "if [ \"$action\" = remove ] && has_systemctl && systemd_running; then\n\
             \x20 try systemctl daemon-reload\n\
             fi\n",
        ),
    }
    s
}

/// The scripts for `format` (deb, rpm or pacman), for `package`
/// (validated as `[a-z0-9][a-z0-9.-]+`) managing `units` (validated unit
/// names and paths). `None` for a format that isn't a Linux package, and
/// for a package without units (a tool, or a desktop app without the
/// helper): it needs no scripts. A desktop app whose only unit is its
/// helper's gets the short lifecycle the module docs describe.
#[must_use]
pub fn scripts(format: Output, package: &str, units: &Units) -> Option<Scripts> {
    if units.enabled().is_empty() {
        let unit = units.update_service.as_deref()?;
        let one = |caller, phase| helper_only_script(caller, phase, package, unit);
        return match format {
            Output::Deb | Output::Rpm => {
                let caller = if format == Output::Deb {
                    Caller::Deb
                } else {
                    Caller::Rpm
                };
                Some(Scripts {
                    pre_install: one(caller, Phase::PreInstall),
                    post_install: one(caller, Phase::PostInstall),
                    pre_remove: one(caller, Phase::PreRemove),
                    post_remove: one(caller, Phase::PostRemove),
                    pre_upgrade: None,
                    post_upgrade: None,
                })
            }
            Output::Pacman => Some(Scripts {
                pre_install: one(Caller::Fixed("install"), Phase::PreInstall),
                post_install: one(Caller::Fixed("install"), Phase::PostInstall),
                pre_remove: one(Caller::Fixed("remove"), Phase::PreRemove),
                post_remove: one(Caller::Fixed("remove"), Phase::PostRemove),
                pre_upgrade: Some(one(Caller::Fixed("upgrade"), Phase::PreInstall)),
                post_upgrade: Some(one(Caller::Fixed("upgrade"), Phase::PostInstall)),
            }),
            Output::Msi | Output::Zip | Output::Tar | Output::Dmg | Output::Pkg => None,
        };
    }
    let one = |caller, phase| script(caller, phase, package, units);
    match format {
        Output::Deb | Output::Rpm => {
            let caller = if format == Output::Deb {
                Caller::Deb
            } else {
                Caller::Rpm
            };
            Some(Scripts {
                pre_install: one(caller, Phase::PreInstall),
                post_install: one(caller, Phase::PostInstall),
                pre_remove: one(caller, Phase::PreRemove),
                post_remove: one(caller, Phase::PostRemove),
                pre_upgrade: None,
                post_upgrade: None,
            })
        }
        Output::Pacman => Some(Scripts {
            pre_install: one(Caller::Fixed("install"), Phase::PreInstall),
            post_install: one(Caller::Fixed("install"), Phase::PostInstall),
            pre_remove: one(Caller::Fixed("remove"), Phase::PreRemove),
            post_remove: one(Caller::Fixed("remove"), Phase::PostRemove),
            pre_upgrade: Some(one(Caller::Fixed("upgrade"), Phase::PreInstall)),
            post_upgrade: Some(one(Caller::Fixed("upgrade"), Phase::PostInstall)),
        }),
        Output::Msi | Output::Zip | Output::Tar | Output::Dmg | Output::Pkg => None,
    }
}
