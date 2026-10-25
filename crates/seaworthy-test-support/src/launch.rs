//! The ONE container launch path every builder rides.
//!
//! - **Publish address.** Every published port is pinned to the
//!   topology's address ([`crate::dind::publish_ip`]): the daemon's
//!   loopback on a plain host, the bridge gateway in socket-mount mode
//!   (never the host's LAN interfaces), all interfaces only for a remote
//!   `tcp://` daemon, a Docker Desktop / rootless gateway that cannot be
//!   bound (a loud, logged, process-latched fallback), or an explicit
//!   `SEAWORTHY_TEST_CONTAINERS_PUBLISH_IP`.
//! - **Ownership labels + a dead-owner sweep.** testcontainers cleans up
//!   in `Drop` only: a SIGKILLed test (a runner timeout, a CI cancel, a
//!   `kill -9`) leaks its containers, and a leaked fixed-port service
//!   wedges every later run with the daemon's opaque "port is already
//!   allocated". Every container carries its owner's pid, process start
//!   time, pid-namespace id and hostname; the first [`docker_or_skip`]
//!   of each process removes labeled containers whose owner (same host,
//!   same pid namespace) is dead, plus any past the one-hour ceiling (no
//!   container test runs that long).
//! - **Unique names + failed-start cleanup.** A start that fails after
//!   the daemon created the container (a port collision, a readiness
//!   timeout) leaves it `Created`; every launch names its container
//!   (`seaworthy-tc-{role}-{pid}-{seq}`) so the failure path removes it by
//!   name, and a fixed-port collision names the container HOLDING the
//!   port instead of the daemon's opaque message.
//! - **The image first, with transient pulls retried.** Before the first
//!   start, [`crate::pull::ensure_image`] makes the digest-pinned image
//!   present: a registry rate limit, 5xx, reset or timeout is retried with
//!   bounded backoff HERE, before the test body runs, so it never surfaces
//!   as a test failure (or as a runner retry that a fail-if-flaky rule
//!   turns red). Only the pull is retried: a create or
//!   start failure, a readiness timeout, and a port collision below fail
//!   exactly as before.
//!
//! [`docker_or_skip`]: crate::docker_or_skip

use std::{
    collections::HashMap,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};

use testcontainers::{
    ContainerAsync, ContainerRequest, GenericImage, ImageExt as _, runners::AsyncRunner as _,
};

use crate::dind::{self, PublishIp};

/// Label: the owning process's pid.
pub const LABEL_OWNER_PID: &str = "seaworthy.tc.owner-pid";
/// Label: the owning process's start time (Linux `/proc/<pid>/stat`
/// field 22: pid reuse can never impersonate a dead owner).
pub const LABEL_OWNER_START: &str = "seaworthy.tc.owner-start";
/// Label: the owning pid's namespace id (a pid means nothing across
/// namespaces: two development containers sharing one daemon).
pub const LABEL_OWNER_PIDNS: &str = "seaworthy.tc.owner-pidns";
/// Label: the owning host (container hostname in socket-mount mode).
pub const LABEL_OWNER_HOST: &str = "seaworthy.tc.owner-host";
/// Label: unix seconds at launch (the age ceiling's clock).
pub const LABEL_CREATED: &str = "seaworthy.tc.created";
/// Label: the builder role (`rustfs`, `systemd-debian-13`, …): diagnostics.
pub const LABEL_ROLE: &str = "seaworthy.tc.role";

/// No container test runs longer than this; past it a labeled container
/// is swept whoever owns it.
pub const SWEEP_AGE_CEILING_SECS: u64 = 60 * 60;

static SWEPT: AtomicBool = AtomicBool::new(false);
static SEQ: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// Owner identity
// ---------------------------------------------------------------------------

/// Who owns a container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Owner {
    pub(crate) pid: u32,
    /// Process start time in clock ticks; `None` off Linux.
    pub(crate) start: Option<u64>,
    /// pid-namespace inode; `"unknown"` off Linux.
    pub(crate) pidns: String,
    pub(crate) host: String,
}

impl Owner {
    /// This process.
    pub(crate) fn me() -> Self {
        let pid = std::process::id();
        Self {
            pid,
            start: process_start(pid),
            pidns: std::fs::read_link("/proc/self/ns/pid")
                .ok()
                .and_then(|link| {
                    let link = link.to_string_lossy().into_owned();
                    let digits: String = link.chars().filter(char::is_ascii_digit).collect();
                    (!digits.is_empty()).then_some(digits)
                })
                .unwrap_or_else(|| "unknown".into()),
            host: std::fs::read_to_string("/proc/sys/kernel/hostname")
                .ok()
                .or_else(|| std::env::var("HOSTNAME").ok())
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| "unknown".into()),
        }
    }

    fn labels(&self, role: &str) -> [(String, String); 6] {
        [
            (LABEL_OWNER_PID.into(), self.pid.to_string()),
            (
                LABEL_OWNER_START.into(),
                self.start
                    .map_or_else(|| "unknown".into(), |s| s.to_string()),
            ),
            (LABEL_OWNER_PIDNS.into(), self.pidns.clone()),
            (LABEL_OWNER_HOST.into(), self.host.clone()),
            (LABEL_CREATED.into(), unix_now().to_string()),
            (LABEL_ROLE.into(), role.into()),
        ]
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A process's start time (Linux: `/proc/<pid>/stat` field 22, read
/// after the LAST `)`: the comm field may contain spaces/parens).
fn process_start(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    // Fields after `)` start at field 3 (state); field 22 is index 19.
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Whether the recorded owner is still alive. Off Linux there is no
/// `/proc`: assume alive and let the age ceiling collect (the
/// conservative posture).
fn owner_alive(pid: u32, start: Option<u64>) -> bool {
    if !std::path::Path::new("/proc/self/stat").exists() {
        return true;
    }
    match process_start(pid) {
        None => false,
        Some(now) => start.is_none_or(|recorded| recorded == now),
    }
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

/// Why a labeled container should be swept (`None` = keep). Pure: the
/// liveness check is injected.
pub(crate) fn sweep_verdict(
    labels: &HashMap<String, String>,
    docker_created: Option<i64>,
    now: u64,
    me: &Owner,
    alive: impl Fn(u32, Option<u64>) -> bool,
) -> Option<String> {
    let pid: u32 = labels.get(LABEL_OWNER_PID)?.parse().ok()?;
    let start = labels
        .get(LABEL_OWNER_START)
        .and_then(|s| s.parse::<u64>().ok());
    let created = labels
        .get(LABEL_CREATED)
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| docker_created.and_then(|c| u64::try_from(c).ok()));
    let same_ns = labels.get(LABEL_OWNER_HOST) == Some(&me.host)
        && labels.get(LABEL_OWNER_PIDNS) == Some(&me.pidns)
        && me.pidns != "unknown";
    let is_me = same_ns && pid == me.pid && start == me.start;
    if same_ns && !is_me && !alive(pid, start) {
        return Some(format!("its owner pid {pid} is dead"));
    }
    if let Some(created) = created
        && now.saturating_sub(created) > SWEEP_AGE_CEILING_SECS
    {
        return Some(format!(
            "it is older than the {SWEEP_AGE_CEILING_SECS}s ceiling"
        ));
    }
    None
}

/// Sweep once per process (called by `docker_or_skip` on a ready daemon).
pub(crate) async fn sweep_once() {
    if SWEPT.swap(true, Ordering::Relaxed) {
        return;
    }
    sweep().await;
}

/// Remove every labeled container whose [`sweep_verdict`] says so.
/// Best-effort: a sweep failure is logged, never a test failure. Returns
/// the removed container names.
pub(crate) async fn sweep() -> Vec<String> {
    let docker = crate::docker::connect();
    let me = Owner::me();
    let mut removed = Vec::new();
    let options = bollard::query_parameters::ListContainersOptions {
        all: true,
        filters: Some(HashMap::from([(
            "label".to_string(),
            vec![LABEL_OWNER_PID.to_string()],
        )])),
        ..Default::default()
    };
    let containers = match docker.list_containers(Some(options)).await {
        Ok(containers) => containers,
        Err(e) => {
            eprintln!("seaworthy-test-support: leak sweep could not list containers: {e}");
            return removed;
        }
    };
    let now = unix_now();
    for container in containers {
        let labels = container.labels.clone().unwrap_or_default();
        let Some(reason) = sweep_verdict(&labels, container.created, now, &me, owner_alive) else {
            continue;
        };
        let Some(id) = container.id.as_deref() else {
            continue;
        };
        let name = container
            .names
            .as_ref()
            .and_then(|n| n.first())
            .map_or(id, |n| n.trim_start_matches('/'))
            .to_string();
        match remove_force(&docker, id).await {
            Ok(()) => {
                eprintln!("seaworthy-test-support: swept leaked container {name} ({reason})");
                removed.push(name);
            }
            Err(e) => eprintln!("seaworthy-test-support: could not sweep {name}: {e}"),
        }
    }
    removed
}

async fn remove_force(docker: &bollard::Docker, id: &str) -> Result<(), bollard::errors::Error> {
    docker
        .remove_container(
            id,
            Some(
                bollard::query_parameters::RemoveContainerOptionsBuilder::default()
                    .force(true)
                    .v(true)
                    .build(),
            ),
        )
        .await
}

// ---------------------------------------------------------------------------
// Launch
// ---------------------------------------------------------------------------

/// A unique container name for `role` (`seaworthy-tc-{role}-{pid}-{seq}`).
pub(crate) fn unique_name(role: &str) -> String {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("seaworthy-tc-{role}-{}-{seq}", std::process::id())
}

/// Start a container through the one launch path, panicking (with the
/// cause named) on failure. `build` constructs the request (called again
/// for the all-interfaces fallback: requests are not `Clone`); `name`
/// overrides the generated unique name (a DNS alias another container
/// dials); `fixed_ports` are the host ports the request maps explicitly
/// (named in a collision's diagnostics).
pub(crate) async fn start(
    role: &str,
    name: Option<&str>,
    fixed_ports: &[u16],
    build: impl Fn() -> ContainerRequest<GenericImage>,
) -> ContainerAsync<GenericImage> {
    try_start(role, name, fixed_ports, build)
        .await
        .unwrap_or_else(|message| panic!("seaworthy-test-support: {role}: {message}"))
}

/// [`start`] for an image this crate built on the daemon itself (the
/// [`crate::systemd`] hosts' provisioned images): no registry pull, since
/// the image is local and has no digest pin; everything else as [`start`].
pub(crate) async fn start_local(
    role: &str,
    build: impl Fn() -> ContainerRequest<GenericImage>,
) -> ContainerAsync<GenericImage> {
    try_start_with(role, None, &[], false, build)
        .await
        .unwrap_or_else(|message| panic!("seaworthy-test-support: {role}: {message}"))
}

/// [`start`] without the panic (the collision test inspects the message).
pub(crate) async fn try_start(
    role: &str,
    name: Option<&str>,
    fixed_ports: &[u16],
    build: impl Fn() -> ContainerRequest<GenericImage>,
) -> Result<ContainerAsync<GenericImage>, String> {
    try_start_with(role, name, fixed_ports, true, build).await
}

async fn try_start_with(
    role: &str,
    name: Option<&str>,
    fixed_ports: &[u16],
    pull: bool,
    build: impl Fn() -> ContainerRequest<GenericImage>,
) -> Result<ContainerAsync<GenericImage>, String> {
    // The pull, retried on transient registry failures, before any start.
    // The image is present afterwards, so testcontainers' own one-shot
    // on-demand pull (on a create's 404) does not run below.
    if pull {
        crate::pull::ensure_image(&build().descriptor())
            .await
            .map_err(|e| e.to_string())?;
    }
    let mut publish = dind::publish_ip().await;
    loop {
        let container_name = name.map_or_else(|| unique_name(role), str::to_string);
        let request = build()
            .with_container_name(&container_name)
            .with_labels(Owner::me().labels(role))
            .with_host_config_modifier(dind::publish_modifier(publish.clone()));
        let error = match request.start().await {
            Ok(container) => return Ok(container),
            Err(e) => e.to_string(),
        };
        // The daemon created the container before the start failed: remove
        // it so a failed start never leaves `Created` litter.
        let docker = crate::docker::connect();
        let _ = remove_force(&docker, &container_name).await;

        if let PublishIp::Pinned(ip) = &publish
            && dind::gateway_bind_unavailable(&error)
            && dind::fallback_permitted()
        {
            eprintln!(
                "seaworthy-test-support: WARNING: the daemon cannot publish on {ip} \
                 ({error}) — this is Docker Desktop / rootless, where the bridge gateway lives \
                 inside a VM or namespace. FALLING BACK to publishing on ALL interfaces for the \
                 rest of this process: while the suite runs, the services (with their throwaway \
                 credentials) are reachable from your LAN. Set {} \
                 to an address the daemon can bind to avoid this.",
                dind::PUBLISH_IP_ENV
            );
            dind::latch_fallback();
            publish = PublishIp::AllInterfaces;
            continue;
        }
        if is_port_collision(&error) {
            let holders = port_holders(&docker, fixed_ports).await;
            return Err(format!(
                "a fixed host port is already taken ({error}); held by: {} — a leaked \
                 container from a killed run or a parallel suite. Remove it \
                 (`docker rm -f <name>`) or wait for the other run.",
                if holders.is_empty() {
                    "an unknown process (not a container we can see)".into()
                } else {
                    holders.join(", ")
                }
            ));
        }
        return Err(format!("container failed to start: {error}"));
    }
}

fn is_port_collision(error: &str) -> bool {
    error.contains("port is already allocated") || error.contains("address already in use")
}

/// `name (id, labels)` of every container publishing one of `ports`.
async fn port_holders(docker: &bollard::Docker, ports: &[u16]) -> Vec<String> {
    let mut out = Vec::new();
    for port in ports {
        let options = bollard::query_parameters::ListContainersOptions {
            all: true,
            filters: Some(HashMap::from([(
                "publish".to_string(),
                vec![port.to_string()],
            )])),
            ..Default::default()
        };
        let Ok(containers) = docker.list_containers(Some(options)).await else {
            continue;
        };
        for c in containers {
            let name = c
                .names
                .as_ref()
                .and_then(|n| n.first())
                .map_or("?", |n| n.trim_start_matches('/'))
                .to_string();
            let owner = c
                .labels
                .as_ref()
                .and_then(|l| l.get(LABEL_OWNER_PID))
                .map_or_else(String::new, |pid| format!(", owner pid {pid}"));
            out.push(format!(
                "container {name} (port {port}, {}{owner})",
                c.state.as_ref().map_or_else(
                    || "state unknown".into(),
                    |s| format!("{s:?}").to_lowercase()
                )
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        LABEL_CREATED, LABEL_OWNER_HOST, LABEL_OWNER_PID, LABEL_OWNER_PIDNS, LABEL_OWNER_START,
        Owner, sweep_verdict,
    };

    fn me() -> Owner {
        Owner {
            pid: 100,
            start: Some(5000),
            pidns: "4026531836".into(),
            host: "ws".into(),
        }
    }

    fn labels(
        pid: u32,
        start: u64,
        pidns: &str,
        host: &str,
        created: u64,
    ) -> HashMap<String, String> {
        HashMap::from([
            (LABEL_OWNER_PID.to_string(), pid.to_string()),
            (LABEL_OWNER_START.to_string(), start.to_string()),
            (LABEL_OWNER_PIDNS.to_string(), pidns.to_string()),
            (LABEL_OWNER_HOST.to_string(), host.to_string()),
            (LABEL_CREATED.to_string(), created.to_string()),
        ])
    }

    /// The pure sweep matrix: a dead same-namespace owner is swept; a live
    /// one, a foreign namespace, and ourselves are kept; anything past the
    /// ceiling is swept.
    #[test]
    fn sweep_verdict_matrix() {
        let now = 10_000;
        let dead = |_: u32, _: Option<u64>| false;
        let alive = |_: u32, _: Option<u64>| true;
        let young = now - 60;
        assert!(
            sweep_verdict(
                &labels(7, 1, "4026531836", "ws", young),
                None,
                now,
                &me(),
                dead
            )
            .is_some()
        );
        assert!(
            sweep_verdict(
                &labels(7, 1, "4026531836", "ws", young),
                None,
                now,
                &me(),
                alive
            )
            .is_none()
        );
        // Foreign pid namespace / host: our /proc says nothing about it.
        assert!(sweep_verdict(&labels(7, 1, "999", "ws", young), None, now, &me(), dead).is_none());
        assert!(
            sweep_verdict(
                &labels(7, 1, "4026531836", "other", young),
                None,
                now,
                &me(),
                dead
            )
            .is_none()
        );
        // Ourselves, never.
        assert!(
            sweep_verdict(
                &labels(100, 5000, "4026531836", "ws", young),
                None,
                now,
                &me(),
                dead
            )
            .is_none()
        );
        // A REUSED pid (same number, different start) is a dead owner.
        assert!(
            sweep_verdict(
                &labels(100, 4999, "4026531836", "ws", young),
                None,
                now,
                &me(),
                dead
            )
            .is_some()
        );
        // The ceiling applies to everyone.
        let old = now - super::SWEEP_AGE_CEILING_SECS - 1;
        assert!(
            sweep_verdict(&labels(7, 1, "999", "other", old), None, now, &me(), alive).is_some()
        );
        // Unlabeled (not ours): never.
        assert!(sweep_verdict(&HashMap::new(), Some(0), now, &me(), dead).is_none());
    }

    #[test]
    fn owner_identity_reads_proc() {
        let me = Owner::me();
        assert_eq!(me.pid, std::process::id());
        if std::path::Path::new("/proc/self/stat").exists() {
            assert!(me.start.is_some(), "start time from /proc");
            assert_ne!(me.pidns, "unknown");
            assert!(super::owner_alive(me.pid, me.start));
            assert!(
                !super::owner_alive(me.pid, me.start.map(|s| s + 1)),
                "pid reuse"
            );
            assert!(!super::owner_alive(u32::MAX - 1, None), "no such pid");
        }
    }

    #[test]
    fn unique_names_carry_role_and_pid() {
        let a = super::unique_name("rustfs");
        let b = super::unique_name("rustfs");
        assert_ne!(a, b);
        assert!(
            a.starts_with(&format!("seaworthy-tc-rustfs-{}-", std::process::id())),
            "{a}"
        );
    }
}
