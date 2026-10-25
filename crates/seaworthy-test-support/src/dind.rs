//! Docker topology: where the daemon's published ports live relative to
//! the test process, which address they publish on, and how the process
//! reaches them.
//!
//! The decision keys on the DAEMON's location (marker files alone
//! mis-handle Kubernetes pods and a bare host driving a remote daemon):
//!
//! | `DOCKER_HOST` | in a container? | [`Topology`] | publish on | reach via |
//! |---|---|---|---|---|
//! | unix / unset | no | `PlainHost` | `127.0.0.1` | `localhost` directly |
//! | unix / unset | yes | `SocketMount` | the bridge gateway | in-process forwarder → gateway |
//! | `tcp://` loopback | either | `PlainHost` | `127.0.0.1` | `localhost` directly |
//! | `tcp://` elsewhere | either | `Remote` | all interfaces (the daemon's network) | forwarder → the daemon host |
//!
//! "In a container" = docker's `/.dockerenv`, podman's `/run/.containerenv`,
//! or a Kubernetes pod (`KUBERNETES_SERVICE_HOST`, or the service-account
//! mount): a pod carries neither marker file.
//!
//! **Socket-mount publishes bind the bridge gateway, never `0.0.0.0`:**
//! the forwarder dials the gateway, which is a host-local address (not on
//! the LAN interface), and binding a specific IPv4
//! address also drops the `[::]` publish. Docker Desktop and rootless
//! daemons cannot bind the gateway (it lives in a VM/namespace); there a
//! failed pinned start falls back to all interfaces ONCE per process with
//! a loud warning, and `SEAWORTHY_TEST_CONTAINERS_PUBLISH_IP=<ip>` picks an
//! explicit address instead (an explicit value never falls back). The
//! residual: under Linux's weak-host model a same-L2 neighbour that adds a
//! static route for the gateway via the host can still reach a
//! gateway-bound publish: deliberate effort, where `0.0.0.0` needed only
//! a port scan.
//!
//! Bridging into the daemon's ports must not change the semantics the
//! suites are written against (loopback-only rules such as the S3
//! client's plaintext exception, TLS SANs), so the harness runs one tiny
//! TCP forwarder per mapped port,
//! IN-PROCESS: `127.0.0.1:port` then behaves exactly as if the process ran
//! on the daemon's host.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};

use crate::docker::{DaemonAddr, DockerEnv};

/// The publish-address override (`SEAWORTHY_TEST_CONTAINERS_PUBLISH_IP`).
pub const PUBLISH_IP_ENV: &str = "SEAWORTHY_TEST_CONTAINERS_PUBLISH_IP";

// ---------------------------------------------------------------------------
// Topology
// ---------------------------------------------------------------------------

/// Whether the test process runs inside a container: docker's marker file,
/// podman's (`/run/.containerenv`), or a Kubernetes pod.
#[must_use]
pub fn in_container() -> bool {
    in_container_at(
        std::path::Path::new("/"),
        std::env::var_os("KUBERNETES_SERVICE_HOST").is_some(),
    )
}

/// The marker check against a chosen root (testable).
fn in_container_at(root: &std::path::Path, k8s_env: bool) -> bool {
    k8s_env
        || root.join(".dockerenv").exists()
        || root.join("run/.containerenv").exists()
        || root
            .join("var/run/secrets/kubernetes.io/serviceaccount")
            .exists()
}

/// Where the daemon's published ports live relative to us (see the
/// module table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Topology {
    /// The daemon's loopback is ours.
    PlainHost,
    /// A mounted host socket from inside a container: the daemon's
    /// ports live on the host, reached through the bridge gateway.
    SocketMount,
    /// A `tcp://` daemon elsewhere (a CI dind sibling, a build box):
    /// reached at its host (bracket-free).
    Remote {
        /// The daemon's host from `DOCKER_HOST`.
        host: String,
    },
}

/// The pure topology decision.
pub(crate) fn topology_for(addr: &DaemonAddr, in_container: bool) -> Topology {
    match addr {
        DaemonAddr::Tcp { host, .. } if !addr.is_loopback_tcp() => {
            Topology::Remote { host: host.clone() }
        }
        DaemonAddr::Tcp { .. } => Topology::PlainHost,
        _ if in_container => Topology::SocketMount,
        _ => Topology::PlainHost,
    }
}

/// This process's topology.
#[must_use]
pub fn topology() -> Topology {
    topology_for(
        &crate::docker::resolve(&DockerEnv::from_process()),
        in_container(),
    )
}

// ---------------------------------------------------------------------------
// The publish address
// ---------------------------------------------------------------------------

/// Where a launch publishes its ports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublishIp {
    /// Every binding's `host_ip` pinned to this address.
    Pinned(String),
    /// testcontainers' default: all interfaces (IPv4 and IPv6).
    AllInterfaces,
}

/// The pure publish decision (matrix-tested: the plain-host row is pinned
/// even where no plain host exists).
pub(crate) fn publish_ip_for(
    topology: &Topology,
    gateway: Option<&str>,
    override_ip: Option<IpAddr>,
) -> PublishIp {
    if let Some(ip) = override_ip {
        return PublishIp::Pinned(ip.to_string());
    }
    match topology {
        Topology::PlainHost => PublishIp::Pinned(Ipv4Addr::LOCALHOST.to_string()),
        Topology::SocketMount => gateway.map_or(PublishIp::AllInterfaces, |gw| {
            PublishIp::Pinned(gw.to_string())
        }),
        // The publish sits on the remote daemon's network (CI: the
        // job-private build network): the forwarder must reach it there.
        Topology::Remote { .. } => PublishIp::AllInterfaces,
    }
}

/// `SEAWORTHY_TEST_CONTAINERS_PUBLISH_IP`, parsed loudly (a malformed
/// value panics naming it, never a silent default).
pub(crate) fn publish_override() -> Option<IpAddr> {
    let value = std::env::var(PUBLISH_IP_ENV).ok()?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.parse().unwrap_or_else(|_| {
        panic!("seaworthy-test-support: {PUBLISH_IP_ENV}={value:?} is not an IP address")
    }))
}

static FALLBACK: AtomicBool = AtomicBool::new(false);

/// Latch the all-interfaces fallback for the rest of the process.
pub(crate) fn latch_fallback() {
    FALLBACK.store(true, Ordering::Relaxed);
}

/// The fallback applies only to the DEFAULT gateway pin: an explicit
/// override that fails is the operator's error, reported, never widened.
pub(crate) fn fallback_permitted() -> bool {
    publish_override().is_none() && topology() == Topology::SocketMount
}

/// Whether a start error is the daemon failing to bind the pinned address.
pub(crate) fn gateway_bind_unavailable(error: &str) -> bool {
    let e = error.to_ascii_lowercase();
    e.contains("cannot assign requested address") || e.contains("address not available")
}

/// The address this process's launches publish on.
pub async fn publish_ip() -> PublishIp {
    if FALLBACK.load(Ordering::Relaxed) {
        return PublishIp::AllInterfaces;
    }
    let topology = topology();
    let gateway = if topology == Topology::SocketMount {
        Some(host_gateway().await)
    } else {
        None
    };
    publish_ip_for(&topology, gateway.as_deref(), publish_override())
}

/// The host-config modifier pinning every explicit port binding.
pub(crate) fn publish_modifier(
    publish: PublishIp,
) -> impl Fn(&mut bollard::models::HostConfig) + Send + Sync + 'static {
    move |host_config| {
        if let PublishIp::Pinned(ip) = &publish {
            pin_port_bindings(host_config, ip);
        }
    }
}

/// The modifier's rewrite, decision-free for tests: every explicit port
/// binding publishes on `ip` only. (Builders use `with_mapped_port` for
/// every port, so there IS an explicit binding to rewrite: with
/// publish-all-ports there would be nothing for a host-config modifier to
/// pin. The modifier runs after testcontainers builds the bindings:
/// `async_runner.rs`, verified against testcontainers 0.28.)
fn pin_port_bindings(host_config: &mut bollard::models::HostConfig, ip: &str) {
    if let Some(bindings) = host_config.port_bindings.as_mut() {
        for binding in bindings.values_mut().flatten().flatten() {
            binding.host_ip = Some(ip.to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// Reaching the daemon's ports
// ---------------------------------------------------------------------------

/// Whether published ports need the in-process forwarder (anything but a
/// plain host).
#[must_use]
pub fn needs_forwarder() -> bool {
    topology() != Topology::PlainHost
}

/// The address that, from our seat, reaches the daemon's published ports
/// (bracket-free): an explicit specific `SEAWORTHY_TEST_CONTAINERS_PUBLISH_IP`,
/// else the remote daemon's host, the bridge gateway in socket mode, or
/// `127.0.0.1` on a plain host.
pub async fn daemon_host() -> String {
    if let Some(ip) = publish_override()
        && !ip.is_unspecified()
    {
        return ip.to_string();
    }
    match topology() {
        Topology::Remote { host } => host,
        Topology::SocketMount => host_gateway().await,
        Topology::PlainHost => Ipv4Addr::LOCALHOST.to_string(),
    }
}

/// `host:port`, bracketing an IPv6 literal.
fn join_host_port(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => SocketAddr::from((v6, port)).to_string(),
        _ => format!("{host}:{port}"),
    }
}

static GATEWAY: OnceLock<String> = OnceLock::new();

/// The docker host's address from our seat in socket mode: the default
/// bridge's gateway (testcontainers' own `get_host()` computes the same
/// value). Resolved once per process.
async fn host_gateway() -> String {
    if let Some(gateway) = GATEWAY.get() {
        return gateway.clone();
    }
    let docker = crate::docker::connect();
    let network = docker
        .inspect_network(
            "bridge",
            None::<bollard::query_parameters::InspectNetworkOptions>,
        )
        .await
        .expect("inspect bridge network");
    let gateway = network
        .ipam
        .and_then(|ipam| ipam.config)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|config| config.gateway)
        .find(|gateway| !gateway.trim().is_empty())
        .expect("bridge gateway");
    GATEWAY.get_or_init(|| gateway).clone()
}

/// A `127.0.0.1:port` → daemon-published `port` forwarder, in-process.
/// Drop stops it (the accept task is aborted; the port frees).
pub struct LocalhostRelay(tokio::task::JoinHandle<()>);

impl Drop for LocalhostRelay {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A container's published port mapped onto our loopback: the port to
/// actually use, plus the forwarder's guard (None on a plain docker host,
/// where the daemon's published ports already answer on `localhost`).
pub struct LocalRelay {
    /// The loopback port to use: the mapped port directly on a plain
    /// host; the forwarder's EPHEMERAL port when relaying, never the
    /// mapped port, so two suites racing through the daemon's recycled
    /// host ports can never collide on our loopback (the second binder
    /// loses when the first test's forwarder still holds it).
    pub local_port: u16,
    /// The forwarder's guard (kept alive by the caller's ownership).
    pub(crate) guard: Option<LocalhostRelay>,
}

/// Map a container's published port onto our loopback. See
/// [`LocalRelay::local_port`] for the port to use.
pub async fn localhost_relay(target_port: u16) -> LocalRelay {
    if !needs_forwarder() {
        return LocalRelay {
            local_port: target_port,
            guard: None,
        };
    }
    let target = join_host_port(&daemon_host().await, target_port);
    let (guard, local_port) = start_forwarder(target).await;
    LocalRelay {
        local_port,
        guard: Some(guard),
    }
}

/// Bind and spawn one forwarder on an ephemeral loopback port. Returns the
/// guard and the bound port. In-process, so the bind IS the listen: no
/// readiness probe is needed (a relay container's process could bind
/// late).
async fn start_forwarder(target: String) -> (LocalhostRelay, u16) {
    // SO_REUSEADDR: docker re-assigns freed ephemeral ports between
    // sequential tests, and a predecessor's TIME_WAIT connections must not
    // fail our bind.
    let socket = tokio::net::TcpSocket::new_v4().expect("relay socket");
    socket.set_reuseaddr(true).expect("relay set_reuseaddr");
    socket
        .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .unwrap_or_else(|e| panic!("localhost relay to {target} failed to bind: {e}"));
    let listener = socket
        .listen(256)
        .unwrap_or_else(|e| panic!("localhost relay to {target} failed to listen: {e}"));
    let local_port = listener.local_addr().expect("relay local addr").port();
    (
        LocalhostRelay(tokio::spawn(forward_loop(listener, target))),
        local_port,
    )
}

/// Accept-and-pump loop for one relay port. A failed outbound connect
/// (the target container not up yet) drops just that connection — the
/// listener keeps serving.
async fn forward_loop(listener: tokio::net::TcpListener, target: String) {
    loop {
        let Ok((mut inbound, _)) = listener.accept().await else {
            return;
        };
        let target = target.clone();
        tokio::spawn(async move {
            if let Ok(mut outbound) = tokio::net::TcpStream::connect(target).await {
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{PublishIp, Topology, publish_ip_for, topology_for};
    use crate::docker::{DaemonAddr, parse_docker_host};

    #[test]
    fn in_container_recognizes_docker_podman_and_k8s() {
        let root = std::env::temp_dir().join(format!("seaworthy-dind-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        assert!(
            !super::in_container_at(&root, false),
            "bare root is not a container"
        );

        std::fs::write(root.join(".dockerenv"), "").expect("dockerenv");
        assert!(super::in_container_at(&root, false), "docker's marker");
        std::fs::remove_file(root.join(".dockerenv")).expect("remove");

        std::fs::create_dir_all(root.join("run")).expect("run dir");
        std::fs::write(root.join("run/.containerenv"), "").expect("containerenv");
        assert!(super::in_container_at(&root, false), "podman's marker");
        std::fs::remove_file(root.join("run/.containerenv")).expect("remove");

        // A Kubernetes pod carries neither marker file.
        assert!(
            super::in_container_at(&root, true),
            "KUBERNETES_SERVICE_HOST"
        );
        std::fs::create_dir_all(root.join("var/run/secrets/kubernetes.io/serviceaccount"))
            .expect("sa dir");
        assert!(
            super::in_container_at(&root, false),
            "the service-account mount"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The decision keys on the DAEMON's location.
    #[test]
    fn topology_matrix() {
        let unix = DaemonAddr::Unix("/var/run/docker.sock".into());
        assert_eq!(topology_for(&unix, false), Topology::PlainHost);
        assert_eq!(topology_for(&unix, true), Topology::SocketMount);
        let none = DaemonAddr::None { tried: vec![] };
        assert_eq!(topology_for(&none, true), Topology::SocketMount);
        // A bare host driving a remote tcp daemon needs the forwarder: a
        // marker-only check would pin publishes to the REMOTE daemon's
        // loopback and dial our own.
        let remote = parse_docker_host("tcp://build-box:2375", false);
        for in_container in [false, true] {
            assert_eq!(
                topology_for(&remote, in_container),
                Topology::Remote {
                    host: "build-box".into()
                }
            );
        }
        // A loopback tcp daemon (a netns-sharing k8s dind sidecar, a local
        // tcp listener) is plain, marker or not, IPv6 literals included.
        for value in [
            "tcp://127.0.0.1:2375",
            "tcp://localhost:2375",
            "tcp://[::1]:2375",
        ] {
            let addr = parse_docker_host(value, false);
            assert_eq!(topology_for(&addr, true), Topology::PlainHost, "{value}");
            assert_eq!(topology_for(&addr, false), Topology::PlainHost, "{value}");
        }
    }

    /// The pure publish decision: socket mode pins the gateway, never all
    /// interfaces; the override wins everywhere.
    #[test]
    fn publish_ip_matrix() {
        let gw = Some("172.17.0.1");
        assert_eq!(
            publish_ip_for(&Topology::PlainHost, gw, None),
            PublishIp::Pinned("127.0.0.1".into())
        );
        assert_eq!(
            publish_ip_for(&Topology::SocketMount, gw, None),
            PublishIp::Pinned("172.17.0.1".into()),
            "socket mode binds the bridge gateway, not 0.0.0.0"
        );
        let remote = Topology::Remote {
            host: "docker".into(),
        };
        assert_eq!(
            publish_ip_for(&remote, None, None),
            PublishIp::AllInterfaces
        );
        let over: IpAddr = "10.1.2.3".parse().expect("ip");
        for topology in [Topology::PlainHost, Topology::SocketMount, remote] {
            assert_eq!(
                publish_ip_for(&topology, gw, Some(over)),
                PublishIp::Pinned("10.1.2.3".into())
            );
        }
    }

    #[test]
    fn gateway_bind_failures_are_recognized() {
        assert!(super::gateway_bind_unavailable(
            "Error starting userland proxy: listen tcp4 172.17.0.1:15556: bind: cannot assign requested address"
        ));
        assert!(!super::gateway_bind_unavailable(
            "Bind for 0.0.0.0:15556 failed: port is already allocated"
        ));
    }

    #[test]
    fn host_port_brackets_ipv6() {
        assert_eq!(super::join_host_port("::1", 2375), "[::1]:2375");
        assert_eq!(super::join_host_port("docker", 2375), "docker:2375");
        assert_eq!(super::join_host_port("10.0.0.1", 80), "10.0.0.1:80");
    }

    #[test]
    fn port_bindings_pin_to_the_chosen_address() {
        for ip in ["127.0.0.1", "172.17.0.1"] {
            let mut host_config = bollard::models::HostConfig {
                port_bindings: Some(std::collections::HashMap::from([
                    (
                        "1025/tcp".to_string(),
                        Some(vec![bollard::models::PortBinding {
                            host_ip: None,
                            host_port: Some("0".to_string()),
                        }]),
                    ),
                    (
                        "8025/tcp".to_string(),
                        Some(vec![bollard::models::PortBinding {
                            host_ip: None,
                            host_port: Some("18025".to_string()),
                        }]),
                    ),
                ])),
                ..Default::default()
            };
            super::publish_modifier(PublishIp::Pinned(ip.into()))(&mut host_config);
            let bindings = host_config.port_bindings.as_ref().expect("bindings");
            for (port, entries) in bindings {
                for entry in entries.iter().flatten() {
                    assert_eq!(entry.host_ip.as_deref(), Some(ip), "{port}");
                }
            }
            // The requested host ports are untouched (0 = ephemeral stays).
            assert_eq!(
                bindings["1025/tcp"].as_ref().expect("entries")[0]
                    .host_port
                    .as_deref(),
                Some("0")
            );
        }
        // AllInterfaces leaves testcontainers' binding alone.
        let mut host_config = bollard::models::HostConfig {
            port_bindings: Some(std::collections::HashMap::from([(
                "1/tcp".to_string(),
                Some(vec![bollard::models::PortBinding {
                    host_ip: None,
                    host_port: Some("0".to_string()),
                }]),
            )])),
            ..Default::default()
        };
        super::publish_modifier(PublishIp::AllInterfaces)(&mut host_config);
        assert_eq!(
            host_config.port_bindings.expect("b")["1/tcp"]
                .as_ref()
                .expect("e")[0]
                .host_ip,
            None
        );
    }

    #[test]
    fn port_bindings_pin_tolerates_empty_maps() {
        // No explicit bindings at all (the publish-all shape): nothing to
        // rewrite, no panic.
        let mut host_config = bollard::models::HostConfig::default();
        super::pin_port_bindings(&mut host_config, "127.0.0.1");
        assert!(host_config.port_bindings.is_none());
    }
}
