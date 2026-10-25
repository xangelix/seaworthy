//! # seaworthy-test-support
//!
//! Docker-backed integration-test harness for seaworthy's own suites, on
//! [testcontainers](https://crates.io/crates/testcontainers): real services
//! for the seams the in-process suites cannot cover. [`rustfs`] is an
//! S3-compatible store for the publisher, and [`systemd`] runs containers
//! booting systemd as PID 1 on each supported distribution, for the Linux
//! package conformance lane. Unpublished (`publish = false`): a
//! dev-dependency of seaworthy's crates, never a runtime one.
//!
//! **Skip semantics (three-state, [`docker`]):** every suite starts with
//! [`docker_or_skip`], which resolves the daemon exactly as testcontainers
//! does, pings it, and classifies the answer. No daemon at all → skip
//! (announced on stderr). A daemon/socket that EXISTS but is unusable
//! (EACCES, a stale socket, a wedged daemon, an unsupported `DOCKER_HOST`)
//! → a loud failure naming the cause, never a skip.
//! `SEAWORTHY_TEST_CONTAINERS_REQUIRED=1` fails on any unavailability (CI);
//! `=0` skips on any (the escape hatch). The harness itself builds
//! everywhere; no docker socket is needed to COMPILE. On Windows the crate
//! is empty: the harness is unix-only, and so are the suites using it.
//!
//! **Publish address and cleanup ([`dind`], [`launch`]):** every container
//! publishes on the topology's address (loopback on a plain host, the
//! bridge gateway when a host socket is mounted into the test container,
//! never the host's LAN interfaces), carries owner labels, and is swept by
//! the next process if its owner was SIGKILLed.
//!
//! Image versions are pinned in [`images`] as `name:tag@sha256:…` digest
//! references of public images (latest stable at pin time, never a
//! floating tag: a tag alone is mutable upstream, and a re-tagged image
//! runs with daemon access).
//!
//! **Image pulls ([`pull`], [`prepull`]):** every launch first makes its
//! pinned image present, retrying TRANSIENT registry failures (rate
//! limits, 5xx, resets, timeouts, truncated downloads) with bounded,
//! jittered backoff before the test body runs: a registry hiccup is never
//! a test failure. Auth, missing-manifest and digest failures are never
//! retried. `scripts/pull-test-images.sh` warms the daemon serially from
//! [`images::ALL`]'s `Suites` group before the suites run; the systemd
//! hosts and the builder image are pulled only when named.
//!
//! ```no_run
//! # #[cfg(unix)]
//! # async fn suite() {
//! if !seaworthy_test_support::docker_or_skip().await {
//!     return; // no daemon here: skipped, announced on stderr
//! }
//! let store = seaworthy_test_support::rustfs::start_rustfs("acme-artifacts").await;
//! // … an S3 client against `store.endpoint_url`, bucket `store.bucket` …
//! # drop(store);
//! # }
//! ```

// A test harness: a failure to start a container, or a broken fixture, is
// a test failure, so the harness panics with the cause named (the
// documented contract of `docker_or_skip`, `launch::start` and the
// builders) instead of handing every suite an error to unwrap.
#![cfg_attr(
    unix,
    allow(
        clippy::panic,
        clippy::expect_used,
        reason = "a test harness: a failed container start or a broken fixture is a test \
                  failure, reported by panicking with the cause named"
    )
)]
#![forbid(unsafe_code)]

#[cfg(unix)]
pub mod dind;
#[cfg(unix)]
pub mod docker;
#[cfg(unix)]
pub mod images;
#[cfg(unix)]
pub mod launch;
#[cfg(unix)]
pub mod prepull;
#[cfg(unix)]
pub mod pull;
#[cfg(unix)]
pub mod rustfs;
#[cfg(unix)]
pub mod systemd;

#[cfg(unix)]
pub use docker::{
    Probe, RequiredMode, assert_suite_compiled_in, docker_available, docker_or_skip, probe,
    required, required_mode,
};

/// The environment variable of the skip contract ([`docker`]):
/// `SEAWORTHY_TEST_CONTAINERS_REQUIRED`.
pub const REQUIRED_ENV: &str = "SEAWORTHY_TEST_CONTAINERS_REQUIRED";

/// Split a pinned reference into `(name, tag)`:
/// - `name:tag` splits at the LAST colon (registry hosts carry ports:
///   `registry.example:5000/app:v1.0.0` splits right);
/// - the digest-pinned `name:tag@sha256:…` form splits at the `@`, the tag
///   slice running THROUGH the digest (`tag@digest` is one contiguous
///   slice), so the reassembled `{name}:{tag}` descriptor is the valid
///   `name:tag@sha256:…` reference docker pulls by digest.
#[cfg(unix)]
fn split_image(image: &str) -> (&str, &str) {
    if let Some(at) = image.find('@') {
        let named = &image[..at];
        let (name, _) = named
            .rsplit_once(':')
            .unwrap_or_else(|| panic!("pinned image reference {image:?} has no tag"));
        return (name, &image[name.len() + 1..]);
    }
    image
        .rsplit_once(':')
        .unwrap_or_else(|| panic!("pinned image reference {image:?} has no tag"))
}

#[cfg(all(test, unix))]
mod tests {
    use crate::dind::{PublishIp, Topology};

    /// Every published binding of `id` sits on the topology's address.
    async fn assert_published_on_topology_address(id: &str, expected: &PublishIp) {
        let docker = crate::docker::connect();
        let inspect = docker
            .inspect_container(
                id,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await
            .expect("inspect");
        let bindings = inspect
            .host_config
            .expect("host_config")
            .port_bindings
            .expect("port_bindings: every published port is an explicit binding");
        assert!(!bindings.is_empty(), "{id} publishes nothing");
        for (port, entries) in &bindings {
            for entry in entries.iter().flatten() {
                let host_ip = entry.host_ip.as_deref().unwrap_or("");
                match expected {
                    PublishIp::Pinned(ip) => assert_eq!(
                        host_ip, ip,
                        "{id} {port}: must publish on {ip} only, got {host_ip:?}"
                    ),
                    PublishIp::AllInterfaces => assert!(
                        matches!(crate::dind::topology(), Topology::Remote { .. })
                            || std::env::var(crate::dind::PUBLISH_IP_ENV).is_ok(),
                        "{id} {port}: an all-interfaces publish is only legitimate for a \
                         remote tcp:// daemon (or the loud Desktop fallback)"
                    ),
                }
                assert!(
                    !matches!(expected, PublishIp::Pinned(_))
                        || (host_ip != "0.0.0.0" && host_ip != "::" && !host_ip.is_empty()),
                    "{id} {port}: wildcard publish {host_ip:?}"
                );
            }
        }
        // Resolved side: the daemon's actual listeners match too (no `[::]`).
        let ports = inspect
            .network_settings
            .and_then(|n| n.ports)
            .unwrap_or_default();
        if let PublishIp::Pinned(ip) = expected {
            for (port, entries) in ports {
                for entry in entries.into_iter().flatten() {
                    assert_eq!(
                        entry.host_ip.as_deref(),
                        Some(ip.as_str()),
                        "{id} {port}: resolved listener"
                    );
                }
            }
        }
    }

    /// Every builder publishes on the topology's address: in socket-mount
    /// mode the bridge gateway, never `0.0.0.0`/`[::]`; on a plain host
    /// loopback; the pure matrix (`dind::tests::publish_ip_matrix`) pins
    /// the rows no available host exercises. Skips without a daemon.
    #[tokio::test]
    async fn every_builder_publishes_on_the_topology_address() {
        if !crate::docker_or_skip().await {
            return;
        }
        let expected = crate::dind::publish_ip().await;
        eprintln!(
            "topology {:?}, publishing on {expected:?}",
            crate::dind::topology()
        );
        let rustfs = crate::rustfs::start_rustfs("publish-check").await;
        for id in &rustfs.container_ids() {
            assert_published_on_topology_address(id, &expected).await;
        }
    }

    /// A container labeled with a DEAD same-namespace owner (and a
    /// `Created`-state one, the failed-start litter shape) is swept; one we
    /// own survives; a foreign-namespace young one survives; one past the
    /// ceiling is swept.
    #[tokio::test]
    async fn the_leak_sweep_removes_dead_owners_only() {
        use crate::launch::{
            LABEL_CREATED, LABEL_OWNER_HOST, LABEL_OWNER_PID, LABEL_OWNER_PIDNS, LABEL_OWNER_START,
            Owner,
        };
        use testcontainers::{
            GenericImage,
            core::{ImageExt as _, WaitFor},
        };
        if !crate::docker_or_skip().await {
            return;
        }
        // Ours (live): also guarantees the image is local.
        let (name, tag) = crate::split_image(crate::images::DEBIAN_13);
        let ours = crate::launch::start("sweep-live", None, &[], || {
            GenericImage::new(name, tag)
                .with_wait_for(WaitFor::Nothing)
                .with_cmd(["true"])
        })
        .await;

        let me = Owner::me();
        let docker = crate::docker::connect();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let create = |suffix: &str, pid: &str, pidns: &str, created: u64| {
            let name = format!("seaworthy-tc-sweep-{suffix}-{}", std::process::id());
            let labels = std::collections::HashMap::from([
                (LABEL_OWNER_PID.to_string(), pid.to_string()),
                (LABEL_OWNER_START.to_string(), "1".to_string()),
                (LABEL_OWNER_PIDNS.to_string(), pidns.to_string()),
                (LABEL_OWNER_HOST.to_string(), me.host.clone()),
                (LABEL_CREATED.to_string(), created.to_string()),
            ]);
            let docker = docker.clone();
            async move {
                let _ = docker
                    .remove_container(
                        &name,
                        Some(
                            bollard::query_parameters::RemoveContainerOptionsBuilder::default()
                                .force(true)
                                .build(),
                        ),
                    )
                    .await;
                docker
                    .create_container(
                        Some(bollard::query_parameters::CreateContainerOptions {
                            name: Some(name.clone()),
                            ..Default::default()
                        }),
                        bollard::models::ContainerCreateBody {
                            image: Some(crate::images::DEBIAN_13.to_string()),
                            cmd: Some(vec!["true".to_string()]),
                            labels: Some(labels),
                            ..Default::default()
                        },
                    )
                    .await
                    .expect("create probe container");
                name
            }
        };
        // pid 4_000_000_000 exceeds any pid_max: definitely dead.
        let dead = create("dead", "4000000000", &me.pidns, now).await;
        let foreign = create("foreign", "4000000000", "1", now).await;
        let ancient = create("ancient", "4000000000", "1", now - 7200).await;

        let removed = crate::launch::sweep().await;
        let exists = |name: String| {
            let docker = docker.clone();
            async move {
                docker
                    .inspect_container(
                        &name,
                        None::<bollard::query_parameters::InspectContainerOptions>,
                    )
                    .await
                    .is_ok()
            }
        };
        assert!(removed.contains(&dead), "dead owner swept: {removed:?}");
        assert!(!exists(dead).await);
        assert!(removed.contains(&ancient), "ceiling: {removed:?}");
        assert!(
            exists(ours.id().to_string()).await,
            "our own container survives"
        );
        assert!(
            exists(foreign.clone()).await,
            "a young foreign-namespace one survives"
        );
        let _ = docker
            .remove_container(
                &foreign,
                Some(
                    bollard::query_parameters::RemoveContainerOptionsBuilder::default()
                        .force(true)
                        .build(),
                ),
            )
            .await;
    }

    /// Every launch makes its image present through `pull::ensure_image`
    /// BEFORE anything is created, which is where a transient pull failure
    /// is retried. The observable proof: a launch of an UNPINNED image
    /// (debian by its bare tag) is refused by the pin check, and no
    /// container was created. Without the call, testcontainers would
    /// happily start (or pull) the floating tag.
    #[tokio::test]
    async fn every_launch_ensures_its_pinned_image_first() {
        use testcontainers::{
            GenericImage,
            core::{ImageExt as _, WaitFor},
        };
        if !crate::docker_or_skip().await {
            return;
        }
        let (name, pinned_tag) = crate::split_image(crate::images::DEBIAN_13);
        let floating = pinned_tag
            .split_once('@')
            .map_or(pinned_tag, |(tag, _)| tag);
        let err = match crate::launch::try_start("unpinned", None, &[], || {
            GenericImage::new(name, floating)
                .with_wait_for(WaitFor::Nothing)
                .with_cmd(["true"])
        })
        .await
        {
            Ok(_) => panic!("{name}:{floating} is not digest-pinned and must be refused"),
            Err(e) => e,
        };
        assert!(
            err.contains("refusing to pull") && err.contains("digest pin"),
            "{err}"
        );
        let options = bollard::query_parameters::ListContainersOptions {
            all: true,
            filters: Some(std::collections::HashMap::from([(
                "name".to_string(),
                vec![format!("seaworthy-tc-unpinned-{}-", std::process::id())],
            )])),
            ..Default::default()
        };
        let created = crate::docker::connect()
            .list_containers(Some(options))
            .await
            .expect("list");
        assert!(created.is_empty(), "a refused launch created {created:?}");
    }

    /// A fixed-port collision names the container holding the port (the
    /// daemon says only "port is already allocated"), and the failed start
    /// leaves no `Created` litter behind.
    #[tokio::test]
    async fn a_fixed_port_collision_names_the_holder_and_leaves_no_litter() {
        use testcontainers::{
            GenericImage,
            core::{ContainerPort, ImageExt as _, WaitFor},
        };
        if !crate::docker_or_skip().await {
            return;
        }
        const PORT: u16 = 15592;
        let (name, tag) = crate::split_image(crate::images::DEBIAN_13);
        // The daemon allocates a published host port at start, whether or
        // not anything in the container listens on it: a sleeping
        // container holds it.
        let build = || {
            GenericImage::new(name, tag)
                .with_wait_for(WaitFor::Nothing)
                .with_mapped_port(PORT, ContainerPort::Tcp(PORT))
                .with_cmd(["sleep", "300"])
        };
        let holder = crate::launch::start("collide-holder", None, &[PORT], build).await;
        let holder_name = holder.id().to_string();
        let err = match crate::launch::try_start("collide-loser", None, &[PORT], build).await {
            Ok(_) => panic!("the second fixed-port start must collide"),
            Err(e) => e,
        };
        let docker = crate::docker::connect();
        let holder_inspect = docker
            .inspect_container(
                &holder_name,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await
            .expect("inspect holder");
        let holder_display = holder_inspect
            .name
            .expect("name")
            .trim_start_matches('/')
            .to_string();
        assert!(err.contains(&holder_display), "names the holder: {err}");
        // No litter: nothing named collide-loser remains.
        let options = bollard::query_parameters::ListContainersOptions {
            all: true,
            filters: Some(std::collections::HashMap::from([(
                "name".to_string(),
                vec![format!(
                    "seaworthy-tc-collide-loser-{}-",
                    std::process::id()
                )],
            )])),
            ..Default::default()
        };
        let litter = docker.list_containers(Some(options)).await.expect("list");
        assert!(litter.is_empty(), "failed start left litter: {litter:?}");
    }
}
