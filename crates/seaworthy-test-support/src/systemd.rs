//! Containers that boot **systemd as PID 1**, one per supported
//! distribution: the Linux conformance lane's hosts (the seaworthy CLI's
//! `conformance` suite), where real packages are installed by the
//! distribution's own package manager and their units run under the
//! distribution's own systemd.
//!
//! Each [`Distro`] starts from its digest-pinned image ([`crate::images`]).
//! The first [`start`] on a daemon **provisions** it (systemd where the
//! image lacks it; the lane's repositories are built outside, by the CLI,
//! so no host needs a repository tool) and commits the result to a local
//! image tagged with a hash of the pin, the provisioning script, the
//! masked units and the committed settings
//! (`seaworthy-tc-systemd/<distro>:<hash>`), so later starts reuse it and
//! any change provisions afresh; older tags of that distribution are
//! removed.
//! Provisioning needs the distribution's package mirrors, and installs
//! what they serve that day (only the base image is pinned): the reports
//! record each host's systemd version.
//!
//! # Containment
//!
//! A systemd booted in a **privileged** container reaches the host: its
//! `systemd-sysctl` writes the distribution's kernel parameters into the
//! host's global `/proc/sys` (`kernel.core_pattern`,
//! `kernel.yama.ptrace_scope`, `kernel.sysrq`, …), udev coldplug triggers
//! events on the host's devices, gettys open its consoles. A review proved
//! it, through docker-in-docker too: dind shares the runner's kernel. So
//! hosts never boot privileged:
//!
//! - the container gets only `CAP_SYS_ADMIN` (systemd's mount namespaces,
//!   what service sandboxing needs) on top of docker's defaults; `/proc/sys`
//!   and `/sys` stay read-only and `/dev` holds the container's own minimal
//!   set, no host device;
//! - its entrypoint remounts the container's own cgroup mount read-write
//!   (in a private cgroup namespace it shows only the container's subtree)
//!   and then runs systemd;
//! - provisioning masks every unit that exists to touch hardware or kernel
//!   state ([`MASKED`]), and [`start`] checks the containment held: the
//!   container isn't privileged, `/proc/sys` refuses a write, those units
//!   are masked.
//!
//! The daemon must use cgroup v2 (systemd 255+ refuses v1): checked first.
//!
//! What provisioning undoes, so a container behaves like a host:
//!
//! - Debian's and Ubuntu's images carry `/usr/sbin/policy-rc.d` exiting
//!   101 (no daemon starts during `docker build`). A real host has none,
//!   and packages honour it (the CLI's package scripts do): removed.
//! - Arch's enables systemd-networkd, whose wait-online holds
//!   `network-online.target` for two minutes when no link is its to manage
//!   (docker provides the network): masked.

use std::collections::HashMap;
use std::time::Duration;

use testcontainers::core::{CgroupnsMode, ExecCommand, Mount};
use testcontainers::{ContainerAsync, CopyDataSource, GenericImage, ImageExt as _};

use crate::{images, split_image};

/// The package family a distribution installs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// dpkg and apt.
    Deb,
    /// rpm and dnf.
    Rpm,
    /// pacman.
    Pacman,
}

/// A distribution the conformance lane runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Distro {
    /// Debian 13 (trixie).
    Debian13,
    /// Ubuntu 24.04 LTS.
    Ubuntu2404,
    /// Red Hat Universal Base Image 9, init flavour (RHEL 9's systemd 252
    /// and rpm 4.16).
    Ubi9,
    /// Fedora 43.
    Fedora43,
    /// Arch Linux (rolling; the pin's dated tag).
    Arch,
}

/// Units masked on every host: each exists to touch hardware or kernel
/// state, which a container must never reach (see the module docs), or
/// can't work in one at all.
pub const MASKED: &[&str] = &[
    "systemd-sysctl.service",
    "systemd-udevd.service",
    "systemd-udevd-control.socket",
    "systemd-udevd-kernel.socket",
    "systemd-udev-trigger.service",
    "systemd-udev-settle.service",
    "systemd-modules-load.service",
    "systemd-binfmt.service",
    "proc-sys-fs-binfmt_misc.automount",
    "proc-sys-fs-binfmt_misc.mount",
    "systemd-firstboot.service",
    "systemd-timesyncd.service",
    "systemd-rfkill.service",
    "systemd-rfkill.socket",
    "systemd-pstore.service",
    "systemd-hwdb-update.service",
    "systemd-remount-fs.service",
    "systemd-backlight@.service",
    "getty.target",
    "console-getty.service",
    "serial-getty@.service",
];

/// The image settings provisioning commits: an entrypoint that makes the
/// container's own cgroup mount writable and runs systemd, no arguments,
/// the signal systemd halts on, and the variable it reads to know it runs
/// in a container.
const COMMIT_CHANGES: &str = "ENTRYPOINT [\"/bin/sh\", \"-c\", \"mount -o remount,bind,rw /sys/fs/cgroup && exec /usr/lib/systemd/systemd\"]\nCMD []\nSTOPSIGNAL SIGRTMIN+3\nENV container=docker";

impl Distro {
    /// Every distribution, in report order.
    pub const ALL: [Self; 5] = [
        Self::Debian13,
        Self::Ubuntu2404,
        Self::Ubi9,
        Self::Fedora43,
        Self::Arch,
    ];

    /// Its short name (`debian-13`), for container names and reports.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Debian13 => "debian-13",
            Self::Ubuntu2404 => "ubuntu-24.04",
            Self::Ubi9 => "ubi-9",
            Self::Fedora43 => "fedora-43",
            Self::Arch => "arch",
        }
    }

    /// Its pinned image.
    #[must_use]
    pub fn image(self) -> &'static str {
        match self {
            Self::Debian13 => images::DEBIAN_13,
            Self::Ubuntu2404 => images::UBUNTU_2404,
            Self::Ubi9 => images::UBI9_INIT,
            Self::Fedora43 => images::FEDORA_43,
            Self::Arch => images::ARCH,
        }
    }

    /// Its package family.
    #[must_use]
    pub fn family(self) -> Family {
        match self {
            Self::Debian13 | Self::Ubuntu2404 => Family::Deb,
            Self::Ubi9 | Self::Fedora43 => Family::Rpm,
            Self::Arch => Family::Pacman,
        }
    }

    /// The distribution's own provisioning (before [`MASKED`] is applied).
    /// Every host has a CA store, as every real one does: the update
    /// helper's TLS client loads it (the platform verifier) before any
    /// request, the lane's loopback ones included. The Debian and Ubuntu
    /// images ship without one. Debian and Ubuntu also get needrestart,
    /// set to restart services by itself (as fleets often run it, and
    /// Ubuntu's noninteractive default leans to): after an upgrade it
    /// restarts every service still running a replaced binary — the update
    /// helper running that very upgrade included, unless the helper
    /// suspends it (`NEEDRESTART_SUSPEND=1`).
    ///
    /// Every host also has polkit and `pam_systemd`, as every desktop does:
    /// a desktop product's package depends on polkit, and the lane checks
    /// the rule letting a logged-in session start its update helper from a
    /// real logind session. Debian's and Ubuntu's `polkitd` pulls
    /// `libpam-systemd`; Fedora's and UBI's systemd carries
    /// `systemd-pam`, Arch's its own module. Arch upgrades as it installs
    /// (`-Syu`): a partial upgrade is unsupported there.
    #[must_use]
    pub fn provisioning(self) -> &'static str {
        match self {
            Self::Debian13 | Self::Ubuntu2404 => {
                "export DEBIAN_FRONTEND=noninteractive\n\
                 apt-get update -qq\n\
                 apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus ca-certificates needrestart polkitd libpam-systemd >/dev/null\n\
                 mkdir -p /etc/needrestart/conf.d\n\
                 echo \"\\$nrconf{restart} = 'a';\" > /etc/needrestart/conf.d/50-conformance.conf\n\
                 rm -f /usr/sbin/policy-rc.d\n\
                 apt-get clean\n\
                 rm -rf /var/lib/apt/lists/*\n"
            }
            // The image already runs systemd.
            Self::Ubi9 => "dnf install -y -q polkit >/dev/null\ndnf clean all >/dev/null\n",
            Self::Fedora43 => {
                "dnf install -y -q systemd polkit >/dev/null\ndnf clean all >/dev/null\n"
            }
            // The image enables systemd-networkd, whose wait-online holds
            // network-online.target for two minutes in a container with no
            // links it manages (docker provides the network): masked, as
            // a host with managed links wouldn't wait.
            Self::Arch => {
                "pacman-key --init >/dev/null 2>&1\n\
                 pacman-key --populate archlinux >/dev/null 2>&1\n\
                 pacman -Syu --noconfirm --needed polkit >/dev/null\n\
                 rm -rf /var/cache/pacman/pkg/*\n\
                 ln -sf /dev/null /etc/systemd/system/systemd-networkd-wait-online.service\n"
            }
        }
    }

    /// The whole provisioning script: the distribution's, then [`MASKED`].
    #[must_use]
    pub fn provisioning_script(self) -> String {
        let mut script = format!(
            "set -e\n{}mkdir -p /etc/systemd/system\n",
            self.provisioning()
        );
        for unit in MASKED {
            script.push_str(&format!("ln -sf /dev/null /etc/systemd/system/{unit}\n"));
        }
        script
    }

    /// The local image provisioning commits: `(repository, tag)`, the tag
    /// a hash of the pin, the script and the image settings committed.
    #[must_use]
    pub fn provisioned_image(self) -> (String, String) {
        let digest = seaworthy_crypto::digest::sha256_hex(
            format!(
                "{}\n{}\n{COMMIT_CHANGES}",
                self.image(),
                self.provisioning_script()
            )
            .as_bytes(),
        );
        (
            format!("seaworthy-tc-systemd/{}", self.name()),
            digest.get(..16).unwrap_or_default().to_owned(),
        )
    }
}

/// What a command in a host printed, and how it exited.
#[derive(Debug, Clone)]
pub struct Output {
    /// The exit code (`None` when the daemon didn't report one).
    pub code: Option<i64>,
    /// Its standard output.
    pub stdout: String,
    /// Its standard error.
    pub stderr: String,
}

/// A running container with systemd as PID 1.
pub struct SystemdHost {
    container: ContainerAsync<GenericImage>,
    distro: Distro,
}

impl std::fmt::Debug for SystemdHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemdHost")
            .field("distro", &self.distro)
            .field("id", &self.container.id())
            .finish()
    }
}

/// Runs `script` with `sh -c` in the container, under root's usual umask
/// (022). An exec'd process inherits the daemon's umask, and some CI
/// docker-in-docker services run it at 0000: a directory a test created was
/// world-writable there (mode 777) and 755 on a workstation, so the lane
/// behaved differently in CI. The update helper's policy reader rightly
/// refuses a world-writable configuration directory.
async fn exec(container: &ContainerAsync<GenericImage>, script: &str) -> Output {
    let script = format!("umask 022\n{script}");
    let mut result = container
        .exec(ExecCommand::new(["sh", "-c", script.as_str()]))
        .await
        .unwrap_or_else(|e| {
            panic!("seaworthy-test-support: systemd: the exec could not start: {e}")
        });
    let stdout =
        String::from_utf8_lossy(&result.stdout_to_vec().await.unwrap_or_default()).into_owned();
    let stderr =
        String::from_utf8_lossy(&result.stderr_to_vec().await.unwrap_or_default()).into_owned();
    Output {
        code: result.exit_code().await.ok().flatten(),
        stdout,
        stderr,
    }
}

impl SystemdHost {
    /// The distribution it runs.
    #[must_use]
    pub fn distro(&self) -> Distro {
        self.distro
    }

    /// Runs `script` with `sh -c` as root; never panics on its exit code.
    pub async fn sh(&self, script: &str) -> Output {
        exec(&self.container, script).await
    }

    /// Runs `script`, which must exit 0; its stdout. Panics with both
    /// streams otherwise.
    pub async fn ok(&self, script: &str) -> String {
        let output = self.sh(script).await;
        assert_eq!(
            output.code,
            Some(0),
            "{}: `{script}` exited {:?}\nstdout:\n{}\nstderr:\n{}",
            self.distro.name(),
            output.code,
            output.stdout,
            output.stderr
        );
        output.stdout
    }

    /// The container's own log (systemd's console output), for messages.
    async fn log(&self) -> String {
        let stdout = self.container.stdout_to_vec().await.unwrap_or_default();
        let stderr = self.container.stderr_to_vec().await.unwrap_or_default();
        format!(
            "{}{}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        )
    }
}

/// Refuses a daemon on cgroup v1: systemd 255 and later (four of the five
/// hosts) won't boot there, and the failure would only say "didn't finish
/// booting".
async fn require_cgroup_v2(docker: &bollard::Docker) {
    use bollard::models::SystemInfoCgroupVersionEnum as V;
    let info = docker
        .info()
        .await
        .unwrap_or_else(|e| panic!("seaworthy-test-support: systemd: docker info: {e}"));
    assert!(
        matches!(info.cgroup_version, Some(V::_2)),
        "seaworthy-test-support: systemd: the docker daemon uses cgroup {:?}; systemd hosts \
         need cgroup v2",
        info.cgroup_version
    );
}

/// Makes sure the daemon holds `distro`'s provisioned image, provisioning
/// it from the pinned image when it doesn't, and removes the distribution's
/// older provisioned images. Returns the image's ID (`sha256:…`): the host
/// starts by ID, so a missing local image can never become a registry pull.
async fn provisioned(docker: &bollard::Docker, distro: Distro) -> String {
    let (repository, tag) = distro.provisioned_image();
    let reference = format!("{repository}:{tag}");
    if let Ok(image) = docker.inspect_image(&reference).await
        && let Some(id) = image.id
    {
        return id;
    }
    eprintln!(
        "seaworthy-test-support: systemd: provisioning {} from {} (once per daemon)",
        distro.name(),
        distro.image()
    );
    let (name, image_tag) = split_image(distro.image());
    let builder = crate::launch::start(&format!("provision-{}", distro.name()), None, &[], || {
        GenericImage::new(name, image_tag)
            .with_entrypoint("sleep")
            .with_cmd(["infinity"])
    })
    .await;
    let output = exec(&builder, &distro.provisioning_script()).await;
    assert_eq!(
        output.code,
        Some(0),
        "seaworthy-test-support: systemd: provisioning {} failed\nstdout:\n{}\nstderr:\n{}",
        distro.name(),
        output.stdout,
        output.stderr
    );
    let options = bollard::query_parameters::CommitContainerOptionsBuilder::new()
        .container(builder.id())
        .repo(&repository)
        .tag(&tag)
        .comment("seaworthy-test-support systemd provisioning")
        .changes(COMMIT_CHANGES)
        .build();
    let committed = docker
        .commit_container(options, bollard::models::ContainerConfig::default())
        .await
        .unwrap_or_else(|e| {
            panic!(
                "seaworthy-test-support: systemd: committing {} failed: {e}",
                distro.name()
            )
        });
    drop(builder);
    // Older provisioned images of this distribution (a changed pin or
    // script) would only pile up: removed. One still used by a running
    // host stays (the daemon refuses without force).
    let filter = bollard::query_parameters::ListImagesOptions {
        filters: Some(HashMap::from([(
            "reference".to_owned(),
            vec![repository.clone()],
        )])),
        ..Default::default()
    };
    if let Ok(images) = docker.list_images(Some(filter)).await {
        for image in images {
            if image.id != committed.id {
                let _ = docker
                    .remove_image(
                        &image.id,
                        None::<bollard::query_parameters::RemoveImageOptions>,
                        None,
                    )
                    .await;
            }
        }
    }
    committed.id
}

/// Boots `distro` with systemd as PID 1, `files` (`(path, bytes)`) copied
/// in first, waits for the boot to finish and checks the containment (the
/// module docs). CALL `docker_or_skip` first.
pub async fn start(distro: Distro, files: &[(String, Vec<u8>)]) -> SystemdHost {
    let docker = crate::docker::connect();
    require_cgroup_v2(&docker).await;
    let id = provisioned(&docker, distro).await;
    let (name, digest) = id
        .split_once(':')
        .unwrap_or_else(|| panic!("seaworthy-test-support: systemd: an image id {id:?}"));
    let role = format!("systemd-{}", distro.name());
    let container = crate::launch::start_local(&role, || {
        // The committed image runs systemd (COMMIT_CHANGES). Never
        // privileged: only CAP_SYS_ADMIN, for systemd's namespaces and the
        // entrypoint's remount of the container's own cgroup.
        let mut request = GenericImage::new(name, digest)
            .with_cap_add("SYS_ADMIN")
            .with_cgroupns_mode(CgroupnsMode::Private)
            .with_mount(Mount::tmpfs_mount("/run"))
            .with_mount(Mount::tmpfs_mount("/run/lock"))
            .with_mount(Mount::tmpfs_mount("/tmp"))
            .with_startup_timeout(Duration::from_secs(120));
        for (path, bytes) in files {
            request = request.with_copy_to(path.clone(), CopyDataSource::Data(bytes.clone()));
        }
        request
    })
    .await;
    let host = SystemdHost { container, distro };
    // `degraded` is normal in a container (units for hardware it lacks).
    // systemctl can't reach systemd until its bus socket exists; then
    // `--wait` blocks until the boot has finished.
    let output = host
        .sh("for i in $(seq 1 240); do \
               state=$(systemctl is-system-running --wait 2>/dev/null); \
               case \"$state\" in running|degraded) echo \"$state\"; exit 0 ;; esac; sleep 0.5; \
             done; systemctl is-system-running")
        .await;
    let state = output.stdout.trim().to_owned();
    if !matches!(state.as_str(), "running" | "degraded") {
        panic!(
            "{}: systemd didn't finish booting (state {state:?}): {}\ncontainer log:\n{}",
            distro.name(),
            output.stderr.trim(),
            host.log().await
        );
    }
    check_containment(&docker, &host).await;
    host
}

/// The containment the module docs promise, checked on the running host.
async fn check_containment(docker: &bollard::Docker, host: &SystemdHost) {
    let name = host.distro.name();
    let inspect = docker
        .inspect_container(
            host.container.id(),
            None::<bollard::query_parameters::InspectContainerOptions>,
        )
        .await
        .unwrap_or_else(|e| panic!("{name}: inspecting the host: {e}"));
    let privileged = inspect
        .host_config
        .and_then(|h| h.privileged)
        .unwrap_or(false);
    assert!(
        !privileged,
        "{name}: a systemd host must never be privileged"
    );
    let write = host.sh("echo 1 > /proc/sys/kernel/sysrq").await;
    assert_ne!(
        write.code,
        Some(0),
        "{name}: /proc/sys took a write: the host's kernel parameters are reachable"
    );
    let units = MASKED.join(" ");
    let states = host
        .ok(&format!("systemctl is-enabled {units} 2>/dev/null || true"))
        .await;
    for (unit, state) in MASKED.iter().zip(states.lines()) {
        assert_eq!(
            state.trim(),
            "masked",
            "{name}: {unit} isn't masked ({state})"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_distro_has_a_pin_a_family_and_a_distinct_image() {
        let mut tags = std::collections::BTreeSet::new();
        for distro in Distro::ALL {
            images::validate_pin(distro.image()).unwrap();
            let (repository, tag) = distro.provisioned_image();
            assert!(repository.starts_with("seaworthy-tc-systemd/"));
            assert_eq!(tag.len(), 16);
            assert!(tags.insert(repository));
        }
    }

    #[test]
    fn provisioning_masks_every_host_facing_unit() {
        for distro in Distro::ALL {
            let script = distro.provisioning_script();
            assert!(script.starts_with("set -e\n"));
            for unit in MASKED {
                assert!(
                    script.contains(&format!("ln -sf /dev/null /etc/systemd/system/{unit}\n")),
                    "{}: {unit}",
                    distro.name()
                );
            }
        }
        assert!(MASKED.contains(&"systemd-sysctl.service"));
        assert!(MASKED.contains(&"systemd-udev-trigger.service"));
    }
}
