//! The Linux conformance lane: `seaworthy`'s
//! packages, built from a real product by `scripts/linux-conformance.sh
//! build`, installed by each distribution's own package manager in a
//! container running systemd as PID 1 (`seaworthy_test_support::systemd`).
//!
//! Per distribution, from the lane's published repositories (the
//! signed APT, DNF and pacman repositories `seaworthy repo` builds,
//! fetched over HTTP from the lane's server as clients fetch the store, each
//! client set up as an administrator sets it up). apt and dnf are set up by
//! installing the repository package from the publication's `setup/` (a
//! deb822 source with `Signed-By:` its own keyring, a `.repo` with
//! `gpgcheck` and `repo_gpgcheck`; the rpm installed from its URL after
//! `rpm --import` of the published key, as the README says). pacman is set
//! up by hand (its section with `SigLevel = Required`, the key locally
//! signed). The releases rotate the OpenPGP key as the README says: v1
//! pins one key; v2 pins it and the next, still signed by the first, so
//! its repository package carries both; v3 is signed by the next key —
//! which the hosts trust only through that package's upgrade (Arch: the
//! administrator adds it). The repositories hold the latest release only, as
//! published ones do, so an older release goes in from its own file
//! (`localpkg_gpgcheck` and `LocalFileSigLevel = Required` still check an
//! rpm's and a pacman package's signature; a deb has none, and apt checks
//! nothing about a file):
//!
//! 0. **foreign signatures** — an rpm or pacman package signed by a key the
//!    host doesn't trust is refused by the package manager (and by `rpm -K`
//!    and `pacman-key --verify`), and repositories whose indexes such a key
//!    signed are refused by apt, dnf and pacman alike (nothing installable
//!    from them; the same repositories signed by the trusted key read
//!    fine; Fedora's dnf5 skips such a repository, exit 0, as its
//!    `skip_if_unavailable=True` default says, still naming the
//!    signature);
//! 1. **install v1** — the service and the helper's path unit enabled by the
//!    vendor preset and running; the service as its sandbox user, its state
//!    directory 0700 and the user's; the tree root's; the service's settings
//!    exactly as rendered; `systemd-analyze security` below 1.5 for the
//!    service (below 4.0 for the root helper; 3.8 today) and `verify` silent on systemd
//!    254+; then (step 1b, the launcher fixture's lane) **a desktop
//!    product** installed from the same repository: `/usr/bin/<command>`
//!    resolves to its launcher and runs a core through the link, its menu
//!    entry and icons are where the packages put them (0644), its data files
//!    too; its update helper's unit and polkit rule: the unit
//!    `static`, never started by the package, and polkit's verdicts for a
//!    regular user — from a seatless logind session (`pam_systemd`) and
//!    from none, everything is refused (polkit counts only a session with a
//!    seat as local; seaworthy_service's rule test evaluates the grant), and the
//!    unit runs when started; removing it leaves none of them, and the
//!    vendor directory the service still uses stays;
//!
//! Then the update flow, through the product's real
//! update helper (seaworthy_updater's, built with the lane's keys) and the
//! lane's server in the host: a version gate the helper probes and a file
//! server, on loopback (`conformance_server`). The helper fetches releases
//! from the published repository's release tree (the update helper's URL
//! template, as `seaworthy repo` writes it), where the refused cases are laid out
//! too. A run is triggered the way the app triggers it — the service's
//! user truncates the update request file the helper's path unit watches:
//!
//! 2. **refused releases never reach the installer** (v1 installed, the
//!    gate naming v2): a manifest for another format, a tampered package,
//!    and (rpm, pacman) a package signed by an untrusted key under a
//!    manifest the trusted release key signed — each refused with its
//!    reason, v1 still installed, the install unit never run;
//! 3. **the helper upgrades to v2** — the service restarted, the path unit
//!    untouched (its InvocationID kept), the helper's run a success (the
//!    package scripts never stop it); then (deb, rpm) **the
//!    repository package upgrades through the repository** to v2's, its
//!    keyring now the two keys, the administrator's edit to its definition
//!    kept and nothing left beside it (`.dpkg-dist`, `.rpmnew`): how a key
//!    rotation reaches machines (Arch: the administrator adds the next key);
//! 4. **a downgrade is refused** (the gate naming v1);
//! 5. **an administrator's upgrade overtakes a run**: the gate holds the
//!    helper's probe while the administrator installs v3 (which drops the
//!    helper, and whose repositories and packages the next key signed: the
//!    rotation's switch) with the service disabled — the running helper isn't stopped,
//!    and once released it refuses to install over the release
//!    that changed under it; the trigger stopped and its links
//!    gone, the service still disabled;
//!
//! then the lifecycle again, and the helper's own removal:
//!
//! 6. **downgrade to v2**, with the service masked by the administrator — the
//!    trigger back, enabled and running; the service still masked;
//! 7. **the helper upgrades to v3, removing itself** — its install finishes
//!    and is confirmed (the scripts stop only the trigger), the trigger
//!    gone;
//! 8. **remove** — both units stopped and their links gone; the state
//!    directory (0700, the user's) and the user kept;
//! 9. **reinstall** (v2) — both units enabled and running again;
//! 10. **purge** (deb) — the state directory and the user kept.
//!
//! Between helper runs the suite removes the helper's `last-run` and
//! `failure-memo` (standing in for the time its throttle and backoff
//! wait).
//!
//! The installed version is checked after every step. Signatures go through
//! the package managers: apt verifies `InRelease` against the `Signed-By`
//! key alone, dnf checks `repomd.xml.asc` and every rpm, pacman the
//! database and every package; directly, `rpm -K` (rpm 4.16 on UBI 9) and
//! `pacman-key --verify`. Ubuntu's needrestart: the Debian and
//! Ubuntu hosts run it set to restart services itself, so the helper's
//! upgrades (steps 3 and 7) pass only because the helper suspends it
//! (`NEEDRESTART_SUSPEND=1`); without that it restarts the helper's own
//! unit mid-install (checked once by hand: the run's journal stops at
//! "installing"). The suite's own apt runs suspend it too.
//!
//! Each distribution's findings land in `<lane>/report/<distro>.json`
//! (RHEL 9's systemd 252 ignores `RestartSteps=`; the lane records what
//! `systemd-analyze verify` says).
//!
//! Runs only with `--features conformance` and `SEAWORTHY_CONFORMANCE`
//! naming the built lane (the script sets both), against a docker daemon
//! on cgroup v2. `SEAWORTHY_TEST_CONTAINERS_REQUIRED=1` turns a missing daemon
//! or lane into a failure.

#![cfg(all(unix, feature = "conformance"))]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use seaworthy_test_support::systemd::{self, Distro, Family, SystemdHost};
use serde_json::{Value, json};

/// Where the suite lays out each case for the lane's file server.
const RELEASES: &str = "/conformance/releases";
/// The lane's server inside the host (`lane.json`'s `server`).
const SERVER: &str = "/conformance/bin/conformance_server";
/// The published repositories, under the server's root: what clients read.
const REPO: &str = "/conformance/releases/repo";
/// Their URL, as clients name it.
const REPO_URL: &str = "http://127.0.0.1:8470/repo";
/// The gate's hold: probes wait until RELEASE exists; HELD says one is.
const RELEASE: &str = "/run/conformance-gate-release";
const HELD: &str = "/run/conformance-gate-held";

/// The built lane (`lane.json` and its files).
struct Lane {
    dir: PathBuf,
    package: String,
    service: String,
    fingerprint: String,
    /// The rotation's next key (pinned from v2, signing v3).
    next_fingerprint: String,
    /// The releases' build metadata (`conformance`): a version token is
    /// `<version>+<build>`.
    build: String,
    /// The lane's server binary, relative to the lane.
    server: String,
    /// The repositories' name (pacman's section, the dnf repository id).
    repository: String,
    /// The built repositories (`repos/<name>/`): `v1`, `v3`, `foreign`.
    repositories: Vec<String>,
    /// Release name (`v1`) to version (`1.0.0`) and sequence.
    releases: BTreeMap<String, (String, u64)>,
    /// The product as installed (`lane.json`'s `product`).
    product: Installed,
    /// The device-driven scenario, for a product whose service itself asks
    /// for updates (a reference product's lane).
    device: Option<DeviceDriven>,
    /// The desktop product beside the service (step 1b), when the lane
    /// builds one.
    desktop: Option<DesktopProduct>,
    /// Whether the lifecycle suite (`conformance`) runs: the steps trigger
    /// the helper themselves, which a product whose service asks for updates
    /// on its own would race (its lane runs the device-driven scenario).
    lifecycle: bool,
}

/// The product as its packages install it (the lane's product: the
/// launcher fixture, or a reference product).
struct Installed {
    /// The sandbox user.
    user: String,
    /// The service's state directory, holding the update request file.
    state: String,
    /// The helper's staging directory, its throttle and its failure memo.
    cache: String,
    /// The launcher, as installed (`/opt/<vendor>/<id>/<executable>`).
    executable: String,
    /// The service's arguments (`serve`), space-separated; empty for none.
    arguments: String,
    /// What the core logs first (a `grep -E` pattern).
    core_marker: String,
    /// What the gate puts before a version token (`v` for a gate that
    /// spells them `v1.2.3`; the helper removes it).
    token_prefix: String,
}

/// The desktop product as its packages install it (`lane.json`'s
/// `desktop`).
struct DesktopProduct {
    /// Its package.
    package: String,
    /// `/usr/bin/<command>`.
    command: String,
    /// The launcher the command links to.
    launcher: String,
    /// The menu entry.
    entry: String,
    /// The icons.
    icons: Vec<String>,
    /// Some of its data files.
    data: Vec<String>,
    /// Its install root.
    root: String,
    /// The vendor directory, shared with the service.
    vendor: String,
    /// Its update helper's unit, when its packages ship the helper.
    helper_unit: Option<String>,
    /// The polkit rule letting the logged-in session start that unit.
    polkit_rule: Option<String>,
}

/// The device-driven scenario's inputs.
#[derive(Clone)]
struct DeviceDriven {
    /// The server configuration file the device and its helper read.
    config: String,
    /// Its contents: the lane's gate.
    content: String,
}

fn lane() -> Option<Lane> {
    // allow-std-env: the lane directory the script built
    let Some(dir) = std::env::var_os("SEAWORTHY_CONFORMANCE").map(PathBuf::from) else {
        assert!(
            !seaworthy_test_support::required(),
            "SEAWORTHY_CONFORMANCE is unset (run scripts/linux-conformance.sh)"
        );
        eprintln!("SKIPPED: SEAWORTHY_CONFORMANCE is unset (run scripts/linux-conformance.sh)");
        return None;
    };
    let text = std::fs::read_to_string(dir.join("lane.json"))
        .expect("lane.json (run scripts/linux-conformance.sh build)");
    let lane: Value = serde_json::from_str(&text).expect("lane.json is JSON");
    let releases = lane["releases"]
        .as_object()
        .expect("releases")
        .iter()
        .map(|(name, r)| {
            (
                name.clone(),
                (
                    r["version"].as_str().unwrap().to_owned(),
                    r["sequence"].as_u64().unwrap(),
                ),
            )
        })
        .collect();
    Some(Lane {
        dir,
        package: lane["package"].as_str().unwrap().to_owned(),
        service: lane["service"].as_str().unwrap().to_owned(),
        fingerprint: lane["openpgp-fingerprint"].as_str().unwrap().to_owned(),
        next_fingerprint: lane["next-fingerprint"].as_str().unwrap().to_owned(),
        build: lane["build"].as_str().unwrap().to_owned(),
        server: lane["server"].as_str().unwrap().to_owned(),
        repository: lane["repository"].as_str().unwrap().to_owned(),
        repositories: lane["repositories"]
            .as_array()
            .expect("repositories")
            .iter()
            .map(|r| r.as_str().unwrap().to_owned())
            .collect(),
        releases,
        product: Installed {
            user: lane["product"]["user"].as_str().unwrap().to_owned(),
            state: lane["product"]["state"].as_str().unwrap().to_owned(),
            cache: lane["product"]["cache"].as_str().unwrap().to_owned(),
            executable: lane["product"]["executable"].as_str().unwrap().to_owned(),
            arguments: lane["product"]["arguments"].as_str().unwrap().to_owned(),
            core_marker: lane["product"]["core-marker"].as_str().unwrap().to_owned(),
            token_prefix: lane["product"]["token-prefix"].as_str().unwrap().to_owned(),
        },
        lifecycle: lane["lifecycle"].as_bool().unwrap_or(true),
        desktop: lane.get("desktop").map(|d| {
            let strings = |key: &str| -> Vec<String> {
                d[key]
                    .as_array()
                    .expect(key)
                    .iter()
                    .map(|s| s.as_str().unwrap().to_owned())
                    .collect()
            };
            DesktopProduct {
                package: d["package"].as_str().unwrap().to_owned(),
                command: d["command"].as_str().unwrap().to_owned(),
                launcher: d["launcher"].as_str().unwrap().to_owned(),
                entry: d["entry"].as_str().unwrap().to_owned(),
                icons: strings("icons"),
                data: strings("data"),
                root: d["root"].as_str().unwrap().to_owned(),
                vendor: d["vendor"].as_str().unwrap().to_owned(),
                helper_unit: d.get("helper-unit").map(|u| u.as_str().unwrap().to_owned()),
                polkit_rule: d.get("polkit-rule").map(|r| r.as_str().unwrap().to_owned()),
            }
        }),
        device: lane.get("device-driven").map(|d| DeviceDriven {
            config: d["config"].as_str().unwrap().to_owned(),
            content: d["content"].as_str().unwrap().to_owned(),
        }),
    })
}

impl Lane {
    /// Release `release`'s package file for `family` (`foreign` is v1's,
    /// `foreign-v2` v2's, signed by an untrusted key).
    fn package_file(&self, release: &str, family: Family) -> String {
        let release = match release {
            "foreign" => "v1",
            "foreign-v2" => "v2",
            other => other,
        };
        let (version, sequence) = &self.releases[release];
        match family {
            Family::Deb => format!("{}_{version}-{sequence}_amd64.deb", self.package),
            Family::Rpm => format!("{}-{version}-{sequence}.x86_64.rpm", self.package),
            Family::Pacman => format!("{}-{version}-{sequence}-x86_64.pkg.tar.zst", self.package),
        }
    }

    /// The release's version token (`1.1.0+conformance`): its manifests'
    /// and the release tree's.
    fn token(&self, release: &str) -> String {
        format!("{}+{}", self.releases[release].0, self.build)
    }

    /// What the gate names for the release (`v1.1.0+conformance` for a
    /// product whose tokens carry a `v`).
    fn gate_token(&self, release: &str) -> String {
        format!("{}{}", self.product.token_prefix, self.token(release))
    }

    /// The app's update request file, in the service's state directory.
    fn request(&self) -> String {
        format!("{}/update-request", self.product.state)
    }

    /// The release as the helper logs it (`1.1.0 (sequence 2)`).
    fn logged(&self, release: &str) -> String {
        let (version, sequence) = &self.releases[release];
        format!("{version} (sequence {sequence})")
    }

    /// The package manager's spelling of the release's version.
    fn full_version(&self, release: &str) -> String {
        let (version, sequence) = &self.releases[release];
        format!("{version}-{sequence}")
    }

    /// Every file the container needs: each release's package (and .sig)
    /// with every family's release manifest at `/conformance/<release>/`,
    /// the foreign-signed ones at `/conformance/foreign/` and (with their
    /// trusted-key manifests) `/conformance/foreign-v2/` (rpm and pacman),
    /// the family's repository, the key, the release tree and `setup/` of
    /// every built repository at `/conformance/repos/<name>/`, both OpenPGP
    /// keys (pacman's setup by hand), and the lane's server.
    fn files(&self, family: Family) -> Vec<(String, Vec<u8>)> {
        let mut files = vec![
            (
                "/conformance/repo.asc".to_owned(),
                std::fs::read(self.dir.join("keys/repo.asc")).unwrap(),
            ),
            (
                "/conformance/next.asc".to_owned(),
                std::fs::read(self.dir.join("keys/next.asc")).unwrap(),
            ),
            (
                SERVER.to_owned(),
                std::fs::read(self.dir.join(&self.server)).unwrap(),
            ),
        ];
        let format_dir = match family {
            Family::Deb => "apt",
            Family::Rpm => "rpm",
            Family::Pacman => "pacman",
        };
        for repository in &self.repositories {
            // The family's repository, the key, the release tree the
            // helper fetches from, and the repository package.
            for sub in [format_dir, "keys", "releases", "setup"] {
                let root = self.dir.join("repos").join(repository);
                for file in files_under(&root.join(sub)) {
                    let relative = file.strip_prefix(&root).unwrap().to_string_lossy();
                    files.push((
                        format!("/conformance/repos/{repository}/{relative}"),
                        std::fs::read(&file).unwrap(),
                    ));
                }
            }
        }
        let mut dirs: Vec<&str> = self.releases.keys().map(String::as_str).collect();
        if family != Family::Deb {
            dirs.extend(["foreign", "foreign-v2"]);
        }
        for release in dirs {
            let name = self.package_file(release, family);
            let mut names = vec![name.clone()];
            if family == Family::Pacman {
                names.push(format!("{name}.sig"));
            }
            if release == "foreign-v2" {
                names.push(format!("{name}.manifest"));
            } else if release != "foreign" {
                // Every family's manifest: a case serves another format's.
                for other in [Family::Deb, Family::Rpm, Family::Pacman] {
                    names.push(format!("{}.manifest", self.package_file(release, other)));
                }
            }
            for name in names {
                let path = self.dir.join("packages").join(release).join(&name);
                files.push((
                    format!("/conformance/{release}/{name}"),
                    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
                ));
            }
        }
        files
    }
}

/// Every file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(files_under(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// Where an install takes a release from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    /// The published repository ([`Run::publish`] first): a fresh install
    /// or an upgrade to the release it holds.
    Repository,
    /// The release's own file, as an administrator installs a release the
    /// repository no longer holds (it holds the latest only).
    File { downgrade: bool },
}

/// One distribution's run: the host, the lane, and what it found.
struct Run<'a> {
    host: SystemdHost,
    lane: &'a Lane,
    family: Family,
    report: serde_json::Map<String, Value>,
}

/// A unit's state: `(is-enabled, is-active)`.
type UnitState = (String, String);

impl Run<'_> {
    fn distro(&self) -> Distro {
        self.host.distro()
    }

    fn name(&self) -> &'static str {
        self.distro().name()
    }

    fn service(&self) -> String {
        format!("{}.service", self.lane.service)
    }

    fn path_unit(&self) -> String {
        format!("{}-update.path", self.lane.service)
    }

    fn helper_unit(&self) -> String {
        format!("{}-update.service", self.lane.service)
    }

    async fn unit(&self, unit: &str) -> UnitState {
        let enabled = self
            .host
            .sh(&format!("systemctl is-enabled {unit} 2>/dev/null || true"))
            .await;
        let active = self
            .host
            .sh(&format!("systemctl is-active {unit} 2>/dev/null || true"))
            .await;
        let first = |s: &str| s.lines().next().unwrap_or("").trim().to_owned();
        (first(&enabled.stdout), first(&active.stdout))
    }

    async fn show(&self, unit: &str, property: &str) -> String {
        self.host
            .ok(&format!("systemctl show -p {property} --value {unit}"))
            .await
            .trim()
            .to_owned()
    }

    /// Polls `condition` (a shell test) for up to `seconds`; on timeout,
    /// panics with `what` and the unit's status and journal.
    async fn poll(&self, condition: &str, seconds: u32, unit: &str, what: &str) {
        let script = format!(
            "for i in $(seq 1 {}); do {condition} && exit 0; sleep 0.5; done; exit 1",
            seconds * 2
        );
        if self.host.sh(&script).await.code != Some(0) {
            let status = self
                .host
                .sh(&format!(
                    "systemctl status --no-pager {unit}; echo '--- jobs'; systemctl list-jobs --no-pager; \
                     echo '--- journal'; journalctl --no-pager -n 40"
                ))
                .await;
            panic!("{}: {unit} {what}:\n{}", self.name(), status.stdout);
        }
    }

    /// Waits for `unit` to be active: starts are queued (`--no-block`).
    async fn wait_active(&self, unit: &str) {
        self.poll(
            &format!("systemctl is-active --quiet {unit}"),
            60,
            unit,
            "never became active",
        )
        .await;
    }

    /// Waits for `unit` to stop: a retired unit's stop is queued too.
    async fn wait_inactive(&self, unit: &str) {
        self.poll(
            &format!("! systemctl is-active --quiet {unit}"),
            30,
            unit,
            "never stopped",
        )
        .await;
    }

    /// Waits for `unit` to run a new main process (an upgrade's restart is
    /// queued: the old process can still be the active one right after the
    /// package manager returns). Returns the new PID.
    async fn wait_restarted(&self, unit: &str, previous_pid: &str) -> String {
        self.poll(
            &format!(
                "pid=$(systemctl show -p MainPID --value {unit}) && [ \"$pid\" != 0 ] && \
                 [ \"$pid\" != {previous_pid} ] && systemctl is-active --quiet {unit}"
            ),
            60,
            unit,
            &format!("wasn't restarted (main PID still {previous_pid})"),
        )
        .await;
        self.show(unit, "MainPID").await
    }

    /// The installed version, as the package manager spells it; `None`
    /// when the package isn't installed (deb: in any state but `ii`).
    async fn installed_version(&self) -> Option<String> {
        let package = &self.lane.package;
        let query = match self.family {
            Family::Deb => format!(
                "[ \"$(dpkg-query -W -f '${{db:Status-Abbrev}}' {package} 2>/dev/null)\" = 'ii ' ] && \
                 dpkg-query -W -f '${{Version}}' {package}"
            ),
            Family::Rpm => format!("rpm -q --qf '%{{VERSION}}-%{{RELEASE}}' {package}"),
            // `pacman -Q` prints `<name> <version>`; a pipe would hide its
            // exit status.
            Family::Pacman => format!("pacman -Q {package}"),
        };
        let output = self.host.sh(&query).await;
        let text = output.stdout.trim();
        let version = match self.family {
            Family::Pacman => text.split_whitespace().nth(1).unwrap_or_default(),
            Family::Deb | Family::Rpm => text,
        };
        (output.code == Some(0) && !version.is_empty()).then(|| version.to_owned())
    }

    /// The package database names release `release`.
    async fn assert_version(&self, release: &str) {
        assert_eq!(
            self.installed_version().await,
            Some(self.lane.full_version(release)),
            "{}: after putting {release} in place",
            self.name()
        );
    }

    /// Enablement links under /etc/systemd/system matching `pattern`.
    async fn links(&self, pattern: &str) -> Vec<String> {
        self.host
            .ok(&format!(
                "find /etc/systemd/system -name '{pattern}' -print"
            ))
            .await
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// The state directory (0700, the user's) and the user exist.
    async fn assert_state_kept(&self, after: &str) {
        let (user, dir) = (&self.lane.product.user, &self.lane.product.state);
        let state = self.host.sh(&format!("stat -c '%U %a' {dir}")).await;
        assert_eq!(
            (state.code, state.stdout.trim()),
            (Some(0), format!("{user} 700").as_str()),
            "{}: {after} keeps the state directory ({})",
            self.name(),
            state.stderr.trim()
        );
        let user = self.host.sh(&format!("id -u {user}")).await;
        assert_eq!(
            user.code,
            Some(0),
            "{}: {after} keeps the user",
            self.name()
        );
    }

    /// The package manager's command to put release `release` in place
    /// from `source`.
    fn install_command(&self, release: &str, source: Source) -> String {
        let package = &self.lane.package;
        let repository = &self.lane.repository;
        let version = self.lane.full_version(release);
        let file = format!(
            "/conformance/{release}/{}",
            self.lane.package_file(release, self.family)
        );
        match (self.family, source) {
            // The administrator's apt suspends needrestart as the helper's
            // does: the hosts' needrestart restarts services itself, and
            // would restart a helper that step 5 holds mid-run (which the
            // helper survives by design, its install running in its own
            // unit, but step 5 is about the package scripts).
            (Family::Deb, Source::Repository) => format!(
                "export NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive && apt-get update -q && \
                 apt-get install -y -q {package}={version}"
            ),
            (Family::Deb, Source::File { downgrade }) => format!(
                "export NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive && apt-get install -y -q {} {file}",
                if downgrade { "--allow-downgrades" } else { "" }
            ),
            (Family::Rpm, Source::Repository) => {
                format!("dnf install -y -q --refresh --repo={repository} {package}-{version}")
            }
            (Family::Rpm, Source::File { downgrade: true }) => {
                format!("dnf downgrade -y -q {file}")
            }
            (Family::Rpm, Source::File { downgrade: false }) => {
                format!("dnf install -y -q {file}")
            }
            // `-Syy`: a database rewritten within the second of the last
            // sync looks unchanged to `-Sy`.
            (Family::Pacman, Source::Repository) => {
                format!("pacman -Syy --noconfirm {package}")
            }
            (Family::Pacman, Source::File { .. }) => format!("pacman -U --noconfirm {file}"),
        }
    }

    /// 1b. The desktop product from the published repository: its command,
    /// menu entry, icons and data files, then its removal leaving none of
    /// them.
    async fn desktop_product(&self, desktop: &DesktopProduct) {
        let name = self.name();
        let package = &desktop.package;
        let install = match self.family {
            Family::Deb => format!(
                "export DEBIAN_FRONTEND=noninteractive && apt-get update -q && apt-get install -y -q {package}"
            ),
            Family::Rpm => format!(
                "dnf install -y -q --refresh --repo={} {package}",
                self.lane.repository
            ),
            Family::Pacman => format!("pacman -Syy --noconfirm {package}"),
        };
        self.host.ok(&install).await;
        let resolved = self
            .host
            .ok(&format!("readlink -f {}", desktop.command))
            .await;
        assert_eq!(
            resolved.trim(),
            desktop.launcher,
            "{name}: {} links to the launcher",
            desktop.command
        );
        let output = self.host.ok(&desktop.command).await;
        assert!(
            output.lines().any(|l| l.starts_with("core=x86-64-v")),
            "{name}: the command runs a core through the link:\n{output}"
        );
        let entry = self.host.ok(&format!("cat {}", desktop.entry)).await;
        assert!(
            entry.starts_with("[Desktop Entry]\n")
                && entry.contains(&format!("\nExec={}\n", desktop.launcher))
                && entry.contains(&format!("\nIcon={package}\n")),
            "{name}: the menu entry:\n{entry}"
        );
        let helper_files: Vec<String> = match (&desktop.helper_unit, &desktop.polkit_rule) {
            (Some(unit), Some(rule)) => {
                self.desktop_helper(unit).await;
                vec![format!("/usr/lib/systemd/system/{unit}"), rule.clone()]
            }
            _ => Vec::new(),
        };
        let shipped: Vec<&String> = std::iter::once(&desktop.entry)
            .chain(&desktop.icons)
            .chain(&desktop.data)
            .chain(&helper_files)
            .collect();
        for path in &shipped {
            let mode = self.host.ok(&format!("stat -c %a {path}")).await;
            assert_eq!(mode.trim(), "644", "{name}: {path}'s mode");
        }
        let remove = match self.family {
            Family::Deb => {
                format!("DEBIAN_FRONTEND=noninteractive apt-get remove -y -q {package}")
            }
            Family::Rpm => format!("dnf remove -y -q {package}"),
            Family::Pacman => format!("pacman -R --noconfirm {package}"),
        };
        self.host.ok(&remove).await;
        for path in shipped.into_iter().chain([&desktop.command, &desktop.root]) {
            self.host
                .ok(&format!("test ! -e {path} && test ! -L {path}"))
                .await;
        }
        // The service's package still owns the vendor directory.
        self.host.ok(&format!("test -d {}", desktop.vendor)).await;
    }

    /// 1b: the desktop product's update helper. Its unit is installed
    /// but never enabled or run by the package (`static`, not started).
    /// Then polkit's verdicts, as `systemctl --no-ask-password` gets them
    /// (a refusal is an exit, never a prompt), for a regular user:
    ///
    /// - **in a seatless logind session**, opened by `pam_systemd`
    ///   (`systemd-run -p PAMName=` with a PAM service of the lane's own:
    ///   permit, then `pam_systemd`), active and not remote as logind
    ///   reports it — an ssh or `su` login's kind: everything is refused,
    ///   starting the helper's unit too. polkit counts a session as local
    ///   only when it has a seat, and no container session has one, so the
    ///   grant (an active session on a seat: a desktop's) can't be shown
    ///   here: seaworthy_service's rule test runs the rule's JavaScript for it
    ///   (only `start`, only this unit, only local and active), and a
    ///   desktop updates through it. UBI 9's systemd 252 refuses the
    ///   lane's PAM service (exit 224, no session): its verdicts are the
    ///   no-session ones, as refused;
    /// - **in no session at all** (a service's process): everything is
    ///   refused.
    ///
    /// The unit itself runs when root starts it. The unit runs the lane's
    /// helper, built for the agent: under the viewer's sandbox it can't
    /// write the agent's staging directory and stops there, so the step
    /// checks that systemd ran it, not what it did.
    async fn desktop_helper(&self, unit: &str) {
        let name = self.name();
        let enabled = self.host.sh(&format!("systemctl is-enabled {unit}")).await;
        assert_eq!(
            enabled.stdout.trim(),
            "static",
            "{name}: {unit} has no [Install] section: {enabled:?}"
        );
        let started = format!("systemctl show -p ExecMainStartTimestampMonotonic --value {unit}");
        assert_eq!(
            self.host.ok(&started).await.trim(),
            "0",
            "{name}: the package never starts {unit}"
        );
        // A regular user (60123: outside the system range), the PAM service
        // that opens its sessions, and what it asks systemd for.
        self.host
            .ok(&format!(
                r#"printf 'auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_systemd.so\n' > /etc/pam.d/seaworthy-conformance-session
id swsession >/dev/null 2>&1 || systemd-sysusers --inline 'u swsession 60123 "seaworthy conformance session" / /bin/sh'
cat > /run/seaworthy-conformance-polkit.sh <<'SH'
r() {{ if systemctl --no-ask-password "$@" >/dev/null 2>&1; then echo ok; else echo "refused($?)"; fi; }}
echo "session=${{XDG_SESSION_ID:-none}}"
echo "start=$(r start --no-block {unit})"
echo "stop=$(r stop --no-block {unit})"
echo "restart=$(r restart --no-block {unit})"
echo "other=$(r start --no-block systemd-tmpfiles-clean.service)"
SH
chmod 0755 /run/seaworthy-conformance-polkit.sh"#
            ))
            .await;
        let in_session = self
            .host
            .sh("systemd-run --quiet --wait --pipe --uid=swsession -p PAMName=seaworthy-conformance-session --setenv=XDG_SESSION_CLASS=user /bin/sh /run/seaworthy-conformance-polkit.sh")
            .await;
        let outside = self
            .host
            .sh("systemd-run --quiet --wait --pipe --uid=swsession /bin/sh /run/seaworthy-conformance-polkit.sh")
            .await;
        let diagnostics = self
            .host
            .sh("loginctl list-sessions --no-legend; journalctl -u polkit --no-pager -n 30")
            .await;
        let verdicts = |stdout: &str| -> BTreeMap<String, String> {
            stdout
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect()
        };
        let (inside, out) = (verdicts(&in_session.stdout), verdicts(&outside.stdout));
        let context = format!(
            "in a session: {in_session:?}\noutside one: {outside:?}\n{}{}",
            diagnostics.stdout, diagnostics.stderr
        );
        // A seatless session is never local to polkit: nothing is granted
        // (UBI 9 opens none: its run is the no-session case).
        for verb in ["start", "stop", "restart", "other"] {
            assert!(
                inside.get(verb).is_some_and(|v| v.starts_with("refused"))
                    || (in_session.code != Some(0) && inside.is_empty()),
                "{name}: a seatless session may not {verb} ({unit}, or another unit)\n{context}"
            );
        }
        assert_eq!(
            out.get("session").map(String::as_str),
            Some("none"),
            "{name}: the outside run is in no session\n{context}"
        );
        assert!(
            out.get("start").is_some_and(|v| v.starts_with("refused")),
            "{name}: outside a session, starting {unit} is refused\n{context}"
        );
        // The unit runs when started (root here: no container session can
        // be granted it; queued: --no-block).
        self.host
            .ok(&format!("systemctl start --no-block {unit}"))
            .await;
        self.poll(
            &format!("[ \"$({started})\" != 0 ]"),
            30,
            unit,
            "never ran when started",
        )
        .await;
        self.host
            .ok(&format!(
                "systemctl reset-failed {unit} 2>/dev/null || true\n\
                 rm -f /etc/pam.d/seaworthy-conformance-session /run/seaworthy-conformance-polkit.sh"
            ))
            .await;
    }

    /// The client's refresh of the repository's indexes alone.
    fn refresh_command(&self) -> String {
        match self.family {
            Family::Deb => "apt-get update -q".to_owned(),
            // Not -q: dnf5 prints a skipped repository's reason only
            // without it.
            Family::Rpm => format!("dnf makecache -y --refresh --repo={}", self.lane.repository),
            Family::Pacman => "pacman -Syy --noconfirm".to_owned(),
        }
    }

    /// Publishes repository `name` (`repos/<name>/`, the latest release
    /// only): it replaces what the server served.
    async fn publish(&self, name: &str) {
        self.host
            .ok(&format!(
                "rm -rf {REPO} && mkdir -p {RELEASES} && cp -r /conformance/repos/{name} {REPO}"
            ))
            .await;
    }

    /// Puts `release` in place from `source` and checks the package
    /// database.
    async fn install(&self, release: &str, source: Source) {
        self.host.ok(&self.install_command(release, source)).await;
        self.assert_version(release).await;
    }

    async fn remove(&self, purge: bool) {
        let package = &self.lane.package;
        let command = match self.family {
            Family::Deb if purge => {
                format!("DEBIAN_FRONTEND=noninteractive apt-get purge -y -q {package}")
            }
            Family::Deb => format!("DEBIAN_FRONTEND=noninteractive apt-get remove -y -q {package}"),
            Family::Rpm => format!("dnf remove -y -q {package}"),
            Family::Pacman => format!("pacman -R --noconfirm {package}"),
        };
        self.host.ok(&command).await;
        assert_eq!(
            self.installed_version().await,
            None,
            "{}: the package is still installed after removal",
            self.name()
        );
    }

    /// The lane's server (serving v1's published repositories from here
    /// on) and the client set up as an administrator sets it up, every
    /// other repository off: apt and dnf by installing the repository
    /// package from `setup/` (its definition and the pinned keys, trusted
    /// for this repository alone), pacman by hand.
    async fn set_up(&mut self) {
        self.serve("v1", false).await;
        self.publish("v1").await;
        let name = &self.lane.repository;
        let setup = format!("{name}-repository");
        match self.family {
            // As downloaded from setup/: apt installs a file.
            Family::Deb => {
                self.host
                    .ok(&format!(
                        "rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list.d/ubuntu.sources && \
                         export NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive && \
                         apt-get install -y -q {REPO}/setup/{setup}.deb"
                    ))
                    .await;
            }
            // The published key imported, then the package from its URL:
            // its signature checked (localpkg_gpgcheck, which also checks
            // every release installed from its file later).
            Family::Rpm => {
                self.host
                    .ok(&format!(
                        "for f in /etc/yum.repos.d/*.repo; do sed -i 's/^enabled=1/enabled=0/' \"$f\"; done && \
                         sed -i 's/^localpkg_gpgcheck=.*//' /etc/dnf/dnf.conf && echo localpkg_gpgcheck=1 >> /etc/dnf/dnf.conf && \
                         rpm --import {REPO}/keys/{name}.asc && \
                         dnf install -y -q {REPO_URL}/setup/{setup}.rpm"
                    ))
                    .await;
            }
            // The key locally signed (`pacman-key --lsign-key`), as the
            // README's client setup says; the database and every package
            // must be signed, a file installed with -U too.
            Family::Pacman => {
                let fingerprint = &self.lane.fingerprint;
                self.host
                    .ok(&format!(
                        "pacman-key --add /conformance/repo.asc >/dev/null 2>&1 && pacman-key --lsign-key {fingerprint} >/dev/null 2>&1 && \
                         printf '\\n[{name}]\\nSigLevel = Required\\nServer = {REPO_URL}/pacman/stable/$arch\\n' >> /etc/pacman.conf && \
                         sed -i 's/^#\\?LocalFileSigLevel.*/LocalFileSigLevel = Required/' /etc/pacman.conf && \
                         sed -i '/^\\[core\\]/,/^$/d; /^\\[extra\\]/,/^$/d' /etc/pacman.conf"
                    ))
                    .await;
            }
        }
        self.check_repository_package().await;
    }

    /// The repository package as installed (deb, rpm): v1's version, its
    /// definition a configuration file the package manager tracks.
    async fn check_repository_package(&mut self) {
        let name = &self.lane.repository;
        let setup = format!("{name}-repository");
        let (query, definition) = match self.family {
            Family::Deb => (
                format!("dpkg-query -W -f '${{Version}}\\n${{Conffiles}}\\n' {setup}"),
                format!("/etc/apt/sources.list.d/{name}.sources"),
            ),
            Family::Rpm => (
                format!("rpm -q --qf '%{{VERSION}}-%{{RELEASE}}\\n' {setup} && rpm -qc {setup}"),
                format!("/etc/yum.repos.d/{name}.repo"),
            ),
            Family::Pacman => return,
        };
        assert_eq!(
            self.keyring_keys().await,
            1,
            "{}: v1's package pins one key",
            self.name()
        );
        let installed = self.host.ok(&query).await;
        assert_eq!(
            installed.lines().next().map(str::trim),
            Some(self.lane.full_version("v1").as_str()),
            "{}: the repository package's version:\n{installed}",
            self.name()
        );
        assert!(
            installed.contains(&definition),
            "{}: {definition} is a configuration file:\n{installed}",
            self.name()
        );
        let text = self.host.ok(&format!("cat {definition}")).await;
        self.report.insert(
            "repository package".into(),
            json!({
                "package": setup,
                "version": self.lane.full_version("v1"),
                "configuration file": definition,
                "definition": text.lines().collect::<Vec<_>>(),
            }),
        );
    }

    /// How many keys the repository package's keyring holds (deb, rpm).
    async fn keyring_keys(&self) -> usize {
        let name = &self.lane.repository;
        let keyring = match self.family {
            Family::Deb => format!("/usr/share/keyrings/{name}-archive-keyring.asc"),
            Family::Rpm => format!("/etc/pki/rpm-gpg/RPM-GPG-KEY-{name}"),
            Family::Pacman => return 0,
        };
        self.host
            .ok(&format!("grep -c 'BEGIN PGP PUBLIC KEY BLOCK' {keyring}"))
            .await
            .trim()
            .parse()
            .unwrap()
    }

    /// The rotation's switch, before the next key signs (v3): apt and dnf
    /// hosts already trust it through the repository package's upgrade;
    /// on Arch the administrator adds it and signs it locally.
    async fn trust_next_key(&mut self) {
        if self.family == Family::Pacman {
            let fingerprint = &self.lane.next_fingerprint;
            self.host
                .ok(&format!(
                    "pacman-key --add /conformance/next.asc >/dev/null 2>&1 && pacman-key --lsign-key {fingerprint} >/dev/null 2>&1"
                ))
                .await;
        }
        let how = match self.family {
            Family::Deb => {
                "the repository package's keyring, upgraded through the repository (Signed-By)"
            }
            Family::Rpm => {
                "the repository package's key file, upgraded through the repository (gpgkey=, imported by dnf)"
            }
            Family::Pacman => "added and locally signed by the administrator",
        };
        self.report.insert(
            "key rotation".into(),
            json!({
                "v1": "one key pinned",
                "v2": "both pinned, signed by the first",
                "v3": "signed by the next key: installed from its repository, then by the helper from its file",
                "next key trusted through": how,
            }),
        );
    }

    /// The repository package upgrades through the repository to
    /// `release`'s (deb, rpm): its keyring now holds the rotation's two
    /// keys, and the administrator's edit to its definition stays, with
    /// nothing left beside it: how a key rotation reaches machines.
    async fn upgrade_repository_package(&mut self, release: &str) {
        let name = &self.lane.repository;
        let setup = format!("{name}-repository");
        let (definition, upgrade, query, leftovers) = match self.family {
            Family::Deb => (
                format!("/etc/apt/sources.list.d/{name}.sources"),
                format!(
                    "export NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive && apt-get update -q && \
                     apt-get install -y -q --only-upgrade {setup}"
                ),
                format!("dpkg-query -W -f '${{Version}}' {setup}"),
                "dpkg-dist dpkg-new dpkg-old",
            ),
            Family::Rpm => (
                format!("/etc/yum.repos.d/{name}.repo"),
                format!("dnf upgrade -y -q --refresh --repo={name} {setup}"),
                format!("rpm -q --qf '%{{VERSION}}-%{{RELEASE}}' {setup}"),
                "rpmnew rpmsave",
            ),
            Family::Pacman => return,
        };
        let edit = "# edited by the administrator: kept across upgrades";
        self.host
            .ok(&format!("echo '{edit}' >> {definition}"))
            .await;
        self.host.ok(&upgrade).await;
        let version = self.host.ok(&query).await;
        assert_eq!(
            version.trim(),
            self.lane.full_version(release),
            "{}: the repository package after its upgrade",
            self.name()
        );
        assert_eq!(
            self.keyring_keys().await,
            2,
            "{}: the upgraded package carries the rotation's two keys",
            self.name()
        );
        let text = self.host.ok(&format!("cat {definition}")).await;
        assert!(
            text.contains(edit),
            "{}: the upgrade replaced the administrator's {definition}:\n{text}",
            self.name()
        );
        let left = self
            .host
            .ok(&format!(
                "for s in {leftovers}; do [ ! -e {definition}.$s ] || echo {definition}.$s; done"
            ))
            .await;
        assert_eq!(
            left.trim(),
            "",
            "{}: left beside the definition",
            self.name()
        );
        self.report.insert(
            "repository package upgrade".into(),
            json!({
                "to": self.lane.full_version(release),
                "through": "the repository",
                "keys": 2,
                "administrator's edit": "kept",
            }),
        );
    }

    /// Step 0, the repositories: indexes an untrusted key signed are
    /// refused by the client's refresh, which names the signature, and
    /// nothing is installable from them; the same indexes signed by the
    /// trusted key read fine. Fedora's dnf5 skips a repository that fails
    /// its check rather than failing the command (Fedora ships
    /// `skip_if_unavailable=True`): its refresh exits 0, but still names
    /// the signature, and the repository's packages never appear.
    async fn foreign_repository(&mut self) {
        self.publish("foreign").await;
        let refused = self.host.sh(&self.refresh_command()).await;
        let said = format!("{}{}", refused.stdout, refused.stderr);
        let skips = self.distro() == Distro::Fedora43;
        assert!(
            skips || refused.code != Some(0),
            "{}: the client read indexes an untrusted key signed:\n{said}",
            self.name()
        );
        // What each client says about the signature.
        let names = match self.family {
            Family::Deb => "is not signed",
            Family::Rpm => "signature verification error",
            Family::Pacman => "(PGP signature)",
        };
        assert!(
            said.contains(names),
            "{}: the refresh never said {names:?}:\n{said}",
            self.name()
        );
        let install = self
            .host
            .sh(&self.install_command("v1", Source::Repository))
            .await;
        assert_ne!(
            install.code,
            Some(0),
            "{}: installed from indexes an untrusted key signed:\n{}{}",
            self.name(),
            install.stdout,
            install.stderr
        );
        assert_eq!(self.installed_version().await, None, "{}", self.name());
        // The same indexes signed by the trusted key read fine: the refresh
        // succeeds, and (Fedora's exit 0 proving nothing) says nothing
        // about a signature.
        self.publish("v1").await;
        let read = self.host.sh(&self.refresh_command()).await;
        let read_said = format!("{}{}", read.stdout, read.stderr);
        assert!(
            read.code == Some(0) && !read_said.contains(names),
            "{}: the trusted key's indexes didn't read:\n{read_said}",
            self.name()
        );
        let reason: Vec<&str> = said
            .lines()
            .map(str::trim)
            .filter(|l| l.contains(names) || l.to_lowercase().contains("signature"))
            .take(3)
            .collect();
        self.report.insert(
            "foreign repository".into(),
            json!({
                "refresh exit": refused.code,
                "refused": reason,
                "installable": false,
                "the trusted key's indexes": "read",
            }),
        );
    }

    /// Step 0: a package signed by a key the host doesn't trust is refused,
    /// by the package manager and by the format's own check. Nothing is
    /// installed before or after.
    async fn foreign_signatures(&mut self) {
        let file = format!(
            "/conformance/foreign/{}",
            self.lane.package_file("foreign", self.family)
        );
        let refused = |what: &str, output: &systemd::Output| {
            assert_ne!(
                output.code,
                Some(0),
                "{}: {what} accepted a package signed by an untrusted key:\n{}{}",
                self.name(),
                output.stdout,
                output.stderr
            );
        };
        let checks = match self.family {
            Family::Deb => {
                json!({"deb": "unsigned packages: apt verifies the repository's signed index (the foreign repository below)"})
            }
            Family::Rpm => {
                let checked = self.host.sh(&format!("rpm -K {file}")).await;
                refused("rpm -K", &checked);
                let dnf = self.host.sh(&format!("dnf install -y -q {file}")).await;
                refused("dnf", &dnf);
                json!({
                    "foreign rpm -K": checked.stdout.trim(),
                    "foreign dnf": "refused",
                })
            }
            Family::Pacman => {
                let verify = self
                    .host
                    .sh(&format!("pacman-key --verify {file}.sig {file}"))
                    .await;
                refused("pacman-key --verify", &verify);
                let pacman = self.host.sh(&format!("pacman -U --noconfirm {file}")).await;
                refused("pacman -U", &pacman);
                json!({"foreign pacman-key --verify": "refused", "foreign pacman -U": "refused"})
            }
        };
        assert_eq!(
            self.installed_version().await,
            None,
            "{}: a refused package left something installed",
            self.name()
        );
        self.report.insert("foreign signatures".into(), checks);
    }

    /// The trusted signature checks each family's own tools make.
    async fn signatures(&mut self) {
        let checks = match self.family {
            Family::Deb => {
                json!({"apt": "InRelease verified against the Signed-By key alone on every refresh; unsigned packages, each named by its index's hash"})
            }
            Family::Rpm => {
                let file = format!(
                    "/conformance/v1/{}",
                    self.lane.package_file("v1", Family::Rpm)
                );
                let checked = self.host.ok(&format!("rpm -K {file}")).await;
                assert!(
                    checked.contains("signatures OK"),
                    "{}: rpm -K: {checked}",
                    self.name()
                );
                let rpm = self.host.ok("rpm --version").await;
                json!({"rpm -K": checked.trim(), "rpm": rpm.trim(), "dnf": "every install and upgrade through dnf: gpgcheck=1 and repo_gpgcheck=1 from the repository, localpkg_gpgcheck=1 from a file"})
            }
            Family::Pacman => {
                let file = format!(
                    "/conformance/v1/{}",
                    self.lane.package_file("v1", Family::Pacman)
                );
                self.host
                    .ok(&format!("pacman-key --verify {file}.sig {file}"))
                    .await;
                json!({"pacman-key --verify": "ok", "pacman SigLevel": "Required (the database and every package), and LocalFileSigLevel Required"})
            }
        };
        self.report.insert("signatures".into(), checks);
    }

    /// `systemd-analyze security`'s exposure for `unit`, bounded by `max`.
    async fn exposure(&self, unit: &str, max: f64) -> (f64, String) {
        let security = self
            .host
            .ok(&format!(
                "systemd-analyze security --no-pager {unit} 2>&1 | tail -1"
            ))
            .await;
        let exposure: f64 = security
            .rsplit_once(": ")
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("{}: no exposure level in {security:?}", self.name()));
        assert!(
            exposure < max,
            "{}: {unit}'s exposure is {exposure} (`{}`), above {max}",
            self.name(),
            security.trim()
        );
        (exposure, security.trim().to_owned())
    }

    /// What `systemd-analyze verify` says about `unit`'s file: lines naming
    /// the file or starting with the unit (the container's own unit noise
    /// left out). Systemd 254+ must say nothing.
    async fn verify(&self, unit: &str, systemd: u32) -> Vec<Value> {
        let unit_file = format!("/usr/lib/systemd/system/{unit}");
        let verify = self
            .host
            .sh(&format!("systemd-analyze verify {unit_file} 2>&1 || true"))
            .await;
        let findings: Vec<Value> = verify
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| line.contains(&unit_file) || line.starts_with(&format!("{unit}:")))
            .map(|line| Value::String(line.into()))
            .collect();
        if systemd >= 254 {
            assert!(
                findings.is_empty(),
                "{}: systemd {systemd} has something to say about {unit}: {findings:?}",
                self.name()
            );
        }
        findings
    }

    /// v1 freshly installed: units, identities, ownership, settings.
    async fn check_fresh_install(&mut self) {
        let (service, path_unit, helper) = (self.service(), self.path_unit(), self.helper_unit());
        self.wait_active(&service).await;
        self.wait_active(&path_unit).await;
        assert_eq!(
            self.unit(&service).await,
            ("enabled".into(), "active".into()),
            "{}",
            self.name()
        );
        assert_eq!(
            self.unit(&path_unit).await,
            ("enabled".into(), "active".into()),
            "{}",
            self.name()
        );
        // Active means forked. Before systemd 255 the child is a copy of
        // systemd (root, every capability) until it executes the program:
        // wait for the program itself. A sandbox systemd can't set up never
        // gets there, and the poll shows the unit's journal.
        self.poll(
            &format!(
                "[ \"$(readlink /proc/$(systemctl show -p MainPID --value {service})/exe)\" = \"$(readlink -f '{}')\" ]",
                self.lane.product.executable
            ),
            60,
            &service,
            "never executed the product",
        )
        .await;
        let pid = self.show(&service, "MainPID").await;
        // The process's real user, from its status: /proc/<pid>'s owner is
        // root whenever the process isn't dumpable, whoever it runs as.
        let owner = self
            .host
            .ok(&format!(
                "id -nu \"$(sed -n 's/^Uid:[[:space:]]*\\([0-9]*\\).*/\\1/p' /proc/{pid}/status)\""
            ))
            .await;
        assert_eq!(
            owner.trim(),
            self.lane.product.user,
            "{}: the service runs as its sandbox user ({})",
            self.name(),
            self.host
                .ok(&format!(
                    "grep -E '^(Uid|Gid|CapEff|NoNewPrivs):' /proc/{pid}/status; stat -c 'proc owner %U' /proc/{pid}"
                ))
                .await
                .replace('\n', "; ")
        );
        self.assert_state_kept("a fresh install").await;
        let executable = &self.lane.product.executable;
        let install = Path::new(executable)
            .parent()
            .unwrap()
            .display()
            .to_string();
        let tree = self
            .host
            .ok(&format!("stat -c '%U:%G %a' {install} {executable}"))
            .await;
        assert_eq!(
            tree.lines().collect::<Vec<_>>(),
            ["root:root 755", "root:root 755"],
            "{}",
            self.name()
        );
        let cmdline = self
            .host
            .ok(&format!("tr '\\0' ' ' < /proc/{pid}/cmdline"))
            .await;
        assert_eq!(
            cmdline.trim(),
            format!("{executable} {}", self.lane.product.arguments).trim(),
            "{}",
            self.name()
        );
        // The core's first line, once journald has it (it can lag the unit
        // becoming active).
        let marker = &self.lane.product.core_marker;
        let core = self
            .host
            .ok(&format!(
                "for i in $(seq 1 20); do journalctl --no-pager -o cat -u {service} 2>/dev/null | grep -m1 -E '{marker}' && exit 0; sleep 0.5; done; exit 1"
            ))
            .await;
        // The service's settings exactly as seaworthy_service renders them for
        // this product.
        let expected = [
            ("User", self.lane.product.user.as_str()),
            ("Restart", "on-failure"),
            ("RestartUSec", "15s"),
            ("NoNewPrivileges", "yes"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "yes"),
            ("PrivateTmp", "yes"),
            ("CapabilityBoundingSet", ""),
            ("StateDirectoryMode", "0700"),
        ];
        let mut settings = serde_json::Map::new();
        for (property, want) in expected {
            let got = self.show(&service, property).await;
            assert_eq!(got, want, "{}: {service}'s {property}", self.name());
            settings.insert(property.into(), Value::String(got));
        }
        // systemd's own exposure scores: the service in the "OK" band with
        // room to spare (1.2 everywhere at the time of writing), the root
        // helper bounded too.
        let (exposure, security) = self.exposure(&service, 1.5).await;
        let (helper_exposure, helper_security) = self.exposure(&helper, 4.0).await;
        let systemd = self.host.ok("systemctl --version | head -1").await;
        let version: u32 = systemd
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("{}: no systemd version in {systemd:?}", self.name()));
        // RHEL 9's systemd 252 doesn't know `RestartSteps=` and
        // `RestartMaxDelaySec=` (254+): escalating restart delays degrade to
        // the first delay there.
        let findings = self.verify(&service, version).await;
        let helper_findings = self.verify(&helper, version).await;
        self.report
            .insert("systemd".into(), Value::String(systemd.trim().into()));
        self.report
            .insert("core".into(), Value::String(core.trim().into()));
        self.report
            .insert("settings".into(), Value::Object(settings));
        self.report
            .insert("security".into(), Value::String(security));
        self.report.insert("exposure".into(), json!(exposure));
        self.report
            .insert("helper security".into(), Value::String(helper_security));
        self.report
            .insert("helper exposure".into(), json!(helper_exposure));
        self.report.insert("verify".into(), Value::Array(findings));
        self.report
            .insert("helper verify".into(), Value::Array(helper_findings));
    }

    /// The format tag the helper fetches for this family.
    fn format(family: Family) -> &'static str {
        match family {
            Family::Deb => "deb",
            Family::Rpm => "rpm",
            Family::Pacman => "pacman",
        }
    }

    /// (Re)starts the lane's server naming `release`'s token, its probes
    /// held until [`RELEASE`] exists when `hold`.
    async fn serve(&self, release: &str, hold: bool) {
        self.serve_token(&self.lane.gate_token(release), hold).await;
    }

    /// The lane's server, its gate naming `token`.
    async fn serve_token(&self, token: &str, hold: bool) {
        let hold = if hold {
            format!("--hold {RELEASE} --held {HELD}")
        } else {
            String::new()
        };
        self.host
            .ok(&format!(
                "systemctl stop conformance-server 2>/dev/null; systemctl reset-failed conformance-server 2>/dev/null; \
                 rm -f /run/conformance-server.ready {RELEASE} {HELD}; chmod 0755 {SERVER}; mkdir -p {RELEASES}; \
                 systemd-run --quiet --unit=conformance-server {SERVER} --root {RELEASES} --token {token} \
                 --ready /run/conformance-server.ready {hold}"
            ))
            .await;
        self.poll(
            "[ -f /run/conformance-server.ready ]",
            30,
            "conformance-server.service",
            "never listened",
        )
        .await;
    }

    /// Lays out one case for `token_release`'s token where the helper
    /// fetches releases — the published release tree, at the token's path
    /// (`releases/<package>/stable/<token>/<target>/<package>.<format>`,
    /// replacing what's there): the package from
    /// `/conformance/<package_from>/` (one byte flipped when `tamper`), and
    /// the manifest `manifest_family`'s manifest of `manifest_from`
    /// (another family's: a manifest for the wrong format). Clears the
    /// helper's throttle and memo, as the time they wait would.
    async fn stage(
        &self,
        token_release: &str,
        package_from: &str,
        manifest_from: &str,
        manifest_family: Family,
        tamper: bool,
    ) {
        let package_name = &self.lane.package;
        let dir = format!(
            "{REPO}/releases/{package_name}/stable/{}/x86_64-unknown-linux-gnu",
            self.lane.token(token_release)
        );
        let target = format!("{dir}/{package_name}.{}", Self::format(self.family));
        let package = format!(
            "/conformance/{package_from}/{}",
            self.lane.package_file(package_from, self.family)
        );
        let manifest = format!(
            "/conformance/{manifest_from}/{}.manifest",
            self.lane.package_file(manifest_from, manifest_family)
        );
        let mut script = format!(
            "rm -rf {dir} && mkdir -p {dir} && cp {package} {target} && cp {manifest} {target}.manifest"
        );
        if self.family == Family::Pacman {
            script.push_str(&format!(" && cp {package}.sig {target}.sig"));
        }
        if tamper {
            // One byte, mid-file, inverted: the same size, another digest.
            script.push_str(&format!(
                " && n=$(( $(stat -c %s {target}) / 2 )) && b=$(od -An -tu1 -j \"$n\" -N1 {target} | tr -d ' ') && \
                 printf \"$(printf '\\\\%03o' $(( b ^ 255 )))\" | dd of={target} bs=1 seek=\"$n\" conv=notrunc status=none"
            ));
        }
        self.host.ok(&script).await;
        self.reset_throttle().await;
    }

    /// Clears the helper's throttle and failure memo, as the time they
    /// wait would.
    async fn reset_throttle(&self) {
        let cache = &self.lane.product.cache;
        self.host
            .ok(&format!("rm -f {cache}/last-run {cache}/failure-memo"))
            .await;
    }

    /// Asks for an update the way the app does — the service's user
    /// truncates the request file the helper's path unit watches — and
    /// returns the started run's invocation id.
    async fn request_update(&self) -> String {
        let helper = self.helper_unit();
        let before = self.show(&helper, "InvocationID").await;
        let (user, request) = (&self.lane.product.user, self.lane.request());
        self.host
            .ok(&format!(
                "systemd-run --wait --collect --quiet --uid={user} --gid={user} /bin/sh -c ': > {request}'"
            ))
            .await;
        self.poll(
            &format!(
                "id=$(systemctl show -p InvocationID --value {helper}) && [ -n \"$id\" ] && [ \"$id\" != '{before}' ]"
            ),
            30,
            &helper,
            "never started on the update request",
        )
        .await;
        self.show(&helper, "InvocationID").await
    }

    /// Waits for the helper run `invocation` to end; its result
    /// (`success`, `exit-code`, …) and its journal.
    async fn helper_outcome(&self, invocation: &str, expect: &str) -> (String, String) {
        let helper = self.helper_unit();
        // A oneshot run ends inactive (or failed). After the helper's own
        // package removes its unit file the unit may be unloaded: then the
        // journal, not `Result`, tells the outcome.
        self.poll(
            &format!(
                "state=$(systemctl show -p ActiveState --value {helper}) && \
                 [ \"$state\" != activating ] && [ \"$state\" != active ] && [ \"$state\" != deactivating ]"
            ),
            240,
            &helper,
            "never finished",
        )
        .await;
        let result = self.show(&helper, "Result").await;
        // journald can still be writing the run's last lines when the unit
        // goes inactive: wait (briefly) for the line the case expects.
        let journal = self
            .host
            .ok(&format!(
                "read_run() {{ journalctl --no-pager -o cat _SYSTEMD_INVOCATION_ID={invocation}; }}; \
                 for i in $(seq 1 30); do read_run | grep -qF -- '{expect}' && break; sleep 0.5; done; read_run"
            ))
            .await;
        (result, journal)
    }

    /// A helper run against the staged case: requested, finished; its
    /// result and journal (once it shows `expect`, or a while passed).
    async fn run_helper(&self, expect: &str) -> (String, String) {
        let invocation = self.request_update().await;
        self.helper_outcome(&invocation, expect).await
    }

    /// A refused case: the run fails naming `reason`, the installed release
    /// is still `installed`, and no install unit has ever run.
    async fn assert_refused(&self, case: &str, reason: &str, installed: &str) {
        let (result, journal) = self.run_helper(reason).await;
        assert!(
            journal.contains(reason),
            "{}: {case}: expected {reason:?} in the helper's journal (result {result}):\n{journal}",
            self.name()
        );
        assert_ne!(
            result,
            "success",
            "{}: {case}: the run must fail",
            self.name()
        );
        self.assert_version(installed).await;
        assert_eq!(
            self.install_runs().await,
            0,
            "{}: {case}: the refused release reached the installer",
            self.name()
        );
    }

    /// How many times the helper's install unit has run.
    async fn install_runs(&self) -> usize {
        self.host
            .ok(&format!(
                "journalctl -q --no-pager -u {}-install.service | wc -l",
                self.lane.package
            ))
            .await
            .trim()
            .parse()
            .unwrap_or(0)
    }
}

async fn conformance(distro: Distro) {
    if !seaworthy_test_support::docker_or_skip().await {
        return;
    }
    let Some(lane) = lane() else { return };
    assert!(
        !product_required("reference") || !lane.lifecycle,
        "the reference product's lane must turn the lifecycle suite off"
    );
    assert!(
        !product_required("fixture") || lane.lifecycle,
        "the launcher fixture's lane runs the lifecycle suite"
    );
    if !lane.lifecycle {
        eprintln!(
            "SKIPPED: this lane's product asks for updates itself (the device-driven scenario covers it)"
        );
        return;
    }
    let family = distro.family();
    let host = systemd::start(distro, &lane.files(family)).await;
    let mut run = Run {
        host,
        lane: &lane,
        family,
        report: serde_json::Map::new(),
    };
    let (service, path_unit) = (run.service(), run.path_unit());
    run.set_up().await;
    let mut steps = Vec::new();

    // 0. Packages, and repositories, signed by a key the host doesn't trust
    // are refused.
    run.foreign_signatures().await;
    run.foreign_repository().await;
    steps.push("foreign signatures: packages refused by the package manager and the format's own check; repositories whose indexes an untrusted key signed refused by the client");

    // 1. A fresh install of v1, from the published repository.
    run.publish("v1").await;
    run.install("v1", Source::Repository).await;
    run.check_fresh_install().await;
    let pid = run.show(&service, "MainPID").await;
    let invocation = run.show(&path_unit, "InvocationID").await;
    assert!(
        !invocation.is_empty(),
        "{}: the path unit has an invocation",
        distro.name()
    );
    steps.push("install v1 from the signed repository: both units enabled by the preset and running; the service as its sandbox user, settings as rendered");

    // 1b. A desktop product from the same repository.
    assert!(
        !product_required("fixture")
            || lane
                .desktop
                .as_ref()
                .is_some_and(|d| d.helper_unit.is_some() && d.polkit_rule.is_some()),
        "the launcher fixture's lane builds the desktop product, with its helper"
    );
    if let Some(desktop) = &lane.desktop {
        run.desktop_product(desktop).await;
        steps.push("a desktop product: its /usr/bin link runs a core, its menu entry, icons and data files installed 0644, and its removal leaves none of them");
        if desktop.helper_unit.is_some() {
            steps.push("its update helper: the unit static and never started by the package; polkit lets an active local session start it (and systemd runs it), refuses that session stop, restart and another unit, and refuses a process in no session");
        }
    }

    // The lane's server: a version gate and a file server, on loopback.
    let family_other = match family {
        Family::Deb => Family::Rpm,
        Family::Rpm | Family::Pacman => Family::Deb,
    };

    // 2. Refused releases never reach the installer (v1 installed, the gate
    // naming v2).
    run.serve("v2", false).await;
    run.stage("v2", "v2", "v2", family_other, false).await;
    run.assert_refused(
        "a manifest for another format",
        "release manifest format mismatch",
        "v1",
    )
    .await;
    run.stage("v2", "v2", "v2", family, true).await;
    run.assert_refused("a tampered package", "digest mismatch", "v1")
        .await;
    if family != Family::Deb {
        // A manifest the trusted release key signed, over a package an
        // untrusted key signed: the package's own signature refuses it.
        run.stage("v2", "foreign-v2", "foreign-v2", family, false)
            .await;
        run.assert_refused(
            "a package signed by an untrusted key, under a trusted manifest",
            "package signature:",
            "v1",
        )
        .await;
    }
    steps.push("refused releases never reach the installer: a manifest for another format, a tampered package, an untrusted package signature under a trusted manifest (rpm, pacman)");

    // 3. The helper upgrades to v2, published: from the release tree
    // `seaworthy repo` wrote, as from the store.
    run.publish("v2").await;
    run.reset_throttle().await;
    let installed_v2 = format!("installed {} {}", lane.package, lane.logged("v2"));
    let (result, journal) = run.run_helper(&installed_v2).await;
    assert!(
        journal.contains(&installed_v2),
        "{}: the helper's upgrade to v2 (result {result}):\n{journal}",
        distro.name()
    );
    assert_eq!(result, "success", "{}: the helper's run", distro.name());
    run.assert_version("v2").await;
    let pid = run.wait_restarted(&service, &pid).await;
    assert_eq!(
        run.unit(&path_unit).await,
        ("enabled".into(), "active".into()),
        "{}",
        distro.name()
    );
    assert_eq!(
        run.show(&path_unit, "InvocationID").await,
        invocation,
        "{}: the update path unit is never restarted by an upgrade",
        distro.name()
    );
    assert!(
        run.install_runs().await > 0,
        "{}: the install ran in its unit",
        distro.name()
    );
    steps.push("the helper upgrades to v2 (requested as the app requests it), fetched from the published release tree: the service restarted; the path unit untouched; the run a success");
    if family != Family::Pacman {
        run.upgrade_repository_package("v2").await;
        steps.push("the repository package upgrades to v2's through the repository: its keyring now the rotation's two keys, the administrator's edit to its definition kept, nothing left beside it");
    }

    // 4. A downgrade is refused.
    run.serve("v1", false).await;
    run.stage("v1", "v1", "v1", family, false).await;
    let installs = run.install_runs().await;
    let (result, journal) = run.run_helper("refusing to downgrade").await;
    assert!(
        journal.contains("refusing to downgrade"),
        "{}: a downgrade (result {result}):\n{journal}",
        distro.name()
    );
    assert_ne!(
        result,
        "success",
        "{}: the downgrade's run must fail",
        distro.name()
    );
    run.assert_version("v2").await;
    assert_eq!(
        run.install_runs().await,
        installs,
        "{}: the older release reached the installer",
        distro.name()
    );
    steps.push("a downgrade is refused: the installer never ran, v2 still installed");

    // 5. An administrator's upgrade overtakes a run: the gate holds the
    // probe while the administrator installs v3 (which drops the helper)
    // with the service disabled.
    // The helper fetches v3 once released: the administrator publishes it
    // meanwhile.
    run.trust_next_key().await;
    run.serve("v3", true).await;
    run.reset_throttle().await;
    run.host
        .ok(&format!("systemctl disable --quiet {service}"))
        .await;
    let held = run.request_update().await;
    let helper = run.helper_unit();
    run.poll(
        &format!("[ -f {HELD} ]"),
        60,
        &helper,
        "never reached the gate",
    )
    .await;
    let helper_pid = run.show(&helper, "MainPID").await;
    run.publish("v3").await;
    run.install("v3", Source::Repository).await;
    run.wait_restarted(&service, &pid).await;
    assert_eq!(
        (
            run.show(&helper, "ActiveState").await,
            run.show(&helper, "MainPID").await
        ),
        ("activating".to_owned(), helper_pid),
        "{}: the administrator's upgrade stopped or restarted the running helper",
        distro.name()
    );
    run.host.ok(&format!("touch {RELEASE}")).await;
    let (result, journal) = run
        .helper_outcome(&held, "the installed release changed during the run")
        .await;
    assert!(
        journal.contains("the installed release changed during the run"),
        "{}: the overtaken run (result {result}):\n{journal}",
        distro.name()
    );
    run.assert_version("v3").await;
    run.wait_inactive(&path_unit).await;
    let (enabled, _) = run.unit(&path_unit).await;
    assert!(
        matches!(enabled.as_str(), "" | "not-found" | "disabled"),
        "{}: the dropped trigger is {enabled}",
        distro.name()
    );
    assert_eq!(
        run.links(&path_unit).await,
        Vec::<String>::new(),
        "{}: the dropped trigger was disabled, not just stopped",
        distro.name()
    );
    assert_eq!(
        run.unit(&service).await.0,
        "disabled",
        "{}: an upgrade keeps the administrator's disable",
        distro.name()
    );
    run.host
        .ok(&format!("systemctl enable --quiet {service}"))
        .await;
    steps.push("an administrator's upgrade to v3 (repositories and packages signed by the rotation's next key) from the repository, once published (no helper; the service disabled), overtakes a held run: the running helper never stopped, then refusing to install over the changed release; the trigger stopped and disabled; the service still disabled");

    // 6. A downgrade to v2, with the service masked by the administrator:
    // the trigger is back, the mask stays.
    run.host
        .ok(&format!("systemctl mask --now --quiet {service}"))
        .await;
    run.install("v2", Source::File { downgrade: true }).await;
    run.wait_active(&path_unit).await;
    assert_eq!(
        run.unit(&path_unit).await,
        ("enabled".into(), "active".into()),
        "{}",
        distro.name()
    );
    assert_eq!(
        run.unit(&service).await,
        ("masked".into(), "inactive".into()),
        "{}: a downgrade keeps the administrator's mask",
        distro.name()
    );
    run.host
        .ok(&format!(
            "systemctl unmask --quiet {service} && systemctl start {service}"
        ))
        .await;
    run.wait_active(&service).await;
    steps.push("downgrade to v2 from its file (the service masked by the administrator): the trigger back, enabled and running; the service still masked");

    // 7. The helper upgrades to v3, removing itself: the scripts stop only
    // the trigger, so its install finishes and is confirmed.
    run.serve("v3", false).await;
    run.reset_throttle().await;
    let installed_v3 = format!("installed {} {}", lane.package, lane.logged("v3"));
    let (result, journal) = run.run_helper(&installed_v3).await;
    assert!(
        journal.contains(&installed_v3),
        "{}: the helper's upgrade to v3, which removes it (result {result}):\n{journal}",
        distro.name()
    );
    run.assert_version("v3").await;
    run.wait_inactive(&path_unit).await;
    run.wait_active(&service).await;
    steps.push("the helper upgrades to v3 from the published release tree, removing itself: its install finished and confirmed; the trigger gone");

    // 8. Removal: units stopped and disabled, state and user kept.
    run.remove(false).await;
    for unit in [&service, &path_unit] {
        run.wait_inactive(unit).await;
    }
    assert_eq!(
        run.links(&format!("{}*", lane.service)).await,
        Vec::<String>::new(),
        "{}: removal disables both units",
        distro.name()
    );
    run.assert_state_kept("removal").await;
    steps.push("remove: both units stopped and disabled; the state directory and the user kept");

    // 9. A reinstall after removal (v2, with the helper): both units enabled
    // and running again.
    run.install("v2", Source::File { downgrade: false }).await;
    run.wait_active(&service).await;
    run.wait_active(&path_unit).await;
    for unit in [&service, &path_unit] {
        assert_eq!(
            run.unit(unit).await,
            ("enabled".into(), "active".into()),
            "{}: {unit} after a reinstall",
            distro.name()
        );
    }
    steps.push("reinstall v2 from its file after removal: both units enabled and running again");

    // 10. deb: purge keeps the state and the user.
    if family == Family::Deb {
        run.remove(true).await;
        run.assert_state_kept("purge").await;
        steps.push("purge: the state directory and the user kept");
    }

    run.signatures().await;
    run.report
        .insert("distro".into(), Value::String(distro.name().into()));
    run.report
        .insert("image".into(), Value::String(distro.image().into()));
    run.report.insert(
        "steps".into(),
        Value::Array(steps.into_iter().map(|s| Value::String(s.into())).collect()),
    );
    let report = serde_json::to_string_pretty(&Value::Object(run.report)).unwrap();
    let dir: &Path = &lane.dir.join("report");
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join(format!("{}.json", distro.name())),
        format!("{report}\n"),
    )
    .unwrap();
    println!("{}: conformance passed\n{report}", distro.name());
}

#[tokio::test(flavor = "multi_thread")]
async fn debian_13() {
    conformance(Distro::Debian13).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ubuntu_24_04() {
    conformance(Distro::Ubuntu2404).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ubi_9() {
    conformance(Distro::Ubi9).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn fedora_43() {
    conformance(Distro::Fedora43).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn arch() {
    conformance(Distro::Arch).await;
}

/// The device itself drives its update (`lane.json`'s `device-driven`: a
/// reference product whose service asks its helper when
/// its version gate refuses a newer server). v1 installed from the
/// repository with the device pointed at the lane's gate (the server
/// configuration file its helper reads too) while the gate names the
/// device's own version: it connects and asks for nothing. Then v2 is
/// published and the gate names it: the device's next connect is refused,
/// the device truncates its update request file (nothing in this test
/// does), and the helper installs v2 from the published repository; the
/// service restarts on it.
async fn device_driven(distro: Distro) {
    if !seaworthy_test_support::docker_or_skip().await {
        return;
    }
    let Some(lane) = lane() else { return };
    let Some(device) = lane.device.clone() else {
        assert!(
            !product_required("reference"),
            "the reference product's lane.json has no device-driven scenario"
        );
        eprintln!(
            "SKIPPED: this lane's product has no device-driven scenario (the reference product's lane has: scripts/linux-conformance.sh reference)"
        );
        return;
    };
    let family = distro.family();
    let host = systemd::start(distro, &lane.files(family)).await;
    let mut run = Run {
        host,
        lane: &lane,
        family,
        report: serde_json::Map::new(),
    };
    let (service, helper) = (run.service(), run.helper_unit());
    run.set_up().await;
    // The device's server: the lane's gate, naming v1 (the device's own
    // version: v1's build compiled its token from v1's name).
    run.serve("v1", false).await;
    let dir = Path::new(&device.config)
        .parent()
        .unwrap()
        .display()
        .to_string();
    // The configuration directory and its parent as a package would leave
    // them (0755, root's), asserted: the update helper reads its policy only
    // from a directory nobody else can write, so a world-writable one turns
    // updates off (CI's docker-in-docker ran execs under umask 0000).
    let parent = Path::new(&dir).parent().unwrap().display().to_string();
    run.host
        .ok(&format!(
            "mkdir -p {dir} && chmod 0755 {parent} {dir} && cat > {config} <<'EOF'\n{content}EOF\nchmod 0644 {config}",
            config = device.config,
            content = device.content
        ))
        .await;
    assert_eq!(
        run.host
            .ok(&format!("stat -c '%a %U' {parent} {dir}"))
            .await
            .lines()
            .collect::<Vec<_>>(),
        ["755 root", "755 root"],
        "{}: the configuration directories' modes",
        distro.name()
    );
    run.publish("v1").await;
    run.install("v1", Source::Repository).await;
    // The fresh install as the lifecycle suite checks it: units enabled and
    // running, the sandbox user, the tree, the command line, the core's
    // first line (here: which core runs, FIPS mode on), the rendered
    // settings, systemd's exposure scores and its verify.
    run.check_fresh_install().await;
    let pid = run.show(&service, "MainPID").await;
    let before = run.show(&helper, "InvocationID").await;
    // A newer server: v2 published, the gate naming it.
    run.publish("v2").await;
    run.serve("v2", false).await;
    // The device's next connect is refused; it asks; the helper runs.
    run.poll(
        &format!(
            "id=$(systemctl show -p InvocationID --value {helper}) && [ -n \"$id\" ] && [ \"$id\" != '{before}' ]"
        ),
        240,
        &helper,
        "never started: the device didn't ask for the server's release",
    )
    .await;
    let invocation = run.show(&helper, "InvocationID").await;
    let installed = format!("installed {} {}", lane.package, lane.logged("v2"));
    let (result, journal) = run.helper_outcome(&invocation, &installed).await;
    assert!(
        journal.contains(&installed),
        "{}: the device-requested run didn't install v2 ({result}):\n{journal}",
        distro.name()
    );
    assert_eq!(result, "success", "{}:\n{journal}", distro.name());
    run.assert_version("v2").await;
    let new_pid = run.wait_restarted(&service, &pid).await;
    // v2's device is v2's server's: its version gate lets it through (it
    // goes on to enroll, which needs a ticket this lane doesn't give), and
    // it asks for nothing more.
    let accepted = "DEVICE_ENROLLMENT_KEY must be set to enroll a new device";
    run.poll(
        &format!("journalctl --no-pager -o cat _PID={new_pid} | grep -qF '{accepted}'"),
        120,
        &service,
        "never got past the version gate after the update",
    )
    .await;
    let after = run
        .host
        .ok(&format!(
            "journalctl --no-pager -o cat _PID={new_pid} | grep -cF 'asked the update helper' || true"
        ))
        .await;
    assert_eq!(
        after.trim(),
        "0",
        "{}: the updated device still asked for an update",
        distro.name()
    );
    // The request was the device's: its own journal says it asked, naming
    // the server's version (nothing in this test touched the request file).
    let asked = run
        .host
        .ok(&format!(
            "journalctl --no-pager -o cat -u {service} | grep -F 'asked the update helper to install it' || true"
        ))
        .await;
    assert!(
        asked.contains(&lane.gate_token("v2")),
        "{}: the device never logged asking for v2:\n{asked}",
        distro.name()
    );
    run.report
        .insert("distro".into(), Value::String(distro.name().into()));
    run.report
        .insert("image".into(), Value::String(distro.image().into()));
    run.report.insert(
        "device request".into(),
        Value::String(asked.lines().next().unwrap_or_default().trim().into()),
    );
    run.report.insert(
        "after the update".into(),
        Value::String(format!(
            "pid {new_pid}: through the version gate, nothing asked"
        )),
    );
    run.report.insert(
        "helper run".into(),
        Value::String(
            journal
                .lines()
                .find(|l| l.contains(&installed))
                .unwrap_or_default()
                .trim()
                .into(),
        ),
    );
    let report = serde_json::to_string_pretty(&Value::Object(run.report)).unwrap();
    let dir: &Path = &lane.dir.join("report");
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join(format!("device-driven-{}.json", distro.name())),
        format!("{report}\n"),
    )
    .unwrap();
    println!("{}: device-driven update passed\n{report}", distro.name());
}

#[tokio::test(flavor = "multi_thread")]
async fn device_driven_debian_13() {
    device_driven(Distro::Debian13).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn device_driven_ubuntu_24_04() {
    device_driven(Distro::Ubuntu2404).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn device_driven_ubi_9() {
    device_driven(Distro::Ubi9).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn device_driven_fedora_43() {
    device_driven(Distro::Fedora43).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn device_driven_arch() {
    device_driven(Distro::Arch).await;
}

/// Whether the lane script asked for `product`'s scenario
/// (`SEAWORTHY_CONFORMANCE_PRODUCT`): then a scenario that can't run fails
/// instead of skipping.
fn product_required(product: &str) -> bool {
    // allow-std-env: the lane script's product
    std::env::var("SEAWORTHY_CONFORMANCE_PRODUCT").is_ok_and(|p| p == product)
}
