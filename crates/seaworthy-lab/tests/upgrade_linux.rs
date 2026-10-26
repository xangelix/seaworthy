//! The upgrade-from-previous lane on Linux: the lab fixture's PREVIOUS
//! build (the latest successful lab run on `main`, fetched and checked by
//! `scripts/upgrade-previous.sh`) installed, then updated to this
//! checkout's build (`scripts/upgrade-candidate.sh linux`) by its own
//! update helper, exactly as a fleet updates — on Debian 13, Ubuntu 24.04,
//! UBI 9, Fedora 43 and Arch, systemd as PID 1 in an unprivileged container
//! (seaworthy-test-support's systemd hosts, as the conformance suite runs).
//!
//! Both builds are non-release builds of the desktop fixture's `agent`
//! product (`crates/seaworthy-launcher/e2e/desktop/seaworthy.toml`),
//! signed with the public CI test key their helpers are built to trust.
//!
//! Per distribution, in one host:
//!
//! 1. **the previous build**, installed by the distribution's package
//!    manager: the service running, the path unit waiting;
//! 2. **the lab**: the lab server on 443, behind TLS from a throwaway CA
//!    (name-constrained to the lab's names, its key never written) the
//!    host's system store trusts (the helper's platform verifier reads
//!    it), under the names the helper dials (hosts entries):
//!    `updates.lab.invalid` answers the candidate's version token at the
//!    required-version endpoint, `packages.lab.invalid` serves the release
//!    tree with the candidate's package;
//! 3. **policy honored**: an administrator's `updates = "off"` policy
//!    file; the service's user asks for an update (the request file the
//!    path unit watches, as the app asks) and the helper installs nothing;
//! 4. **another key refused**: the candidate's manifest re-signed by a
//!    throwaway key; the helper refuses it ("no trusted release key
//!    verified it") and installs nothing;
//! 5. **the update**: once the helper's backoff has passed (a run within
//!    30 s of the last is throttled; a failed release waits a minute), the
//!    real manifest; the helper installs the candidate;
//! 6. **the transition**: the package manager reports the candidate, the
//!    helper's journal says it installed it, the service restarted on the
//!    new build (a new main PID, its core's start-up line), the installed
//!    files are the candidate's (`lab/build.txt` names its token), the path
//!    unit was never restarted, and the service's state survived (a file
//!    in its state directory, the directory still its user's and 0700).
//!
//! Each distribution's findings land in `$SEAWORTHY_UPGRADE_REPORT/<distro>.json`
//! when that is set.
//!
//! Runs only with `--features upgrade` and `SEAWORTHY_UPGRADE_PREVIOUS` and
//! `SEAWORTHY_UPGRADE_CANDIDATE` naming the two builds
//! (`scripts/upgrade-linux.sh` sets them); the candidate carries the lab
//! server (`bin/conformance_server`, built beside it in the pinned
//! builder, whose glibc every distribution here runs).
//! `SEAWORTHY_TEST_CONTAINERS_REQUIRED=1` turns a missing docker daemon or
//! lane into a failure.

#![cfg(all(unix, feature = "upgrade"))]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs,
    reason = "test assertions"
)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use seaworthy_lab::ca::{DEFAULT_VALIDITY, LabCa};
use seaworthy_test_support::systemd::{self, Distro, Family, SystemdHost};
use serde_json::{Value, json};

const TARGET: &str = "x86_64-unknown-linux-gnu";
const CHANNEL: &str = "stable";
const PACKAGES_HOST: &str = "packages.lab.invalid";
const UPDATES_HOST: &str = "updates.lab.invalid";
const SERVICE: &str = "AcmeAgent.service";
const HELPER: &str = "AcmeAgent-update.service";
const PATH_UNIT: &str = "AcmeAgent-update.path";
const USER: &str = "acme-agent";
const STATE: &str = "/var/lib/acme/agent";
const POLICY: &str = "/etc/acme/agent/policy.toml";
const MARKER: &str = "/opt/acme/agent/lab/build.txt";
/// What the helper says of a manifest no compiled-in key verifies.
const REFUSED: &str = "no trusted release key verified it";
/// What it says when the administrator's policy is `off`.
const POLICY_OFF: &str = "update policy is `off` from";
/// The helper's run throttle (30 s) and a failed release's first backoff
/// (one minute), with slack.
const BACKOFF: Duration = Duration::from_secs(70);

/// One lab build (`lab-build.json`, written by scripts/upgrade-candidate.sh).
struct Build {
    dir: PathBuf,
    package: String,
    version: String,
    sequence: u64,
    token: String,
    trust: String,
}

impl Build {
    fn read(dir: &Path) -> Self {
        let path = dir.join("lab-build.json");
        let text = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let build: Value = serde_json::from_slice(&text).unwrap();
        assert_eq!(build["format"], json!(1), "{}: format", path.display());
        assert_eq!(
            build["platform"],
            json!("linux"),
            "{}: platform",
            path.display()
        );
        assert_eq!(
            build["product"],
            json!("agent"),
            "{}: product",
            path.display()
        );
        let listing: Value =
            serde_json::from_slice(&std::fs::read(dir.join("packages.json")).unwrap()).unwrap();
        assert_eq!(
            listing["ci_test"],
            json!(true),
            "{}: signed with the CI test key",
            dir.display()
        );
        let string = |key: &str| build[key].as_str().unwrap().to_owned();
        Self {
            dir: dir.to_owned(),
            package: string("package"),
            version: string("version"),
            sequence: build["sequence"].as_u64().unwrap(),
            token: string("token"),
            trust: string("trust"),
        }
    }

    /// The one package of `family`.
    fn package_file(&self, family: Family) -> PathBuf {
        let suffix = match family {
            Family::Deb => "_amd64.deb",
            Family::Rpm => ".x86_64.rpm",
            Family::Pacman => "-x86_64.pkg.tar.zst",
        };
        let found: Vec<PathBuf> = std::fs::read_dir(self.dir.join("packages"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(&self.package) && name.ends_with(suffix))
            })
            .collect();
        assert_eq!(
            found.len(),
            1,
            "one *{suffix} in {}: {found:?}",
            self.dir.display()
        );
        found.into_iter().next().unwrap()
    }

    /// How the package manager spells this build's release.
    fn installed(&self) -> String {
        format!("{}-{}", self.version, self.sequence)
    }
}

/// The lane's inputs, or `None`: the suite skips.
struct Lane {
    previous: Build,
    candidate: Build,
    server: PathBuf,
    report: Option<PathBuf>,
}

impl Lane {
    fn from_env() -> Option<Self> {
        // allow-std-env: the builds the lane's script fetched and built
        let candidate = std::env::var_os("SEAWORTHY_UPGRADE_CANDIDATE").map(PathBuf::from);
        let previous = std::env::var_os("SEAWORTHY_UPGRADE_PREVIOUS").map(PathBuf::from);
        let (Some(candidate), Some(previous)) = (candidate, previous) else {
            assert!(
                !seaworthy_test_support::required(),
                "SEAWORTHY_UPGRADE_PREVIOUS and SEAWORTHY_UPGRADE_CANDIDATE are unset (run scripts/upgrade-linux.sh)"
            );
            eprintln!(
                "SKIPPED: SEAWORTHY_UPGRADE_PREVIOUS/CANDIDATE unset (run scripts/upgrade-linux.sh)"
            );
            return None;
        };
        let (previous, candidate) = (Build::read(&previous), Build::read(&candidate));
        assert_eq!(previous.package, candidate.package, "one product");
        assert_eq!(
            previous.trust, candidate.trust,
            "the previous build's helper trusts another CI test key than the candidate is signed with \
             (scripts/upgrade-previous.sh skips such a build)"
        );
        assert!(
            previous.sequence < candidate.sequence,
            "the candidate ({}) is newer than the previous build ({})",
            candidate.sequence,
            previous.sequence
        );
        let server = candidate.dir.join("bin/conformance_server");
        assert!(server.is_file(), "{}: the lab server", server.display());
        Some(Self {
            previous,
            candidate,
            server,
            // allow-std-env: where the lane's script collects the reports
            report: std::env::var_os("SEAWORTHY_UPGRADE_REPORT").map(PathBuf::from),
        })
    }
}

/// The format tag the release tree names a package by (`{format}`).
fn tag(family: Family) -> &'static str {
    match family {
        Family::Deb => "deb",
        Family::Rpm => "rpm",
        Family::Pacman => "pacman",
    }
}

/// Installs the previous build's package, and what it declares.
fn install_command(family: Family, file: &str) -> String {
    match family {
        Family::Deb => format!(
            "export DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1; \
             apt-get update -qq && apt-get install -y -qq --no-install-recommends {file}"
        ),
        Family::Rpm => format!("dnf install -y -q --setopt=install_weak_deps=False {file}"),
        Family::Pacman => format!("pacman -U --noconfirm {file}"),
    }
}

/// Makes the system store trust the lab's CA, as each distribution adds a
/// local anchor.
fn trust_command(family: Family) -> &'static str {
    match family {
        Family::Deb => {
            "cp /lab/tls/ca.pem /usr/local/share/ca-certificates/seaworthy-lab.crt && update-ca-certificates"
        }
        Family::Rpm => {
            "cp /lab/tls/ca.pem /etc/pki/ca-trust/source/anchors/seaworthy-lab.pem && update-ca-trust extract"
        }
        Family::Pacman => {
            "cp /lab/tls/ca.pem /etc/ca-certificates/trust-source/anchors/seaworthy-lab.crt && update-ca-trust"
        }
    }
}

struct Run {
    host: SystemdHost,
    family: Family,
    report: serde_json::Map<String, Value>,
}

impl Run {
    fn name(&self) -> &'static str {
        self.host.distro().name()
    }

    async fn installed(&self, package: &str) -> String {
        let query = match self.family {
            Family::Deb => format!("dpkg-query -W -f='${{Version}}' {package}"),
            Family::Rpm => format!("rpm -q --qf '%{{VERSION}}-%{{RELEASE}}' {package}"),
            Family::Pacman => format!("pacman -Q {package} | cut -d' ' -f2"),
        };
        self.host.ok(&query).await.trim().to_owned()
    }

    async fn show(&self, unit: &str, property: &str) -> String {
        self.host
            .ok(&format!("systemctl show -p {property} --value {unit}"))
            .await
            .trim()
            .to_owned()
    }

    /// Everything the lane's units said since `since` (a `date +%s`).
    async fn journals(&self, since: &str) -> String {
        self.host
            .sh(&format!(
                "journalctl --no-pager --since @{since} -u {SERVICE} -u {HELPER} -u {PATH_UNIT} -u seaworthy-lab"
            ))
            .await
            .stdout
    }

    async fn now(&self) -> String {
        self.host.ok("date +%s").await.trim().to_owned()
    }

    /// Polls `condition` (a shell test) for up to `seconds`.
    async fn poll(&self, condition: &str, seconds: u64, since: &str, what: &str) {
        let start = Instant::now();
        while self.host.sh(condition).await.code != Some(0) {
            assert!(
                start.elapsed() < Duration::from_secs(seconds),
                "{}: {what} within {seconds} s; the lane's journals:\n{}",
                self.name(),
                self.journals(since).await
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// Asks for an update as the app does (the service's user truncates the
    /// request file the path unit watches), waits for the helper run it
    /// starts to end; that run's result and journal.
    async fn request_update(&self, since: &str) -> (String, String) {
        let before = self.show(HELPER, "InvocationID").await;
        self.host
            .ok(&format!(
                "systemd-run --wait --collect --quiet --uid={USER} --gid={USER} /bin/sh -c ': > {STATE}/update-request'"
            ))
            .await;
        self.poll(
            &format!(
                "id=$(systemctl show -p InvocationID --value {HELPER}) && [ -n \"$id\" ] && [ \"$id\" != '{before}' ]"
            ),
            60,
            since,
            "the helper started on the update request",
        )
        .await;
        let invocation = self.show(HELPER, "InvocationID").await;
        self.poll(
            &format!(
                "state=$(systemctl show -p ActiveState --value {HELPER}) && \
                 [ \"$state\" != activating ] && [ \"$state\" != active ] && [ \"$state\" != deactivating ]"
            ),
            900,
            since,
            "the helper's run ended",
        )
        .await;
        let result = self.show(HELPER, "Result").await;
        // journald may still be writing the run's last lines.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let journal = self
            .host
            .ok(&format!(
                "journalctl --no-pager -o cat _SYSTEMD_INVOCATION_ID={invocation}"
            ))
            .await;
        (result, journal)
    }

    /// The installed release is still `release` and the service the same
    /// process (`pid`).
    async fn assert_untouched(&self, case: &str, release: &str, pid: &str) {
        let package = self.report["package"].as_str().unwrap().to_owned();
        assert_eq!(
            self.installed(&package).await,
            release,
            "{}: {case}: the installed release changed",
            self.name()
        );
        assert_eq!(
            self.show(SERVICE, "MainPID").await,
            pid,
            "{}: {case}: the service was stopped or restarted",
            self.name()
        );
    }
}

async fn upgrade(distro: Distro) {
    let Some(lane) = Lane::from_env() else { return };
    if !seaworthy_test_support::docker_or_skip().await {
        return;
    }
    let family = distro.family();
    let (previous, candidate) = (&lane.previous, &lane.candidate);
    let package = candidate.package.clone();

    // The host's files: the previous package, the release tree (the
    // candidate's package; its real manifest and one another key signed,
    // beside the tree), the lab server, its TLS and its token.
    let old = previous.package_file(family);
    let old_inside = format!(
        "/lab/previous/{}",
        old.file_name().unwrap().to_string_lossy()
    );
    let new = candidate.package_file(family);
    let tree = format!(
        "/lab/root/repo/releases/{package}/{CHANNEL}/{token}/{TARGET}/{package}.{tag}",
        token = candidate.token,
        tag = tag(family)
    );
    let manifest = std::fs::read(format!("{}.manifest", new.display())).unwrap();
    let foreign = seaworthy_lab::manifest::resign_with_throwaway_key(&manifest).unwrap();
    let ca = LabCa::generate(
        &[PACKAGES_HOST.to_owned(), UPDATES_HOST.to_owned()],
        DEFAULT_VALIDITY,
    )
    .unwrap();
    let files = vec![
        (old_inside.clone(), std::fs::read(&old).unwrap()),
        (tree.clone(), std::fs::read(&new).unwrap()),
        ("/lab/manifests/real".to_owned(), manifest),
        ("/lab/manifests/foreign".to_owned(), foreign),
        (
            "/lab/bin/conformance_server".to_owned(),
            std::fs::read(&lane.server).unwrap(),
        ),
        (
            "/lab/tls/ca.pem".to_owned(),
            ca.ca_pem().as_bytes().to_vec(),
        ),
        (
            "/lab/tls/leaf.pem".to_owned(),
            ca.leaf_pem().as_bytes().to_vec(),
        ),
        (
            "/lab/tls/leaf.key".to_owned(),
            ca.leaf_key_pem().as_bytes().to_vec(),
        ),
        (
            "/lab/token".to_owned(),
            format!("{}\n", candidate.token).into_bytes(),
        ),
    ];
    let host = systemd::start(distro, &files).await;
    let mut run = Run {
        host,
        family,
        report: serde_json::Map::new(),
    };
    run.report.insert("package".into(), json!(package));
    run.report
        .insert("previous".into(), json!(previous.installed()));
    run.report
        .insert("candidate".into(), json!(candidate.installed()));
    let started = run.now().await;
    let mut steps = Vec::new();

    // 1. The previous build.
    run.host.ok(&install_command(family, &old_inside)).await;
    assert_eq!(
        run.installed(&package).await,
        previous.installed(),
        "{}: the previous build is installed",
        run.name()
    );
    run.poll(
        &format!(
            "systemctl is-active --quiet {SERVICE} && systemctl is-active --quiet {PATH_UNIT}"
        ),
        60,
        &started,
        "the service and its path unit running",
    )
    .await;
    // The service's state: a file in its state directory, as its own
    // user writes it.
    run.host
        .ok(&format!(
            "systemd-run --wait --collect --quiet --uid={USER} --gid={USER} /bin/sh -c 'echo kept > {STATE}/lab-state'"
        ))
        .await;
    let first_pid = run.show(SERVICE, "MainPID").await;
    let path_invocation = run.show(PATH_UNIT, "InvocationID").await;
    steps.push(format!(
        "installed the previous build ({})",
        previous.installed()
    ));

    // 2. The lab: its names, its CA in the system store, the server.
    run.host
        .ok(&format!(
            "printf '127.0.0.1 {PACKAGES_HOST} {UPDATES_HOST}\\n' >> /etc/hosts"
        ))
        .await;
    run.host.ok(trust_command(family)).await;
    run.host
        .ok(
            "chmod 0755 /lab/bin/conformance_server && chmod 0600 /lab/tls/leaf.key && \
             systemd-run --unit=seaworthy-lab --quiet /lab/bin/conformance_server --root /lab/root \
             --token-file /lab/token --ready /lab/ready --listen 127.0.0.1:443 \
             --tls-cert /lab/tls/leaf.pem --tls-key /lab/tls/leaf.key",
        )
        .await;
    run.poll(
        "test -f /lab/ready",
        30,
        &started,
        "the lab server listening",
    )
    .await;
    steps.push(
        "the lab: a name-constrained CA in the system store, the server on 443 behind TLS"
            .to_owned(),
    );

    // 3. The administrator's policy says off: nothing is installed.
    run.host
        .ok(&format!(
            "mkdir -p $(dirname {POLICY}) && printf 'updates = \"off\"\\n' > {POLICY} && chmod 0644 {POLICY}"
        ))
        .await;
    let (result, journal) = run.request_update(&started).await;
    assert!(
        journal.contains(POLICY_OFF),
        "{}: the helper honors the policy (result {result}):\n{journal}",
        run.name()
    );
    run.assert_untouched("the policy's off", &previous.installed(), &first_pid)
        .await;
    run.host.ok(&format!("rm -f {POLICY}")).await;
    steps.push("an administrator's `off` policy: the helper installs nothing".to_owned());

    // 4. A manifest another key signed: refused.
    run.host
        .ok(&format!("cp /lab/manifests/foreign '{tree}.manifest'"))
        .await;
    let (result, journal) = run.request_update(&started).await;
    assert!(
        journal.contains(REFUSED),
        "{}: the helper refuses another key's manifest (result {result}):\n{journal}",
        run.name()
    );
    assert_ne!(result, "success", "{}: the refused run fails", run.name());
    let refused_at = Instant::now();
    run.assert_untouched("another key", &previous.installed(), &first_pid)
        .await;
    steps.push("a manifest another key signed: refused, nothing installed".to_owned());

    // 5. The update, once the backoff has passed.
    tokio::time::sleep(BACKOFF.saturating_sub(refused_at.elapsed())).await;
    run.host
        .ok(&format!("cp /lab/manifests/real '{tree}.manifest'"))
        .await;
    let updating = run.now().await;
    let (result, journal) = run.request_update(&updating).await;
    let installed_line = format!(
        "installed {package} {} (sequence {})",
        candidate.version, candidate.sequence
    );
    assert!(
        result == "success" && journal.contains(&installed_line),
        "{}: the helper installs the candidate (result {result}):\n{journal}\n\nthe lane's journals:\n{}",
        run.name(),
        run.journals(&updating).await
    );
    steps.push(format!(
        "the helper installed the candidate ({})",
        candidate.installed()
    ));

    // 6. The transition.
    assert_eq!(
        run.installed(&package).await,
        candidate.installed(),
        "{}: the candidate is installed",
        run.name()
    );
    run.poll(
        &format!(
            "pid=$(systemctl show -p MainPID --value {SERVICE}) && [ \"$pid\" != 0 ] && [ \"$pid\" != '{first_pid}' ] && \
             systemctl is-active --quiet {SERVICE}"
        ),
        120,
        &updating,
        "the service running again under a new process",
    )
    .await;
    run.poll(
        &format!(
            "journalctl --no-pager -o cat --since @{updating} -u {SERVICE} | grep -q '^core='"
        ),
        60,
        &updating,
        "the restarted service's core start-up line",
    )
    .await;
    assert_eq!(
        run.host.ok(&format!("cat {MARKER}")).await.trim(),
        candidate.token,
        "{}: the installed files are the candidate's",
        run.name()
    );
    assert_eq!(
        run.show(PATH_UNIT, "InvocationID").await,
        path_invocation,
        "{}: the update path unit was restarted",
        run.name()
    );
    assert_eq!(
        run.host.ok(&format!("cat {STATE}/lab-state")).await.trim(),
        "kept",
        "{}: the service's state survives",
        run.name()
    );
    assert_eq!(
        run.host
            .ok(&format!("stat -c '%a %U' {STATE}"))
            .await
            .trim(),
        format!("700 {USER}"),
        "{}: the state directory",
        run.name()
    );
    steps.push(
        "the transition: the candidate installed and running (a new process, its core), its files in place, \
         the path unit untouched, the state kept"
            .to_owned(),
    );

    run.report.insert("steps".into(), json!(steps));
    run.report.insert(
        "systemd".into(),
        json!(run.host.ok("systemctl --version | head -n1").await.trim()),
    );
    if let Some(dir) = &lane.report {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join(format!("{}.json", run.name())),
            serde_json::to_vec_pretty(&Value::Object(run.report.clone())).unwrap(),
        )
        .unwrap();
    }
    println!(
        "{}: upgraded {} -> {}",
        run.name(),
        previous.installed(),
        candidate.installed()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn debian_13() {
    upgrade(Distro::Debian13).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ubuntu_24_04() {
    upgrade(Distro::Ubuntu2404).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ubi_9() {
    upgrade(Distro::Ubi9).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fedora_43() {
    upgrade(Distro::Fedora43).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn arch() {
    upgrade(Distro::Arch).await;
}

/// The lane's view of the builds it reads, on a build written as
/// scripts/upgrade-candidate.sh writes one.
#[test]
fn reads_a_lab_build() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("packages")).unwrap();
    std::fs::write(
        dir.path().join("lab-build.json"),
        r#"{"format": 1, "platform": "linux", "product": "agent", "package": "acme-agent",
            "version": "0.1.0", "sequence": 42, "build": "g0123456789ab",
            "token": "0.1.0+g0123456789ab", "commit": "0123456789ab", "trust": "ab12", "files": {}}"#,
    )
    .unwrap();
    std::fs::write(dir.path().join("packages.json"), r#"{"ci_test": true}"#).unwrap();
    for name in [
        "acme-agent_0.1.0-42_amd64.deb",
        "acme-agent-0.1.0-42.x86_64.rpm",
        "acme-agent-0.1.0-42-x86_64.pkg.tar.zst",
        "acme-agent_0.1.0-42_amd64.deb.manifest",
    ] {
        std::fs::write(dir.path().join("packages").join(name), b"x").unwrap();
    }
    let build = Build::read(dir.path());
    assert_eq!(build.installed(), "0.1.0-42");
    assert_eq!(build.token, "0.1.0+g0123456789ab");
    for family in [Family::Deb, Family::Rpm, Family::Pacman] {
        assert!(build.package_file(family).is_file());
    }
}
