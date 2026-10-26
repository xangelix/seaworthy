//! The policy on Linux (and other Unix systems, which have no package
//! holds to find): package holds first, then the administrator's file,
//! which may also name the machine's update server.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use seaworthy_fsguard::mode::{Owners, untrusted};

use super::{
    AdminServer, PolicyDecision, PolicyFile, PolicySource, UpdatePolicy, dpkg_holds,
    parse_policy_settings, versionlock_holds,
};
use crate::Product;

/// The longest policy file read: its settings and comments.
const MAX_POLICY_BYTES: u64 = 64 * 1024;

/// The longest package database file read for a hold (dpkg's status file
/// on a large system is a few MiB).
const MAX_HOLDS_BYTES: u64 = 64 * 1024 * 1024;

/// Where the reader looks: `/` and the system's `pacman-conf` outside
/// tests.
#[derive(Debug, Clone)]
pub(crate) struct Machine {
    /// Every path is read under this root.
    pub(crate) root: PathBuf,
    /// `pacman-conf`, run when `<root>/etc/pacman.conf` exists.
    pub(crate) pacman_conf: PathBuf,
    /// Whether files and directories must be root's. Tests, which can't
    /// create root's files, turn it off; group- and world-writable files
    /// and symlinks are refused either way.
    pub(crate) require_root_owner: bool,
}

impl Machine {
    /// This machine.
    pub(crate) fn system() -> Self {
        Self {
            root: PathBuf::from("/"),
            pacman_conf: PathBuf::from("/usr/bin/pacman-conf"),
            require_root_owner: true,
        }
    }

    fn path(&self, absolute: &Path) -> PathBuf {
        self.root
            .join(absolute.strip_prefix("/").unwrap_or(absolute))
    }
}

/// Reads `absolute` under the machine's root, if it exists and isn't
/// larger than `limit`.
fn read_capped(machine: &Machine, absolute: &str, limit: u64) -> Option<String> {
    use std::io::Read as _;
    let file = std::fs::File::open(machine.path(Path::new(absolute))).ok()?;
    let mut text = String::new();
    file.take(limit).read_to_string(&mut text).ok()?;
    Some(text)
}

/// macOS links `/etc` to `private/etc` (root's, under System Integrity
/// Protection): the walk follows that one link, checked, and no other.
#[cfg(target_os = "macos")]
fn system_link(path: &Path) -> std::borrow::Cow<'_, Path> {
    let link = Path::new("/etc");
    let Ok(rest) = path.strip_prefix(link) else {
        return path.into();
    };
    match (std::fs::symlink_metadata(link), std::fs::read_link(link)) {
        (Ok(metadata), Ok(target))
            if metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && target == Path::new("private/etc") =>
        {
            Path::new("/private/etc").join(rest).into()
        }
        _ => path.into(),
    }
}

#[cfg(not(target_os = "macos"))]
fn system_link(path: &Path) -> std::borrow::Cow<'_, Path> {
    path.into()
}

/// `path` and each directory above it, up to and including `top`, must be
/// root's (when `require_root_owner`), not writable by group or others,
/// and not a symlink (macOS's own `/etc` link aside, [`system_link`]).
pub(crate) fn trusted(path: &Path, top: &Path, require_root_owner: bool) -> Result<(), String> {
    let (path, top) = (system_link(path), system_link(top));
    let (path, top) = (path.as_ref(), top.as_ref());
    let owners = if require_root_owner {
        Owners::Root
    } else {
        Owners::Anyone
    };
    let mut current = Some(path);
    while let Some(p) = current {
        let metadata = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
        if let Some(why) = untrusted(
            &p.display().to_string(),
            metadata.uid(),
            metadata.mode(),
            metadata.file_type().is_symlink(),
            owners,
        ) {
            return Err(why);
        }
        if p == top {
            return Ok(());
        }
        current = p.parent();
    }
    Err(format!("{} is not under {}", path.display(), top.display()))
}

fn hold(mechanism: &'static str) -> PolicyDecision {
    PolicyDecision {
        policy: UpdatePolicy::Off,
        source: PolicySource::PackageHold(mechanism),
    }
}

fn denied(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::PermissionDenied
}

/// The decision for `product` on `machine`.
pub(crate) fn read(product: &Product, machine: &Machine) -> PolicyDecision {
    let package = product.package();
    if read_capped(machine, "/var/lib/dpkg/status", MAX_HOLDS_BYTES)
        .is_some_and(|status| dpkg_holds(&status, &package))
    {
        return hold("apt-mark hold");
    }
    let locks = [
        read_capped(
            machine,
            "/etc/dnf/plugins/versionlock.list",
            MAX_HOLDS_BYTES,
        ),
        read_capped(machine, "/etc/dnf/versionlock.toml", MAX_HOLDS_BYTES),
    ];
    if locks
        .iter()
        .flatten()
        .any(|list| versionlock_holds(list, &package))
    {
        return hold("dnf versionlock");
    }
    let pacman_conf = machine.path(Path::new("/etc/pacman.conf"));
    if pacman_conf.exists() {
        // pacman's own reading, includes and all. A configuration
        // pacman refuses, or no pacman-conf beside it, can't be judged.
        match crate::pacman_conf::read(&machine.pacman_conf, &pacman_conf) {
            Ok(conf) if conf.ignores(&package) => return hold("pacman IgnorePkg"),
            Ok(_) => {}
            Err(why) => return PolicyDecision::untrusted(format!("pacman holds: {why}")),
        }
    }
    match load(product, machine) {
        Loaded::Settings(
            file,
            PolicyFile {
                updates: Some(policy),
                ..
            },
        ) => PolicyDecision {
            policy,
            source: PolicySource::File(file),
        },
        // No file, or one naming only the server: the product's default.
        Loaded::Missing | Loaded::Settings(..) => PolicyDecision::product_default(product),
        Loaded::Untrusted(why) => PolicyDecision::untrusted(why),
        Loaded::Unreadable(why) => PolicyDecision::unreadable(why),
    }
}

/// The server the administrator's file names for `product` on `machine`
///, under the policy's trust rules; holds don't apply.
pub(crate) fn read_server(
    product: &Product,
    machine: &Machine,
) -> Result<Option<AdminServer>, String> {
    match load(product, machine) {
        Loaded::Missing => Ok(None),
        Loaded::Settings(file, settings) => Ok(settings.server.map(|url| AdminServer {
            url,
            source: PolicySource::File(file),
        })),
        Loaded::Untrusted(why) | Loaded::Unreadable(why) => Err(why),
    }
}

/// The administrator's policy file, as this process may read it.
enum Loaded {
    /// No file, under directories only root can write.
    Missing,
    /// The file's settings.
    Settings(PathBuf, PolicyFile),
    /// A file (or, without one, a directory above it) someone else could
    /// have written, or a file that doesn't parse.
    Untrusted(String),
    /// A file this process isn't allowed to read.
    Unreadable(String),
}

fn load(product: &Product, machine: &Machine) -> Loaded {
    let file = product.policy_file();
    let path = machine.path(&file);
    let etc = machine.path(Path::new("/etc"));
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // No file: still refuse when someone else could have removed
            // the administrator's. Walk the deepest directory that
            // exists.
            let mut existing = path.parent();
            while let Some(dir) = existing {
                if dir.exists() || dir == etc {
                    break;
                }
                existing = dir.parent();
            }
            let dir = existing.unwrap_or(&etc);
            return match trusted(dir, &etc, machine.require_root_owner) {
                Ok(()) => Loaded::Missing,
                Err(why) => Loaded::Untrusted(format!(
                    "{} is missing, under a directory someone else could write: {why}",
                    file.display()
                )),
            };
        }
        Err(e) if denied(&e) => {
            return Loaded::Unreadable(format!("{}: {e}", file.display()));
        }
        Err(e) => return Loaded::Untrusted(format!("{}: {e}", file.display())),
        Ok(_) => {}
    }
    if let Err(why) = trusted(&path, &etc, machine.require_root_owner) {
        return Loaded::Untrusted(why);
    }
    match std::fs::metadata(&path) {
        Ok(m) if m.len() > MAX_POLICY_BYTES => {
            return Loaded::Untrusted(format!(
                "{} is larger than {MAX_POLICY_BYTES} bytes",
                file.display()
            ));
        }
        _ => {}
    }
    match std::fs::read_to_string(&path) {
        Err(e) if denied(&e) => Loaded::Unreadable(format!("{}: {e}", file.display())),
        Err(e) => Loaded::Untrusted(format!("{}: {e}", file.display())),
        Ok(text) => match parse_policy_settings(&text) {
            Ok(settings) => Loaded::Settings(file, settings),
            Err(why) => Loaded::Untrusted(format!("{}: {why}", file.display())),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn product() -> Product {
        Product::new("Acme", "agent", "Agent", "stable").unwrap()
    }

    /// A machine rooted at `root`, its `/etc` 0755, with a fake
    /// pacman-conf printing `pacman_conf_output` (exit 0) or failing.
    fn machine(root: &Path, pacman_conf: Option<&str>) -> Machine {
        let etc = root.join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::set_permissions(&etc, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let tool = root.join("pacman-conf");
        let script = match pacman_conf {
            Some(output) => format!("#!/bin/sh\nprintf '%s' '{output}'\n"),
            None => "#!/bin/sh\necho 'error parsing' >&2\nexit 1\n".to_owned(),
        };
        crate::tests_support::write_script(&tool, &script);
        Machine {
            root: root.to_owned(),
            pacman_conf: tool,
            require_root_owner: false,
        }
    }

    fn write(root: &Path, relative: &str, text: &str, mode: u32) {
        let path = root.join(relative);
        let mut dir = path.parent().unwrap().to_owned();
        std::fs::create_dir_all(&dir).unwrap();
        while dir != root.join("etc") && dir.starts_with(root.join("etc")) {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            dir = dir.parent().unwrap().to_owned();
        }
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn decisions_follow_the_documented_order() {
        let root = tempfile::tempdir().unwrap();
        let m = machine(root.path(), Some(""));
        // Nothing: the product's default.
        assert_eq!(
            read(&product(), &m),
            PolicyDecision {
                policy: UpdatePolicy::Auto,
                source: PolicySource::ProductDefault
            }
        );
        let notify = product().with_default_policy(UpdatePolicy::Notify);
        assert_eq!(read(&notify, &m).policy, UpdatePolicy::Notify);
        // The administrator's file.
        write(
            root.path(),
            "etc/acme/agent/policy.toml",
            "updates = \"notify\"\n",
            0o644,
        );
        assert_eq!(
            read(&product(), &m),
            PolicyDecision {
                policy: UpdatePolicy::Notify,
                source: PolicySource::File("/etc/acme/agent/policy.toml".into())
            }
        );
        // The test's files aren't root's: with the ownership check on, the
        // same file is refused.
        let strict = Machine {
            require_root_owner: true,
            ..m.clone()
        };
        let refused = read(&product(), &strict);
        assert_eq!(refused.policy, UpdatePolicy::Off);
        assert!(
            matches!(&refused.source, PolicySource::Untrusted(why) if why.contains("not root")),
            "{refused:?}"
        );
        // A file that doesn't parse: off.
        write(
            root.path(),
            "etc/acme/agent/policy.toml",
            "updates = \"sometimes\"\n",
            0o644,
        );
        assert_eq!(read(&product(), &m).policy, UpdatePolicy::Off);
        // A file past the size cap: off, whatever it says.
        let mut big = "# padding\n".repeat(7000);
        big.push_str("updates = \"auto\"\n");
        write(root.path(), "etc/acme/agent/policy.toml", &big, 0o644);
        assert!(matches!(
            read(&product(), &m).source,
            PolicySource::Untrusted(why) if why.contains("larger than")
        ));
        // A writable file: off, whatever it says.
        write(
            root.path(),
            "etc/acme/agent/policy.toml",
            "updates = \"auto\"\n",
            0o666,
        );
        let writable = read(&product(), &m);
        assert_eq!(writable.policy, UpdatePolicy::Off);
        assert!(matches!(writable.source, PolicySource::Untrusted(_)));
        // A symlink: off.
        let path = root.path().join("etc/acme/agent/policy.toml");
        std::fs::remove_file(&path).unwrap();
        let elsewhere = root.path().join("elsewhere.toml");
        std::fs::write(&elsewhere, "updates = \"auto\"\n").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        assert_eq!(read(&product(), &m).policy, UpdatePolicy::Off);
        std::fs::remove_file(&path).unwrap();
        // A hold wins over everything, in each package manager's format.
        write(
            root.path(),
            "etc/acme/agent/policy.toml",
            "updates = \"auto\"\n",
            0o644,
        );
        write(root.path(), "etc/pacman.conf", "[options]\n", 0o644);
        let pacman_hold = machine(
            root.path(),
            Some("SigLevel = PackageRequired\nIgnorePkg = acme-*\n"),
        );
        assert_eq!(
            read(&product(), &pacman_hold),
            PolicyDecision {
                policy: UpdatePolicy::Off,
                source: PolicySource::PackageHold("pacman IgnorePkg")
            }
        );
        // A pacman configuration pacman itself refuses can't be judged.
        let broken = machine(root.path(), None);
        assert!(matches!(
            read(&product(), &broken).source,
            PolicySource::Untrusted(_)
        ));
        let m = machine(root.path(), Some("IgnorePkg = other\n"));
        assert_eq!(read(&product(), &m).policy, UpdatePolicy::Auto);
        for (relative, text, mechanism) in [
            (
                "etc/dnf/plugins/versionlock.list",
                "acme-agent-0:1.0.0-1.*\n",
                "dnf versionlock",
            ),
            (
                "var/lib/dpkg/status",
                "Package: acme-agent\nStatus: hold ok installed\n",
                "apt-mark hold",
            ),
        ] {
            write(root.path(), relative, text, 0o644);
            assert_eq!(
                read(&product(), &m),
                PolicyDecision {
                    policy: UpdatePolicy::Off,
                    source: PolicySource::PackageHold(mechanism)
                }
            );
        }
    }

    #[test]
    fn the_admin_server_comes_from_the_policy_file_under_the_same_trust() {
        let root = tempfile::tempdir().unwrap();
        let m = machine(root.path(), Some(""));
        let file = "etc/acme/agent/policy.toml";
        // No file: none set, the product's default applies.
        assert_eq!(read_server(&product(), &m), Ok(None));
        // A file naming only the policy: none set.
        write(root.path(), file, "updates = \"notify\"\n", 0o644);
        assert_eq!(read_server(&product(), &m), Ok(None));
        // The server, beside the policy or alone.
        write(
            root.path(),
            file,
            "updates = \"auto\"\nserver = \"https://updates.acme.example\"\n",
            0o644,
        );
        let set = AdminServer {
            url: "https://updates.acme.example".to_owned(),
            source: PolicySource::File("/etc/acme/agent/policy.toml".into()),
        };
        assert_eq!(read_server(&product(), &m), Ok(Some(set.clone())));
        write(
            root.path(),
            file,
            "server = \"https://updates.acme.example\"\n",
            0o644,
        );
        assert_eq!(read_server(&product(), &m), Ok(Some(set)));
        // A file naming only the server leaves the policy at the default.
        assert_eq!(
            read(&product(), &m),
            PolicyDecision {
                policy: UpdatePolicy::Auto,
                source: PolicySource::ProductDefault
            }
        );
        let notify = product().with_default_policy(UpdatePolicy::Notify);
        assert_eq!(read(&notify, &m).policy, UpdatePolicy::Notify);
        // A server that isn't https: an error, and the policy is off.
        write(
            root.path(),
            file,
            "updates = \"auto\"\nserver = \"http://a.example\"\n",
            0o644,
        );
        assert!(
            read_server(&product(), &m)
                .unwrap_err()
                .contains("https://")
        );
        assert_eq!(read(&product(), &m).policy, UpdatePolicy::Off);
        // A file someone else could write, or not root's: an error.
        write(root.path(), file, "server = \"https://a.example\"\n", 0o666);
        assert!(
            read_server(&product(), &m)
                .unwrap_err()
                .contains("writable")
        );
        write(root.path(), file, "server = \"https://a.example\"\n", 0o644);
        let strict = Machine {
            require_root_owner: true,
            ..m.clone()
        };
        assert!(
            read_server(&product(), &strict)
                .unwrap_err()
                .contains("not root")
        );
        // No file under a directory someone else could write: an error (the
        // administrator's file could have been removed).
        std::fs::remove_file(root.path().join(file)).unwrap();
        let vendor = root.path().join("etc/acme");
        std::fs::set_permissions(&vendor, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            read_server(&product(), &m)
                .unwrap_err()
                .contains("is missing")
        );
        // Holds don't apply to the server.
        std::fs::set_permissions(&vendor, std::fs::Permissions::from_mode(0o755)).unwrap();
        write(root.path(), file, "server = \"https://a.example\"\n", 0o644);
        write(
            root.path(),
            "var/lib/dpkg/status",
            "Package: acme-agent\nStatus: hold ok installed\n",
            0o644,
        );
        assert_eq!(read(&product(), &m).policy, UpdatePolicy::Off);
        assert!(read_server(&product(), &m).unwrap().is_some());
    }

    #[test]
    fn every_directory_up_to_etc_must_be_trusted_even_without_a_file() {
        let root = tempfile::tempdir().unwrap();
        let m = machine(root.path(), Some(""));
        write(
            root.path(),
            "etc/acme/agent/policy.toml",
            "updates = \"notify\"\n",
            0o644,
        );
        // A group-writable directory above the file.
        let vendor = root.path().join("etc/acme");
        std::fs::set_permissions(&vendor, std::fs::Permissions::from_mode(0o775)).unwrap();
        let decision = read(&product(), &m);
        assert!(
            matches!(&decision.source, PolicySource::Untrusted(why) if why.contains("etc/acme ")),
            "{decision:?}"
        );
        // Removing the file doesn't turn the product's default back on
        //: someone else could have removed it.
        std::fs::remove_file(root.path().join("etc/acme/agent/policy.toml")).unwrap();
        let decision = read(&product(), &m);
        assert_eq!(decision.policy, UpdatePolicy::Off, "{decision:?}");
        assert!(
            matches!(&decision.source, PolicySource::Untrusted(why) if why.contains("missing"))
        );
        // With the directories trusted again, a missing file is the default.
        std::fs::set_permissions(&vendor, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(read(&product(), &m).source, PolicySource::ProductDefault);
        // Only part of the path exists: the deepest existing directory is
        // walked.
        std::fs::remove_dir_all(&vendor).unwrap();
        assert_eq!(read(&product(), &m).source, PolicySource::ProductDefault);
        std::fs::set_permissions(
            root.path().join("etc"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert_eq!(read(&product(), &m).policy, UpdatePolicy::Off);
    }

    #[test]
    fn unreadable_and_odd_policy_paths_are_off() {
        let root = tempfile::tempdir().unwrap();
        let m = machine(root.path(), Some(""));
        // The policy path runs through a file (ENOTDIR): not "missing", so
        // off.
        write(root.path(), "etc/acme/agent", "not a directory", 0o644);
        let decision = read(&product(), &m);
        assert_eq!(decision.policy, UpdatePolicy::Off);
        assert!(
            matches!(decision.source, PolicySource::Untrusted(_)),
            "{decision:?}"
        );
        std::fs::remove_file(root.path().join("etc/acme/agent")).unwrap();
        // A root-only file read by someone else: unreadable. (As
        // root, nothing is unreadable, so this only runs unprivileged.)
        #[allow(unsafe_code, reason = "geteuid(2)")]
        // SAFETY: geteuid takes no arguments and can't fail.
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            write(
                root.path(),
                "etc/acme/agent/policy.toml",
                "updates = \"auto\"\n",
                0o000,
            );
            let decision = read(&product(), &m);
            assert_eq!(decision.policy, UpdatePolicy::Off);
            assert!(
                matches!(decision.source, PolicySource::Unreadable(_)),
                "{decision:?}"
            );
            let agent = root.path().join("etc/acme/agent");
            std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o000)).unwrap();
            let decision = read(&product(), &m);
            std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(
                matches!(decision.source, PolicySource::Unreadable(_)),
                "{decision:?}"
            );
        }
    }

    #[test]
    fn the_real_etc_is_trusted() {
        // Root's and not group-writable on any sane host.
        assert!(trusted(Path::new("/etc"), Path::new("/etc"), true).is_ok());
        let root = tempfile::tempdir().unwrap();
        assert!(trusted(root.path(), Path::new("/nowhere"), false).is_err());
    }
}
