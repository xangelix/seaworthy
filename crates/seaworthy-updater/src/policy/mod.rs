//! The update policy: whether a product updates itself (`auto`), only says which version it needs
//! (`notify`), or neither (`off`). The machine's administrator decides.
//! The app reads it before requesting an update, and the helper reads it
//! again before installing one, so neither trusts the other's reading.
//!
//! Where it comes from, highest first:
//!
//! - **Windows:** `HKLM\SOFTWARE\Policies\<Vendor>\<Directory>\UpdatePolicy`
//!   (Group Policy or Intune, through the ADMX template the seaworthy CLI
//!   writes), then `HKLM\SOFTWARE\<Vendor>\<Directory>\UpdatePolicy` (the
//!   MSI's install-time default, `UPDATES=`).
//! - **Linux:** a package hold (`apt-mark hold`, `dnf versionlock`,
//!   pacman's `IgnorePkg`, read through `pacman-conf` so `Include`d files
//!   count) counts as `off`; then
//!   `/etc/<vendor>/<id>/policy.toml`, written by the administrator.
//! - Otherwise the product's default (`seaworthy.toml`'s `updates.default`,
//!   [`Product::default_policy`]).
//!
//! **Failing safe means not installing.** A policy file or key that a
//! non-administrator could have written counts as `off`, with a warning
//! naming why:
//!
//! - Linux: the file, or any directory above it up to `/etc`, isn't
//!   root's, is group- or world-writable, or is a symlink;
//! - Windows: the key, or any existing key above it up to `SOFTWARE`, is
//!   owned by anyone but SYSTEM, Administrators or TrustedInstaller, has no
//!   DACL, or grants anyone else a right that writes (set value, create
//!   subkey, delete, change permissions or owner).
//!
//! A file or value that doesn't parse counts as `off` too, and so does a
//! missing policy file under a directory someone else can write (they
//! could have removed the administrator's file). A file the reading
//! process can't open (a root-only file read by the unprivileged app) is
//! [`PolicySource::Unreadable`]: `off` for that reader, which asks the
//! helper anyway.
//!
//! The Linux file is a small TOML document: the policy, and optionally
//! the update server an administrator set for the machine
//! ([`read_admin_server`]):
//!
//! ```toml
//! # /etc/acme/agent/policy.toml
//! updates = "notify"
//! server = "https://updates.acme.example"
//! ```
//!
//! A file with only `server` leaves the policy at the product's default.

use std::fmt;
use std::path::PathBuf;

use crate::{Product, UpdatePolicy};

#[cfg(any(windows, test))]
pub(crate) mod acl;
mod server;
#[cfg(not(windows))]
pub(crate) mod unix;
#[cfg(windows)]
pub(crate) mod windows;

pub use server::{AdminServer, is_machine_server, read_admin_server};

/// Where a decision came from, for logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySource {
    /// Windows Group Policy (the `Policies` key).
    GroupPolicy,
    /// The MSI's install-time default.
    InstallDefault,
    /// The Linux policy file.
    File(PathBuf),
    /// A package hold (Linux), naming the package manager's mechanism.
    PackageHold(&'static str),
    /// A source a non-administrator could have written, or one that
    /// didn't parse: `off`.
    Untrusted(String),
    /// A policy file this process isn't allowed to read (a root-only file
    /// or directory, read by the unprivileged app): `off` for this reader.
    /// The app side asks the helper anyway, since the helper reads it as
    /// root and decides for itself ([`crate::UpdateRequester`]).
    Unreadable(String),
    /// Nothing on the machine: the product's default.
    ProductDefault,
}

impl fmt::Display for PolicySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GroupPolicy => f.write_str("Group Policy"),
            Self::InstallDefault => f.write_str("the installer's default"),
            Self::File(path) => write!(f, "{}", path.display()),
            Self::PackageHold(mechanism) => write!(f, "a package hold ({mechanism})"),
            Self::Untrusted(why) => write!(f, "an untrusted or invalid source ({why})"),
            Self::Unreadable(why) => write!(f, "a policy file this process can't read ({why})"),
            Self::ProductDefault => f.write_str("the product's default"),
        }
    }
}

/// The policy in force, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    /// The policy.
    pub policy: UpdatePolicy,
    /// Where it came from.
    pub source: PolicySource,
}

impl PolicyDecision {
    pub(crate) fn untrusted(why: String) -> Self {
        tracing::warn!(
            "update policy: {}; treating it as `off` (failing safe: no update installs)",
            crate::log::line_safe(&why)
        );
        Self {
            policy: UpdatePolicy::Off,
            source: PolicySource::Untrusted(why),
        }
    }

    #[cfg(not(windows))]
    pub(crate) fn unreadable(why: String) -> Self {
        tracing::info!(
            "update policy: {}; this process can't read it (the update helper reads it as root)",
            crate::log::line_safe(&why)
        );
        Self {
            policy: UpdatePolicy::Off,
            source: PolicySource::Unreadable(why),
        }
    }

    pub(crate) fn product_default(product: &Product) -> Self {
        Self {
            policy: product.default_policy(),
            source: PolicySource::ProductDefault,
        }
    }
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}` from {}", self.policy, self.source)
    }
}

/// The policy in force for `product` on this machine (see the module
/// docs). It reads files or the registry, and on Linux runs the package
/// managers' hold queries; never the network. Cheap enough to call on
/// every version mismatch, but blocking: call it off an async executor.
#[must_use]
pub fn read_policy(product: &Product) -> PolicyDecision {
    #[cfg(windows)]
    {
        windows::read(product)
    }
    #[cfg(not(windows))]
    {
        unix::read(product, &unix::Machine::system())
    }
}

/// The settings of the Linux policy file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyFile {
    /// `updates = "<policy>"`.
    pub updates: Option<UpdatePolicy>,
    /// `server = "https://…"`, checked as [`read_admin_server`]
    /// checks it.
    pub server: Option<String>,
}

/// Parses the Linux policy file: comments, blank lines, and at most one
/// each of `updates = "<policy>"` and `server = "https://…"`, at least one
/// of them (a strict subset of TOML; nothing else is accepted, so a typo
/// can't silently leave a different policy or server in force).
///
/// # Errors
/// What's wrong, for the warning.
pub fn parse_policy_settings(text: &str) -> Result<PolicyFile, String> {
    let mut settings = PolicyFile::default();
    for (number, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {}: not `key = \"value\"`", number + 1));
        };
        let quoted = value
            .trim()
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'));
        match key.trim() {
            "updates" => {
                let policy = quoted.and_then(UpdatePolicy::parse).ok_or_else(|| {
                    format!(
                        "line {}: `updates` must be \"auto\", \"notify\" or \"off\"",
                        number + 1
                    )
                })?;
                if settings.updates.replace(policy).is_some() {
                    return Err(format!("line {}: `updates` is set twice", number + 1));
                }
            }
            "server" => {
                let url = quoted.ok_or_else(|| {
                    format!(
                        "line {}: `server` must be a quoted https:// URL",
                        number + 1
                    )
                })?;
                let url = server::validate(&format!("line {}: `server`", number + 1), url)?;
                if settings.server.replace(url).is_some() {
                    return Err(format!("line {}: `server` is set twice", number + 1));
                }
            }
            other => {
                return Err(format!(
                    "line {}: unknown setting {:?} (only `updates` and `server`)",
                    number + 1,
                    crate::log::line_safe(other)
                ));
            }
        }
    }
    if settings == PolicyFile::default() {
        return Err("no `updates` or `server` setting".to_owned());
    }
    Ok(settings)
}

/// The policy the Linux policy file sets ([`parse_policy_settings`]),
/// which must set one.
///
/// # Errors
/// What's wrong, for the warning; a file with no `updates`.
pub fn parse_policy_file(text: &str) -> Result<UpdatePolicy, String> {
    parse_policy_settings(text)?
        .updates
        .ok_or_else(|| "no `updates` setting".to_owned())
}

/// Whether dpkg's status file holds `package` (`Status: hold …`).
#[must_use]
pub fn dpkg_holds(status: &str, package: &str) -> bool {
    status.split("\n\n").any(|stanza| {
        let mut name = None;
        let mut held = false;
        for line in stanza.lines() {
            if let Some(value) = line.strip_prefix("Package:") {
                name = Some(value.trim());
            } else if let Some(value) = line.strip_prefix("Status:") {
                held = value.split_whitespace().next() == Some("hold");
            }
        }
        name == Some(package) && held
    })
}

/// Whether a dnf versionlock list locks `package`: dnf 4's
/// `versionlock.list` (one `<name>-<epoch>:<version>-<release>.<arch>`
/// pattern per line; `!` lines exclude, `#` lines are comments) or dnf 5's
/// `versionlock.toml` (`name = "<name>"`).
#[must_use]
pub fn versionlock_holds(list: &str, package: &str) -> bool {
    let prefix = format!("{package}-");
    let quoted = format!("\"{package}\"");
    list.lines().map(str::trim).any(|line| {
        // A comment (`#`) or an exclusion (`!`) never starts with the name.
        let dnf4 = line
            .strip_prefix(&prefix)
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()));
        let dnf5 = line
            .strip_prefix("name")
            .map(str::trim_start)
            .and_then(|rest| rest.strip_prefix('='))
            .map(|value| value.split('#').next().unwrap_or_default().trim())
            == Some(quoted.as_str());
        dnf4 || dnf5
    })
}

/// fnmatch-style `*` and `?` over bytes (pacman's `IgnorePkg` globs).
#[cfg(not(windows))]
pub(crate) fn glob_matches(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    // Iterative backtracking over the last `*`: linear for real patterns,
    // and no recursion depth for hostile ones.
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while let Some(&byte) = t.get(ti) {
        match p.get(pi) {
            Some(b'*') => {
                star = Some((pi, ti));
                pi += 1;
            }
            Some(&c) if c == b'?' || c == byte => {
                pi += 1;
                ti += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    pi = sp + 1;
                    ti = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    p.get(pi..).unwrap_or_default().iter().all(|&c| c == b'*')
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_file_is_one_setting_and_nothing_else() {
        assert_eq!(
            parse_policy_file("updates = \"notify\"\n"),
            Ok(UpdatePolicy::Notify)
        );
        assert_eq!(
            parse_policy_file("# managed by ops\n\nupdates=\"off\"  # quiet\n"),
            Ok(UpdatePolicy::Off)
        );
        for bad in [
            "",
            "# only a comment\n",
            "updates = notify\n",
            "updates = \"Auto\"\n",
            "updates = \"auto\"\nupdates = \"off\"\n",
            "update = \"auto\"\n",
            "updates = \"auto\"\nchannel = \"beta\"\n",
            "[section]\nupdates = \"auto\"\n",
            "updates = 'auto'\n",
            // A server alone sets no policy.
            "server = \"https://updates.acme.example\"\n",
        ] {
            assert!(parse_policy_file(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_policy_file_may_name_the_machines_update_server() {
        assert_eq!(
            parse_policy_settings(
                "updates = \"auto\"\nserver = \"https://updates.acme.example:8443/t\"  # ops\n"
            ),
            Ok(PolicyFile {
                updates: Some(UpdatePolicy::Auto),
                server: Some("https://updates.acme.example:8443/t".to_owned()),
            })
        );
        assert_eq!(
            parse_policy_file("server = \"https://a.example\"\nupdates = \"notify\"\n"),
            Ok(UpdatePolicy::Notify)
        );
        assert_eq!(
            parse_policy_settings("server = \"https://a.example\"\n"),
            Ok(PolicyFile {
                updates: None,
                server: Some("https://a.example".to_owned()),
            })
        );
        for bad in [
            "server = https://a.example\n",
            "server = \"http://a.example\"\n",
            "server = \"https://a.example/?x=1\"\n",
            "server = \"https://u@a.example\"\n",
            "server = \"\"\n",
            "server = \"https://a.example\"\nserver = \"https://b.example\"\n",
            "servers = \"https://a.example\"\n",
            // `#` starts a comment, so the value's quote never closes.
            "server = \"https://a.example/#x\"\n",
        ] {
            assert!(parse_policy_settings(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn package_holds_are_recognized_in_each_format() {
        let status = "Package: acme-agent\nStatus: hold ok installed\nVersion: 1.0.0-1\n\n\
                      Package: other\nStatus: install ok installed\n";
        assert!(dpkg_holds(status, "acme-agent"));
        assert!(!dpkg_holds(status, "other"));
        assert!(!dpkg_holds(status, "acme"));
        assert!(!dpkg_holds(
            "Package: acme-agent\nStatus: install ok installed\n",
            "acme-agent"
        ));
        assert!(versionlock_holds("acme-agent-0:1.0.0-1.*\n", "acme-agent"));
        assert!(versionlock_holds(
            "version = \"1.0\"\n[[packages]]\nname = \"acme-agent\"  # pinned\n",
            "acme-agent"
        ));
        assert!(!versionlock_holds(
            "acme-agent-tools-0:1.0-1.*\n",
            "acme-agent"
        ));
        assert!(!versionlock_holds(
            "# acme-agent-0:1.0.0-1.*\n!acme-agent-0:1.0.0-1.*\n",
            "acme-agent"
        ));
        assert!(!versionlock_holds(
            "name = \"acme-agent-tools\"\n",
            "acme-agent"
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn globs_match_as_fnmatch_does() {
        for (pattern, text, matches) in [
            ("*", "", true),
            ("*", "abc", true),
            ("a*c", "abbbc", true),
            ("a*c", "abcd", false),
            ("?bc", "abc", true),
            ("?bc", "bc", false),
            ("a**b", "ab", true),
            ("*a*a*a*a*a*b", &"a".repeat(64), false),
            ("acme-agent", "acme-agent", true),
            ("acme-agent", "acme-agen", false),
        ] {
            assert_eq!(glob_matches(pattern, text), matches, "{pattern} {text}");
        }
    }
}
