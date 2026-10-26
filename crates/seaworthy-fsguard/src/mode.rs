//! The Unix rule for one object: no symlink, an owner the policy accepts,
//! and no write permission for group or others. Pure, so every branch is
//! unit-tested on every platform; the walk that feeds it is in the `unix`
//! module.
//!
//! The sticky bit doesn't help: anyone could replace an object in a
//! world-writable directory they created, so group or world write fails
//! whatever else is set.

#![forbid(unsafe_code)]

/// Who may own an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owners<'a> {
    /// Root alone.
    Root,
    /// Root or the user `uid`, named `named` in a refusal (for example
    /// "the service's user").
    RootOr {
        /// The other uid that may own (a service's effective uid).
        uid: u32,
        /// How a refusal names that user.
        named: &'a str,
    },
    /// Anyone: the owner isn't checked (a test that can't create root's
    /// files). Symlinks and group or world write still fail.
    Anyone,
}

/// Why `what` (owned by `uid`, with `mode`; `symlink` when it is one) could
/// be changed by someone `owners` doesn't name, or `None` when it can't.
#[must_use]
pub fn untrusted(
    what: &str,
    uid: u32,
    mode: u32,
    symlink: bool,
    owners: Owners<'_>,
) -> Option<String> {
    if symlink {
        return Some(format!("{what} is a symlink"));
    }
    match owners {
        Owners::Root if uid != 0 => {
            return Some(format!("{what} is owned by uid {uid}, not root"));
        }
        Owners::RootOr { uid: other, named } if uid != 0 && uid != other => {
            return Some(format!(
                "{what} is owned by uid {uid}, not root or {named} ({other})"
            ));
        }
        Owners::Root | Owners::RootOr { .. } | Owners::Anyone => {}
    }
    if mode & 0o022 != 0 {
        return Some(format!(
            "{what} is writable by group or others (mode {:o})",
            mode & 0o7777
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE: Owners<'static> = Owners::RootOr {
        uid: 990,
        named: "the service's user",
    };

    #[test]
    fn root_alone() {
        assert_eq!(untrusted("x", 0, 0o40755, false, Owners::Root), None);
        assert_eq!(
            untrusted("x", 1000, 0o40700, false, Owners::Root).as_deref(),
            Some("x is owned by uid 1000, not root")
        );
    }

    #[test]
    fn root_or_a_named_user() {
        assert_eq!(untrusted("x", 0, 0o40700, false, SERVICE), None);
        assert_eq!(untrusted("x", 990, 0o100644, false, SERVICE), None);
        assert_eq!(
            untrusted("x", 1000, 0o100600, false, SERVICE).as_deref(),
            Some("x is owned by uid 1000, not root or the service's user (990)")
        );
    }

    #[test]
    fn symlinks_and_shared_write_fail_for_anyone() {
        assert_eq!(untrusted("x", 1000, 0o100600, false, Owners::Anyone), None);
        assert_eq!(
            untrusted("x", 0, 0o120777, true, Owners::Anyone).as_deref(),
            Some("x is a symlink")
        );
        assert_eq!(
            untrusted("x", 0, 0o41777, false, Owners::Anyone).as_deref(),
            Some("x is writable by group or others (mode 1777)")
        );
        assert!(untrusted("x", 0, 0o100620, false, Owners::Root).is_some());
    }
}
