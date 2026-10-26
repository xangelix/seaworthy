//! Who may write a Windows registry key or directory, as a pure decision
//! over its owner and DACL (the FFI that reads them is in `windows.rs` and
//! seaworthy-fsguard). The rule is seaworthy-fsguard's, pure so it is
//! unit-tested on every platform, not only on the Windows runner; this
//! module holds the updater's policy: SYSTEM, Administrators and
//! TrustedInstaller alone may own or write (an OWNER RIGHTS entry holding a
//! write right is refused too).

pub(crate) use seaworthy_fsguard::acl::Ace;
/// Access rights that change a directory or a file (the update helper's
/// staging directory and those above it, its log): seaworthy-fsguard's.
#[cfg(any(feature = "helper", test))]
pub(crate) use seaworthy_fsguard::acl::DIRECTORY_WRITE_RIGHTS;
use seaworthy_fsguard::acl::{WriterPolicy, untrusted};

/// Access rights that change a key or what's under it: set value, create
/// subkey, create link, delete, write DAC, write owner, generic write,
/// generic all, maximum allowed.
pub(crate) const WRITE_RIGHTS: u32 = 0x0000_0002
    | 0x0000_0004
    | 0x0000_0020
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x4000_0000
    | 0x1000_0000
    | 0x0200_0000;

/// Why `key` could be written by someone other than SYSTEM, Administrators
/// or TrustedInstaller, or `None` when it can't. `dacl` is `None` for a
/// NULL DACL (full access for everyone).
pub(crate) fn untrusted_writer(
    key: &str,
    owner: Option<&str>,
    dacl: Option<&[Ace]>,
) -> Option<String> {
    untrusted_writer_of(&format!("HKLM\\{key}"), owner, dacl, WRITE_RIGHTS)
}

/// [`untrusted_writer`] for anything named `what` whose `rights` mean a
/// write ([`WRITE_RIGHTS`] for a key, [`DIRECTORY_WRITE_RIGHTS`] for a
/// directory or a file).
pub(crate) fn untrusted_writer_of(
    what: &str,
    owner: Option<&str>,
    dacl: Option<&[Ace]>,
    rights: u32,
) -> Option<String> {
    untrusted(what, owner, dacl, &WriterPolicy::administrators(rights))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ace(sid: &str, mask: u32) -> Ace {
        Ace {
            allow: true,
            inherit_only: false,
            mask,
            sid: Some(sid.to_owned()),
        }
    }

    const READ: u32 = 0x0002_0019;
    const FULL: u32 = 0x000F_003F;

    #[test]
    fn only_system_administrators_and_trustedinstaller_may_write() {
        let key = "SOFTWARE\\Policies\\Acme\\Agent";
        // The default HKLM\SOFTWARE shape.
        let default = [
            ace("S-1-5-18", FULL),
            ace("S-1-5-32-544", FULL),
            ace("S-1-5-32-545", READ),
            Ace {
                inherit_only: true,
                ..ace("S-1-3-0", 0x1000_0000)
            },
            ace("S-1-15-2-1", READ),
        ];
        assert_eq!(
            untrusted_writer(key, Some("S-1-5-32-544"), Some(&default)),
            None
        );
        // An owner outside the set, or none readable.
        assert!(untrusted_writer(key, Some("S-1-5-21-1-2-3-1001"), Some(&default)).is_some());
        assert!(untrusted_writer(key, None, Some(&default)).is_some());
        // A NULL DACL.
        assert!(untrusted_writer(key, Some("S-1-5-18"), None).is_some());
        // Users with set value, create subkey, delete, write DAC or owner,
        // or a generic right.
        for mask in [
            0x2,
            0x4,
            0x20,
            0x1_0000,
            0x4_0000,
            0x8_0000,
            0x4000_0000,
            0x1000_0000,
            FULL,
        ] {
            let mut dacl = default.to_vec();
            dacl.push(ace("S-1-5-32-545", mask));
            let why = untrusted_writer(key, Some("S-1-5-18"), Some(&dacl)).unwrap();
            assert!(why.contains("S-1-5-32-545"), "{why}");
        }
        // Everyone, Authenticated Users, a user: refused.
        for sid in ["S-1-1-0", "S-1-5-11", "S-1-5-21-1-2-3-1001"] {
            assert!(untrusted_writer(key, Some("S-1-5-18"), Some(&[ace(sid, 0x2)])).is_some());
        }
        // An unreadable trustee with a write right: refused.
        let unknown = Ace {
            sid: None,
            ..ace("S-1-5-18", 0x2)
        };
        assert!(untrusted_writer(key, Some("S-1-5-18"), Some(&[unknown])).is_some());
        // Deny ACEs and inherit-only grants change nothing.
        let ignored = [
            Ace {
                allow: false,
                ..ace("S-1-1-0", FULL)
            },
            Ace {
                inherit_only: true,
                ..ace("S-1-1-0", FULL)
            },
        ];
        assert_eq!(
            untrusted_writer(key, Some("S-1-5-18"), Some(&ignored)),
            None
        );
    }

    #[test]
    fn a_staging_directory_only_system_administrators_and_trustedinstaller_may_write() {
        let what = "C:\\ProgramData\\Acme\\Agent\\updates";
        let rule = |owner: &str, dacl: &[Ace]| {
            untrusted_writer_of(what, Some(owner), Some(dacl), DIRECTORY_WRITE_RIGHTS)
        };
        // What the MSI sets (seaworthy-service's staging-directory DACL): SYSTEM
        // and Administrators full control, OWNER RIGHTS read control.
        let msi = [
            ace("S-1-5-18", 0x001F_01FF),
            ace("S-1-5-32-544", 0x001F_01FF),
            ace("S-1-3-4", 0x0002_0000),
        ];
        assert_eq!(rule("S-1-5-32-544", &msi), None);
        assert_eq!(rule("S-1-5-18", &msi), None);
        // A user who created the directory first still owns it.
        let why = rule("S-1-5-21-1-2-3-1001", &msi).unwrap();
        assert!(
            why.starts_with(what) && why.contains("is owned by"),
            "{why}"
        );
        // %ProgramData%'s inheritable grant to Users (WD, AD, WEA, WA), and
        // each directory write right alone: refused.
        for mask in [
            0x0000_0116,
            0x2,
            0x4,
            0x10,
            0x40,
            0x100,
            0x1_0000,
            0x4_0000,
            0x8_0000,
            0x4000_0000,
            0x1000_0000,
            0x0200_0000,
        ] {
            let mut dacl = msi.to_vec();
            dacl.push(ace("S-1-5-32-545", mask));
            let why = rule("S-1-5-18", &dacl).unwrap();
            assert!(why.contains("S-1-5-32-545"), "{mask:#x}: {why}");
        }
        // Read and execute, traverse, synchronize: not writes.
        let mut dacl = msi.to_vec();
        dacl.push(ace("S-1-5-32-545", 0x0012_00A9));
        assert_eq!(rule("S-1-5-18", &dacl), None);
        // The key rule's set doesn't apply to directories: 0x20 is
        // traverse here, create link on a key.
        let mut dacl = msi.to_vec();
        dacl.push(ace("S-1-5-32-545", 0x20));
        assert_eq!(rule("S-1-5-18", &dacl), None);
        assert!(untrusted_writer("SOFTWARE\\Acme", Some("S-1-5-18"), Some(&dacl)).is_some());
    }
}
