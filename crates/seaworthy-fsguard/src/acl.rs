//! The Windows rule: who may own an object, and who may hold a write right
//! on it, decided from its owner and DACL alone. Pure, so every branch is
//! unit-tested on every platform, not only on a Windows runner; the reads
//! that feed it are in the `windows` module.
//!
//! An object passes when its owner is SYSTEM, Administrators,
//! TrustedInstaller or one of the policy's accounts, and no allow ACE that
//! applies to the object itself grants one of the policy's write rights to
//! anyone else. Deny ACEs are skipped (the question is whether anything
//! grants a write), and so are inherit-only ACEs (they apply to children).
//! A NULL DACL (everyone has full access), an unreadable owner and an
//! unreadable trustee holding a write right all fail. CREATOR OWNER is
//! always accepted: in an effective ACE it matches no token. OWNER RIGHTS
//! (the object's owner, whom the rule checks itself) is accepted when the
//! policy says so.

#![forbid(unsafe_code)]

/// LocalSystem.
pub const LOCAL_SYSTEM: &str = "S-1-5-18";
/// BUILTIN\Administrators.
pub const ADMINISTRATORS: &str = "S-1-5-32-544";
/// TrustedInstaller (`NT SERVICE\TrustedInstaller`).
pub const TRUSTED_INSTALLER: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
/// The principals that may always own or write: LocalSystem,
/// Administrators and TrustedInstaller.
pub const TRUSTED: [&str; 3] = [LOCAL_SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER];
/// CREATOR OWNER: in an effective ACE it matches no token (it only means
/// something when inherited), so it grants nothing.
pub const CREATOR_OWNER: &str = "S-1-3-0";
/// OWNER RIGHTS: the object's owner.
pub const OWNER_RIGHTS: &str = "S-1-3-4";

/// Access rights that change a directory or a file (the same bits on
/// both): add file / write data, add subdirectory / append data, write
/// extended attributes, delete child, write attributes, delete, write DAC,
/// write owner, generic write, generic all, maximum allowed. Traverse,
/// execute and the read rights change nothing.
pub const DIRECTORY_WRITE_RIGHTS: u32 = 0x0000_0002
    | 0x0000_0004
    | 0x0000_0010
    | 0x0000_0040
    | 0x0000_0100
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x4000_0000
    | 0x1000_0000
    | 0x0200_0000;

/// One ACE, reduced to what the rule needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// An allow ACE of any kind (plain, object, callback, callback object).
    /// Deny ACEs are skipped by the rule.
    pub allow: bool,
    /// `INHERIT_ONLY_ACE`: for children only, not this object.
    pub inherit_only: bool,
    /// The access mask.
    pub mask: u32,
    /// The trustee as a string SID; `None` when it couldn't be read (an
    /// object ACE's trustee follows optional GUIDs): untrusted.
    pub sid: Option<String>,
}

/// One caller's policy: which rights count as a write, which accounts may
/// own and write besides SYSTEM, Administrators and TrustedInstaller (and
/// how a refusal names them), and whether OWNER RIGHTS entries are accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterPolicy<'a> {
    rights: u32,
    accounts: &'a [&'a str],
    accounts_named: Option<&'a str>,
    owner_rights: bool,
}

impl<'a> WriterPolicy<'a> {
    /// Only SYSTEM, Administrators and TrustedInstaller may own or hold any
    /// of `rights` (for example [`DIRECTORY_WRITE_RIGHTS`]); an OWNER
    /// RIGHTS entry holding one is refused.
    #[must_use]
    pub const fn administrators(rights: u32) -> Self {
        Self {
            rights,
            accounts: &[],
            accounts_named: None,
            owner_rights: false,
        }
    }

    /// Also `accounts` (string SIDs; possibly none) may own and write; a
    /// refusal names them `named` (for example "the service's account").
    #[must_use]
    pub const fn with_accounts(self, accounts: &'a [&'a str], named: &'a str) -> Self {
        Self {
            accounts,
            accounts_named: Some(named),
            ..self
        }
    }

    /// Accept OWNER RIGHTS entries: they grant the owner, whom the rule
    /// checks itself.
    #[must_use]
    pub const fn trusting_owner_rights(self) -> Self {
        Self {
            owner_rights: true,
            ..self
        }
    }

    /// The rights that count as a write.
    #[must_use]
    pub const fn rights(&self) -> u32 {
        self.rights
    }

    fn allowed(&self, sid: &str) -> bool {
        TRUSTED.contains(&sid) || self.accounts.contains(&sid)
    }

    fn owners(&self) -> String {
        match self.accounts_named {
            None => "SYSTEM, Administrators or TrustedInstaller".to_owned(),
            Some(named) => format!("SYSTEM, Administrators, TrustedInstaller or {named}"),
        }
    }
}

/// Why `what` (owned by `owner`, with `dacl`; `None` for a NULL DACL) could
/// be changed by someone `policy` doesn't trust, or `None` when it can't.
#[must_use]
pub fn untrusted(
    what: &str,
    owner: Option<&str>,
    dacl: Option<&[Ace]>,
    policy: &WriterPolicy<'_>,
) -> Option<String> {
    match owner {
        Some(owner) if policy.allowed(owner) => {}
        other => {
            return Some(format!(
                "{what} is owned by {}, not {}",
                other.unwrap_or("an unreadable SID"),
                policy.owners()
            ));
        }
    }
    let Some(dacl) = dacl else {
        return Some(format!("{what} has no DACL (everyone has full access)"));
    };
    dacl.iter()
        .filter(|ace| ace.allow && !ace.inherit_only && ace.mask & policy.rights != 0)
        .find(|ace| {
            !ace.sid.as_deref().is_some_and(|sid| {
                policy.allowed(sid)
                    || sid == CREATOR_OWNER
                    || (policy.owner_rights && sid == OWNER_RIGHTS)
            })
        })
        .map(|ace| {
            format!(
                "{what} grants {} write access (mask {:#010x})",
                ace.sid.as_deref().unwrap_or("an unreadable trustee"),
                ace.mask
            )
        })
}

/// The SIDs besides [`TRUSTED`], CREATOR OWNER and OWNER RIGHTS that `dacl`
/// lets hold any of `rights` (inherit-only entries included: what a folder's
/// descriptor grants its children), sorted and without duplicates: whom a
/// folder's own descriptor makes a writer of what it holds.
#[must_use]
pub fn writers(dacl: &[Ace], rights: u32) -> Vec<String> {
    let mut sids: Vec<String> = dacl
        .iter()
        .filter(|ace| ace.allow && ace.mask & rights != 0)
        .filter_map(|ace| ace.sid.clone())
        .filter(|sid| {
            !TRUSTED.contains(&sid.as_str()) && sid != CREATOR_OWNER && sid != OWNER_RIGHTS
        })
        .collect();
    sids.sort();
    sids.dedup();
    sids
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE: &str = "S-1-5-80-1-2-3-4-5";
    const USER: &str = "S-1-5-21-1-2-3-1001";
    const WHAT: &str = "C:\\ProgramData\\Acme\\Agent\\state";

    fn ace(sid: &str, mask: u32) -> Ace {
        Ace {
            allow: true,
            inherit_only: false,
            mask,
            sid: Some(sid.to_owned()),
        }
    }

    fn locked() -> Vec<Ace> {
        vec![
            ace(LOCAL_SYSTEM, 0x001F_01FF),
            ace(ADMINISTRATORS, 0x001F_01FF),
            ace(OWNER_RIGHTS, 0x0002_0000),
        ]
    }

    #[test]
    fn the_administrators_alone_own_and_write_by_default() {
        let policy = WriterPolicy::administrators(DIRECTORY_WRITE_RIGHTS);
        for owner in TRUSTED {
            assert_eq!(untrusted(WHAT, Some(owner), Some(&locked()), &policy), None);
        }
        let why = untrusted(WHAT, Some(USER), Some(&locked()), &policy).unwrap();
        assert_eq!(
            why,
            format!("{WHAT} is owned by {USER}, not SYSTEM, Administrators or TrustedInstaller")
        );
        let why = untrusted(WHAT, None, Some(&locked()), &policy).unwrap();
        assert!(why.contains("an unreadable SID"), "{why}");
        let why = untrusted(WHAT, Some(LOCAL_SYSTEM), None, &policy).unwrap();
        assert_eq!(
            why,
            format!("{WHAT} has no DACL (everyone has full access)")
        );
        let mut granted = locked();
        granted.push(ace(USER, 0x0000_0002));
        let why = untrusted(WHAT, Some(LOCAL_SYSTEM), Some(&granted), &policy).unwrap();
        assert_eq!(
            why,
            format!("{WHAT} grants {USER} write access (mask 0x00000002)")
        );
    }

    #[test]
    fn owner_rights_with_a_write_right_needs_the_policy_s_consent() {
        let mut dacl = locked();
        dacl.push(ace(OWNER_RIGHTS, 0x001F_01FF));
        let strict = WriterPolicy::administrators(DIRECTORY_WRITE_RIGHTS);
        assert!(untrusted(WHAT, Some(LOCAL_SYSTEM), Some(&dacl), &strict).is_some());
        let lenient = strict.trusting_owner_rights();
        assert_eq!(
            untrusted(WHAT, Some(LOCAL_SYSTEM), Some(&dacl), &lenient),
            None
        );
    }

    #[test]
    fn a_policy_s_accounts_own_and_write_and_are_named_in_refusals() {
        let accounts = [SERVICE];
        let policy = WriterPolicy::administrators(DIRECTORY_WRITE_RIGHTS)
            .with_accounts(&accounts, "the service's account");
        let mut dacl = locked();
        dacl.push(ace(SERVICE, 0x0013_01BF));
        assert_eq!(untrusted(WHAT, Some(SERVICE), Some(&dacl), &policy), None);
        let why = untrusted(WHAT, Some(USER), Some(&dacl), &policy).unwrap();
        assert!(
            why.ends_with("not SYSTEM, Administrators, TrustedInstaller or the service's account"),
            "{why}"
        );
        // Named even when the list is empty.
        let none = WriterPolicy::administrators(DIRECTORY_WRITE_RIGHTS)
            .with_accounts(&[], "its folder's account");
        let why = untrusted(WHAT, Some(SERVICE), Some(&dacl), &none).unwrap();
        assert!(why.ends_with("or its folder's account"), "{why}");
    }

    #[test]
    fn only_the_policy_s_rights_count_and_harmless_entries_pass() {
        // 0x20: traverse on a directory, create link on a registry key.
        let mut dacl = locked();
        dacl.push(ace("S-1-5-32-545", 0x20));
        let directories = WriterPolicy::administrators(DIRECTORY_WRITE_RIGHTS);
        assert_eq!(
            untrusted(WHAT, Some(LOCAL_SYSTEM), Some(&dacl), &directories),
            None
        );
        let keys = WriterPolicy::administrators(0x20);
        assert!(untrusted(WHAT, Some(LOCAL_SYSTEM), Some(&dacl), &keys).is_some());
        let harmless = [
            ace(LOCAL_SYSTEM, 0x001F_01FF),
            ace("S-1-5-32-545", 0x0012_00A9),
            Ace {
                inherit_only: true,
                ..ace("S-1-1-0", 0x001F_01FF)
            },
            Ace {
                allow: false,
                ..ace("S-1-1-0", 0x001F_01FF)
            },
            ace(CREATOR_OWNER, 0x1000_0000),
        ];
        assert_eq!(
            untrusted(WHAT, Some(LOCAL_SYSTEM), Some(&harmless), &directories),
            None
        );
        let unknown = Ace {
            sid: None,
            ..ace(LOCAL_SYSTEM, 0x2)
        };
        let why = untrusted(WHAT, Some(LOCAL_SYSTEM), Some(&[unknown]), &directories).unwrap();
        assert!(why.contains("an unreadable trustee"), "{why}");
    }

    #[test]
    fn a_folder_s_writers_are_the_others_its_descriptor_lets_write() {
        let mut dacl = locked();
        dacl.push(ace(SERVICE, 0x0013_01BF));
        dacl.push(Ace {
            inherit_only: true,
            ..ace(SERVICE, 0x0013_01BF)
        });
        dacl.push(ace("S-1-5-32-545", 0x0012_00A9));
        dacl.push(ace(CREATOR_OWNER, 0x1000_0000));
        assert_eq!(writers(&dacl, DIRECTORY_WRITE_RIGHTS), [SERVICE]);
        assert!(writers(&locked(), DIRECTORY_WRITE_RIGHTS).is_empty());
    }
}
