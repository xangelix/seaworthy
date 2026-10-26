# seaworthy-fsguard

*The ownership and permission audits the seaworthy crates run before they trust an
administrator-owned folder or file.*

An installer, a service and a privileged update helper each rely on folders that only
administrators (and sometimes one service account) may change: the update helper's staging
directory and log, a service's state directory, a product's `%ProgramData%` folders. Anything a
less privileged user could have created, written or redirected there must be refused. This crate
makes that decision in one place, for `seaworthy-updater`, `seaworthy-service` and
`seaworthy-launcher`:

| Module | What |
|---|---|
| `acl` | The Windows rule: the owner must be SYSTEM, Administrators, TrustedInstaller or one of the caller's accounts, and no ACE may grant anyone else a write right. The caller's `WriterPolicy` says which rights count as a write, which accounts are trusted (and how a refusal names them), and whether OWNER RIGHTS entries are accepted |
| `mode` | The Unix rule: no symlink, an owner the caller names (`Owners`), no group or world write |
| `windows` | The audits (`audit_object`, `audit_tree`, `audit_directory`), each object opened by handle without following a reparse point; and the primitives a caller's own walk needs: attributes, link counts, final paths, security descriptors (read by handle, by name or from a caller's buffer; made from SDDL; taken back; propagated), folders created with their descriptor, listings, known folders, the process token and privileges |
| `unix` | `audit_directory`: a canonical path, and it and everything below it judged by `mode` |

## The rules

1. **Fail closed.** An object whose owner, DACL, attributes or listing can't be read is refused,
   with the object and the reason in the error.
2. **Judge what was opened.** On Windows every object is opened without following a reparse point,
   its attributes and security are read through that handle, and a directory's final path must be
   the one asked for, so a junction anywhere on the way is refused.
3. **Bounded.** One audit visits at most `MAX_ENTRIES` (100,000) objects, `MAX_DEPTH` (32) levels
   deep; a larger tree is refused.
4. **The policy is the caller's.** The crate decides nothing about who may own or write beyond
   SYSTEM, Administrators and TrustedInstaller (and root on Unix); each caller passes its own
   accounts and write rights explicitly.
5. **Unsafe code in one module.** The private FFI module (windows-sys, libc) is the only one that
   allows `unsafe`, each block on its own with its `// SAFETY:` invariant; every other module
   forbids it.

## Using it

```toml
[dependencies]
seaworthy-fsguard = "0.1"
```

```rust
use seaworthy_fsguard::acl::{DIRECTORY_WRITE_RIGHTS, WriterPolicy, untrusted};

// SYSTEM, Administrators, TrustedInstaller and one service account may own
// and write; OWNER RIGHTS entries grant the owner, whom the rule checks.
let accounts = ["S-1-5-80-1-2-3-4-5"];
let policy = WriterPolicy::administrators(DIRECTORY_WRITE_RIGHTS)
    .with_accounts(&accounts, "the service's account")
    .trusting_owner_rights();
let why = untrusted("C:\\ProgramData\\Acme\\Agent\\state", Some("S-1-5-21-1-2-3-1001"), Some(&[]), &policy);
assert!(why.is_some_and(|why| why.contains("is owned by")));
```

The Windows audits run on Windows only; their behavior is exercised by the seaworthy lab's MSI
install, update and service lanes on Windows runners.

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or
[MIT license](../../LICENSE-MIT) at your option.
