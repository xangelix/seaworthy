//! Pinned image references: public images, latest stable at pin time
//! (2026-10), as `name:tag@sha256:…` digest pins: a tag alone is mutable
//! upstream, and a re-tagged image would run with daemon access. The tag
//! documents what the digest pins (docker pulls by digest either way).
//! Bumping is a deliberate one-line change here, and THIS SOURCE DIFF is
//! the supply-chain evidence: a cargo SBOM does NOT see image pins.
//!
//! Re-resolve a digest after a tag bump (anonymous registry flow, Docker
//! Hub shown):
//!
//! ```sh
//! TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:<repo>:pull" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
//! curl -s -o /dev/null -D - -H "Authorization: Bearer $TOKEN" \
//!   -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json" \
//!   "https://registry-1.docker.io/v2/<repo>/manifests/<tag>" | grep -i docker-content-digest
//! ```
//!
//! (Official images live under `library/<name>`. Red Hat's registry,
//! `registry.access.redhat.com`, answers the same manifest request without
//! a token. A registry that omits the digest header: fetch the manifest
//! body with the manifest-list `Accept` and `sha256sum` the EXACT bytes;
//! verify by refetching `…/manifests/sha256:<d>`.)
//!
//! [`ALL`] lists every pin, named. It is the ONE list the pre-pull step
//! (`scripts/pull-test-images.sh` → [`crate::prepull`]) reads (there is no
//! second, hand-kept copy) and a test parses this file, so a pin added
//! without its [`ALL`] row fails the suite. Bumping a pin is still one
//! line: the constant.

/// RustFS standalone S3 (fs layout: a bucket is a directory in the data
/// root): the S3-compatible store the publisher's suites run against.
pub const RUSTFS: &str = "rustfs/rustfs:1.0.0-rc.6@sha256:97171b3d72cd47dc81000f92ea84de25608bfc35a94c965501afaeb5d99f6035";

// The Linux conformance lane's systemd hosts (`crate::systemd`): each
// distribution the CLI's packages must install on. Group `SystemdHosts`:
// pulled only when named (`--only debian-13,…`), not by the default
// pre-pull.

/// Debian 13 (trixie).
pub const DEBIAN_13: &str =
    "debian:13@sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5";
/// Ubuntu 24.04 LTS.
pub const UBUNTU_2404: &str =
    "ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55";
/// Red Hat UBI 9, init flavour (systemd 252, rpm 4.16: RHEL 9's).
pub const UBI9_INIT: &str = "registry.access.redhat.com/ubi9/ubi-init:9.8-1791927685@sha256:c892e9655a76c9c44ac27d639b1ccffd5590521bf7858a3b4cacb806688cfb08";
/// Fedora 43.
pub const FEDORA_43: &str =
    "fedora:43@sha256:a651ddf48ea28a06ed4e1e6519f51c9f47e7a5a138722ade87369b8fbb7e5b42";
/// Arch Linux (rolling; the dated tag of the pinned image).
pub const ARCH: &str = "archlinux:base-20261011.0.609700@sha256:3c64b538588416593f69a1aebd2f2ec0f2541b29159f32556fa7def2167147a0";

// The Linux conformance lane's builder: the pinned toolchain on Debian 12,
// whose glibc (2.36) builds binaries needing no symbol past 2.34 (RHEL 9's,
// the lane's oldest host, and the CLI's default glibc floor). Group
// `Builders`.

/// Rust (the `rust-toolchain.toml` pin) on Debian 12 (bookworm).
pub const RUST_BUILDER: &str =
    "rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e";

/// Which pre-pulls take a pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    /// The container suites' services: pulled by the default pre-pull.
    Suites,
    /// The Linux conformance lane's systemd hosts ([`crate::systemd`]):
    /// pulled only when named (`--only debian-13,…`), by that lane.
    SystemdHosts,
    /// Images a lane builds in (the conformance lane's [`RUST_BUILDER`]):
    /// pulled only when named.
    Builders,
}

/// One pinned image: the short name the pre-pull step selects it by
/// (`scripts/pull-test-images.sh --only rustfs,debian-13`), its reference,
/// and its group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pin {
    /// The selector name (`rustfs`, `debian-13`, …).
    pub name: &'static str,
    /// The `name:tag@sha256:…` reference.
    pub reference: &'static str,
    /// Which pre-pulls take it.
    pub group: Group,
}

/// Every pin above: the list the pre-pull step reads. Keep it complete:
/// `tests::all_lists_every_pin_in_this_file` parses this file and fails
/// on a pinned constant missing here.
pub const ALL: &[Pin] = &[
    Pin {
        name: "rustfs",
        reference: RUSTFS,
        group: Group::Suites,
    },
    Pin {
        name: "debian-13",
        reference: DEBIAN_13,
        group: Group::SystemdHosts,
    },
    Pin {
        name: "ubuntu-24.04",
        reference: UBUNTU_2404,
        group: Group::SystemdHosts,
    },
    Pin {
        name: "ubi-9",
        reference: UBI9_INIT,
        group: Group::SystemdHosts,
    },
    Pin {
        name: "fedora-43",
        reference: FEDORA_43,
        group: Group::SystemdHosts,
    },
    Pin {
        name: "arch",
        reference: ARCH,
        group: Group::SystemdHosts,
    },
    Pin {
        name: "rust-builder",
        reference: RUST_BUILDER,
        group: Group::Builders,
    },
];

/// Check that `reference` is a digest pin: `name:tag@sha256:<64 lowercase
/// hex>` (a tag alone is mutable upstream, and a re-tagged image runs with
/// daemon access). The tag must be present (it documents what the digest
/// pins); the name and tag must use the reference grammar's characters
/// (the string reaches the daemon verbatim). Every pull this crate makes
/// passes through here first ([`crate::pull::ensure_image`]): the
/// launcher's pins and a caller's extra pre-pull images alike.
///
/// # Errors
/// What is wrong with the reference, for the message.
pub fn validate_pin(reference: &str) -> Result<(), String> {
    let Some((named, digest)) = reference.rsplit_once('@') else {
        return Err("not digest-pinned (expected name:tag@sha256:<64 hex>)".into());
    };
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err("the digest algorithm must be sha256".into());
    };
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err("a sha256 digest is 64 lowercase hex characters".into());
    }
    // The tag follows the LAST colon; a colon inside a registry host's
    // port (`host:5000/repo`) leaves a `/` in that "tag", i.e. no tag.
    let Some((name, tag)) = named.rsplit_once(':') else {
        return Err("no tag before the digest (expected name:tag@sha256:…)".into());
    };
    let tag_ok = !tag.is_empty()
        && tag.len() <= 128
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    if !tag_ok {
        return Err(format!(
            "{tag:?} is not a valid tag (expected name:tag@sha256:…)"
        ));
    }
    // A colon in the name is only a registry host's port: in the first
    // path component, numeric, with a repository path after it.
    let port_ok = match name.split_once('/') {
        Some((host, path)) => {
            !path.contains(':')
                && host.split_once(':').is_none_or(|(host, port)| {
                    !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
                })
        }
        None => !name.contains(':'),
    };
    let name_ok = port_ok
        && !name.is_empty()
        && !name.starts_with('/')
        && !name.ends_with('/')
        && !name.contains("//")
        && name.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'_' | b'-' | b'/' | b':')
        });
    if !name_ok {
        return Err(format!("{name:?} is not a valid image name"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{super::split_image, ALL, validate_pin};

    #[test]
    fn pinned_images_split_into_name_and_tag() {
        for pin in ALL {
            let (name, tag) = split_image(pin.reference);
            assert!(
                !name.is_empty() && !tag.is_empty(),
                "malformed pin: {pin:?}"
            );
            assert_ne!(tag, "latest", "a floating tag is not a pin: {pin:?}");
        }
        // The registry-host-with-port case (the reason for rsplit_once).
        assert_eq!(
            split_image("registry.example:5000/acme/tool:v1.0.0"),
            ("registry.example:5000/acme/tool", "v1.0.0")
        );
    }

    /// Every pin is a digest pin (`name:tag@sha256:<64 hex>`): a tag alone
    /// is mutable upstream, and a re-tagged image runs with daemon access.
    /// The tag documents what the digest pins; the digest is the identity.
    #[test]
    fn every_pin_is_digest_pinned() {
        for pin in ALL {
            let image = pin.reference;
            validate_pin(image).unwrap_or_else(|problem| panic!("{image:?}: {problem}"));
            // The tag half must survive the split (it documents the pin and
            // keeps the assembled reference valid).
            let (name, tag) = split_image(image);
            assert!(tag.starts_with(|c: char| c != '@'), "tag lost in {image:?}");
            assert!(
                !name.contains(':'),
                "name must not carry the tag: {image:?}"
            );
        }
    }

    /// The validator every pull passes through: the digest form with a tag
    /// is the only accepted shape.
    #[test]
    fn validate_pin_accepts_only_tagged_digest_pins() {
        let hex = "24220ef2c80a2a421ea08e4624488e985330c421b6aa3329bae14b0933a1d403";
        for good in [
            format!("acme/tool:1.8.1.3@sha256:{hex}"),
            format!("public.ecr.aws/acme/tool:v1.0.0@sha256:{hex}"),
            format!("registry.example:5000/team/app:2026.10-rc_1@sha256:{hex}"),
            format!("busybox:1.37.0@sha256:{hex}"),
        ] {
            assert_eq!(validate_pin(&good), Ok(()), "{good}");
        }
        for (bad, why) in [
            ("acme/tool:1.8.1.3".to_string(), "floating tag"),
            ("acme/tool:latest".to_string(), "floating tag"),
            (format!("acme/tool@sha256:{hex}"), "no tag"),
            (
                format!("registry.example:5000/app@sha256:{hex}"),
                "port, no tag",
            ),
            (format!("acme/tool:1.8@sha512:{hex}"), "not sha256"),
            (
                format!("acme/tool:1.8@sha256:{}", &hex[..63]),
                "short digest",
            ),
            (
                format!("acme/tool:1.8@sha256:{}", hex.to_uppercase()),
                "uppercase hex",
            ),
            (format!("acme/tool:@sha256:{hex}"), "empty tag"),
            (format!(":1.8@sha256:{hex}"), "empty name"),
            (format!("Acme/Tool:1.8@sha256:{hex}"), "uppercase name"),
            (format!("acme/tool:1.8 --rm@sha256:{hex}"), "whitespace"),
            (format!("/acme:1.8@sha256:{hex}"), "leading slash"),
            (format!("acme//tool:1.8@sha256:{hex}"), "empty component"),
            (format!("a/b:c/d:1.8@sha256:{hex}"), "colon past the host"),
            (
                format!("host:port/app:1.8@sha256:{hex}"),
                "non-numeric port",
            ),
        ] {
            assert!(validate_pin(&bad).is_err(), "{why}: {bad} must be refused");
        }
    }

    /// [`ALL`] is the list the pre-pull step reads, so it must be EXACTLY
    /// the pins this file declares. Parsed from the source (the production
    /// half, before the test module): every digest-pinned string literal
    /// must be an [`ALL`] reference, and every `pub const …: &str` must be
    /// one of them. A pin added without its row (or a row left behind by a
    /// removed pin) fails here, naming it.
    #[test]
    fn all_lists_every_pin_in_this_file() {
        let source = include_str!("images.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("the file has a production half");
        let mut literals = BTreeSet::new();
        let mut str_consts = 0;
        for line in production.lines().map(str::trim) {
            if line.starts_with("//") {
                continue;
            }
            if line.starts_with("pub const ") && line.contains(": &str") {
                str_consts += 1;
            }
            // Odd segments of a `"`-split line are string literals (the
            // production half has no escaped quotes outside comments); a
            // pin is one ending in `@sha256:<64 hex>` (the validator's own
            // messages mention the shape but never carry a digest).
            for literal in line.split('"').skip(1).step_by(2) {
                let is_pin = literal.rsplit_once("@sha256:").is_some_and(|(_, hex)| {
                    hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())
                });
                if is_pin {
                    literals.insert(literal.to_string());
                }
            }
        }
        let listed: BTreeSet<String> = ALL.iter().map(|p| p.reference.to_string()).collect();
        let missing: Vec<_> = literals.difference(&listed).collect();
        assert!(
            missing.is_empty(),
            "images.rs pins these but images::ALL omits them; add a Pin row: {missing:?}"
        );
        let stale: Vec<_> = listed.difference(&literals).collect();
        assert!(
            stale.is_empty(),
            "images::ALL lists references this file no longer pins: {stale:?}"
        );
        assert_eq!(
            str_consts,
            ALL.len(),
            "every `pub const …: &str` in images.rs is a pin and must have exactly one ALL row"
        );
        let names: BTreeSet<_> = ALL.iter().map(|p| p.name).collect();
        assert_eq!(names.len(), ALL.len(), "ALL names must be unique");
        assert_eq!(listed.len(), ALL.len(), "ALL references must be unique");
        for pin in ALL {
            assert!(
                !pin.name.is_empty()
                    && pin.name.bytes().all(|b| b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || b == b'-'
                        || b == b'.'),
                "selector names are lowercase-kebab (a `.` for versions): {pin:?}"
            );
        }
    }

    /// The digest form splits so the reassembled `{name}:{tag}` descriptor is
    /// the valid `name:tag@sha256:…` reference (docker pulls by digest).
    #[test]
    fn split_image_handles_the_digest_form() {
        assert_eq!(
            split_image("acme/collector-contrib:0.160.0@sha256:799dc6cf"),
            ("acme/collector-contrib", "0.160.0@sha256:799dc6cf")
        );
        // Registry host with a port AND a digest.
        assert_eq!(
            split_image("registry.example:5000/acme/tool:v1.0.0@sha256:d581789c"),
            ("registry.example:5000/acme/tool", "v1.0.0@sha256:d581789c")
        );
        // A digest pin reassembles byte-for-byte.
        let image = "acme/idp:v2.45.1@sha256:8499afd6";
        let (name, tag) = split_image(image);
        assert_eq!(format!("{name}:{tag}"), image);
    }

    /// Every pin is a public image: Docker Hub (official images and
    /// `rustfs/`) or Red Hat's public registry. No private registry is ever
    /// a default (a caller's own images go through `--image`).
    #[test]
    fn every_pin_is_a_public_image() {
        for pin in ALL {
            let (name, _) = split_image(pin.reference);
            let public = (!name.contains('.') && !name.contains(':'))
                || name.starts_with("registry.access.redhat.com/");
            assert!(public, "{pin:?} is not on a public registry");
        }
    }
}
