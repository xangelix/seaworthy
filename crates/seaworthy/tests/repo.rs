//! `seaworthy repo`: two products' signed releases published as
//! APT, DNF and pacman repositories and the update helper's release tree,
//! then read back the way each client does — `gpgv` over `InRelease`,
//! `Release.gpg`, `repomd.xml.asc` and the pacman database signatures with
//! the published key alone; every index hash checked down to the package
//! bytes; the pacman database read with `bsdtar` — and the publish plan
//! checked against the tree (every file once, immutable files first, the
//! indexes in their order). Then everything `repo` must refuse: a release
//! no client would accept (a missing or foreign manifest, an unsigned rpm,
//! a pacman package without its signature, a manifest by an untrusted
//! key), listings that don't belong together, a changed or escaping file,
//! an index signer the pins don't name, an existing output.
//!
//! Installing from these repositories with the real apt, dnf and pacman is
//! the Linux conformance lane's (`tests/conformance.rs`). A missing tool is
//! skipped loudly, unless `SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1` turns the
//! skip into a failure.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::repo_fixture::{CONFIG, DATE, Fixture, TOKEN, tools};
use common::{Keyring, have, run};
use seaworthy::config::Config;
use seaworthy::package::Kind;
use seaworthy::repo::{Class, Listing, Options, Plan, Signers, Tools, read_listing};

/// An executable script at `path`.
fn script(path: &Path, text: &str) -> PathBuf {
    std::fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    path.to_path_buf()
}

/// `gpgv` with the published key alone, as apt runs it (`Signed-By:`):
/// checks `args` (a signature and its file, or a clear-signed file) and,
/// for a clear-signed file, returns the text it signs.
fn gpgv(key: &Path, args: &[&Path]) -> Vec<u8> {
    let home = tempfile::tempdir().unwrap();
    let keyring = home.path().join("published.gpg");
    run(Command::new("gpg")
        .arg("--homedir")
        .arg(home.path())
        .args(["--batch", "--yes", "--dearmor", "--output"])
        .arg(&keyring)
        .arg(key));
    let text = home.path().join("text");
    let out = Command::new("gpgv")
        .arg("--homedir")
        .arg(home.path())
        .arg("--keyring")
        .arg(&keyring)
        .arg("--output")
        .arg(&text)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "gpgv {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(&text).unwrap_or_default()
}

fn sha256(bytes: &[u8]) -> String {
    seaworthy_crypto::digest::sha256_hex(bytes)
}

/// `field: value` of a deb822 stanza.
fn field<'a>(stanza: &'a str, name: &str) -> &'a str {
    stanza
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name}: ")))
        .unwrap_or_else(|| panic!("no {name} in {stanza}"))
}

/// The listed artifact of `kind`.
fn listed(listing: &Listing, kind: Kind) -> &seaworthy::repo::ListedArtifact {
    listing
        .artifacts
        .iter()
        .find(|a| a.kind == kind)
        .unwrap_or_else(|| panic!("no {kind:?} in {}", listing.package))
}

fn files_under(dir: &Path, base: &Path, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        assert!(!kind.is_symlink(), "{}: a link", entry.path().display());
        if kind.is_dir() {
            files_under(&entry.path(), base, out);
        } else {
            out.insert(
                entry
                    .path()
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
}

#[test]
fn signed_releases_publish_as_repositories_every_client_reads() {
    let Some(nfpm) = tools() else { return };
    let fixture = Fixture::new(&nfpm, true);
    let listings = fixture.listings();
    let out = fixture.path().join("repo");
    let plan = fixture.build(&listings, &out).unwrap();
    let key = out.join("keys/acme.asc");
    assert_eq!(
        std::fs::read(&key).unwrap(),
        std::fs::read(fixture.path().join("pgp.asc")).unwrap(),
        "the published key is the pinned key"
    );

    // APT: InRelease and Release.gpg verify with the published key alone
    // and sign exactly Release; Release names every index by size and
    // hash, by-hash copies included; Packages names every deb in the pool
    // by size and hash.
    let dists = out.join("apt/dists/stable");
    let release = std::fs::read_to_string(dists.join("Release")).unwrap();
    assert_eq!(
        gpgv(&key, &[&dists.join("InRelease")]),
        release.as_bytes(),
        "InRelease signs exactly Release"
    );
    gpgv(&key, &[&dists.join("Release.gpg"), &dists.join("Release")]);
    for line in [
        "Origin: acme",
        "Suite: stable",
        "Codename: stable",
        "Date: Wed, 14 Oct 2026 12:00:00 UTC",
        "Architectures: amd64",
        "Components: main",
        "Acquire-By-Hash: yes",
    ] {
        assert!(release.lines().any(|l| l == line), "{line}: {release}");
    }
    let indexes: Vec<(&str, u64, &str)> = release
        .split_once("SHA256:\n")
        .unwrap()
        .1
        .lines()
        .map(|l| {
            let mut parts = l.split_whitespace();
            (
                parts.next().unwrap(),
                parts.next().unwrap().parse().unwrap(),
                parts.next().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        indexes.iter().map(|i| i.2).collect::<Vec<_>>(),
        [
            "main/binary-amd64/Packages",
            "main/binary-amd64/Packages.gz"
        ]
    );
    for (hash, size, path) in &indexes {
        let bytes = std::fs::read(dists.join(path)).unwrap();
        assert_eq!(
            (sha256(&bytes).as_str(), bytes.len() as u64),
            (*hash, *size)
        );
        assert_eq!(
            std::fs::read(dists.join("main/binary-amd64/by-hash/SHA256").join(hash)).unwrap(),
            bytes
        );
    }
    let packages = std::fs::read_to_string(dists.join("main/binary-amd64/Packages")).unwrap();
    let gz = std::fs::read(dists.join("main/binary-amd64/Packages.gz")).unwrap();
    assert_eq!(
        miniz_oxide::inflate::decompress_to_vec(&gz[10..gz.len() - 8]).unwrap(),
        packages.as_bytes()
    );
    let stanzas: Vec<&str> = packages
        .split("\n\n")
        .filter(|s| !s.trim().is_empty())
        .collect();
    assert_eq!(stanzas.len(), 2, "{packages}");
    for listing in &listings {
        let stanza = stanzas
            .iter()
            .find(|s| field(s, "Package") == listing.package)
            .unwrap();
        let deb = listed(listing, Kind::Deb);
        let bytes = std::fs::read(deb.path(listing)).unwrap();
        assert_eq!(field(stanza, "Version"), "2.1.0-9");
        assert_eq!(field(stanza, "Architecture"), "amd64");
        assert_eq!(field(stanza, "SHA256"), sha256(&bytes));
        assert_eq!(field(stanza, "Size"), bytes.len().to_string());
        let filename = field(stanza, "Filename");
        assert_eq!(
            filename,
            format!(
                "pool/main/{}/{}",
                listing.package,
                deb.file.rsplit('/').next().unwrap()
            )
        );
        assert_eq!(
            std::fs::read(out.join("apt").join(filename)).unwrap(),
            bytes
        );
    }

    // DNF: repomd.xml.asc verifies; repomd names the hash-named primary
    // metadata by hash, which lists every rpm under Packages/.
    let rpm_root = out.join("rpm/stable/x86_64");
    let repomd = std::fs::read_to_string(rpm_root.join("repodata/repomd.xml")).unwrap();
    gpgv(
        &key,
        &[
            &rpm_root.join("repodata/repomd.xml.asc"),
            &rpm_root.join("repodata/repomd.xml"),
        ],
    );
    assert!(
        repomd.contains(&format!("<revision>{DATE}</revision>")),
        "{repomd}"
    );
    let primary = repomd.split("<data type=\"primary\">").nth(1).unwrap();
    let checksum = primary
        .split("<checksum type=\"sha256\">")
        .nth(1)
        .unwrap()
        .split('<')
        .next()
        .unwrap();
    let href = primary
        .split("<location href=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    assert_eq!(href, format!("repodata/{checksum}-primary.xml.gz"));
    let primary_gz = rpm_root.join(href);
    assert_eq!(sha256(&std::fs::read(&primary_gz).unwrap()), checksum);
    let primary_xml = run(Command::new("gzip").arg("-dc").arg(&primary_gz));
    for listing in &listings {
        let rpm = listed(listing, Kind::Rpm);
        let name = rpm.file.rsplit('/').next().unwrap();
        assert!(
            primary_xml.contains(&format!("<name>{}</name>", listing.package)),
            "{primary_xml}"
        );
        assert!(
            primary_xml.contains(&format!("<location href=\"Packages/{name}\"/>")),
            "{primary_xml}"
        );
        assert_eq!(
            std::fs::read(rpm_root.join("Packages").join(name)).unwrap(),
            std::fs::read(rpm.path(listing)).unwrap()
        );
    }

    // pacman: the names pacman reads are the databases' bytes, each
    // signature verifies, and the database lists every package by its
    // file name, its detached signature beside it.
    let pacman_root = out.join("pacman/stable/x86_64");
    for (archive, alias) in [
        ("acme.db.tar.zst", "acme.db"),
        ("acme.files.tar.zst", "acme.files"),
    ] {
        let bytes = std::fs::read(pacman_root.join(archive)).unwrap();
        assert_eq!(std::fs::read(pacman_root.join(alias)).unwrap(), bytes);
        assert_eq!(
            std::fs::read(pacman_root.join(format!("{alias}.sig"))).unwrap(),
            std::fs::read(pacman_root.join(format!("{archive}.sig"))).unwrap()
        );
        gpgv(
            &key,
            &[
                &pacman_root.join(format!("{alias}.sig")),
                &pacman_root.join(alias),
            ],
        );
    }
    let db = pacman_root.join("acme.db");
    let entries = run(Command::new("bsdtar").arg("-tf").arg(&db));
    for listing in &listings {
        let entry = format!("{}-2.1.0-9/desc", listing.package);
        assert!(entries.lines().any(|l| l == entry), "{entries}");
        let desc = run(Command::new("bsdtar").arg("-xOf").arg(&db).arg(&entry));
        let package = listed(listing, Kind::Pacman);
        let name = package.file.rsplit('/').next().unwrap();
        assert!(desc.contains(&format!("%FILENAME%\n{name}\n")), "{desc}");
        gpgv(
            &key,
            &[
                &pacman_root.join(format!("{name}.sig")),
                &pacman_root.join(name),
            ],
        );
    }

    // Releases: every installable artifact where the helper's URL template
    // points, with its manifest and (pacman) its signature, byte for byte;
    // never its SBOM, which this seaworthy.toml doesn't publish.
    let mut released = 0;
    for listing in &listings {
        for artifact in &listing.artifacts {
            let Some(format) = artifact.kind.artifact_format() else {
                continue;
            };
            released += 1;
            let dir = out
                .join("releases")
                .join(&listing.package)
                .join("stable")
                .join(TOKEN)
                .join(&artifact.target);
            let name = format!("{}.{}", listing.package, format.tag());
            assert_eq!(
                std::fs::read(dir.join(&name)).unwrap(),
                std::fs::read(artifact.path(listing)).unwrap(),
                "{name}"
            );
            assert!(
                !dir.join(format!("{name}.cdx.json")).exists(),
                "{name}: an SBOM published without publish-sboms"
            );
            let mut companions = vec![".manifest"];
            if artifact.kind == Kind::Pacman {
                companions.push(".sig");
            }
            for suffix in companions {
                assert_eq!(
                    std::fs::read(dir.join(format!("{name}{suffix}"))).unwrap(),
                    std::fs::read(listing.dir.join(format!("{}{suffix}", artifact.file))).unwrap(),
                    "{name}{suffix}"
                );
            }
        }
    }
    assert_eq!(
        released, 8,
        "agent: deb, rpm, pacman, tar, zip; console: three"
    );
    assert!(
        out.join(format!(
            "releases/acme-agent/stable/{TOKEN}/x86_64-pc-windows-msvc/acme-agent.zip"
        ))
        .is_file()
    );

    // The plan: written as returned; every file once; the immutable files
    // first (sorted), then the indexes in the order each client needs.
    let written: Plan =
        serde_json::from_slice(&std::fs::read(out.join("publish-plan.json")).unwrap()).unwrap();
    assert_eq!(written, plan);
    assert_eq!(
        (plan.repository.as_str(), plan.channel.as_str()),
        ("acme", "stable")
    );
    assert_eq!(
        plan.tools.keys().map(String::as_str).collect::<Vec<_>>(),
        ["createrepo_c", "dpkg-scanpackages", "repo-add"]
    );
    assert!(
        plan.tools["repo-add"].contains("pacman"),
        "{:?}",
        plan.tools
    );
    let mut on_disk = BTreeSet::new();
    files_under(&out, &out, &mut on_disk);
    on_disk.remove("publish-plan.json");
    let planned: BTreeSet<String> = plan.files.iter().map(|f| f.path.clone()).collect();
    assert_eq!(planned.len(), plan.files.len(), "a file planned twice");
    assert_eq!(planned, on_disk);
    for file in &plan.files {
        let bytes = std::fs::read(out.join(&file.path)).unwrap();
        assert_eq!(
            (file.sha256.clone(), file.size),
            (sha256(&bytes), bytes.len() as u64)
        );
    }
    let first_index = plan
        .files
        .iter()
        .position(|f| f.class == Class::Index)
        .unwrap();
    let (immutable, index) = plan.files.split_at(first_index);
    assert!(immutable.iter().all(|f| f.class == Class::Immutable));
    assert!(immutable.windows(2).all(|w| w[0].path < w[1].path));
    assert_eq!(
        index.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(),
        [
            "keys/acme.asc",
            "apt/dists/stable/main/binary-amd64/Packages",
            "apt/dists/stable/main/binary-amd64/Packages.gz",
            "apt/dists/stable/Release",
            "apt/dists/stable/Release.gpg",
            "apt/dists/stable/InRelease",
            "rpm/stable/x86_64/repodata/repomd.xml",
            "rpm/stable/x86_64/repodata/repomd.xml.asc",
            "pacman/stable/x86_64/acme.files.tar.zst",
            "pacman/stable/x86_64/acme.files.tar.zst.sig",
            "pacman/stable/x86_64/acme.files",
            "pacman/stable/x86_64/acme.files.sig",
            "pacman/stable/x86_64/acme.db.tar.zst",
            "pacman/stable/x86_64/acme.db.tar.zst.sig",
            "pacman/stable/x86_64/acme.db",
            "pacman/stable/x86_64/acme.db.sig",
        ]
    );
    assert!(index.iter().all(|f| f.class == Class::Index));
    for immutable_path in [
        format!(
            "apt/dists/stable/main/binary-amd64/by-hash/SHA256/{}",
            indexes[0].0
        ),
        format!("rpm/stable/x86_64/{href}"),
        format!("releases/acme-console/stable/{TOKEN}/x86_64-unknown-linux-gnu/acme-console.deb"),
    ] {
        assert!(
            immutable.iter().any(|f| f.path == immutable_path),
            "{immutable_path}"
        );
    }
}

/// Copies `from` into `to`, recursively.
/// With `publish-sboms`, every installable artifact's SBOM is published
/// beside it, byte for byte, and the plan names it as immutable.
#[test]
fn sboms_are_published_when_seaworthy_toml_asks() {
    let Some(nfpm) = tools() else { return };
    let mut fixture = Fixture::new(&nfpm, true);
    fixture.config.defaults.publish_sboms = true;
    let listings = fixture.listings();
    let out = fixture.path().join("repo");
    let plan = fixture.build(&listings, &out).unwrap();
    let mut published = 0;
    for listing in &listings {
        for artifact in &listing.artifacts {
            let Some(format) = artifact.kind.artifact_format() else {
                continue;
            };
            let path = format!(
                "releases/{package}/stable/{TOKEN}/{target}/{package}.{format}.cdx.json",
                package = listing.package,
                target = artifact.target,
                format = format.tag()
            );
            assert_eq!(
                std::fs::read(out.join(&path)).unwrap(),
                std::fs::read(listing.dir.join(format!("{}.cdx.json", artifact.file))).unwrap(),
                "{path}"
            );
            assert!(
                plan.files
                    .iter()
                    .any(|f| f.path == path && f.class == Class::Immutable),
                "{path} isn't planned as immutable"
            );
            published += 1;
        }
    }
    assert_eq!(
        published, 8,
        "agent: deb, rpm, pacman, tar, zip; console: three"
    );
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// A copy of the fixture's packages, `edit` applied to product `id`'s
/// listing (as JSON) and its directory.
fn edited(
    fixture: &Fixture,
    name: &str,
    id: &str,
    edit: impl FnOnce(&mut serde_json::Value, &Path),
) -> PathBuf {
    let packages = fixture.path().join(name);
    copy_dir(&fixture.path().join("dist"), &packages);
    let listing = packages.join(id).join("packages.json");
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&listing).unwrap()).unwrap();
    edit(&mut json, &packages.join(id));
    std::fs::write(&listing, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
    packages
}

/// The index of the listed artifact `file` ends with.
fn position(json: &serde_json::Value, suffix: &str) -> usize {
    json["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .position(|a| a["file"].as_str().unwrap().ends_with(suffix))
        .unwrap_or_else(|| panic!("no artifact ending {suffix}"))
}

#[test]
fn anything_a_client_would_refuse_is_never_published() {
    let Some(nfpm) = tools() else { return };
    let fixture = Fixture::new(&nfpm, true);
    let out = |name: &str| fixture.path().join(name);
    let refused = |result: Result<Plan, seaworthy::DistError>, mentions: &str| {
        let err = result.unwrap_err().to_string();
        assert!(err.contains(mentions), "{mentions}: {err}");
    };

    // Listings that don't belong together.
    let listings = fixture.listings();
    refused(
        fixture.build(&listings[..1], &out("r1")),
        "no release of product \"console\"",
    );
    let twice = [
        listings[0].clone(),
        listings[0].clone(),
        listings[1].clone(),
    ];
    refused(fixture.build(&twice, &out("r2")), "listed twice");
    for (name, key, value, mentions) in [
        (
            "p-channel",
            "channel",
            "beta",
            "a release for channel \"beta\"",
        ),
        (
            "p-product",
            "product",
            "relay",
            "isn't a product of this seaworthy.toml",
        ),
        ("p-token", "token", "2.1.0", "isn't version[+build]"),
    ] {
        let packages = edited(&fixture, name, "agent", |json, _| {
            json[key] = value.into();
        });
        refused(
            fixture.build(&fixture.listings_in(&packages), &out(&format!("r-{name}"))),
            mentions,
        );
    }

    // A product this seaworthy.toml doesn't define, named consistently.
    let packages = edited(&fixture, "p-stranger", "agent", |json, _| {
        json["product"] = "relay".into();
        json["package"] = "acme-relay".into();
    });
    refused(
        fixture.build(&fixture.listings_in(&packages), &out("r-stranger-product")),
        "acme-relay (product \"relay\") isn't a product of this seaworthy.toml",
    );

    // A file that escapes its directory, or changed since packaging.
    let packages = edited(&fixture, "p-escape", "agent", |json, _| {
        let at = position(json, ".deb");
        json["artifacts"][at]["file"] = "../console/packages.json".into();
    });
    let err = read_listing(&packages.join("agent"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("leaves its directory"), "{err}");
    let packages = edited(&fixture, "p-changed", "agent", |json, dir| {
        let at = position(json, ".deb");
        let deb = dir.join(json["artifacts"][at]["file"].as_str().unwrap());
        let mut bytes = std::fs::read(&deb).unwrap();
        bytes.push(0);
        std::fs::write(&deb, bytes).unwrap();
    });
    let err = read_listing(&packages.join("agent"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("changed since it was packaged"), "{err}");
    // Past the update helper's limits: a manifest over 64 KiB
    // (listed with its hash), an artifact over 1 GiB (sparse: refused by
    // its length, never read).
    let packages = edited(&fixture, "p-big-manifest", "agent", |json, dir| {
        let at = position(json, ".deb.manifest");
        let big = vec![b'x'; 64 * 1024 + 1];
        std::fs::write(
            dir.join(json["artifacts"][at]["file"].as_str().unwrap()),
            &big,
        )
        .unwrap();
        json["artifacts"][at]["sha256"] = sha256(&big).into();
    });
    let err = read_listing(&packages.join("agent"))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("larger than the update helper accepts (65536 bytes)"),
        "{err}"
    );
    let packages = edited(&fixture, "p-big-artifact", "agent", |json, dir| {
        let at = position(json, ".tar.zst");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join(json["artifacts"][at]["file"].as_str().unwrap()))
            .unwrap();
        file.set_len(seaworthy_updater::MAX_ARTIFACT_BYTES + 1)
            .unwrap();
    });
    let err = read_listing(&packages.join("agent"))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("larger than the update helper accepts (1073741824 bytes)"),
        "{err}"
    );
    // Links: Unix only (creating them on Windows needs a privilege).
    #[cfg(unix)]
    {
        // A listed file reached through a link: the file, or a
        // directory on its way.
        let packages = edited(&fixture, "p-link", "agent", |json, dir| {
            let at = position(json, ".deb");
            let file = dir.join(json["artifacts"][at]["file"].as_str().unwrap());
            let moved = dir.join("elsewhere.deb");
            std::fs::rename(&file, &moved).unwrap();
            std::os::unix::fs::symlink(&moved, &file).unwrap();
        });
        let err = read_listing(&packages.join("agent"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("is a link"), "{err}");
        let packages = edited(&fixture, "p-dir-link", "agent", |_, dir| {
            std::fs::rename(dir.join("packages"), dir.join("real")).unwrap();
            std::os::unix::fs::symlink(dir.join("real"), dir.join("packages")).unwrap();
        });
        let err = read_listing(&packages.join("agent"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("packages is a link"), "{err}");
    }

    // A release no client would accept.
    let packages = edited(&fixture, "p-no-manifest", "agent", |json, _| {
        let at = position(json, ".deb.manifest");
        json["artifacts"].as_array_mut().unwrap().remove(at);
    });
    refused(
        fixture.build(&fixture.listings_in(&packages), &out("r-no-manifest")),
        "no signed release manifest beside it",
    );
    let packages = edited(&fixture, "p-swapped", "agent", |json, dir| {
        // The deb's manifest in the rpm's place, listed with its hash: a
        // valid signature over the wrong artifact.
        let deb = position(json, ".deb.manifest");
        let rpm = position(json, ".rpm.manifest");
        let deb_manifest =
            std::fs::read(dir.join(json["artifacts"][deb]["file"].as_str().unwrap())).unwrap();
        std::fs::write(
            dir.join(json["artifacts"][rpm]["file"].as_str().unwrap()),
            &deb_manifest,
        )
        .unwrap();
        json["artifacts"][rpm]["sha256"] = sha256(&deb_manifest).into();
    });
    refused(
        fixture.build(&fixture.listings_in(&packages), &out("r-swapped")),
        "its manifest: it describes acme-agent 2.1.0+cafe12 (x86_64-unknown-linux-gnu deb, ",
    );
    let packages = edited(&fixture, "p-no-sig", "agent", |json, _| {
        let at = position(json, ".pkg.tar.zst.sig");
        json["artifacts"].as_array_mut().unwrap().remove(at);
    });
    refused(
        fixture.build(&fixture.listings_in(&packages), &out("r-no-sig")),
        "no detached signature beside it",
    );
    // Manifests by a key this seaworthy.toml doesn't trust.
    let other = fixture.path().join("other");
    std::fs::create_dir(&other).unwrap();
    let stranger =
        seaworthy::sign::generate_key(seaworthy_updater::SignatureAlgorithm::MlDsa87).unwrap();
    std::fs::write(other.join("release.pub"), hex::encode(&stranger.public_key)).unwrap();
    std::fs::copy(fixture.path().join("pgp.asc"), other.join("pgp.asc")).unwrap();
    std::fs::write(other.join("seaworthy.toml"), CONFIG).unwrap();
    let other_config = Config::load(&other.join("seaworthy.toml")).unwrap();
    refused(
        fixture.build_with(
            &other_config,
            &listings,
            &out("r-stranger"),
            &fixture.keyring.signer(),
        ),
        "no ml-dsa-87 signature by one of defaults.release-keys verifies",
    );

    // A listing naming one file twice; a token that isn't a plain path
    // segment (its build too, so it's still version+build).
    let packages = edited(&fixture, "p-dup", "agent", |json, _| {
        let at = position(json, ".deb");
        let again = json["artifacts"][at].clone();
        json["artifacts"].as_array_mut().unwrap().push(again);
    });
    let err = read_listing(&packages.join("agent"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("is listed twice"), "{err}");
    let packages = edited(&fixture, "p-segment", "agent", |json, _| {
        json["build"] = "x/../../y".into();
        json["token"] = "2.1.0+x/../../y".into();
    });
    refused(
        fixture.build(&fixture.listings_in(&packages), &out("r-segment")),
        "isn't a plain path segment",
    );
    // An artifact listed for another target.
    let packages = edited(&fixture, "p-target", "agent", |json, _| {
        let at = position(json, ".deb");
        json["artifacts"][at]["target"] = "x86_64-pc-windows-msvc".into();
    });
    refused(
        fixture.build(&fixture.listings_in(&packages), &out("r-target")),
        "listed for x86_64-pc-windows-msvc, but a deb is for x86_64-unknown-linux-gnu",
    );
    // A pacman package whose .sig a staging key made (listed with its
    // hash).
    let staging = Keyring::new();
    let packages = edited(&fixture, "p-foreign-sig", "agent", |json, dir| {
        let at = position(json, ".pkg.tar.zst");
        let package = dir.join(json["artifacts"][at]["file"].as_str().unwrap());
        let sig = position(json, ".pkg.tar.zst.sig");
        let signature = dir.join(json["artifacts"][sig]["file"].as_str().unwrap());
        std::fs::remove_file(&signature).unwrap();
        seaworthy::codesign::OpenPgpSigner::detach_sign(&staging.signer(), &package, &signature)
            .unwrap();
        json["artifacts"][sig]["sha256"] = sha256(&std::fs::read(&signature).unwrap()).into();
    });
    refused(
        fixture.build(&fixture.listings_in(&packages), &out("r-foreign-sig")),
        "no pinned OpenPGP key made it",
    );
    // Nothing installable: only an SBOM left.
    let packages = edited(&fixture, "p-empty", "console", |json, _| {
        let sbom = json["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["kind"] == "sbom")
            .unwrap()
            .clone();
        json["artifacts"] = serde_json::Value::Array(vec![sbom]);
    });
    refused(
        fixture.build(&fixture.listings_in(&packages), &out("r-empty")),
        "nothing installable to publish",
    );
    // Two artifacts landing on one published path: the deb listed again
    // under another directory, with its (valid) manifest beside it.
    let packages = edited(&fixture, "p-collide", "agent", |json, dir| {
        for suffix in [".deb", ".deb.manifest"] {
            let at = position(json, suffix);
            let mut copy = json["artifacts"][at].clone();
            let file = copy["file"].as_str().unwrap().to_owned();
            let moved = file.replacen("packages/", "packages/again/", 1);
            std::fs::create_dir_all(dir.join("packages/again")).unwrap();
            std::fs::copy(dir.join(&file), dir.join(&moved)).unwrap();
            copy["file"] = moved.into();
            json["artifacts"].as_array_mut().unwrap().push(copy);
        }
    });
    refused(
        fixture.build(&fixture.listings_in(&packages), &out("r-collide")),
        "File exists",
    );
    // No OpenPGP key pinned: with only debs and tarballs left, nothing else
    // asks for one, and the repositories still can't be signed for anyone.
    let mut unpinned = fixture.config.clone();
    unpinned.defaults.openpgp_keys.clear();
    let mut debs_only = Vec::new();
    for id in ["agent", "console"] {
        let packages = edited(&fixture, &format!("p-debs-{id}"), id, |json, _| {
            json["artifacts"].as_array_mut().unwrap().retain(|a| {
                let file = a["file"].as_str().unwrap();
                !file.contains(".rpm") && !file.contains(".pkg.tar.zst")
            });
        });
        debs_only.push(read_listing(&packages.join(id)).unwrap());
    }
    refused(
        fixture.build_with(
            &unpinned,
            &debs_only,
            &out("r-unpinned"),
            &fixture.keyring.signer(),
        ),
        "defaults.openpgp-keys is empty",
    );
    // A pinned key clients refuse: refused before anything is
    // written, whatever gpg would sign with it.
    let weak = Keyring::with_algorithm("rsa1024", &[]);
    weak.export(&out("weak.asc"));
    let mut weak_config = fixture.config.clone();
    weak_config.defaults.openpgp_keys = vec![out("weak.asc")];
    refused(
        fixture.build_with(&weak_config, &listings, &out("r-weak"), &weak.signer()),
        "uses RSA 1024, below 2048",
    );
    assert!(!out("r-weak").exists());

    // An index signer the pins don't name: signed, checked, refused.
    refused(
        fixture.build_with(
            &fixture.config,
            &listings,
            &out("r-staging"),
            &staging.signer(),
        ),
        "no pinned OpenPGP key made it",
    );
    assert!(
        !out("r-staging").join("publish-plan.json").exists(),
        "no plan: nothing to publish"
    );

    // An existing output directory.
    std::fs::create_dir(out("r-exists")).unwrap();
    refused(fixture.build(&listings, &out("r-exists")), "already exists");
    assert!(std::fs::read_dir(out("r-exists")).unwrap().next().is_none());

    // And the untouched packages still publish.
    fixture.build(&listings, &out("r-ok")).unwrap();
    assert!(fixture.pins().openpgp.len() == 1);
}

#[test]
fn unsigned_packages_are_never_published() {
    // Manifests, but no OpenPGP signer: the pacman package has no .sig and
    // the rpm no signature, so pacman and dnf (gpgcheck=1) would refuse
    // them.
    let Some(nfpm) = tools() else { return };
    let fixture = Fixture::new(&nfpm, false);
    let err = fixture
        .build(&fixture.listings(), &fixture.path().join("repo"))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(".pkg.tar.zst: no detached signature beside it"),
        "{err}"
    );
    assert!(!fixture.path().join("repo").exists());
    // Without the pacman packages, the unsigned rpm.
    let mut listings = Vec::new();
    for id in ["agent", "console"] {
        let packages = edited(&fixture, &format!("no-pacman-{id}"), id, |json, _| {
            json["artifacts"]
                .as_array_mut()
                .unwrap()
                .retain(|a| !a["file"].as_str().unwrap().contains(".pkg.tar.zst"));
        });
        listings.push(read_listing(&packages.join(id)).unwrap());
    }
    let err = fixture
        .build(&listings, &fixture.path().join("repo"))
        .unwrap_err()
        .to_string();
    assert!(err.contains(".rpm"), "{err}");
    assert!(err.contains("no pinned OpenPGP key signed it"), "{err}");
    assert!(!fixture.path().join("repo").exists());
    // A listing packaged without signers (an unsigned build's) is never
    // published, whatever its artifacts carry.
    let signed = Fixture::new(&nfpm, true);
    let mut listings = Vec::new();
    for id in ["agent", "console"] {
        let packages = edited(&signed, &format!("unsigned-{id}"), id, |json, _| {
            json["signed"] = serde_json::Value::Bool(id != "console");
        });
        listings.push(read_listing(&packages.join(id)).unwrap());
    }
    let err = signed
        .build(&listings, &signed.path().join("repo"))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(
            "was packaged unsigned (no --signing): the repositories publish signed releases only"
        ),
        "{err}"
    );
    assert!(!signed.path().join("repo").exists());
    // Nor is a dev build's (--authenticode-only), even one that
    // claims to be signed too.
    let mut listings = Vec::new();
    for id in ["agent", "console"] {
        let packages = edited(&signed, &format!("dev-{id}"), id, |json, _| {
            json["authenticode_only"] = serde_json::Value::Bool(id == "console");
        });
        listings.push(read_listing(&packages.join(id)).unwrap());
    }
    assert!(listings[1].authenticode_only && listings[1].signed);
    let err = signed
        .build(&listings, &signed.path().join("repo"))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("is a dev build (Authenticode alone, --authenticode-only): the repositories publish signed releases only"),
        "{err}"
    );
    assert!(!signed.path().join("repo").exists());
}

#[test]
fn without_an_update_helper_releases_publish_on_the_packages_own_signatures() {
    // No product ships an update helper and seaworthy.toml lists no
    // release-signatures. `package` writes no manifests, and `repo`
    // publishes the packages on their own signatures: the rpm's, the pacman
    // package's detached one, and the clear-signed indexes.
    let Some(nfpm) = tools() else { return };
    let fixture = Fixture::without_manifests(&nfpm);
    assert!(!fixture.config.signs_manifests());
    let dist = fixture.path().join("dist");
    let mut packaged = BTreeSet::new();
    files_under(&dist, &dist, &mut packaged);
    assert!(packaged.iter().any(|f| f.ends_with(".rpm")), "{packaged:?}");
    assert!(
        packaged.iter().all(|f| !f.ends_with(".manifest")),
        "{packaged:?}"
    );
    let plan = fixture
        .build(&fixture.listings(), &fixture.path().join("repo"))
        .unwrap();
    let paths: Vec<&str> = plan.files.iter().map(|f| f.path.as_str()).collect();
    assert!(paths.iter().all(|p| !p.ends_with(".manifest")), "{paths:?}");
    for wanted in [
        ".deb",
        ".rpm",
        ".pkg.tar.zst",
        ".pkg.tar.zst.sig",
        "/InRelease",
        "/repomd.xml.asc",
    ] {
        assert!(
            paths.iter().any(|p| p.ends_with(wanted)),
            "no {wanted} in {paths:?}"
        );
    }
    // A manifest beside a package anyway (packaged under a seaworthy.toml that
    // signs them): this seaworthy.toml never vouched for it.
    let packages = edited(&fixture, "p-stray-manifest", "agent", |json, dir| {
        let at = position(json, ".deb");
        let file = format!(
            "{}.manifest",
            json["artifacts"][at]["file"].as_str().unwrap()
        );
        std::fs::write(dir.join(&file), b"a manifest").unwrap();
        let entry = serde_json::json!({
            "kind": "manifest",
            "file": file,
            "target": json["artifacts"][at]["target"].clone(),
            "sha256": sha256(b"a manifest"),
        });
        json["artifacts"].as_array_mut().unwrap().push(entry);
    });
    let err = fixture
        .build(
            &fixture.listings_in(&packages),
            &fixture.path().join("r-stray-manifest"),
        )
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("a release manifest beside it, but seaworthy.toml signs none"),
        "{err}"
    );
    assert!(!fixture.path().join("r-stray-manifest").exists());
}

#[test]
fn the_repo_command_publishes_with_signing_toml_and_exits_like_every_command() {
    let Some(nfpm) = tools() else { return };
    let fixture = Fixture::new(&nfpm, true);
    let signing = fixture.path().join("signing.toml");
    std::fs::write(
        &signing,
        format!(
            "[openpgp]\nhome = {:?}\nkey = \"{}\"\n",
            fixture.keyring.home().to_str().unwrap(),
            fixture.keyring.fingerprint
        ),
    )
    .unwrap();
    let no_openpgp = fixture.path().join("no-openpgp.toml");
    std::fs::write(&no_openpgp, "").unwrap();
    let path = |name: &str| fixture.path().join(name).to_str().unwrap().to_owned();
    let repo = |extra: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
            .arg("repo")
            .args(extra)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.code(), text)
    };
    let config = path("seaworthy.toml");
    let packages = path("dist");
    let base = |out: &str, signing: &str| {
        vec![
            "--config".to_owned(),
            config.clone(),
            "--packages".to_owned(),
            packages.clone(),
            "--out".to_owned(),
            path(out),
            "--signing".to_owned(),
            signing.to_owned(),
        ]
    };
    fn args(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    let mut ok = base("cli", signing.to_str().unwrap());
    ok.extend(["--date".to_owned(), DATE.to_string()]);
    let (code, text) = repo(&args(&ok));
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains(&format!("acme-agent {TOKEN}: published")),
        "{text}"
    );
    assert!(
        text.contains(&format!("acme-console {TOKEN}: published")),
        "{text}"
    );
    assert!(text.contains("repository acme (stable): "), "{text}");
    assert!(text.contains("16 of them indexes"), "{text}");
    let release =
        std::fs::read_to_string(fixture.path().join("cli/apt/dists/stable/Release")).unwrap();
    assert!(
        release.contains("Date: Wed, 14 Oct 2026 12:00:00 UTC"),
        "{release}"
    );

    // Usage (2): a missing, repeated or malformed option.
    let mut no_signing = base("u1", signing.to_str().unwrap());
    no_signing.truncate(6);
    let (code, text) = repo(&args(&no_signing));
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("repo needs --signing"), "{text}");
    let mut twice = base("u2", signing.to_str().unwrap());
    twice.extend(["--packages".to_owned(), packages.clone()]);
    let (code, text) = repo(&args(&twice));
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("--packages given twice"), "{text}");
    for date in ["soon", "-1", "100", "4294967296", ""] {
        let mut bad = base("u3", signing.to_str().unwrap());
        bad.extend(["--date".to_owned(), date.to_owned()]);
        let (code, text) = repo(&args(&bad));
        assert_eq!(code, Some(2), "{date:?}: {text}");
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut future = base("u5", signing.to_str().unwrap());
    future.extend(["--date".to_owned(), (now + 3600).to_string()]);
    let (code, text) = repo(&args(&future));
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("apt refuses a Release dated in the future"),
        "{text}"
    );
    // After the first publication: not again at its date, later fine.
    let previous = fixture.path().join("cli/publish-plan.json");
    let mut stale = base("p1", signing.to_str().unwrap());
    stale.extend([
        "--previous".to_owned(),
        previous.to_str().unwrap().to_owned(),
        "--date".to_owned(),
        DATE.to_string(),
    ]);
    let (code, text) = repo(&args(&stale));
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("isn't after the last publication's"),
        "{text}"
    );
    assert!(!fixture.path().join("p1").exists());
    let mut later = base("p2", signing.to_str().unwrap());
    later.extend([
        "--previous".to_owned(),
        previous.to_str().unwrap().to_owned(),
        "--date".to_owned(),
        (DATE + 60).to_string(),
    ]);
    let (code, text) = repo(&args(&later));
    assert_eq!(code, Some(0), "{text}");
    let mut foreign = base("u4", signing.to_str().unwrap());
    foreign.extend(["--release".to_owned(), "1.0.0".to_owned()]);
    let (code, text) = repo(&args(&foreign));
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("repo does not take \"--release\""), "{text}");

    // Refusals (1): no [openpgp] signer; the output already exists; a
    // product without a listing.
    let (code, text) = repo(&args(&base("r1", no_openpgp.to_str().unwrap())));
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("no [openpgp] signer"), "{text}");
    let (code, text) = repo(&args(&base("cli", signing.to_str().unwrap())));
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("already exists"), "{text}");
    std::fs::remove_file(fixture.path().join("dist/console/packages.json")).unwrap();
    let (code, text) = repo(&args(&base("r2", signing.to_str().unwrap())));
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("console/packages.json"), "{text}");
    assert!(!fixture.path().join("r2").exists());
}

/// Which signatures (`how`: detach, armored or clear; of `file`) the
/// staging key makes.
type Staged = dyn Fn(&str, &Path) -> bool;

/// Signs as `pinned` except where `staged` says, which `staging` signs:
/// one index's signature by another key among good ones.
struct Mixed<'a> {
    pinned: seaworthy::codesign::Gpg,
    staging: seaworthy::codesign::Gpg,
    staged: &'a Staged,
}

impl seaworthy::codesign::OpenPgpSigner for Mixed<'_> {
    fn sign_rpm(&self, rpm: &Path) -> Result<(), seaworthy::DistError> {
        self.pinned.sign_rpm(rpm)
    }
    fn detach_sign(&self, file: &Path, signature: &Path) -> Result<(), seaworthy::DistError> {
        self.pick("detach", file).detach_sign(file, signature)
    }
    fn armored_detach_sign(
        &self,
        file: &Path,
        signature: &Path,
    ) -> Result<(), seaworthy::DistError> {
        self.pick("armored", file)
            .armored_detach_sign(file, signature)
    }
    fn clear_sign(&self, file: &Path, signed: &Path) -> Result<(), seaworthy::DistError> {
        self.pick("clear", file).clear_sign(file, signed)
    }
    fn describe(&self) -> String {
        "mixed".to_owned()
    }
}

impl Mixed<'_> {
    fn pick(&self, how: &str, file: &Path) -> &seaworthy::codesign::Gpg {
        if (self.staged)(how, file) {
            &self.staging
        } else {
            &self.pinned
        }
    }
}

#[test]
fn every_index_signature_is_checked_against_the_pins() {
    // Each signature on its own: a staging key's InRelease beside a good
    // Release.gpg, a staging repomd.xml.asc, a staging pacman database
    // signature — each refused, no plan written.
    let Some(nfpm) = tools() else { return };
    let fixture = Fixture::new(&nfpm, true);
    let staging = Keyring::new();
    let listings = fixture.listings();
    fn name(file: &Path) -> String {
        file.file_name().unwrap().to_string_lossy().into_owned()
    }
    let cases: [(&str, &Staged, &str); 4] = [
        (
            "release-gpg",
            &|how, file| how == "armored" && name(file) == "Release",
            "no pinned OpenPGP key made it",
        ),
        (
            "inrelease",
            &|how, _| how == "clear",
            "no pinned OpenPGP key signed it",
        ),
        (
            "repomd",
            &|how, file| how == "armored" && name(file) == "repomd.xml",
            "no pinned OpenPGP key made it",
        ),
        (
            "pacman-db",
            &|how, file| how == "detach" && name(file) == "acme.db.tar.zst",
            "no pinned OpenPGP key made it",
        ),
    ];
    for (case, staged, mentions) in cases {
        let signer = Mixed {
            pinned: fixture.keyring.signer(),
            staging: staging.signer(),
            staged,
        };
        let out = fixture.path().join(format!("r-{case}"));
        let err = fixture
            .build_with(&fixture.config, &listings, &out, &signer)
            .unwrap_err()
            .to_string();
        assert!(err.contains(mentions), "{case}: {err}");
        assert!(!out.join("publish-plan.json").exists(), "{case}");
    }
    // InRelease signed by the pinned key, over another text.
    struct OtherText(seaworthy::codesign::Gpg, PathBuf);
    impl seaworthy::codesign::OpenPgpSigner for OtherText {
        fn sign_rpm(&self, rpm: &Path) -> Result<(), seaworthy::DistError> {
            self.0.sign_rpm(rpm)
        }
        fn detach_sign(&self, file: &Path, sig: &Path) -> Result<(), seaworthy::DistError> {
            self.0.detach_sign(file, sig)
        }
        fn armored_detach_sign(&self, file: &Path, sig: &Path) -> Result<(), seaworthy::DistError> {
            self.0.armored_detach_sign(file, sig)
        }
        fn clear_sign(&self, _: &Path, signed: &Path) -> Result<(), seaworthy::DistError> {
            self.0.clear_sign(&self.1, signed)
        }
        fn describe(&self) -> String {
            "other text".to_owned()
        }
    }
    let other = fixture.path().join("other-release");
    std::fs::write(&other, "Origin: acme\nSuite: stale\n").unwrap();
    let err = fixture
        .build_with(
            &fixture.config,
            &listings,
            &fixture.path().join("r-other-text"),
            &OtherText(fixture.keyring.signer(), other),
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("signs something other than Release"), "{err}");
}

#[test]
fn a_repository_tool_that_misbehaves_is_caught() {
    let Some(nfpm) = tools() else { return };
    let fixture = Fixture::new(&nfpm, true);
    // dpkg-scanpackages must describe exactly the debs given, each as the
    // listed file: a tool that skipped one, found one that isn't ours, or
    // names other bytes fails the build.
    for (case, body, mentions) in [
        (
            "drops",
            "dpkg-scanpackages \"$@\" | awk -v RS= -v ORS='\\n\\n' '!/Package: acme-console/'",
            "not the packages given",
        ),
        (
            "adds",
            "dpkg-scanpackages \"$@\"; printf 'Package: intruder\\nVersion: 1\\n\\n'",
            "not the packages given",
        ),
        (
            "other-bytes",
            "dpkg-scanpackages \"$@\" | sed 's/^SHA256: ./SHA256: 0/'",
            "dpkg-scanpackages describes acme-",
        ),
    ] {
        let tool = script(
            &fixture.path().join(format!("scan-{case}")),
            &format!(
                "#!/bin/sh\n[ \"$1\" = --version ] && exec dpkg-scanpackages \"$@\"\n{body}\n"
            ),
        );
        let out = fixture.path().join(format!("r-{case}"));
        let err = fixture
            .build_tools(
                &out,
                Tools {
                    dpkg_scanpackages: tool,
                    ..Tools::default()
                },
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains(mentions), "{case}: {err}");
        assert!(!out.exists(), "{case}: a failed build leaves nothing");
    }
    // A tool that leaves a link behind (on every call, --version included,
    // which runs in the output too: never where the caller stands): object
    // storage has no links, so the plan refuses it.
    let tool = script(
        &fixture.path().join("repo-add-link"),
        "#!/bin/sh\nrepo-add \"$@\"; ln -s acme.db.tar.zst extra.db\n",
    );
    let err = fixture
        .build_tools(
            &fixture.path().join("r-link"),
            Tools {
                repo_add: tool,
                ..Tools::default()
            },
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("neither a file nor a directory"), "{err}");
    let here = std::env::current_dir().unwrap();
    assert!(
        std::fs::symlink_metadata(here.join("extra.db")).is_err(),
        "a tool wrote into {}",
        here.display()
    );
    // A source file swapped once its bytes were taken: the
    // published files are the listed ones all the same — every repository
    // copies from the checked release tree, never the source again.
    let again = fixture.package_into("dist-again", 10);
    let listings = fixture.listings();
    let deb = listings[0]
        .artifacts
        .iter()
        .find(|a| a.kind == Kind::Deb)
        .unwrap();
    let source = deb.path(&listings[0]);
    let other = std::fs::read_dir(again.join("agent/packages"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "deb"))
        .unwrap();
    let tool = script(
        &fixture.path().join("scan-swap"),
        &format!(
            "#!/bin/sh\n[ \"$1\" = --version ] && cp {} {} && exec dpkg-scanpackages \"$@\"\nexec dpkg-scanpackages \"$@\"\n",
            other.display(),
            source.display()
        ),
    );
    let out = fixture.path().join("r-swap");
    let plan = seaworthy::repo::build(
        &fixture.config,
        &listings,
        &out,
        &Tools {
            dpkg_scanpackages: tool,
            ..Tools::default()
        },
        &Signers {
            openpgp: &fixture.keyring.signer(),
            pins: &fixture.pins(),
        },
        &Options {
            date: DATE,
            previous: None,
            allow_older: false,
        },
    )
    .unwrap();
    assert_ne!(
        sha256(&std::fs::read(&source).unwrap()),
        deb.sha256,
        "swapped"
    );
    let pool = format!(
        "apt/pool/main/acme-agent/{}",
        deb.file.rsplit('/').next().unwrap()
    );
    let planned = plan.files.iter().find(|f| f.path == pool).unwrap();
    assert_eq!(planned.sha256, deb.sha256);
    assert_eq!(sha256(&std::fs::read(out.join(&pool)).unwrap()), deb.sha256);
    let packages =
        std::fs::read_to_string(out.join("apt/dists/stable/main/binary-amd64/Packages")).unwrap();
    assert!(
        packages.contains(&format!("SHA256: {}", deb.sha256)),
        "{packages}"
    );
}

#[test]
fn a_published_path_never_gets_other_bytes() {
    // Immutable files are cached for a year, so a path is
    // published once. Given the last publication's plan, `repo` refuses a
    // build that would change one, or that isn't newer.
    let Some(nfpm) = tools() else { return };
    let fixture = Fixture::new(&nfpm, true);
    let listings = fixture.listings();
    let at = |name: &str| fixture.path().join(name);
    let first = fixture
        .build_after(&listings, &at("r1"), DATE, None)
        .unwrap();
    assert_eq!(first.date, DATE);
    assert_eq!(
        first
            .releases
            .iter()
            .map(|r| (r.package.as_str(), r.token.as_str(), r.sequence))
            .collect::<Vec<_>>(),
        [("acme-agent", TOKEN, 9), ("acme-console", TOKEN, 9)]
    );
    assert_eq!(Plan::read(&at("r1/publish-plan.json")).unwrap(), first);
    // The same packages again, later: every immutable file the same bytes.
    let second = fixture
        .build_after(&listings, &at("r2"), DATE + 60, Some(&first))
        .unwrap();
    assert_eq!(second.releases, first.releases);
    // Not later: apt would keep the Release it holds.
    for date in [DATE, DATE - 1] {
        let err = fixture
            .build_after(
                &listings,
                &at(&format!("r-date-{date}")),
                date,
                Some(&first),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("isn't after the last publication's"), "{err}");
    }
    // The same token packaged again (a retried pipeline, sequence 10): new
    // signatures and manifests under paths already published.
    let again = fixture.package_into("dist-10", 10);
    let out = at("r-again");
    let err = fixture
        .build_after(&fixture.listings_in(&again), &out, DATE + 120, Some(&first))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("published immutable file(s) would get other bytes"),
        "{err}"
    );
    assert!(
        err.contains(&format!("releases/acme-agent/stable/{TOKEN}/")),
        "{err}"
    );
    assert!(!out.exists(), "a refused build leaves nothing");
    // An older release than the last publication's (a pipeline running
    // out of order): refused, unless a deliberate rollback, which the plan
    // records.
    let older = fixture.package_release("dist-older", "2.0.0", 8);
    let err = fixture
        .build_after(
            &fixture.listings_in(&older),
            &at("r-older"),
            DATE + 150,
            Some(&first),
        )
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("acme-agent 2.0.0+cafe12 (sequence 8) is older than the published 2.1.0+cafe12 (sequence 9)"),
        "{err}"
    );
    assert!(err.contains("repo --allow-older"), "{err}");
    let pins = fixture.pins();
    let rollback = seaworthy::repo::build(
        &fixture.config,
        &fixture.listings_in(&older),
        &at("r-rollback"),
        &Tools::default(),
        &Signers {
            openpgp: &fixture.keyring.signer(),
            pins: &pins,
        },
        &Options {
            date: DATE + 160,
            previous: Some(&first),
            allow_older: true,
        },
    )
    .unwrap();
    assert!(rollback.rollback);
    assert!(!first.rollback);
    // Releases order by version, then sequence, as clients order them: a
    // maintenance release of an older line cut later (2.0.5, sequence 20,
    // after 2.1.0, sequence 9) is older, whatever its sequence; a newer
    // version is newer even with a lower sequence.
    let maintenance = fixture.package_release("dist-maintenance", "2.0.5", 20);
    let err = fixture
        .build_after(
            &fixture.listings_in(&maintenance),
            &at("r-maintenance"),
            DATE + 165,
            Some(&first),
        )
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("acme-agent 2.0.5+cafe12 (sequence 20) is older than the published 2.1.0+cafe12 (sequence 9)"),
        "{err}"
    );
    let reset = fixture.package_release("dist-reset", "2.1.1", 3);
    assert!(
        !fixture
            .build_after(
                &fixture.listings_in(&reset),
                &at("r-reset"),
                DATE + 166,
                Some(&first),
            )
            .unwrap()
            .rollback
    );
    // Products released apart (per-product pipelines): one product's
    // sequence below another's published one is no rollback.
    let newer = fixture.package_release("dist-newer", "2.2.0", 12);
    let mixed: Vec<_> = fixture
        .listings_in(&newer)
        .into_iter()
        .filter(|l| l.product == "agent")
        .chain(
            fixture
                .listings()
                .into_iter()
                .filter(|l| l.product != "agent"),
        )
        .collect();
    let apart = fixture
        .build_after(&mixed, &at("r-apart"), DATE + 170, Some(&first))
        .unwrap();
    assert!(!apart.rollback);
    let again = fixture
        .build_after(&mixed, &at("r-apart-again"), DATE + 180, Some(&apart))
        .unwrap();
    assert!(!again.rollback);
    // Another repository's plan; a path that changes class.
    let mut other = first.clone();
    other.repository = "globex".into();
    let err = fixture
        .build_after(&listings, &at("r-other"), DATE + 180, Some(&other))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("the previous plan publishes globex's stable channel"),
        "{err}"
    );
    let mut flipped = first.clone();
    flipped
        .files
        .iter_mut()
        .find(|f| f.path == "keys/acme.asc")
        .unwrap()
        .class = Class::Immutable;
    let err = fixture
        .build_after(&listings, &at("r-flipped"), DATE + 240, Some(&flipped))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("would get other bytes: keys/acme.asc"),
        "{err}"
    );
    // Not a plan.
    std::fs::write(at("bad.json"), "{}").unwrap();
    let err = Plan::read(&at("bad.json")).unwrap_err().to_string();
    assert!(err.contains("not a publish plan"), "{err}");
}

#[test]
fn the_repository_package_is_published_for_first_installs_and_in_the_repositories() {
    // With [defaults.repository], `<repo>-repository` goes
    // into the APT and DNF repositories like every package (so a key
    // rotation reaches machines through them), and under stable names in
    // setup/ for a first install, the deb with a detached signature by the
    // indexes' key; never into the release tree or the pacman repository.
    // The plan records where it points machines.
    let Some(nfpm) = tools() else { return };
    let fixture = Fixture::with_repository(&nfpm);
    let listings = fixture.listings();
    let repository = &listings[2];
    assert_eq!(
        (repository.product.as_str(), repository.package.as_str()),
        ("repository", "acme-repository")
    );
    let out = fixture.path().join("repo");
    let plan = fixture.build(&listings, &out).unwrap();
    let key = out.join("keys/acme.asc");
    let deb = listed(repository, Kind::Deb);
    let rpm = listed(repository, Kind::Rpm);
    assert_eq!(deb.file, "packages/acme-repository_2.1.0-9_all.deb");
    assert_eq!(rpm.file, "packages/acme-repository-2.1.0-9.noarch.rpm");

    // setup/: the listed bytes under stable names; the deb's signature
    // verifies with the published key alone.
    let setup = out.join("setup");
    let mut in_setup = BTreeSet::new();
    files_under(&setup, &setup, &mut in_setup);
    assert_eq!(
        in_setup.iter().map(String::as_str).collect::<Vec<_>>(),
        [
            "acme-repository.deb",
            "acme-repository.deb.asc",
            "acme-repository.rpm"
        ]
    );
    for (name, listed) in [("acme-repository.deb", deb), ("acme-repository.rpm", rpm)] {
        assert_eq!(
            std::fs::read(setup.join(name)).unwrap(),
            std::fs::read(listed.path(repository)).unwrap(),
            "{name}"
        );
    }
    gpgv(
        &key,
        &[
            &setup.join("acme-repository.deb.asc"),
            &setup.join("acme-repository.deb"),
        ],
    );

    // APT: its stanza (architecture all) beside the products'; no product
    // depends on it.
    let packages =
        std::fs::read_to_string(out.join("apt/dists/stable/main/binary-amd64/Packages")).unwrap();
    let stanzas: Vec<&str> = packages
        .split("\n\n")
        .filter(|s| !s.trim().is_empty())
        .collect();
    assert_eq!(stanzas.len(), 3, "{packages}");
    let stanza = stanzas
        .iter()
        .find(|s| field(s, "Package") == "acme-repository")
        .unwrap();
    assert_eq!(field(stanza, "Architecture"), "all");
    assert_eq!(field(stanza, "Version"), "2.1.0-9");
    let filename = field(stanza, "Filename");
    assert_eq!(
        filename,
        "pool/main/acme-repository/acme-repository_2.1.0-9_all.deb"
    );
    assert_eq!(
        std::fs::read(out.join("apt").join(filename)).unwrap(),
        std::fs::read(deb.path(repository)).unwrap()
    );
    for product in stanzas.iter().filter(|s| *s != stanza) {
        assert!(!product.contains("acme-repository"), "{product}");
    }

    // DNF: noarch, under Packages/ with the products'.
    let rpm_root = out.join("rpm/stable/x86_64");
    let repomd = std::fs::read_to_string(rpm_root.join("repodata/repomd.xml")).unwrap();
    let href = repomd
        .split("<data type=\"primary\">")
        .nth(1)
        .unwrap()
        .split("<location href=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let primary = run(Command::new("gzip").arg("-dc").arg(rpm_root.join(href)));
    assert!(
        primary.contains("<name>acme-repository</name>\n  <arch>noarch</arch>"),
        "{primary}"
    );
    assert!(
        primary.contains("<location href=\"Packages/acme-repository-2.1.0-9.noarch.rpm\"/>"),
        "{primary}"
    );

    // Never the pacman repository or the release tree.
    let db = run(Command::new("bsdtar")
        .arg("-tf")
        .arg(out.join("pacman/stable/x86_64/acme.db")));
    assert!(!db.contains("acme-repository"), "{db}");
    assert!(!out.join("releases/acme-repository").exists());

    // The plan: its URL, the release, the setup files right after the key
    // (indexes: replaced by every publication), the pool copies immutable.
    assert_eq!(
        plan.url.as_deref(),
        Some(common::repo_fixture::REPOSITORY_URL)
    );
    assert!(
        plan.releases
            .iter()
            .any(|r| r.product == "repository" && r.token == TOKEN && r.sequence == 9),
        "{:?}",
        plan.releases
    );
    assert_eq!(
        plan.tools.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "bsdtar",
            "createrepo_c",
            "dpkg-deb",
            "dpkg-scanpackages",
            "repo-add"
        ],
        "the read-back's tools are recorded too"
    );
    let index: Vec<&str> = plan
        .files
        .iter()
        .filter(|f| f.class == Class::Index)
        .map(|f| f.path.as_str())
        .collect();
    assert_eq!(
        index[..5],
        [
            "keys/acme.asc",
            "setup/acme-repository.deb",
            "setup/acme-repository.deb.asc",
            "setup/acme-repository.rpm",
            "apt/dists/stable/main/binary-amd64/Packages",
        ]
    );
    for pool in [
        "apt/pool/main/acme-repository/acme-repository_2.1.0-9_all.deb",
        "rpm/stable/x86_64/Packages/acme-repository-2.1.0-9.noarch.rpm",
    ] {
        assert!(
            plan.files
                .iter()
                .any(|f| f.path == pool && f.class == Class::Immutable),
            "{pool}"
        );
    }

    // What it sets up, read back from the packages: the definitions as
    // configuration files, and exactly the published key.
    let published_key = std::fs::read_to_string(&key).unwrap();
    if have("dpkg-deb", &["--version"]) {
        let unpacked = tempfile::tempdir().unwrap();
        run(Command::new("dpkg-deb")
            .arg("-R")
            .arg(setup.join("acme-repository.deb"))
            .arg(unpacked.path()));
        let read = |path: &str| std::fs::read_to_string(unpacked.path().join(path)).unwrap();
        assert_eq!(
            read("etc/apt/sources.list.d/acme.sources"),
            format!(
                "# Acme's packages, set up by acme-repository (a configuration file: local edits are kept on upgrade).\n\
                 Types: deb\nURIs: {}/apt\nSuites: stable\nComponents: main\nArchitectures: amd64\n\
                 Signed-By: /usr/share/keyrings/acme-archive-keyring.asc\n",
                common::repo_fixture::REPOSITORY_URL
            )
        );
        assert_eq!(
            read("usr/share/keyrings/acme-archive-keyring.asc"),
            published_key
        );
        assert_eq!(
            read("DEBIAN/conffiles"),
            "/etc/apt/sources.list.d/acme.sources\n"
        );
        let control = read("DEBIAN/control");
        for absent in ["Depends", "Recommends", "Pre-Depends"] {
            assert!(!control.contains(absent), "{control}");
        }
    }
    if have("rpm", &["--version"]) {
        let db = tempfile::tempdir().unwrap();
        let file = setup.join("acme-repository.rpm");
        let flags = run(Command::new("rpm")
            .arg("--dbpath")
            .arg(db.path())
            .args(["-qp", "--qf", "[%{FILEFLAGS:fflags} %{FILENAMES}\\n]"])
            .arg(&file));
        assert_eq!(
            flags.lines().map(str::trim).collect::<Vec<_>>(),
            [
                "/etc/pki/rpm-gpg/RPM-GPG-KEY-acme",
                "cn /etc/yum.repos.d/acme.repo"
            ],
            "the definition is %config(noreplace), the key isn't"
        );
        // libarchive reads an rpm's payload itself.
        let extract = |member: &str| run(Command::new("bsdtar").arg("-xOf").arg(&file).arg(member));
        assert_eq!(
            extract("/etc/yum.repos.d/acme.repo"),
            format!(
                "# Acme's packages, set up by acme-repository (a configuration file: local edits are kept on upgrade).\n\
                 [acme]\nname=Acme (stable)\nbaseurl={}/rpm/stable/x86_64\nenabled=1\ngpgcheck=1\n\
                 repo_gpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-acme\n",
                common::repo_fixture::REPOSITORY_URL
            )
        );
        assert_eq!(extract("/etc/pki/rpm-gpg/RPM-GPG-KEY-acme"), published_key);
    }

    // The next publication: a new version's package in the pool beside the
    // last one's (immutable), its copy in setup/ replacing it.
    let next = fixture.package_release("dist-next", "2.2.0", 10);
    let out_next = fixture.path().join("repo-next");
    let second = fixture
        .build_after(
            &fixture.listings_in(&next),
            &out_next,
            DATE + 60,
            Some(&plan),
        )
        .unwrap();
    let next_deb = read_listing(&next.join("repository")).unwrap();
    assert_eq!(
        std::fs::read(out_next.join("setup/acme-repository.deb")).unwrap(),
        std::fs::read(listed(&next_deb, Kind::Deb).path(&next_deb)).unwrap()
    );
    assert!(second.files.iter().any(|f| f.path
        == "apt/pool/main/acme-repository/acme-repository_2.2.0-10_all.deb"
        && f.class == Class::Immutable));
}

#[test]
fn a_repository_package_that_doesnt_fit_is_never_published() {
    let Some(nfpm) = tools() else { return };
    let fixture = Fixture::with_repository(&nfpm);
    let out = |name: &str| fixture.path().join(name);
    let refused = |result: Result<Plan, seaworthy::DistError>, mentions: &str| {
        let err = result.unwrap_err().to_string();
        assert!(err.contains(mentions), "{mentions}: {err}");
    };
    let listings = fixture.listings();

    // Left out: machines set up from setup/ would find nothing there.
    refused(
        fixture.build(&listings[..2], &out("r-missing")),
        "no repository package (acme-repository)",
    );
    // Without the rpm the DNF repository needs.
    let packages = edited(&fixture, "p-no-rpm", "repository", |json, _| {
        json["artifacts"]
            .as_array_mut()
            .unwrap()
            .retain(|a| !a["file"].as_str().unwrap().contains(".rpm"));
    });
    refused(
        fixture.build(&fixture.listings_in(&packages), &out("r-no-rpm")),
        "has no rpm, but the products have one",
    );
    // With an rpm no product's repository needs.
    let mut debs_only = Vec::new();
    for id in ["agent", "console"] {
        let packages = edited(&fixture, &format!("p-debs-{id}"), id, |json, _| {
            json["artifacts"].as_array_mut().unwrap().retain(|a| {
                let file = a["file"].as_str().unwrap();
                !file.contains(".rpm")
            });
        });
        debs_only.push(read_listing(&packages.join(id)).unwrap());
    }
    debs_only.push(listings[2].clone());
    refused(
        fixture.build(&debs_only, &out("r-extra-rpm")),
        "has an rpm, but no product has one",
    );
    // Two debs.
    let packages = edited(&fixture, "p-two-debs", "repository", |json, dir| {
        let at = position(json, "_all.deb");
        let mut copy = json["artifacts"][at].clone();
        let file = copy["file"].as_str().unwrap().to_owned();
        let moved = file.replacen("packages/", "packages/again/", 1);
        std::fs::create_dir_all(dir.join("packages/again")).unwrap();
        std::fs::copy(dir.join(&file), dir.join(&moved)).unwrap();
        copy["file"] = moved.into();
        json["artifacts"].as_array_mut().unwrap().push(copy);
    });
    refused(
        fixture.build(&fixture.listings_in(&packages), &out("r-two-debs")),
        "the repository package is one deb and one rpm at most",
    );
    // Checked as every package: its manifest names exactly it.
    let packages = edited(&fixture, "p-swapped", "repository", |json, dir| {
        let deb = position(json, ".deb.manifest");
        let rpm = position(json, ".rpm.manifest");
        let deb_manifest =
            std::fs::read(dir.join(json["artifacts"][deb]["file"].as_str().unwrap())).unwrap();
        std::fs::write(
            dir.join(json["artifacts"][rpm]["file"].as_str().unwrap()),
            &deb_manifest,
        )
        .unwrap();
        json["artifacts"][rpm]["sha256"] = sha256(&deb_manifest).into();
    });
    refused(
        fixture.build(&fixture.listings_in(&packages), &out("r-swapped")),
        "its manifest: it describes acme-repository 2.1.0+cafe12",
    );
    // A seaworthy.toml without [defaults.repository] has no such product.
    let mut plain = fixture.config.clone();
    plain.defaults.repository = None;
    refused(
        fixture.build_with(
            &plain,
            &listings,
            &out("r-plain"),
            &fixture.keyring.signer(),
        ),
        "acme-repository (product \"repository\") isn't a product of this seaworthy.toml",
    );
    // Read back, it must set machines up as this seaworthy.toml does:
    // a package built for another URL (an earlier run's, say) is refused,
    // though its manifest and signature are good...
    let mut old_url = fixture.config.clone();
    old_url.defaults.repository = Some(seaworthy::config::RepositorySettings {
        url: "https://old.acme.test/repo".into(),
    });
    let packages = fixture.path().join("p-old-url");
    copy_dir(&fixture.path().join("dist"), &packages);
    std::fs::remove_dir_all(packages.join("repository")).unwrap();
    copy_dir(
        &fixture.package_repository(&old_url, "old-url"),
        &packages.join("repository"),
    );
    refused(
        fixture.build(&fixture.listings_in(&packages), &out("r-old-url")),
        "setup/acme-repository.deb: the repository package doesn't set machines up as this seaworthy.toml does: /etc/apt/sources.list.d/acme.sources differs",
    );
    // ...and so is one without a key pinned since (a rotation's step 1
    // published with a stale package: machines would refuse step 2).
    let next = Keyring::new();
    next.export(&out("next.asc"));
    let mut more = fixture.config.clone();
    more.defaults.openpgp_keys.push(out("next.asc"));
    refused(
        fixture.build_with(
            &more,
            &listings,
            &out("r-stale-keys"),
            &fixture.keyring.signer(),
        ),
        "/usr/share/keyrings/acme-archive-keyring.asc differs",
    );
    // Everything else the read-back refuses, through tools that show a
    // package carrying more than seaworthy.toml generates: a maintainer script,
    // other conffiles, an extra file in the deb, an extra file in the rpm.
    let rewrap = |archive: &str, edit: &str| {
        format!(
            "#!/bin/sh\n[ \"$1\" = {archive} ] || exec dpkg-deb \"$@\"\nd=$(mktemp -d)\n\
             dpkg-deb {archive} \"$2\" | bsdtar -xf - -C \"$d\"\n{edit}\nbsdtar -cf - -C \"$d\" .\nrm -rf \"$d\"\n"
        )
    };
    for (case, text, mentions) in [
        (
            "postinst",
            rewrap("--ctrl-tarfile", "printf '#!/bin/sh\\n' > \"$d/postinst\""),
            "not exactly conffiles, control and md5sums (no maintainer scripts)",
        ),
        (
            "conffiles",
            rewrap("--ctrl-tarfile", ": > \"$d/conffiles\""),
            "its conffiles are \"\"",
        ),
        (
            "extra-file",
            rewrap(
                "--fsys-tarfile",
                "mkdir -p \"$d/etc/apt/trusted.gpg.d\" && echo x > \"$d/etc/apt/trusted.gpg.d/other.asc\"",
            ),
            "\"etc/apt/trusted.gpg.d/other.asc\"",
        ),
    ] {
        let dpkg_deb = script(&out(&format!("dpkg-deb-{case}")), &text);
        refused(
            fixture.build_tools(
                &out(&format!("r-{case}")),
                Tools {
                    dpkg_deb,
                    ..Tools::default()
                },
            ),
            mentions,
        );
        assert!(!out(&format!("r-{case}")).exists(), "{case}");
    }
    let bsdtar = script(
        &out("bsdtar-extra"),
        "#!/bin/sh\ncase \"$1 $2\" in -tf\\ *.rpm) bsdtar \"$@\" && echo /etc/yum.repos.d/other.repo; exit ;; esac\nexec bsdtar \"$@\"\n",
    );
    refused(
        fixture.build_tools(
            &out("r-rpm-extra"),
            Tools {
                bsdtar,
                ..Tools::default()
            },
        ),
        "setup/acme-repository.rpm: the repository package doesn't set machines up as this seaworthy.toml does: it installs",
    );
    // The setup deb's signature is checked against the pins like every
    // index signature: a staging key's is refused.
    let staging = Keyring::new();
    let signer = Mixed {
        pinned: fixture.keyring.signer(),
        staging: staging.signer(),
        staged: &|how, file| {
            how == "armored" && file.file_name().is_some_and(|n| n == "acme-repository.deb")
        },
    };
    refused(
        fixture.build_with(&fixture.config, &listings, &out("r-staged-asc"), &signer),
        "no pinned OpenPGP key made it",
    );
    for name in [
        "r-missing",
        "r-no-rpm",
        "r-extra-rpm",
        "r-two-debs",
        "r-swapped",
        "r-plain",
        "r-staged-asc",
        "r-old-url",
        "r-stale-keys",
        "r-rpm-extra",
    ] {
        assert!(
            !out(name).exists(),
            "{name}: a refused build leaves nothing"
        );
    }
    // And the untouched packages publish.
    fixture.build(&listings, &out("r-ok")).unwrap();
}

#[test]
fn the_package_command_builds_the_repository_package_and_repo_publishes_it() {
    // `package --product repository` builds it alone (no artifacts to
    // verify); `repo` reads <packages>/repository/ with the products'.
    let Some(nfpm) = tools() else { return };
    let fixture = Fixture::with_repository(&nfpm);
    let signing = fixture.path().join("signing.toml");
    std::fs::write(
        &signing,
        format!(
            "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey = \"release.key\"\n\n[openpgp]\nhome = {:?}\nkey = \"{}\"\n",
            fixture.keyring.home().to_str().unwrap(),
            fixture.keyring.fingerprint
        ),
    )
    .unwrap();
    let path = |name: &str| fixture.path().join(name).to_str().unwrap().to_owned();
    let command = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
            .current_dir(fixture.path())
            .args(args)
            .env("NFPM", &nfpm)
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.code(), text)
    };
    let (config, cli, signing) = (path("seaworthy.toml"), path("cli"), path("signing.toml"));
    let (code, text) = command(&[
        "package",
        "--config",
        &config,
        "--out",
        &cli,
        "--release",
        "2.1.0",
        "--sequence",
        "9",
        "--build",
        "cafe12",
        "--product",
        "repository",
        "--signing",
        &signing,
    ]);
    assert_eq!(code, Some(0), "{text}");
    for line in [
        "repository Deb: ",
        "repository Rpm: ",
        "repository Manifest: ",
        "repository Sbom: ",
    ] {
        assert!(text.contains(line), "{line}: {text}");
    }
    let listing = read_listing(&fixture.path().join("cli/repository")).unwrap();
    assert_eq!(listing.token, TOKEN);
    assert!(
        !fixture.path().join("cli/agent").exists(),
        "the repository package alone"
    );
    // Without [defaults.repository] there's no such product: --artifacts
    // is required, as for any product.
    std::fs::write(fixture.path().join("plain.toml"), CONFIG).unwrap();
    let (code, text) = command(&[
        "package",
        "--config",
        &path("plain.toml"),
        "--out",
        &path("cli-plain"),
        "--release",
        "2.1.0",
        "--sequence",
        "9",
        "--product",
        "repository",
    ]);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("package needs --artifacts"), "{text}");

    // `repo` with the fixture's packages (both products and the
    // repository package): it's published.
    let (code, text) = command(&[
        "repo",
        "--config",
        &config,
        "--packages",
        &path("dist"),
        "--out",
        &path("cli-repo"),
        "--signing",
        &signing,
        "--date",
        &DATE.to_string(),
    ]);
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains(&format!("acme-repository {TOKEN}: published")),
        "{text}"
    );
    assert!(
        fixture
            .path()
            .join("cli-repo/setup/acme-repository.deb")
            .is_file()
    );
    // An older release after it: refused, unless a deliberate rollback
    // (and a relative --out works: createrepo_c runs inside it).
    fixture.package_release("cli-older", "2.0.0", 8);
    let older = |out: &str, extra: &[&str]| {
        let previous = path("cli-repo/publish-plan.json");
        let date = (DATE + 10).to_string();
        let mut args = vec![
            "repo",
            "--config",
            &config,
            "--packages",
            "cli-older",
            "--out",
            out,
            "--signing",
            &signing,
            "--date",
            &date,
            "--previous",
            &previous,
        ];
        args.extend_from_slice(extra);
        command(&args)
    };
    let (code, text) = older("cli-older-repo", &[]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("repo --allow-older"), "{text}");
    let (code, text) = older("cli-older-repo", &["--allow-older"]);
    assert_eq!(code, Some(0), "{text}");
    let plan = Plan::read(&fixture.path().join("cli-older-repo/publish-plan.json")).unwrap();
    assert!(plan.rollback);
    // The index key handed over in the environment (a custody system's, as
    // a secret store hands it to CI): imported into a private home for the run,
    // and no tool sees it (the repository tools record their environment).
    let wrappers = fixture.path().join("wrappers");
    std::fs::create_dir_all(&wrappers).unwrap();
    let seen = fixture.path().join("tool-env");
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for tool in ["dpkg-scanpackages", "createrepo_c"] {
        let real = std::env::split_paths(&path_var)
            .map(|dir| dir.join(tool))
            .find(|p| p.is_file())
            .unwrap();
        let wrapper = wrappers.join(tool);
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nenv >> '{}'\nexec '{}' \"$@\"\n",
                seen.display(),
                real.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    let armored = fixture.keyring.export_secret();
    std::fs::write(
        fixture.path().join("signing-env.toml"),
        format!(
            // The manifest key is `package`'s: repo neither needs nor
            // requires it (its job is handed the OpenPGP key alone).
            "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey-env = \"SEAWORTHY_RELEASE_KEY_HEX\"\n\n\
             [openpgp]\nsecret-key-env = \"SEAWORTHY_REPO_KEY_ASC\"\nkey = \"{}\"\n",
            fixture.keyring.fingerprint
        ),
    )
    .unwrap();
    let mut path_with_wrappers = std::ffi::OsString::from(&wrappers);
    path_with_wrappers.push(":");
    path_with_wrappers.push(&path_var);
    let out = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
        .current_dir(fixture.path())
        .args([
            "repo",
            "--config",
            &config,
            "--packages",
            &path("dist"),
            "--out",
        ])
        .arg(path("cli-repo-env"))
        .args([
            "--signing",
            &path("signing-env.toml"),
            "--date",
            &DATE.to_string(),
        ])
        .env("PATH", &path_with_wrappers)
        .env("SEAWORTHY_REPO_KEY_ASC", &armored)
        .env("ACME_TEST_MARKER", "visible")
        .env("SEAWORTHY_TOOL_ENV", "ACME_TEST_MARKER")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        fixture
            .path()
            .join("cli-repo-env/apt/dists/stable/InRelease")
            .is_file()
    );
    let env = std::fs::read_to_string(&seen).unwrap();
    assert!(
        env.contains("ACME_TEST_MARKER=visible"),
        "the tools ran: {env}"
    );
    assert!(
        !env.contains("SEAWORTHY_REPO_KEY_ASC"),
        "the key reached a tool"
    );
    assert!(!env.contains("PRIVATE KEY BLOCK"), "the key reached a tool");
    // Handed a key it doesn't use anyway, repo still keeps it from its tools.
    std::fs::remove_file(&seen).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
        .current_dir(fixture.path())
        .args([
            "repo",
            "--config",
            &config,
            "--packages",
            &path("dist"),
            "--out",
        ])
        .arg(path("cli-repo-env-2"))
        .args([
            "--signing",
            &path("signing-env.toml"),
            "--date",
            &DATE.to_string(),
        ])
        .env("PATH", &path_with_wrappers)
        .env("SEAWORTHY_REPO_KEY_ASC", &armored)
        .env("SEAWORTHY_RELEASE_KEY_HEX", "00ff")
        .env("ACME_TEST_MARKER", "visible")
        .env("SEAWORTHY_TOOL_ENV", "ACME_TEST_MARKER")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let env = std::fs::read_to_string(&seen).unwrap();
    assert!(
        env.contains("ACME_TEST_MARKER=visible"),
        "the tools ran: {env}"
    );
    assert!(
        !env.contains("SEAWORTHY_RELEASE_KEY_HEX"),
        "an unused key reached a tool"
    );
    // Interrupted (a cancelled job): the private home and its agent go
    // anyway, and a home a killed run left behind is swept by the next.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::ExitStatusExt as _;
        let tmp = tempfile::Builder::new()
            .prefix("cd")
            .tempdir_in("/tmp")
            .unwrap();
        let dead = (900_000..4_000_000)
            .find(|pid: &u32| !Path::new("/proc").join(pid.to_string()).exists())
            .unwrap();
        let stale = tmp.path().join(format!("sw-openpgp-{dead}-0-1"));
        std::fs::create_dir(&stale).unwrap();
        std::fs::write(stale.join("leftover.key"), "a key a killed run left").unwrap();
        // A live process's home (pid 1's) is never swept.
        let alive = tmp.path().join("sw-openpgp-1-0-1");
        std::fs::create_dir(&alive).unwrap();
        let started = fixture.path().join("started");
        let slow = wrappers.join("dpkg-scanpackages");
        let real = std::fs::read_to_string(&slow).unwrap();
        std::fs::write(
            &slow,
            real.replacen(
                "exec ",
                &format!("touch '{}'\nsleep 20\nexec ", started.display()),
                1,
            ),
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
            .current_dir(fixture.path())
            .args([
                "repo",
                "--config",
                &config,
                "--packages",
                &path("dist"),
                "--out",
            ])
            .arg(path("cli-repo-env-3"))
            .args([
                "--signing",
                &path("signing-env.toml"),
                "--date",
                &DATE.to_string(),
            ])
            .env("PATH", &path_with_wrappers)
            .env("TMPDIR", tmp.path())
            .env("SEAWORTHY_REPO_KEY_ASC", &armored)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !started.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "repo never reached its tools"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let homes = || -> Vec<PathBuf> {
            std::fs::read_dir(tmp.path())
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| {
                    p.file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with("sw-openpgp-"))
                })
                .collect()
        };
        assert!(!stale.exists(), "the killed run's home is swept");
        assert!(alive.exists(), "a live process's home stays");
        std::fs::remove_dir(&alive).unwrap();
        let live = homes();
        assert_eq!(live.len(), 1, "{live:?}");
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap();
        let status = child.wait().unwrap();
        assert_eq!(status.signal(), Some(15), "{status:?}");
        assert!(
            homes().is_empty(),
            "the interrupted run's home is left: {:?}",
            homes()
        );
        // A temporary directory too deep for gpg-agent's socket path: the
        // home goes under /tmp instead, and the key still signs.
        let deep = tmp.path().join("d".repeat(90));
        std::fs::create_dir(&deep).unwrap();
        std::fs::write(&slow, &real).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
            .current_dir(fixture.path())
            .args([
                "repo",
                "--config",
                &config,
                "--packages",
                &path("dist"),
                "--out",
            ])
            .arg(path("cli-repo-env-4"))
            .args([
                "--signing",
                &path("signing-env.toml"),
                "--date",
                &DATE.to_string(),
            ])
            .env("PATH", &path_with_wrappers)
            .env("TMPDIR", &deep)
            .env("SEAWORTHY_REPO_KEY_ASC", &armored)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // A repository listing missing: refused, naming it.
    std::fs::remove_file(fixture.path().join("dist/repository/packages.json")).unwrap();
    let (code, text) = command(&[
        "repo",
        "--config",
        &config,
        "--packages",
        &path("dist"),
        "--out",
        &path("cli-repo-2"),
        "--signing",
        &signing,
        "--date",
        &DATE.to_string(),
    ]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("repository/packages.json"), "{text}");
    assert!(
        text.contains("with --product repository, builds the repository package"),
        "{text}"
    );
    // `--product repository` takes nothing that's about products' artifacts.
    for extra in [&["--artifacts", "x"][..], &["--no-strip"][..]] {
        let mut args = vec![
            "package",
            "--config",
            &config,
            "--out",
            &cli,
            "--release",
            "2.1.0",
            "--sequence",
            "9",
            "--product",
            "repository",
        ];
        args.extend_from_slice(extra);
        let (code, text) = command(&args);
        assert_eq!(code, Some(2), "{extra:?}: {text}");
        assert!(
            text.contains("takes no --artifacts or --no-strip"),
            "{text}"
        );
    }
}

/// A release's Developer ID-signed macOS packages, adopted into the listings
/// (`seaworthy adopt-macos`, what the GitLab template's repo job runs): the
/// pkg in the release tree under its signed manifest where the update helper
/// looks, the dmg beside it with none, and a listing that isn't the same
/// release's, or isn't a signed release's at all, refused.
#[cfg(unix)]
#[test]
fn a_release_s_macos_packages_join_the_release_tree() {
    if !have("gpg", &["--version"]) {
        return;
    }
    // Tarballs alone off the Mac: no packaging tool but gpg, for the indexes.
    let linux = CONFIG
        .replacen(
            "outputs = [\"deb\", \"rpm\", \"pacman\", \"tar\", \"zip\"]",
            "outputs = [\"tar\"]",
            1,
        )
        .replacen(
            "outputs = [\"deb\", \"rpm\", \"pacman\"]",
            "outputs = [\"tar\"]",
            1,
        )
        .replacen("linux.depends.deb = [\"libc6 (>= 2.36)\"]\n", "", 1)
        .replacen("linux.depends.rpm = [\"glibc >= 2.34\"]\n", "", 1)
        .replacen("linux.depends.pacman = [\"glibc\"]\n", "", 1);
    let fixture = Fixture::with_config(Path::new("nfpm"), false, &linux);
    // The same products, with the outputs only the Mac packages.
    let text = linux
        .replacen("outputs = [\"tar\"]", "outputs = [\"tar\", \"pkg\"]", 1)
        .replacen("outputs = [\"tar\"]", "outputs = [\"tar\", \"dmg\"]", 1)
        .replacen(
            "[product.agent.service.sandbox]",
            "[product.agent.macos]\nbundle-id = \"test.acme.agent\"\n\n[product.agent.service.macos]\naccount = \"root\"\n\n[product.agent.service.sandbox]",
            1,
        )
        + "\n[product.console.macos]\nbundle-id = \"test.acme.console\"\n";
    let file = fixture.path().join("mac.toml");
    std::fs::write(&file, text).unwrap();
    let config = Config::load(&file).unwrap();

    // What the Mac's job leaves: the pkg with its manifest, the dmg alone.
    let macos = fixture.path().join("dist-macos");
    let release = seaworthy::version::Release::new("2.1.0", 9).unwrap();
    let build = seaworthy::sign::BuildId {
        metadata: "cafe12".into(),
    };
    let signers: Vec<Box<dyn seaworthy::sign::ManifestSigner>> = vec![Box::new(
        seaworthy::sign::LocalKey::from_file(
            seaworthy_updater::SignatureAlgorithm::MlDsa87,
            &fixture.path().join("release.key"),
        )
        .unwrap(),
    )];
    let target = seaworthy::inputs::MACOS;
    let listing_json = |id: &str, package: &str, artifacts: Vec<serde_json::Value>| {
        serde_json::json!({
            "product": id, "package": package, "channel": "stable", "version": "2.1.0",
            "build": "cafe12", "token": TOKEN, "sequence": 9, "signed": true,
            "artifacts": artifacts,
        })
    };
    let entry = |kind: &str, file: &str, bytes: &[u8]| serde_json::json!({"kind": kind, "file": file, "target": target, "sha256": sha256(bytes)});
    let pkg_bytes = b"a signed pkg".to_vec();
    let manifest = seaworthy::sign::manifest_for_bytes(
        &config,
        "agent",
        &release,
        &build,
        target,
        seaworthy_updater::ArtifactFormat::Pkg,
        &pkg_bytes,
    )
    .unwrap();
    let signed = seaworthy::sign::sign_manifest(&manifest, &signers).unwrap();
    let write = |id: &str, listing: &serde_json::Value, files: &[(&str, &[u8])]| {
        let base = macos.join(id);
        std::fs::create_dir_all(base.join("packages")).unwrap();
        for (name, bytes) in files {
            std::fs::write(base.join(name), bytes).unwrap();
        }
        std::fs::write(
            base.join("packages.json"),
            serde_json::to_string_pretty(listing).unwrap(),
        )
        .unwrap();
    };
    let pkg_name = "packages/acme-agent-2.1.0-9-macos-arm64.pkg";
    let manifest_name = format!("{pkg_name}.manifest");
    let agent = listing_json(
        "agent",
        "acme-agent",
        vec![
            entry("pkg", pkg_name, &pkg_bytes),
            entry("manifest", &manifest_name, &signed),
        ],
    );
    write(
        "agent",
        &agent,
        &[(pkg_name, &pkg_bytes), (&manifest_name, &signed)],
    );
    let dmg_bytes = b"a stapled dmg".to_vec();
    let dmg_name = "packages/acme-console-2.1.0-9-macos-arm64.dmg";
    let console = listing_json(
        "console",
        "acme-console",
        vec![entry("dmg", dmg_name, &dmg_bytes)],
    );
    write("console", &console, &[(dmg_name, &dmg_bytes)]);

    // Into a copy of the packages, as the repo step does.
    let released = fixture.path().join("released");
    copy_dir(&fixture.path().join("dist"), &released);
    for id in ["agent", "console"] {
        seaworthy::package::adopt_macos(&config, id, &released, &macos).unwrap();
    }
    let listings = fixture.listings_in(&released);
    let out = fixture.path().join("repo");
    let plan = fixture
        .build_with(&config, &listings, &out, &fixture.keyring.signer())
        .unwrap();
    let tree = format!("releases/acme-agent/stable/{TOKEN}/{target}/acme-agent.pkg");
    assert_eq!(std::fs::read(out.join(&tree)).unwrap(), pkg_bytes);
    assert_eq!(
        std::fs::read(out.join(format!("{tree}.manifest"))).unwrap(),
        signed
    );
    let dmg = format!("releases/acme-console/stable/{TOKEN}/{target}/acme-console.dmg");
    assert_eq!(std::fs::read(out.join(&dmg)).unwrap(), dmg_bytes);
    assert!(!out.join(format!("{dmg}.manifest")).exists());
    for path in [&tree, &dmg] {
        assert!(
            plan.files
                .iter()
                .any(|f| &f.path == path && f.class == Class::Immutable),
            "{path} isn't planned as immutable"
        );
    }
    // The other packages stay, and each product's listed once.
    assert!(listed(&listings[0], Kind::Tar).file.ends_with(".tar.zst"));
    assert!(listed(&listings[0], Kind::Pkg).file.ends_with(".pkg"));

    // Twice: it would replace a file.
    let err = seaworthy::package::adopt_macos(&config, "console", &released, &macos)
        .unwrap_err()
        .to_string();
    assert!(err.contains("would replace it"), "{err}");

    // Another release's, or one no signer made: refused, the packages as
    // they were.
    let refused = |name: &str, edit: &dyn Fn(&mut serde_json::Value), why: &str| {
        let to = fixture.path().join(name);
        copy_dir(&fixture.path().join("dist"), &to);
        let base = macos.join("console");
        let mut changed = console.clone();
        edit(&mut changed);
        std::fs::write(
            base.join("packages.json"),
            serde_json::to_string_pretty(&changed).unwrap(),
        )
        .unwrap();
        let err = seaworthy::package::adopt_macos(&config, "console", &to, &macos)
            .unwrap_err()
            .to_string();
        assert!(err.contains(why), "{err}");
        assert!(
            !to.join("console").join(dmg_name).exists(),
            "{name}: nothing adopted"
        );
    };
    refused(
        "not-signed",
        &|json| json["signed"] = false.into(),
        "only a signed release's join one",
    );
    refused(
        "ci-test",
        &|json| json["ci_test"] = true.into(),
        "only a signed release's join one",
    );
    refused(
        "other-release",
        &|json| {
            json["sequence"] = 10.into();
        },
        "another release's",
    );
    refused(
        "other-kind",
        &|json| json["artifacts"][0]["kind"] = "tar".into(),
        "no dmg or pkg listed",
    );
    refused(
        "other-target",
        &|json| json["artifacts"][0]["target"] = "x86_64-unknown-linux-gnu".into(),
        "isn't a macOS artifact",
    );
}
