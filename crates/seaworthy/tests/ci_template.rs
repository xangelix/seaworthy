//! seaworthy's GitLab CI templates: `ci/gitlab/seaworthy.yml`,
//! `seaworthy-windows.yml` and `seaworthy-macos.yml` read as GitLab reads
//! them (through the release-ordering lint's loader, every input at its
//! default, or as a product gives it) — every job wired to what it needs,
//! released only by the release rule, published one at a time, Linux jobs
//! untagged, the Mac's job never signed, every input declared and used, no
//! image, runner tag or secret source with an organization default, the
//! build image the toolchain's pinned Rust image — and the steps of
//! `scripts/ci/seaworthy.sh` the jobs run, carried out: the build plan on a
//! small workspace, packaging (unsigned outside a release, macOS left to the
//! Mac), the repositories after a published plan (or a first publication, or
//! a server error), and what each step refuses.
//!
//! A missing tool is skipped loudly, unless
//! `SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1` turns the skip into a failure.

#![cfg(unix)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::collections::BTreeSet;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use seaworthy::ci_order::{Node, Pipeline, load};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn template(name: &str) -> PathBuf {
    repo_root().join("ci/gitlab").join(name)
}

/// Every template included by a product whose CI is `product`.
fn pipeline(product: &str) -> Pipeline {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".gitlab-ci.yml"), product).unwrap();
    load(
        dir.path(),
        &dir.path().join(".gitlab-ci.yml"),
        &[
            template("seaworthy.yml"),
            template("seaworthy-windows.yml"),
            template("seaworthy-macos.yml"),
        ],
    )
    .unwrap()
}

fn job<'a>(pipeline: &'a Pipeline, name: &str) -> &'a Node {
    pipeline
        .jobs
        .get(name)
        .unwrap_or_else(|| panic!("no job {name}"))
}

fn text<'a>(node: &'a Node, key: &str) -> Option<&'a str> {
    node.get(key).and_then(Node::text)
}

/// A sequence's scalars (a `needs` entry's `job`, or itself).
fn list(node: Option<&Node>) -> Vec<String> {
    match node {
        Some(Node::Seq(items)) => items
            .iter()
            .map(|i| {
                i.text()
                    .or_else(|| text(i, "job"))
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect(),
        _ => Vec::new(),
    }
}

#[test]
fn every_job_is_wired_to_what_it_needs() {
    let pipeline = pipeline("");
    let visible: BTreeSet<&str> = pipeline
        .jobs
        .keys()
        .filter(|k| !k.starts_with('.'))
        .map(String::as_str)
        .collect();
    assert_eq!(
        visible.into_iter().collect::<Vec<_>>(),
        [
            "seaworthy-build-linux",
            "seaworthy-build-windows",
            "seaworthy-macos",
            "seaworthy-msi",
            "seaworthy-msi-adopt",
            "seaworthy-package",
            "seaworthy-prepare",
            "seaworthy-publish",
            "seaworthy-repo",
        ]
    );
    let prepare = job(&pipeline, "seaworthy-prepare");
    assert_eq!(
        text(prepare, "stage"),
        Some(".pre"),
        "first in every pipeline"
    );
    assert_eq!(
        list(prepare.get("artifacts").and_then(|a| a.get("paths"))),
        [
            "seaworthy/bin/",
            "seaworthy/scripts/",
            "seaworthy/plan-*.tsv",
            "seaworthy/release.env",
        ]
    );
    for (name, needs) in [
        ("seaworthy-build-linux", vec!["seaworthy-prepare"]),
        ("seaworthy-build-windows", vec!["seaworthy-prepare"]),
        ("seaworthy-macos", vec!["seaworthy-prepare"]),
        (
            "seaworthy-package",
            vec![
                "seaworthy-prepare",
                "seaworthy-build-linux",
                "seaworthy-build-windows",
            ],
        ),
        (
            "seaworthy-msi",
            vec!["seaworthy-prepare", "seaworthy-package"],
        ),
        (
            "seaworthy-msi-adopt",
            vec!["seaworthy-prepare", "seaworthy-package", "seaworthy-msi"],
        ),
        (
            "seaworthy-repo",
            vec![
                "seaworthy-prepare",
                "seaworthy-package",
                "seaworthy-msi-adopt",
            ],
        ),
        (
            "seaworthy-publish",
            vec!["seaworthy-prepare", "seaworthy-repo"],
        ),
    ] {
        assert_eq!(list(job(&pipeline, name).get("needs")), needs, "{name}");
    }
    // The Windows build is optional to the package job: a product without
    // Windows outputs doesn't include its template.
    let package_needs = job(&pipeline, "seaworthy-package").get("needs").unwrap();
    let Node::Seq(items) = package_needs else {
        panic!("needs")
    };
    assert_eq!(items[2].get("optional").and_then(Node::boolean), Some(true));
    // So are the MSI jobs to the repo job: it publishes their adopted
    // copy of the packages when they ran.
    let Some(Node::Seq(items)) = job(&pipeline, "seaworthy-repo").get("needs") else {
        panic!("needs")
    };
    assert_eq!(items[2].get("optional").and_then(Node::boolean), Some(true));
    // Each job's artifacts are what the next reads.
    for (name, path) in [
        (
            "seaworthy-build-linux",
            "seaworthy/artifacts/x86_64-unknown-linux-gnu/",
        ),
        (
            "seaworthy-build-windows",
            "seaworthy/artifacts/x86_64-pc-windows-msvc/",
        ),
        ("seaworthy-package", "seaworthy/dist/"),
        ("seaworthy-macos", "seaworthy/dist-macos/"),
        ("seaworthy-msi", "seaworthy/msi/"),
        ("seaworthy-msi-adopt", "seaworthy/adopted/"),
        ("seaworthy-repo", "seaworthy/repo/"),
    ] {
        assert_eq!(
            list(
                job(&pipeline, name)
                    .get("artifacts")
                    .and_then(|a| a.get("paths"))
            ),
            [path],
            "{name}"
        );
    }
    // One publication at a time.
    assert_eq!(
        text(job(&pipeline, "seaworthy-publish"), "resource_group"),
        Some("seaworthy-publish")
    );
    // The tool's cache lives outside the seaworthy checkout: restored before the
    // fetch, it must not make the checkout's directory exist.
    let prepare = job(&pipeline, "seaworthy-prepare");
    assert_eq!(
        list(prepare.get("cache").and_then(|c| c.get("paths"))),
        ["seaworthy/tool-target/"]
    );
    // The tool's cache is keyed by the ref's protection: an
    // unprotected pipeline's compiled tool never reaches a release.
    let key = prepare
        .get("cache")
        .and_then(|c| c.get("key"))
        .and_then(Node::text)
        .unwrap_or_default();
    assert!(key.ends_with("-$CI_COMMIT_REF_PROTECTED"), "prepare: {key}");
    // The Linux build keeps no target cache: a FIPS product's target
    // directories exceed GitLab's cache size, and a release compiles from
    // source.
    assert!(
        job(&pipeline, "seaworthy-build-linux")
            .get("cache")
            .is_none(),
        "the Linux build keeps no target cache"
    );
    assert_eq!(
        prepare
            .get("variables")
            .and_then(|v| v.get("SEAWORTHY_TOOL_TARGET"))
            .and_then(Node::text),
        Some("seaworthy/tool-target")
    );
    // Secrets go to the script, which applies them on a release only.
    for name in [
        "seaworthy-package",
        "seaworthy-msi-adopt",
        "seaworthy-repo",
        "seaworthy-publish",
    ] {
        let lines = list(job(&pipeline, name).get("script"));
        assert!(
            lines.iter().all(|l| !l.contains("SEAWORTHY_SECRETS")),
            "{name}: {lines:?}"
        );
        assert!(
            job(&pipeline, name)
                .get("variables")
                .and_then(|v| v.get("SEAWORTHY_SECRETS"))
                .is_some(),
            "{name}"
        );
    }
    // Nothing reaches the Mac's job: it never signs, on a release
    // too, and no later job takes its packages.
    let mac = job(&pipeline, "seaworthy-macos");
    for key in ["SEAWORTHY_SECRETS", "SEAWORTHY_DEV_SECRETS"] {
        assert!(
            mac.get("variables").and_then(|v| v.get(key)).is_none(),
            "seaworthy-macos: {key}"
        );
    }
    assert!(
        mac.get("id_tokens").is_none(),
        "seaworthy-macos logs in nowhere"
    );
    for (name, node) in &pipeline.jobs {
        assert!(
            !list(node.get("needs")).contains(&"seaworthy-macos".to_owned()),
            "{name} needs the Mac's job"
        );
    }
}

#[test]
fn the_template_s_marker_is_current() {
    let raw = std::fs::read_to_string(template("seaworthy.yml")).unwrap();
    let marker_line = raw
        .lines()
        .find(|l| l.contains("SEAWORTHY_TEMPLATE:"))
        .expect("a marker line");
    let marker = marker_line.split('"').nth(1).unwrap();
    let without: String = raw
        .split_inclusive('\n')
        .filter(|l| !l.contains("SEAWORTHY_TEMPLATE:"))
        .collect();
    // As the script computes it: `grep -v … | sha256sum | cut -c1-16`.
    assert_eq!(
        marker,
        &seaworthy_crypto::digest::sha256_hex(without.as_bytes())[..16],
        "update SEAWORTHY_TEMPLATE in ci/gitlab/seaworthy.yml (the hash of the file without that line)"
    );
}

#[test]
fn only_a_release_signs_and_publishes() {
    let pipeline = pipeline("");
    let release = "$CI_COMMIT_TAG =~ /^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-(alpha|beta|rc)(\\.(0|[1-9][0-9]*))?)?$/";
    for name in ["seaworthy-repo", "seaworthy-publish"] {
        let Some(Node::Seq(rules)) = job(&pipeline, name).get("rules") else {
            panic!("{name} has no rules")
        };
        assert_eq!(rules.len(), 1, "{name}: the release rule alone");
        assert_eq!(text(&rules[0], "if"), Some(release), "{name}");
        assert_eq!(
            rules[0]
                .get("variables")
                .and_then(|v| v.get("SEAWORTHY_RELEASE"))
                .and_then(Node::text),
            Some("1")
        );
    }
    // Packages on every pipeline, signed on a release; prepare checks a
    // release's version before the builds.
    let prepare = job(&pipeline, "seaworthy-prepare");
    let Some(Node::Seq(rules)) = prepare.get("rules") else {
        panic!("prepare has no rules")
    };
    assert_eq!(text(&rules[0], "if"), Some(release));
    assert_eq!(text(&rules[1], "when"), Some("on_success"));
    assert!(rules[1].get("variables").is_none(), "not a release");
    // The package job, and the MSI adopt (seaworthy-windows.yml): a release,
    // else a dev build (Authenticode alone; by default, never), else
    // unsigned. The dev rule follows the release's, so a release wins.
    for name in ["seaworthy-package", "seaworthy-msi-adopt"] {
        let Some(Node::Seq(rules)) = job(&pipeline, name).get("rules") else {
            panic!("{name} has no rules")
        };
        assert_eq!(rules.len(), 3, "{name}");
        assert_eq!(text(&rules[0], "if"), Some(release), "{name}");
        assert_eq!(
            text(&rules[1], "if"),
            Some("$CI_PIPELINE_ID == \"0\""),
            "{name}"
        );
        assert_eq!(
            rules[1]
                .get("variables")
                .and_then(|v| v.get("SEAWORTHY_DEV_SIGN"))
                .and_then(Node::text),
            Some("1"),
            "{name}"
        );
        assert_eq!(text(&rules[2], "when"), Some("on_success"), "{name}");
        assert!(rules[2].get("variables").is_none(), "{name}");
    }
    // The build jobs know a release (whose steps refuse the CI test-key
    // switch), and run on every pipeline.
    for name in ["seaworthy-build-linux", "seaworthy-build-windows"] {
        let Some(Node::Seq(rules)) = job(&pipeline, name).get("rules") else {
            panic!("{name} has no rules")
        };
        assert_eq!(rules.len(), 2, "{name}");
        assert_eq!(text(&rules[0], "if"), Some(release), "{name}");
        assert_eq!(
            rules[0]
                .get("variables")
                .and_then(|v| v.get("SEAWORTHY_RELEASE"))
                .and_then(Node::text),
            Some("1"),
            "{name}"
        );
        assert_eq!(text(&rules[1], "when"), Some("on_success"), "{name}");
    }
    // The Mac's job names a release's version on a release (and no more:
    // its dmg stays out of the release), and has no dev build.
    let Some(Node::Seq(rules)) = job(&pipeline, "seaworthy-macos").get("rules") else {
        panic!("seaworthy-macos has no rules")
    };
    assert_eq!(rules.len(), 2);
    assert_eq!(text(&rules[0], "if"), Some(release));
    assert_eq!(
        rules[0]
            .get("variables")
            .and_then(|v| v.get("SEAWORTHY_RELEASE"))
            .and_then(Node::text),
        Some("1")
    );
    assert_eq!(text(&rules[1], "when"), Some("on_success"));
    // The release rule is an input, as a product's server deploy needs the
    // same.
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(template("seaworthy.yml"), dir.path().join("seaworthy.yml")).unwrap();
    // Without the tools image (it has no default), the include is refused,
    // as GitLab refuses the pipeline.
    std::fs::write(
        dir.path().join("t.yml"),
        "include: [{local: seaworthy.yml, inputs: {release-if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'}}]\n",
    )
    .unwrap();
    let err = load(dir.path(), &dir.path().join("t.yml"), &[])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("input \"tools-image\" has no default and isn't given"),
        "{err}"
    );
    std::fs::write(
        dir.path().join("t.yml"),
        "include: [{local: seaworthy.yml, inputs: {release-if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH', tools-image: tools}}]\n",
    )
    .unwrap();
    let custom = load(dir.path(), &dir.path().join("t.yml"), &[]).unwrap();
    let Some(Node::Seq(rules)) = job(&custom, "seaworthy-publish").get("rules") else {
        panic!("publish has no rules")
    };
    assert_eq!(
        text(&rules[0], "if"),
        Some("$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH")
    );
}

/// The inputs a template takes for what is the product's own: its images,
/// its runners' tags, its secrets. An image or tag input has no default
/// (GitLab refuses a pipeline that leaves it out), except the Linux build's,
/// whose default is the official Rust image at the toolchain's version,
/// digest-pinned. Every input is declared, used and, when it has no
/// default, says it's required.
#[test]
fn every_input_is_declared_and_used_and_none_defaults_to_an_organization() {
    let toolchain = std::fs::read_to_string(repo_root().join("rust-toolchain.toml")).unwrap();
    let channel = toolchain
        .lines()
        .find_map(|l| l.strip_prefix("channel = \""))
        .and_then(|l| l.strip_suffix('"'))
        .unwrap();
    let mut required = BTreeSet::new();
    for name in [
        "seaworthy.yml",
        "seaworthy-windows.yml",
        "seaworthy-macos.yml",
    ] {
        let raw = std::fs::read_to_string(template(name)).unwrap();
        let (header, body) = raw.split_once("\n---\n").unwrap();
        let spec = seaworthy::ci_order::parse(header, name).unwrap();
        let Some(Node::Map(inputs)) = spec[0].get("spec").and_then(|s| s.get("inputs")) else {
            panic!("{name}: no inputs")
        };
        let declared: BTreeSet<&str> = inputs.iter().map(|(k, _)| k.as_str()).collect();
        let mut used = BTreeSet::new();
        let mut rest = body;
        while let Some(at) = rest.find("$[[ inputs.") {
            let after = &rest[at + "$[[ inputs.".len()..];
            let end = after.find([' ', ']']).unwrap();
            used.insert(&after[..end]);
            rest = &after[end..];
        }
        assert_eq!(declared, used, "{name}: declared vs used inputs");
        for (input, spec) in inputs {
            let default = spec.get("default").and_then(Node::text);
            let organizational = input.ends_with("-image") || input.ends_with("-tags");
            match default {
                None => {
                    assert!(
                        organizational,
                        "{name}: {input} has no default but isn't an image or runner tag"
                    );
                    assert!(
                        text(spec, "description").is_some_and(|d| d.starts_with("Required.")),
                        "{name}: {input} says it's required"
                    );
                    required.insert(input.clone());
                }
                Some(default) if organizational => {
                    assert_eq!(input, "build-image", "{name}: {input} has a default");
                    assert!(
                        default.starts_with(&format!("rust:{channel}-bookworm@sha256:")),
                        "{name}: build-image is the official Rust image at the toolchain's version, digest-pinned: {default}"
                    );
                    // The same pin the container suites build in.
                    assert_eq!(default, seaworthy_test_support::images::RUST_BUILDER);
                }
                Some(_) => {}
            }
        }
        // No registry host, and no secret store: secrets come through the
        // product's command prefixes, and no job asks for an id token.
        for line in body.lines().filter(|l| !l.trim_start().starts_with('#')) {
            assert!(
                !line.contains("registry.") && !line.contains("id_tokens"),
                "{name}: {line}"
            );
        }
    }
    assert_eq!(
        required.into_iter().collect::<Vec<_>>(),
        [
            "macos-image",
            "macos-tags",
            "tools-image",
            "windows-image",
            "windows-tags"
        ]
    );
}

/// Linux jobs carry no tags (any Linux runner takes them); the Windows and
/// Mac jobs run on the runners and images the product names, and the Linux
/// build in the toolchain's Rust image unless the product names another.
#[test]
fn linux_jobs_are_untagged_and_the_product_names_its_runners_and_images() {
    let dir = tempfile::tempdir().unwrap();
    for name in [
        "seaworthy.yml",
        "seaworthy-windows.yml",
        "seaworthy-macos.yml",
    ] {
        std::fs::copy(template(name), dir.path().join(name)).unwrap();
    }
    std::fs::write(
        dir.path().join("t.yml"),
        "include:\n  \
         - {local: seaworthy.yml, inputs: {tools-image: 'tools.example.com/packaging:1'}}\n  \
         - {local: seaworthy-windows.yml, inputs: {windows-image: 'msvc.example.com/rust:1', windows-tags: [windows, msvc]}}\n  \
         - {local: seaworthy-macos.yml, inputs: {macos-image: 'macos-15-rust', macos-tags: [macos]}}\n",
    )
    .unwrap();
    let product = load(dir.path(), &dir.path().join("t.yml"), &[]).unwrap();
    for (name, node) in &product.jobs {
        if ![
            "seaworthy-build-windows",
            "seaworthy-msi",
            "seaworthy-macos",
        ]
        .contains(&name.as_str())
        {
            assert!(
                node.get("tags").is_none(),
                "{name}: Linux jobs carry no tags"
            );
        }
    }
    for name in ["seaworthy-build-windows", "seaworthy-msi"] {
        let node = job(&product, name);
        assert_eq!(list(node.get("tags")), ["windows", "msvc"], "{name}");
        assert_eq!(
            text(node, "image"),
            Some("msvc.example.com/rust:1"),
            "{name}"
        );
    }
    let mac = job(&product, "seaworthy-macos");
    assert_eq!(list(mac.get("tags")), ["macos"]);
    assert_eq!(text(mac, "image"), Some("macos-15-rust"));
    assert_eq!(text(mac, "resource_group"), Some("seaworthy-macos"));
    for name in [
        "seaworthy-prepare",
        "seaworthy-package",
        "seaworthy-msi-adopt",
        "seaworthy-repo",
        "seaworthy-publish",
    ] {
        assert_eq!(
            text(job(&product, name), "image"),
            Some("tools.example.com/packaging:1"),
            "{name}"
        );
    }
    assert!(
        text(job(&product, "seaworthy-build-linux"), "image")
            .is_some_and(|i| i.starts_with("rust:") && i.contains("@sha256:"))
    );
    // A template a product includes without them is refused by GitLab; the
    // release-ordering lint, which reads it as a stand-in, reads them as
    // empty.
    let plain = pipeline("");
    assert_eq!(text(job(&plain, "seaworthy-prepare"), "image"), Some(""));
}

#[test]
fn the_jobs_run_steps_the_script_has() {
    let pipeline = pipeline("");
    let script = repo_root().join("scripts/ci/seaworthy.sh");
    use std::os::unix::fs::PermissionsExt as _;
    assert!(std::fs::metadata(&script).unwrap().permissions().mode() & 0o111 != 0);
    // The scripts a job or a signer runs directly are executable (a script
    // committed 0644 fails only in CI).
    for file in [
        "scripts/ci/azure-sign.sh",
        "scripts/ci/install-nfpm.sh",
        "scripts/ci/install-osslsigncode.sh",
    ] {
        let mode = std::fs::metadata(repo_root().join(file))
            .unwrap()
            .permissions()
            .mode();
        assert!(mode & 0o111 != 0, "{file} is executable: {mode:o}");
    }
    assert!(repo_root().join("scripts/ci/seaworthy-build.ps1").is_file());
    let source = std::fs::read_to_string(&script).unwrap();
    for (name, step) in [
        ("seaworthy-prepare", "prepare"),
        ("seaworthy-build-linux", "build x86_64-unknown-linux-gnu"),
        ("seaworthy-package", "package"),
        ("seaworthy-msi-adopt", "adopt-msi"),
        ("seaworthy-repo", "repo"),
        ("seaworthy-publish", "publish"),
    ] {
        let lines = list(job(&pipeline, name).get("script"));
        let last = lines.last().unwrap().trim_end();
        let verb = step.split(' ').next().unwrap();
        assert!(
            source.contains(&format!("\n    {verb}) ")),
            "the script has {verb}"
        );
        if matches!(verb, "prepare" | "build") {
            assert!(
                last.contains("seaworthy.sh") && last.ends_with(&format!(" {step}")),
                "{name}: {last}"
            );
            continue;
        }
        // A signing job: on a release (or a dev build) seaworthy's own
        // checkout, fetched afresh, runs the step — never the prepare job's
        // copies — and nothing is restored from a cache into it.
        assert!(
            last.contains(&format!(
                "bash \"./$SEAWORTHY_CHECKOUT/scripts/ci/seaworthy.sh\" {step}\n"
            )) || last.ends_with(&format!(
                "bash \"./$SEAWORTHY_CHECKOUT/scripts/ci/seaworthy.sh\" {step}"
            )),
            "{name}: {last}"
        );
        assert!(
            last.contains("rm -rf \"./$SEAWORTHY_CHECKOUT\" && eval \"$SEAWORTHY_FETCH\""),
            "{name}: fetched afresh: {last}"
        );
        if matches!(verb, "package" | "adopt-msi") {
            assert!(
                last.starts_with(
                    "if [ \"${SEAWORTHY_RELEASE:-0}\" = 1 ] || [ \"${SEAWORTHY_DEV_SIGN:-0}\" = 1 ]; then"
                ) && last.contains(&format!("else\n  bash seaworthy/scripts/seaworthy.sh {step}\nfi")),
                "{name}: the prepare job's copies outside a release or a dev build: {last}"
            );
        } else {
            assert!(
                !last.contains("seaworthy/scripts/seaworthy.sh"),
                "{name}: {last}"
            );
        }
        assert!(
            matches!(job(&pipeline, name).get("cache"), Some(Node::Seq(items)) if items.is_empty()),
            "{name}: cache: []"
        );
    }
    // The prepare job's cache: never restored on a release.
    let prepare = job(&pipeline, "seaworthy-prepare");
    assert_eq!(
        text(prepare.get("cache").unwrap(), "policy"),
        Some("$SEAWORTHY_TOOL_CACHE_POLICY")
    );
    assert_eq!(
        prepare
            .get("variables")
            .and_then(|v| v.get("SEAWORTHY_TOOL_CACHE_POLICY"))
            .and_then(Node::text),
        Some("pull-push")
    );
    let Some(Node::Seq(rules)) = prepare.get("rules") else {
        panic!("prepare has no rules")
    };
    assert_eq!(
        rules[0]
            .get("variables")
            .and_then(|v| v.get("SEAWORTHY_TOOL_CACHE_POLICY"))
            .and_then(Node::text),
        Some("push"),
        "a release never pulls the tool's cache"
    );
    // What prepare hands on is what the later jobs run.
    for file in [
        "seaworthy.sh",
        "seaworthy-build.ps1",
        "install-nfpm.sh",
        "install-osslsigncode.sh",
        "seaworthy-msi.ps1",
        "azure-sign.sh",
    ] {
        assert!(source.contains(file), "prepare copies {file}");
        assert!(
            repo_root().join("scripts").join(file).is_file()
                || repo_root().join("scripts/ci").join(file).is_file(),
            "{file} exists"
        );
    }
    let windows = list(job(&pipeline, "seaworthy-build-windows").get("script"));
    assert!(
        windows[0].ends_with("seaworthy\\scripts\\seaworthy-build.ps1"),
        "{windows:?}"
    );
    let msi = list(job(&pipeline, "seaworthy-msi").get("script"));
    assert!(
        msi[0].ends_with("seaworthy\\scripts\\seaworthy-msi.ps1"),
        "{msi:?}"
    );
    // The Mac's job: the macOS plan, then the Mac's own packaging.
    let mac = list(job(&pipeline, "seaworthy-macos").get("script"));
    assert!(
        mac.contains(
            &"bash \"$SEAWORTHY_CHECKOUT/scripts/ci/seaworthy.sh\" build aarch64-apple-darwin"
                .to_owned()
        ),
        "{mac:?}"
    );
    assert_eq!(
        mac.last().map(String::as_str),
        Some("bash \"$SEAWORTHY_CHECKOUT/scripts/ci/seaworthy.sh\" package-macos")
    );
    assert!(
        source.contains("\n    package-macos) "),
        "the script has package-macos"
    );
}

// ---------------------------------------------------------------------------
// The script's steps, carried out

/// A signing step of a release or a dev build runs from seaworthy's own
/// checkout: this one, whose script `step` runs.
const TRUSTED_CHECKOUT: (&str, &str) = (
    "SEAWORTHY_CHECKOUT",
    concat!(env!("CARGO_MANIFEST_DIR"), "/../.."),
);
/// ...with the seaworthy a job built for itself: this build's, standing in
/// for the one the step would compile from the checkout.
const TRUSTED_TOOL: (&str, &str) = ("SEAWORTHY_TOOL_BIN", env!("CARGO_BIN_EXE_seaworthy"));

/// Runs `seaworthy.sh <args>` in `dir` with `env`, never installing tools.
fn step(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    run_script(&repo_root().join("scripts/ci/seaworthy.sh"), dir, args, env)
}

/// Runs a copy of `seaworthy.sh` staged where the prepare job leaves it
/// (`<dir>/seaworthy/scripts/`), so the tool installers beside it are the
/// ones it runs.
fn staged_step(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let staged = dir.join("seaworthy/scripts/seaworthy.sh");
    std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
    std::fs::copy(repo_root().join("scripts/ci/seaworthy.sh"), &staged).unwrap();
    run_script(&staged, dir, args, env)
}

fn run_script(script: &Path, dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new("bash");
    command
        .current_dir(dir)
        .arg(script)
        .args(args)
        .env("SEAWORTHY_NO_INSTALL", "1")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("NFPM")
        .env_remove("SOURCE_DATE_EPOCH");
    // Run in a CI job, the steps would see the job's CI_PIPELINE_IID,
    // GITLAB_CI, CI_COMMIT_REF_PROTECTED and the like, and its
    // RUSTC_WRAPPER: each case sets exactly what it means to.
    for (key, _) in std::env::vars_os() {
        let key = key.to_string_lossy();
        if key.starts_with("CI_")
            || key.starts_with("GITLAB_")
            || key.starts_with("SEAWORTHY_")
            || key.starts_with("GIT_CONFIG_")
            || key.starts_with("GITHUB_")
            || key.starts_with("ACTIONS_")
            || key == "RUNNER_TEMP"
            || key == "RUSTC_WRAPPER"
        {
            command.env_remove(&*key);
        }
    }
    command.env("SEAWORTHY_NO_INSTALL", "1");
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// `seaworthy/bin/seaworthy`, as the prepare job leaves it (this build's):
/// a link to it, not a copy. A file this multi-threaded test process
/// writes and then runs can fail with ETXTBSY: another test's fork may
/// still hold the write descriptor until its child execs.
fn tool_into(dir: &Path) {
    let bin = dir.join("seaworthy/bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_seaworthy"), bin.join("seaworthy")).unwrap();
}

#[test]
fn the_build_step_carries_out_the_plan() {
    if !common::have("cargo", &["--version"]) {
        return;
    }
    // It builds and links an x86-64 Linux plan, which only such a host's
    // linker can (macOS's ld refuses GNU ld's options).
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        eprintln!("SKIPPED: the x86-64 Linux build plan links on an x86-64 Linux host only");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let write = |path: &str, text: &str| {
        let path = dir.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    write(
        "Cargo.toml",
        "[workspace]\nmembers = [\"tool\", \"core\"]\nresolver = \"3\"\n",
    );
    write(
        "tool/Cargo.toml",
        "[package]\nname = \"tiny_tool\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n\
         [[bin]]\nname = \"TinyTool\"\npath = \"src/main.rs\"\n\n\
         [[bin]]\nname = \"TinyUpdate\"\npath = \"src/update.rs\"\n",
    );
    write("tool/src/main.rs", "fn main() { println!(\"tool\"); }\n");
    write(
        "tool/src/update.rs",
        "fn main() { println!(\"update\"); }\n",
    );
    write(
        "core/Cargo.toml",
        "[package]\nname = \"tiny_core\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\ncrate-type = [\"cdylib\"]\n",
    );
    write(
        "core/src/lib.rs",
        "#[unsafe(no_mangle)]\npub extern \"C\" fn tiny_core_answer() -> u32 { 42 }\n\
         #[cfg(target_feature = \"avx2\")]\n#[unsafe(no_mangle)]\npub extern \"C\" fn tiny_core_avx2() {}\n",
    );
    write(
        "seaworthy.toml",
        "[defaults]\nvendor = \"Tiny\"\ntargets = [\"x86-64-v3\", \"x86-64-v2\"]\nchannel = \"stable\"\n\
         release-signatures = [\"ml-dsa-87\"]\nmaintainer = \"Tiny <t@tiny.test>\"\nlicense = \"MIT\"\n\n\
         [product.tool]\ndisplay-name = \"Tiny Tool\"\ndescription = \"A tiny tool.\"\nexecutable = \"TinyTool\"\n\
         core = \"tiny_core\"\nhelper = \"TinyUpdate\"\nkind = \"desktop\"\noutputs = [\"deb\"]\n",
    );
    let lock = Command::new("cargo")
        .current_dir(dir.path())
        .args(["generate-lockfile", "--offline"])
        .output()
        .unwrap();
    assert!(lock.status.success(), "{}", said(&lock));
    tool_into(dir.path());
    let plan = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
        .current_dir(dir.path())
        .args(["build-plan", "--triple", "x86_64-unknown-linux-gnu"])
        .output()
        .unwrap();
    assert!(plan.status.success(), "{}", said(&plan));
    std::fs::write(
        dir.path()
            .join("seaworthy/plan-x86_64-unknown-linux-gnu.tsv"),
        &plan.stdout,
    )
    .unwrap();
    let out = step(dir.path(), &["build", "x86_64-unknown-linux-gnu"], &[]);
    assert!(out.status.success(), "{}", said(&out));
    let artifacts = dir
        .path()
        .join("seaworthy/artifacts/x86_64-unknown-linux-gnu");
    for file in [
        "launcher/TinyTool",
        "helper/TinyUpdate",
        "cores/x86-64-v3/libtiny_core.so",
        "cores/x86-64-v2/libtiny_core.so",
    ] {
        let bytes = std::fs::read(artifacts.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        // Built with strip = false: verify reads the symbol tables.
        let elf = object::File::parse(&*bytes).unwrap();
        use object::Object as _;
        assert!(
            elf.section_by_name(".symtab").is_some(),
            "{file} keeps its symbol table"
        );
    }
    // Each CPU's core built for that CPU: x86-64-v3 has AVX2, v2 hasn't.
    let exports = |file: &str| -> Vec<String> {
        let bytes = std::fs::read(artifacts.join(file)).unwrap();
        let elf = object::File::parse(&*bytes).unwrap();
        use object::Object as _;
        elf.exports()
            .unwrap()
            .filter_map(|e| {
                e.unwrap()
                    .name()
                    .into_name()
                    .map(|name| String::from_utf8_lossy(name).into_owned())
            })
            .collect()
    };
    assert!(exports("cores/x86-64-v3/libtiny_core.so").contains(&"tiny_core_avx2".to_owned()));
    assert!(!exports("cores/x86-64-v2/libtiny_core.so").contains(&"tiny_core_avx2".to_owned()));
    // Refused: RUSTFLAGS (it would replace the per-CPU flags), the Windows
    // triple, an unknown step; nothing to do without a plan.
    let out = step(
        dir.path(),
        &["build", "x86_64-unknown-linux-gnu"],
        &[("RUSTFLAGS", "-C debuginfo=0")],
    );
    assert!(!out.status.success());
    assert!(
        said(&out).contains("RUSTFLAGS (or CARGO_BUILD_RUSTFLAGS) is set"),
        "{}",
        said(&out)
    );
    let out = step(
        dir.path(),
        &["build", "x86_64-unknown-linux-gnu"],
        &[("CARGO_BUILD_RUSTFLAGS", "-Dwarnings")],
    );
    assert!(!out.status.success());
    assert!(
        said(&out).contains("is set: it would replace or drop"),
        "{}",
        said(&out)
    );
    let out = step(dir.path(), &["build", "x86_64-pc-windows-msvc"], &[]);
    assert!(
        said(&out).contains("builds with seaworthy-build.ps1"),
        "{}",
        said(&out)
    );
    // The macOS plan builds on the Mac (seaworthy-macos.yml's job).
    let out = step(dir.path(), &["build", "aarch64-apple-darwin"], &[]);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("aarch64-apple-darwin builds on the Mac"),
        "{}",
        said(&out)
    );
    std::fs::remove_file(
        dir.path()
            .join("seaworthy/plan-x86_64-unknown-linux-gnu.tsv"),
    )
    .unwrap();
    let out = step(dir.path(), &["build", "x86_64-unknown-linux-gnu"], &[]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(said(&out).contains("no product needs it"), "{}", said(&out));
    let out = step(dir.path(), &["nonsense"], &[]);
    assert_eq!(out.status.code(), Some(2), "{}", said(&out));
}

const DESKTOP: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[product.console]
display-name = "Acme Console"
description = "The Acme console."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
kind = "desktop"
sidecars.windows = ["extra_*.dll"]
outputs = ["deb", "tar"]
"#;

#[test]
fn the_package_step_packages_unsigned_outside_a_release_and_refuses_an_unsigned_release() {
    let Some(nfpm) = common::nfpm() else { return };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("seaworthy.toml"), DESKTOP).unwrap();
    common::acme_artifacts(&dir.path().join("seaworthy/artifacts"));
    tool_into(dir.path());
    let env = [
        ("NFPM", nfpm.to_str().unwrap()),
        ("SOURCE_DATE_EPOCH", "1700000000"),
        ("CI_PIPELINE_IID", "41"),
        ("CI_COMMIT_SHORT_SHA", "0a1b2c3"),
        // Outside a release the secrets prefix isn't applied (a protected
        // role would refuse a branch pipeline).
        ("SEAWORTHY_SECRETS", "/nonexistent/wrapper"),
    ];
    let out = step(dir.path(), &["package"], &env);
    assert!(out.status.success(), "{}", said(&out));
    assert!(said(&out).contains("not a release: unsigned packages, version 0.0.0-alpha"));
    let listing: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.path().join("seaworthy/dist/console/packages.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(listing["version"], "0.0.0-alpha");
    assert_eq!(listing["sequence"], 41);
    assert_eq!(listing["token"], "0.0.0-alpha+0a1b2c3");
    // A release: the version from the tag, and signed — refused without
    // signing.toml.
    let mut release = env.to_vec();
    release.extend([("SEAWORTHY_RELEASE", "1"), ("CI_COMMIT_TAG", "v2.1.0")]);
    // A release runs seaworthy's own checkout's script and seaworthy built
    // in the job, never the prepare job's copies.
    let out = step(dir.path(), &["package"], &release);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("the seaworthy checkout (the template's seaworthy-dir"),
        "{}",
        said(&out)
    );
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir_all(elsewhere.join("scripts/ci")).unwrap();
    std::fs::write(elsewhere.join("Cargo.toml"), "[workspace]\n").unwrap();
    let mut another = release.clone();
    another.push(("SEAWORTHY_CHECKOUT", elsewhere.to_str().unwrap()));
    let out = step(dir.path(), &["package"], &another);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("runs package from seaworthy's own checkout"),
        "{}",
        said(&out)
    );
    let mut prepared_tool = release.clone();
    prepared_tool.extend([
        TRUSTED_CHECKOUT,
        ("SEAWORTHY_TOOL_BIN", "seaworthy/bin/seaworthy"),
    ]);
    let out = step(dir.path(), &["package"], &prepared_tool);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("SEAWORTHY_TOOL_BIN is under seaworthy, the prepare job's artifacts"),
        "{}",
        said(&out)
    );
    release.extend([TRUSTED_CHECKOUT, TRUSTED_TOOL]);
    let out = step(dir.path(), &["package"], &release);
    assert!(!out.status.success());
    assert!(
        said(&out).contains(
            "signing.toml (the template's signing-toml; a release or a dev build is signed)"
        ),
        "{}",
        said(&out)
    );
    // No signer handed over at all (the GitHub workflow's
    // SEAWORTHY_UNSIGNED): refused, unless SEAWORTHY_ALLOW_UNSIGNED means it.
    let mut unsigned = release.clone();
    unsigned.retain(|(k, _)| *k != "SEAWORTHY_SECRETS");
    unsigned.push(("SEAWORTHY_UNSIGNED", "1"));
    let out = step(dir.path(), &["package"], &unsigned);
    assert!(!out.status.success());
    assert!(
        said(&out).contains(
            "a release with no signer: no signing secret or signing.toml reached this job"
        ),
        "{}",
        said(&out)
    );
    unsigned.push(("SEAWORTHY_ALLOW_UNSIGNED", "1"));
    let out = step(dir.path(), &["package"], &unsigned);
    assert!(out.status.success(), "{}", said(&out));
    assert!(said(&out).contains("an UNSIGNED release"), "{}", said(&out));
    // A release's binaries never carry the CI test-key marker (a build
    // with seaworthy-formats' switch on).
    let marked = dir
        .path()
        .join("seaworthy/artifacts/x86_64-unknown-linux-gnu/marked.so");
    std::fs::create_dir_all(marked.parent().unwrap()).unwrap();
    std::fs::write(&marked, b"\0\0seaworthy-ci-test-keys:trusted:1\0").unwrap();
    let out = step(dir.path(), &["package"], &unsigned);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("built with the CI test-key switch"),
        "{}",
        said(&out)
    );
    std::fs::remove_file(&marked).unwrap();
    // A release without a tag or a version.
    let out = step(
        dir.path(),
        &["package"],
        &[
            ("SEAWORTHY_RELEASE", "1"),
            ("NFPM", nfpm.to_str().unwrap()),
            ("SOURCE_DATE_EPOCH", "1700000000"),
            ("CI_PIPELINE_IID", "41"),
            TRUSTED_CHECKOUT,
            TRUSTED_TOOL,
        ],
    );
    assert!(!out.status.success());
    assert!(
        said(&out).contains("a release needs a tag (SEAWORTHY_TAG, CI_COMMIT_TAG)"),
        "{}",
        said(&out)
    );
    assert!(!said(&out).contains("signing.toml"), "it stops there");
    // No sequence: refused before anything is set up.
    let out = step(
        dir.path(),
        &["package"],
        &[
            ("NFPM", nfpm.to_str().unwrap()),
            ("SOURCE_DATE_EPOCH", "1700000000"),
        ],
    );
    assert!(!out.status.success());
    assert!(
        said(&out).contains(
            "no release sequence: SEAWORTHY_SEQUENCE (or GitLab's CI_PIPELINE_IID) is unset"
        ),
        "{}",
        said(&out)
    );
    assert!(!said(&out).contains("not a release"), "it stops there");
    // Binaries the build jobs built for another release than this one: refused.
    let work = dir.path().join("seaworthy");
    std::fs::write(
        work.join("release.env"),
        "SEAWORTHY_RELEASE_VERSION=9.9.9\nSEAWORTHY_RELEASE_BUILD=0a1b2c3\n",
    )
    .unwrap();
    let out = step(dir.path(), &["package"], &env);
    assert!(!out.status.success());
    assert!(
        said(&out).contains(
            "the build jobs built release 9.9.9 (prepare's release.env), but this is 0.0.0-alpha"
        ),
        "{}",
        said(&out)
    );
    std::fs::write(
        work.join("release.env"),
        "SEAWORTHY_RELEASE_VERSION=0.0.0-alpha\nSEAWORTHY_RELEASE_BUILD=0a1b2c3\n",
    )
    .unwrap();
    let out = step(dir.path(), &["package"], &env);
    assert!(out.status.success(), "{}", said(&out));
    std::fs::remove_file(work.join("release.env")).unwrap();
    // nFPM that can't be installed stops the step (the installer beside
    // the script, as the prepare job stages them).
    let scripts = dir.path().join("seaworthy/scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    script_at(&scripts.join("install-nfpm.sh"), "#!/bin/sh\nexit 7\n");
    let mut without_nfpm: Vec<(&str, &str)> =
        env.iter().filter(|(k, _)| *k != "NFPM").copied().collect();
    without_nfpm.push(("NFPM", ""));
    let out = staged_step(dir.path(), &["package"], &without_nfpm);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("installing nFPM failed"),
        "{}",
        said(&out)
    );
    // Without the tool or the artifacts.
    std::fs::remove_dir_all(dir.path().join("seaworthy/artifacts")).unwrap();
    let out = step(dir.path(), &["package"], &env);
    assert!(
        said(&out).contains("no seaworthy/artifacts (from the build jobs)"),
        "{}",
        said(&out)
    );
}

/// The package step packages every platform but macOS: a
/// product's dmg is the Mac's (package-macos), never in the listing the
/// repo step publishes, and no macOS artifact is needed here.
#[test]
fn the_package_step_leaves_macos_to_the_mac() {
    let Some(nfpm) = common::nfpm() else { return };
    let dir = tempfile::tempdir().unwrap();
    let config = DESKTOP
        .replace(
            "helper = \"AcmeToolUpdate\"\n",
            "updates.default = \"off\"\n",
        )
        .replace(
            "outputs = [\"deb\", \"tar\"]",
            "outputs = [\"deb\", \"tar\", \"dmg\"]",
        )
        + "\n[product.console.macos]\nbundle-id = \"test.acme.console\"\n";
    std::fs::write(dir.path().join("seaworthy.toml"), config).unwrap();
    common::acme_artifacts(&dir.path().join("seaworthy/artifacts"));
    tool_into(dir.path());
    let env = [
        ("NFPM", nfpm.to_str().unwrap()),
        ("SOURCE_DATE_EPOCH", "1700000000"),
        ("CI_PIPELINE_IID", "41"),
        ("CI_COMMIT_SHORT_SHA", "0a1b2c3"),
    ];
    let out = step(dir.path(), &["package"], &env);
    assert!(out.status.success(), "{}", said(&out));
    let listing: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.path().join("seaworthy/dist/console/packages.json")).unwrap(),
    )
    .unwrap();
    let kinds: Vec<&str> = listing["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["kind"].as_str().unwrap())
        .collect();
    assert!(
        kinds.contains(&"deb") && kinds.contains(&"tar"),
        "{kinds:?}"
    );
    assert!(!kinds.contains(&"dmg"), "{kinds:?}");
    // The Mac's step: off a Mac, refused before anything else.
    let out = step(dir.path(), &["package-macos"], &env);
    assert!(!out.status.success());
    if cfg!(target_os = "macos") {
        // On one, it needs the seaworthy checkout first.
        assert!(
            said(&out).contains("the seaworthy checkout"),
            "{}",
            said(&out)
        );
    } else {
        assert!(
            said(&out).contains("package-macos runs on the Mac"),
            "{}",
            said(&out)
        );
    }
}

#[test]
fn in_gitlab_the_steps_trust_the_job_s_own_checkout() {
    // A job whose image runs as another user than the checkout's owner:
    // git refuses the checkout ("dubious ownership") unless safe.directory
    // names it. In GitLab the steps pass it in git's command scope
    // (GIT_CONFIG_COUNT, which git 2.56 honours for safe.directory); a stub
    // git records what it's given.
    let Some(nfpm) = common::nfpm() else { return };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("seaworthy.toml"), DESKTOP).unwrap();
    common::acme_artifacts(&dir.path().join("seaworthy/artifacts"));
    tool_into(dir.path());
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let seen = dir.path().join("git.env");
    script_at(
        &bin.join("git"),
        &format!(
            "#!/usr/bin/env bash\nenv | grep '^GIT_CONFIG_' | LC_ALL=C sort >> {}\necho -- >> {}\n[ \"$1\" = log ] && echo 1700000000\n",
            seen.display(),
            seen.display()
        ),
    );
    let project = dir.path().to_str().unwrap();
    let path = path_with(&bin);
    let base = [
        ("PATH", path.as_str()),
        ("NFPM", nfpm.to_str().unwrap()),
        ("CI_PIPELINE_IID", "41"),
        ("CI_COMMIT_SHORT_SHA", "0a1b2c3"),
    ];
    let mut gitlab = base.to_vec();
    gitlab.extend([
        ("GITLAB_CI", "true"),
        ("CI_PROJECT_DIR", project),
        ("GIT_CONFIG_COUNT", "1"),
        ("GIT_CONFIG_KEY_0", "core.abbrev"),
        ("GIT_CONFIG_VALUE_0", "12"),
    ]);
    let out = step(dir.path(), &["package"], &gitlab);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        std::fs::read_to_string(&seen).unwrap(),
        format!(
            "GIT_CONFIG_COUNT=2\nGIT_CONFIG_KEY_0=core.abbrev\nGIT_CONFIG_KEY_1=safe.directory\nGIT_CONFIG_VALUE_0=12\nGIT_CONFIG_VALUE_1={project}\n--\n"
        ),
        "the job's checkout, after the product's own entries"
    );
    // Outside GitLab, git's configuration is the caller's.
    std::fs::remove_file(&seen).unwrap();
    let out = step(dir.path(), &["package"], &base);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(std::fs::read_to_string(&seen).unwrap(), "--\n");
    // A malformed count is refused rather than overwritten.
    let mut bad = gitlab.clone();
    bad.retain(|(k, _)| *k != "GIT_CONFIG_COUNT");
    bad.push(("GIT_CONFIG_COUNT", "two"));
    let out = step(dir.path(), &["package"], &bad);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("GIT_CONFIG_COUNT isn't a count"),
        "{}",
        said(&out)
    );
}

#[test]
fn the_package_step_signs_a_release_versioned_from_its_tag() {
    use common::repo_fixture::{CONFIG, Fixture, tools};
    let Some(nfpm) = tools() else { return };
    let fixture = Fixture::new(&nfpm, true);
    let dir = fixture.path();
    tool_into(dir);
    common::acme_artifacts(&dir.join("seaworthy/artifacts"));
    // The fixture's agent ships a zip; this signing.toml has no Authenticode
    // signer, so the release below packages the Linux outputs alone (the
    // zip's refusal is checked at the end).
    let windows_output = "outputs = [\"deb\", \"rpm\", \"pacman\", \"tar\", \"zip\"]";
    assert_eq!(CONFIG.matches(windows_output).count(), 1);
    std::fs::write(
        dir.join("seaworthy.toml"),
        CONFIG.replace(
            windows_output,
            "outputs = [\"deb\", \"rpm\", \"pacman\", \"tar\"]",
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("signing.toml"),
        format!(
            "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey = \"release.key\"\n\n[openpgp]\nhome = {:?}\nkey = \"{}\"\n",
            fixture.keyring.home().to_str().unwrap(),
            fixture.keyring.fingerprint
        ),
    )
    .unwrap();
    // The secrets prefix: a wrapper that notes what it runs, then runs it.
    let wrapper = dir.join("wrap.sh");
    script_at(
        &wrapper,
        &format!(
            "#!/bin/sh\necho \"$@\" >> {}\nexec \"$@\"\n",
            dir.join("wrapped.log").display()
        ),
    );
    let wrapper = wrapper.to_str().unwrap().to_owned();
    let env = [
        ("NFPM", nfpm.to_str().unwrap()),
        ("SOURCE_DATE_EPOCH", "1700000000"),
        ("CI_PIPELINE_IID", "12"),
        ("CI_COMMIT_SHORT_SHA", "cafe12"),
        ("SEAWORTHY_RELEASE", "1"),
        ("CI_COMMIT_TAG", "v2.1.0-rc.1"),
        ("SEAWORTHY_SECRETS", wrapper.as_str()),
        ("GITLAB_CI", "true"),
        TRUSTED_CHECKOUT,
        TRUSTED_TOOL,
    ];
    // In GitLab, a release on an unprotected ref is refused.
    let mut unprotected = env.to_vec();
    unprotected.push(("CI_COMMIT_REF_PROTECTED", "false"));
    let out = step(dir, &["package"], &unprotected);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("a release runs on a protected ref only"),
        "{}",
        said(&out)
    );
    let mut protected = env.to_vec();
    protected.push(("CI_COMMIT_REF_PROTECTED", "true"));
    let out = step(dir, &["package"], &protected);
    assert!(out.status.success(), "{}", said(&out));
    // The seaworthy call ran under the prefix (nothing else did), with the
    // seaworthy this job installed, never the prepare job's.
    let wrapped = std::fs::read_to_string(dir.join("wrapped.log")).unwrap();
    assert_eq!(wrapped.lines().count(), 1, "{wrapped}");
    assert!(
        wrapped.contains("/seaworthy package --config seaworthy.toml")
            && !wrapped.contains("seaworthy/bin/seaworthy"),
        "{wrapped}"
    );
    let listing: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.join("seaworthy/dist/agent/packages.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(listing["version"], "2.1.0-rc.1");
    assert_eq!(listing["token"], "2.1.0-rc.1+cafe12");
    assert_eq!(listing["sequence"], 12);
    assert!(
        listing["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["kind"] == "manifest"),
        "signed: manifests beside the packages"
    );
    // A product composing its own token (build-metadata): the release is
    // named with prepare's build (release.env), and its manifests carry it.
    // The command itself never runs in a signing step: product code never
    // shares a job with the signers.
    std::fs::write(
        dir.join("seaworthy/release.env"),
        "SEAWORTHY_RELEASE_VERSION=2.1.0-rc.1\nSEAWORTHY_RELEASE_BUILD=cafe12345678.lib-0a1b2c3d4e5f\n",
    )
    .unwrap();
    let ran = dir.join("build-metadata-ran");
    let command = format!("touch {}; echo another", ran.display());
    let mut composed = protected.clone();
    composed.push(("SEAWORTHY_BUILD_COMMAND", command.as_str()));
    let out = step(dir, &["package"], &composed);
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        !ran.exists(),
        "the build-metadata command ran in a signing step"
    );
    let listing: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.join("seaworthy/dist/agent/packages.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(listing["token"], "2.1.0-rc.1+cafe12345678.lib-0a1b2c3d4e5f");
    // Without prepare's record, a product that composes its token can't be
    // packaged: refused, the command not run.
    std::fs::remove_file(dir.join("seaworthy/release.env")).unwrap();
    let out = step(dir, &["package"], &composed);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("the build-metadata command runs in prepare alone"),
        "{}",
        said(&out)
    );
    assert!(!ran.exists());
    std::fs::write(
        dir.join("seaworthy/release.env"),
        "SEAWORTHY_RELEASE_VERSION=2.1.0-rc.1\nSEAWORTHY_RELEASE_BUILD=cafe12345678.lib-0a1b2c3d4e5f\n",
    )
    .unwrap();
    // A signed release with a Windows output and no Authenticode signer is
    // refused before anything is packaged: never an MSI or zip of unsigned
    // executables under signed manifests.
    std::fs::write(dir.join("seaworthy.toml"), CONFIG).unwrap();
    std::fs::remove_dir_all(dir.join("seaworthy/dist")).unwrap();
    let out = step(dir, &["package"], &composed);
    assert!(!out.status.success());
    assert!(
        said(&out).contains(
            "product agent ships Windows outputs (zip) but signing.toml has no [authenticode]"
        ),
        "{}",
        said(&out)
    );
    assert!(
        !dir.join("seaworthy/dist/agent/packages.json").exists(),
        "nothing packaged"
    );
}

/// A one-shot-per-request HTTP server answering every request with
/// `status` and `body`; returns its URL.
fn serve(status: u16, body: Vec<u8>) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://127.0.0.1:{}/packages",
        listener.local_addr().unwrap().port()
    );
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut buffer = [0_u8; 4096];
            let _ = stream.read(&mut buffer);
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    url
}

/// A server answering every request with a 200 that claims `length`
/// bytes and sends none of them; returns its URL.
fn serve_claiming(length: u64) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://127.0.0.1:{}/packages",
        listener.local_addr().unwrap().port()
    );
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut buffer = [0_u8; 4096];
            let _ = stream.read(&mut buffer);
            let head =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(head.as_bytes());
        }
    });
    url
}

#[test]
fn the_repo_step_publishes_after_the_last_plan_or_as_the_first() {
    use common::repo_fixture::{DATE, Fixture, tools};
    let Some(nfpm) = tools() else { return };
    let fixture = Fixture::new(&nfpm, true);
    let dir = fixture.path();
    tool_into(dir);
    // The packaged releases where the package job leaves them.
    common_copy(&dir.join("dist"), &dir.join("seaworthy/dist"));
    std::fs::write(
        dir.join("signing.toml"),
        format!(
            "[openpgp]\nhome = {:?}\nkey = \"{}\"\n",
            fixture.keyring.home().to_str().unwrap(),
            fixture.keyring.fingerprint
        ),
    )
    .unwrap();
    let publish_toml = |url: &str| {
        std::fs::write(
            dir.join("publish.toml"),
            format!(
                "endpoint = \"http://127.0.0.1:9\"\nbucket = \"b\"\nregion = \"auto\"\nprefix = \"packages\"\npublic-url = \"{url}\"  # where clients fetch\n"
            ),
        )
        .unwrap();
    };
    let env = [
        ("SEAWORTHY_RELEASE", "1"),
        ("CI_PIPELINE_IID", "9"),
        TRUSTED_CHECKOUT,
        TRUSTED_TOOL,
    ];
    // A first publication: nothing at the public URL yet (here written in
    // single quotes, which TOML allows too).
    let url = serve(404, Vec::new());
    std::fs::write(
        dir.join("publish.toml"),
        format!("endpoint = \"http://127.0.0.1:9\"\nbucket = \"b\"\nregion = \"auto\"\nprefix = \"packages\"\npublic-url = '{url}'\n"),
    )
    .unwrap();
    let out = step(dir, &["repo"], &env);
    assert!(out.status.success(), "{}", said(&out));
    assert!(said(&out).contains("the first"), "{}", said(&out));
    let first = seaworthy::repo::Plan::read(&dir.join("seaworthy/repo/publish-plan.json")).unwrap();
    // After a published plan: --previous, so its immutable files are held to
    // their bytes and the date must be later.
    let mut stale = first.clone();
    stale.date = DATE - 86_400;
    publish_toml(&serve(200, serde_json::to_vec(&stale).unwrap()));
    let out = step(dir, &["repo"], &env);
    assert!(out.status.success(), "{}", said(&out));
    let mut future = first.clone();
    future.date = u64::MAX / 2;
    publish_toml(&serve(200, serde_json::to_vec(&future).unwrap()));
    let out = step(dir, &["repo"], &env);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("isn't after the last publication's"),
        "{}",
        said(&out)
    );
    // A server error is never taken for a first publication.
    publish_toml(&serve(503, Vec::new()));
    let out = step(dir, &["repo"], &env);
    assert!(!out.status.success());
    assert!(said(&out).contains("answered HTTP 503"), "{}", said(&out));
    // Nothing listening: the fetch fails, and says so.
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    publish_toml(&format!("http://127.0.0.1:{closed}"));
    let out = step(dir, &["repo"], &env);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("/publish-plan.json failed"),
        "{}",
        said(&out)
    );
    // In GitLab, on an unprotected ref.
    let mut unprotected = env.to_vec();
    unprotected.extend([("GITLAB_CI", "true"), ("CI_COMMIT_REF_PROTECTED", "false")]);
    let out = step(dir, &["repo"], &unprotected);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("a release runs on a protected ref only"),
        "{}",
        said(&out)
    );
    // Outside a release; without a public URL.
    let out = step(dir, &["repo"], &[("CI_PIPELINE_IID", "9")]);
    assert!(
        said(&out).contains("repo runs on a release only"),
        "{}",
        said(&out)
    );
    std::fs::write(dir.join("publish.toml"), "bucket = \"b\"\n").unwrap();
    let out = step(dir, &["repo"], &env);
    assert!(said(&out).contains("sets no public-url"), "{}", said(&out));
}

#[test]
fn the_publish_step_needs_a_release_a_repository_and_its_credentials() {
    let dir = tempfile::tempdir().unwrap();
    tool_into(dir.path());
    let out = step(
        dir.path(),
        &["publish"],
        &[("SEAWORTHY_RELEASE", "1"), TRUSTED_CHECKOUT, TRUSTED_TOOL],
    );
    assert!(
        said(&out).contains("no seaworthy/repo (from the repo job)"),
        "{}",
        said(&out)
    );
    std::fs::create_dir_all(dir.path().join("seaworthy/repo")).unwrap();
    std::fs::write(dir.path().join("seaworthy/repo/publish-plan.json"), "{}").unwrap();
    let out = step(dir.path(), &["publish"], &[]);
    assert!(
        said(&out).contains("publish runs on a release only"),
        "{}",
        said(&out)
    );
    let out = step(
        dir.path(),
        &["publish"],
        &[
            ("SEAWORTHY_RELEASE", "1"),
            ("GITLAB_CI", "true"),
            ("CI_COMMIT_REF_PROTECTED", "false"),
            TRUSTED_CHECKOUT,
            TRUSTED_TOOL,
        ],
    );
    assert!(
        said(&out).contains("a release runs on a protected ref only"),
        "{}",
        said(&out)
    );
    std::fs::write(dir.path().join("publish.toml"), "").unwrap();
    let out = step(
        dir.path(),
        &["publish"],
        &[
            ("SEAWORTHY_RELEASE", "1"),
            ("SEAWORTHY_S3_ACCESS_KEY_ID", "AKID"),
            TRUSTED_CHECKOUT,
            TRUSTED_TOOL,
        ],
    );
    assert!(
        said(&out).contains("the store's credentials"),
        "{}",
        said(&out)
    );
    assert!(!said(&out).contains("AKID"), "never printed");
    // With a secrets wrapper, the credentials are the wrapper's to give: the
    // step goes on to seaworthy (which reads the plan here, and refuses it).
    let wrapper = dir.path().join("creds.sh");
    script_at(
        &wrapper,
        "#!/bin/sh\nexport SEAWORTHY_S3_ACCESS_KEY_ID=AKID SEAWORTHY_S3_SECRET_ACCESS_KEY=SECRET\nexec \"$@\"\n",
    );
    let out = step(
        dir.path(),
        &["publish"],
        &[
            ("SEAWORTHY_RELEASE", "1"),
            ("SEAWORTHY_SECRETS", wrapper.to_str().unwrap()),
            TRUSTED_CHECKOUT,
            TRUSTED_TOOL,
        ],
    );
    assert!(!out.status.success());
    assert!(
        !said(&out).contains("the store's credentials"),
        "{}",
        said(&out)
    );
    assert!(said(&out).contains("publish.toml"), "{}", said(&out));
}

/// Copies `from` into `to`, recursively.
fn common_copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            common_copy(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// An executable script at `path`.
/// A stub cargo for the Windows build: records its arguments (one file per
/// call), the release and MSVC variables it was given, and leaves what a
/// build would (an .exe, or a core .dll and the FIPS DLL pair).
fn windows_cargo_stub(log: &Path) -> String {
    format!(
        "#!/bin/bash\nprintf '%s\\n' \"$@\" > \"{log}/$(date +%s%N).args\"\n\
                 env | grep '^SEAWORTHY_RELEASE_' | sort > \"{log}/release-env\"\n\
                 env | grep -E '^(INCLUDE|LIB|VCToolsInstallDir|LIBCLANG_PATH)=' | sort > \"{log}/msvc-env\"\n\
                 dir=\"\" name=\"\" kind=\"\"\n\
                 while [ $# -gt 0 ]; do case \"$1\" in --target-dir) dir=\"$2\"; shift ;; --bin) name=\"$2\"; kind=bin; shift ;; -p) name=\"$2\"; kind=lib; shift ;; esac; shift; done\n\
                 release=\"$dir/x86_64-pc-windows-msvc/release\"\nmkdir -p \"$release\"\n\
                 if [ \"$kind\" = bin ]; then echo exe > \"$release/$name.exe\"; else echo dll > \"$release/$name.dll\"\n\
                 out=\"$release/build/aws-lc-fips-sys-1/out\"; mkdir -p \"$out\"\n\
                 echo crypto > \"$out/aws_lc_fips_0_13_crypto.dll\"; echo wrapper > \"$out/aws_lc_fips_0_13_rust_wrapper.dll\"; fi\n",
        log = log.display()
    )
}

fn script_at(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// `PATH` with `dir` first.
/// `pwsh`, without a compiler wrapper the caller's environment may set.
fn pwsh() -> Command {
    let mut command = Command::new("pwsh");
    command.env_remove("RUSTC_WRAPPER");
    command
}

fn path_with(dir: &Path) -> String {
    format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

const WINDOWS_PRODUCT: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[product.console]
display-name = "Acme Console"
description = "The Acme console."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
kind = "desktop"
windows-directory = "Console"
sidecars.windows = ["aws_lc_fips_*_crypto.dll", "aws_lc_fips_*_rust_wrapper.dll"]
outputs = ["deb", "zip"]
"#;

#[test]
fn the_windows_build_carries_out_the_plan_in_both_argument_passing_modes() {
    // pwsh stands in for Windows PowerShell; a stub cargo records what it's
    // given and leaves what a build would.
    let have_pwsh = pwsh()
        .args(["-NoProfile", "-Command", "exit 0"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !have_pwsh {
        eprintln!(
            "SKIPPED: pwsh is not installed (Windows PowerShell 5.1 runs this script on the runner)"
        );
        return;
    }
    for mode in ["Standard", "Legacy"] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("seaworthy.toml"), WINDOWS_PRODUCT).unwrap();
        tool_into(dir.path());
        let plan = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
            .current_dir(dir.path())
            .args(["build-plan", "--triple", "x86_64-pc-windows-msvc"])
            .output()
            .unwrap();
        assert!(plan.status.success(), "{}", said(&plan));
        std::fs::write(
            dir.path().join("seaworthy/plan-x86_64-pc-windows-msvc.tsv"),
            &plan.stdout,
        )
        .unwrap();
        // Prepare's record of the release, which the product's build
        // scripts see (its version token).
        std::fs::write(
            dir.path().join("seaworthy/release.env"),
            "SEAWORTHY_RELEASE_VERSION=1.4.0\nSEAWORTHY_RELEASE_BUILD=0a1b2c3\n",
        )
        .unwrap();
        let bin = dir.path().join("stub-bin");
        std::fs::create_dir_all(&bin).unwrap();
        script_at(&bin.join("cargo"), &windows_cargo_stub(dir.path()));
        let script = repo_root().join("scripts/ci/seaworthy-build.ps1");
        let out = pwsh()
            .current_dir(dir.path())
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg(format!(
                "$PSNativeCommandArgumentPassing = '{mode}'; & '{}'; exit $LASTEXITCODE",
                script.display()
            ))
            .env("PATH", path_with(&bin))
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_BUILD_RUSTFLAGS")
            .output()
            .unwrap();
        assert!(out.status.success(), "{mode}: {}", said(&out));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("release-env")).unwrap(),
            "SEAWORTHY_RELEASE_BUILD=0a1b2c3\nSEAWORTHY_RELEASE_VERSION=1.4.0\n",
            "{mode}"
        );
        let artifacts = dir
            .path()
            .join("seaworthy/artifacts/x86_64-pc-windows-msvc");
        for file in [
            "launcher/AcmeTool.exe",
            "helper/AcmeToolUpdate.exe",
            "cores/x86-64-v3/acme_core.dll",
            "cores/x86-64-v3/aws_lc_fips_0_13_crypto.dll",
            "cores/x86-64-v3/aws_lc_fips_0_13_rust_wrapper.dll",
            "cores/x86-64-v2/acme_core.dll",
            "cores/x86-64-v2/aws_lc_fips_0_13_crypto.dll",
        ] {
            assert!(artifacts.join(file).is_file(), "{mode}: {file}");
        }
        // The per-CPU flags reached cargo as one argument, whole.
        let calls: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "args"))
            .map(|p| std::fs::read_to_string(p).unwrap())
            .collect();
        assert!(
            calls
                .iter()
                .any(|c| c.lines().any(|l| l
                    == "target.x86_64-pc-windows-msvc.rustflags=['-C','target-cpu=x86-64-v3','-C','target-feature=+crt-static']")),
            "{mode}: {calls:#?}"
        );
        assert!(
            calls
                .iter()
                .all(|c| c.lines().any(|l| l == "profile.release.strip=false")),
            "{mode}: {calls:#?}"
        );
        // Every Windows build, the launcher's and helper's too, links the C
        // runtime statically.
        assert!(
            calls.iter().all(|c| c.lines().any(|l| l
                .starts_with("target.x86_64-pc-windows-msvc.rustflags=")
                && l.contains("'-C','target-feature=+crt-static'"))),
            "{mode}: {calls:#?}"
        );
        // Two builds' copies of one sidecar with different bytes: refused.
        let stub = std::fs::read_to_string(bin.join("cargo")).unwrap();
        script_at(
            &bin.join("cargo"),
            &stub.replace(
                "fi\n",
                "mkdir -p \"$release/build/other/out\"; echo other > \"$release/build/other/out/aws_lc_fips_0_13_crypto.dll\"; fi\n",
            ),
        );
        std::fs::remove_dir_all(dir.path().join("seaworthy/target")).unwrap();
        let out = pwsh()
            .current_dir(dir.path())
            .args(["-NoProfile", "-NonInteractive", "-File"])
            .arg(&script)
            .env("PATH", path_with(&bin))
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_BUILD_RUSTFLAGS")
            .output()
            .unwrap();
        assert!(!out.status.success(), "{mode}: {}", said(&out));
        assert!(
            said(&out).contains("builds with different"),
            "{mode}: {}",
            said(&out)
        );
        // Cargo would drop the per-CPU flags for CARGO_BUILD_RUSTFLAGS'.
        let out = pwsh()
            .current_dir(dir.path())
            .args(["-NoProfile", "-NonInteractive", "-File"])
            .arg(&script)
            .env("PATH", path_with(&bin))
            .env_remove("RUSTFLAGS")
            .env("CARGO_BUILD_RUSTFLAGS", "--cfg product_flag")
            .output()
            .unwrap();
        assert!(!out.status.success(), "{mode}: {}", said(&out));
        assert!(
            said(&out).contains("CARGO_BUILD_RUSTFLAGS) is set"),
            "{mode}: {}",
            said(&out)
        );
        // A core built without the module that ships the sidecars: refused.
        let bare = stub.replace(
            "echo crypto > \"$out/aws_lc_fips_0_13_crypto.dll\"; echo wrapper > \"$out/aws_lc_fips_0_13_rust_wrapper.dll\"; ",
            "",
        );
        assert_ne!(bare, stub);
        script_at(&bin.join("cargo"), &bare);
        std::fs::remove_dir_all(dir.path().join("seaworthy/target")).unwrap();
        let out = pwsh()
            .current_dir(dir.path())
            .args(["-NoProfile", "-NonInteractive", "-File"])
            .arg(&script)
            .env("PATH", path_with(&bin))
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_BUILD_RUSTFLAGS")
            .output()
            .unwrap();
        assert!(!out.status.success(), "{mode}: {}", said(&out));
        assert!(
            said(&out).contains("no sidecar matching aws_lc_fips_*_crypto.dll"),
            "{mode}: {}",
            said(&out)
        );
    }
}

/// The Windows build enters the x64 MSVC developer environment before it
/// builds: vswhere finds Visual Studio, vcvarsall.bat x64's environment comes
/// back through cmd.exe, and cargo (so every build script) inherits INCLUDE,
/// LIB and VCToolsInstallDir, plus LIBCLANG_PATH from Visual Studio's Clang
/// tools. A FIPS core's bindgen needs INCLUDE for vcruntime.h. Acme's
/// first Windows build failed without it: "'vcruntime.h' file not found".
/// Stubs stand in for vswhere and cmd.exe. A job already in a developer
/// environment doesn't run vswhere. No installation, or a vcvarsall.bat that
/// sets nothing, is refused.
#[test]
fn the_windows_build_enters_the_msvc_developer_environment() {
    let have_pwsh = pwsh()
        .args(["-NoProfile", "-Command", "exit 0"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !have_pwsh {
        eprintln!(
            "SKIPPED: pwsh is not installed (Windows PowerShell 5.1 runs this script on the runner)"
        );
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("seaworthy.toml"), WINDOWS_PRODUCT).unwrap();
    tool_into(dir.path());
    let plan = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
        .current_dir(dir.path())
        .args(["build-plan", "--triple", "x86_64-pc-windows-msvc"])
        .output()
        .unwrap();
    assert!(plan.status.success(), "{}", said(&plan));
    std::fs::write(
        dir.path().join("seaworthy/plan-x86_64-pc-windows-msvc.tsv"),
        &plan.stdout,
    )
    .unwrap();
    let bin = dir.path().join("stub-bin");
    std::fs::create_dir_all(&bin).unwrap();
    script_at(&bin.join("cargo"), &windows_cargo_stub(dir.path()));
    // A Visual Studio installation: vcvarsall.bat and the Clang tools.
    let vs = dir.path().join("vs");
    std::fs::create_dir_all(vs.join("VC/Auxiliary/Build")).unwrap();
    std::fs::write(vs.join("VC/Auxiliary/Build/vcvarsall.bat"), "@rem\n").unwrap();
    std::fs::create_dir_all(vs.join("VC/Tools/Llvm/x64/bin")).unwrap();
    std::fs::write(vs.join("VC/Tools/Llvm/x64/bin/libclang.dll"), "dll").unwrap();
    let vswhere = dir.path().join("vswhere");
    let finds = |found: &str| {
        format!(
            "#!/bin/bash\necho \"$@\" >> \"{log}/vswhere.calls\"\n\
             case \" $* \" in *' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 '*'-property installationPath'*) echo '{found}' ;; *) exit 9 ;; esac\n",
            log = dir.path().display()
        )
    };
    // cmd.exe runs the temp .cmd file: it must call vcvarsall.bat x64, then
    // `set` prints the environment back.
    let vcvars = |prints: &str| {
        format!(
            "#!/bin/bash\n[ \"$1\" = /d ] && [ \"$2\" = /c ] || exit 8\n\
             grep -q '^@call \".*vcvarsall.bat\" x64 >nul' \"$3\" || exit 7\n\
             grep -q '^@set' \"$3\" || exit 6\n{prints}echo \"PATH=$PATH\"\n"
        )
    };
    let full = "echo 'INCLUDE=C:\\VS\\include'\necho 'LIB=C:\\VS\\lib'\n\
                echo 'VCToolsInstallDir=C:\\VS\\Tools\\MSVC\\14.44\\'\n";
    let run = |mode: &str, env: &[(&str, &str)]| {
        let _ = std::fs::remove_dir_all(dir.path().join("seaworthy/target"));
        let _ = std::fs::remove_file(dir.path().join("msvc-env"));
        let mut command = pwsh();
        command
            .current_dir(dir.path())
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg(format!(
                "$PSNativeCommandArgumentPassing = '{mode}'; & '{}'; exit $LASTEXITCODE",
                repo_root().join("scripts/ci/seaworthy-build.ps1").display()
            ))
            .env("PATH", path_with(&bin))
            .env("SEAWORTHY_VSWHERE", &vswhere)
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_BUILD_RUSTFLAGS")
            .env_remove("INCLUDE")
            .env_remove("LIB")
            .env_remove("VCToolsInstallDir")
            .env_remove("LIBCLANG_PATH");
        for (key, value) in env {
            command.env(key, value);
        }
        command.output().unwrap()
    };
    for mode in ["Standard", "Legacy"] {
        script_at(&vswhere, &finds(&vs.display().to_string()));
        script_at(&bin.join("cmd.exe"), &vcvars(full));
        let out = run(mode, &[]);
        assert!(out.status.success(), "{mode}: {}", said(&out));
        assert!(said(&out).contains("MSVC: "), "{mode}: {}", said(&out));
        let given = std::fs::read_to_string(dir.path().join("msvc-env")).unwrap();
        for line in [
            "INCLUDE=C:\\VS\\include",
            "LIB=C:\\VS\\lib",
            "VCToolsInstallDir=C:\\VS\\Tools\\MSVC\\14.44\\",
        ] {
            assert!(
                given.lines().any(|l| l == line),
                "{mode}: {line} in {given}"
            );
        }
        let clang = given
            .lines()
            .find_map(|l| l.strip_prefix("LIBCLANG_PATH="))
            .unwrap_or_else(|| panic!("{mode}: no LIBCLANG_PATH in {given}"))
            .replace('\\', "/");
        assert!(
            clang.ends_with("vs/VC/Tools/Llvm/x64/bin"),
            "{mode}: {clang}"
        );
    }
    // Already in a developer environment: vswhere never runs.
    let _ = std::fs::remove_file(dir.path().join("vswhere.calls"));
    let out = run(
        "Standard",
        &[
            ("INCLUDE", "C:\\Dev\\include"),
            ("VCToolsInstallDir", "C:\\Dev\\"),
        ],
    );
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        said(&out).contains("already in a developer environment"),
        "{}",
        said(&out)
    );
    assert!(!dir.path().join("vswhere.calls").exists());
    assert!(
        std::fs::read_to_string(dir.path().join("msvc-env"))
            .unwrap()
            .lines()
            .any(|l| l == "INCLUDE=C:\\Dev\\include")
    );
    // No installation with the MSVC x64 tools.
    script_at(&vswhere, &finds(""));
    let out = run("Standard", &[]);
    assert!(!out.status.success(), "{}", said(&out));
    assert!(
        said(&out).contains("no Visual Studio installation"),
        "{}",
        said(&out)
    );
    // vcvarsall.bat that sets nothing. (pwsh wraps a long error across lines:
    // the checks match short fragments.)
    script_at(&vswhere, &finds(&vs.display().to_string()));
    script_at(&bin.join("cmd.exe"), &vcvars(""));
    let out = run("Standard", &[]);
    assert!(!out.status.success(), "{}", said(&out));
    assert!(said(&out).contains("did not set INCLUDE"), "{}", said(&out));
}

#[test]
fn the_prepare_step_builds_the_tool_plans_and_lints() {
    let dir = tempfile::tempdir().unwrap();
    // A seaworthy checkout as the fetch leaves it, and a stub cargo standing
    // in for building seaworthy from it.
    let checkout = dir.path().join(".seaworthy");
    for file in [
        "scripts/ci/seaworthy.sh",
        "scripts/ci/seaworthy-build.ps1",
        "scripts/ci/seaworthy-msi.ps1",
        "scripts/ci/azure-sign.sh",
        "scripts/ci/install-nfpm.sh",
        "scripts/ci/install-osslsigncode.sh",
        "ci/gitlab/seaworthy.yml",
    ] {
        let to = checkout.join(file);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(repo_root().join(file), &to).unwrap();
    }
    std::fs::write(checkout.join("Cargo.toml"), "[workspace]\n").unwrap();
    let bin = dir.path().join("stub-bin");
    std::fs::create_dir_all(&bin).unwrap();
    // The stub notes where it ran, in what environment, and its target
    // directory.
    let seen = dir.path().join("cargo-seen");
    script_at(
        &bin.join("cargo"),
        &format!(
            "#!/bin/bash\n{{ echo \"pwd=$(pwd -P)\"; env | LC_ALL=C sort; }} > {seen}\n\
             while [ $# -gt 0 ]; do [ \"$1\" = --target-dir ] && dir=\"$2\"; shift; done\n\
             echo \"target=$dir\" >> {seen}\n\
             mkdir -p \"$dir/release\" && cp {} \"$dir/release/seaworthy\"\n",
            env!("CARGO_BIN_EXE_seaworthy"),
            seen = seen.display()
        ),
    );
    // The product's own build settings, which must never reach seaworthy's
    // build: its cargo configuration, toolchain file, compiler wrapper,
    // cargo and compiler overrides.
    std::fs::create_dir_all(dir.path().join(".cargo")).unwrap();
    std::fs::write(
        dir.path().join(".cargo/config.toml"),
        "[build]\nrustc-wrapper = \"/nonexistent/wrapper\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"nightly\"\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("seaworthy.toml"), WINDOWS_PRODUCT).unwrap();
    std::fs::write(
        dir.path().join(".gitlab-ci.yml"),
        "include: [{project: acme/seaworthy, file: ci/gitlab/seaworthy.yml}]\n\
         deploy: {needs: [seaworthy-publish], script: [d]}\nlazy: {needs: [seaworthy-package], script: [d]}\n",
    )
    .unwrap();
    let raw = std::fs::read_to_string(repo_root().join("ci/gitlab/seaworthy.yml")).unwrap();
    let marker = raw
        .lines()
        .find(|l| l.contains("SEAWORTHY_TEMPLATE:"))
        .unwrap()
        .split('"')
        .nth(1)
        .unwrap()
        .to_owned();
    let path = path_with(&bin);
    let project = dir.path().to_str().unwrap().to_owned();
    let prepare = |extra: &[(&str, &str)]| {
        let mut env = vec![
            ("PATH", path.as_str()),
            ("SEAWORTHY_TEMPLATE", marker.as_str()),
            ("CI_PROJECT_DIR", project.as_str()),
        ];
        env.extend_from_slice(extra);
        step(dir.path(), &["prepare"], &env)
    };
    let out = prepare(&[
        ("RUSTC_WRAPPER", "/nonexistent/sccache"),
        ("CARGO_BUILD_RUSTC_WRAPPER", "/nonexistent/sccache"),
        ("CARGO_TARGET_DIR", "/nonexistent/target"),
        ("RUSTUP_TOOLCHAIN", "nightly"),
        ("RUSTFLAGS", "-Cevil"),
        ("CC", "/nonexistent/cc"),
        ("CMAKE_C_COMPILER_LAUNCHER", "/nonexistent/ccache"),
        ("SEAWORTHY_ALLOW_CI_TEST_KEYS", "1"),
    ]);
    assert!(out.status.success(), "{}", said(&out));
    let cargo_saw = std::fs::read_to_string(&seen).unwrap();
    let project = std::fs::canonicalize(dir.path()).unwrap();
    let ran_in = cargo_saw
        .lines()
        .find_map(|l| l.strip_prefix("pwd="))
        .unwrap();
    assert!(
        !Path::new(ran_in).starts_with(&project),
        "seaworthy builds outside the product's tree ({ran_in}): its .cargo/config.toml and rust-toolchain.toml stay out"
    );
    assert!(
        std::fs::read_dir(ran_in).is_err(),
        "the private copy it built from is removed afterwards"
    );
    for name in [
        "RUSTC_WRAPPER=",
        "CARGO_BUILD_RUSTC_WRAPPER=",
        "CARGO_TARGET_DIR=",
        "RUSTUP_TOOLCHAIN=",
        "RUSTFLAGS=",
        "CC=",
        "CMAKE_C_COMPILER_LAUNCHER=",
        "SEAWORTHY_",
        "CI_PROJECT_DIR=",
    ] {
        assert!(
            !cargo_saw.lines().any(|l| l.starts_with(name)),
            "{name} reached seaworthy's build:\n{cargo_saw}"
        );
    }
    for file in [
        "bin/seaworthy",
        "scripts/seaworthy.sh",
        "scripts/seaworthy-build.ps1",
        "scripts/install-nfpm.sh",
        "scripts/install-osslsigncode.sh",
        "scripts/seaworthy-msi.ps1",
        "scripts/azure-sign.sh",
        "scripts/seaworthy.yml",
        "plan-x86_64-unknown-linux-gnu.tsv",
        "plan-x86_64-pc-windows-msvc.tsv",
    ] {
        assert!(dir.path().join("seaworthy").join(file).is_file(), "{file}");
    }
    assert!(
        said(&out).contains("no server deploy job named"),
        "{}",
        said(&out)
    );
    // No product of this one's needs the Mac: no macOS plan.
    assert!(
        said(&out).contains("aarch64-apple-darwin: no product needs it"),
        "{}",
        said(&out)
    );
    assert!(
        !dir.path()
            .join("seaworthy/plan-aarch64-apple-darwin.tsv")
            .exists()
    );
    // The release's identity for the build jobs (not a release here).
    assert_eq!(
        std::fs::read_to_string(dir.path().join("seaworthy/release.env")).unwrap(),
        "SEAWORTHY_RELEASE_VERSION=0.0.0-alpha\nSEAWORTHY_RELEASE_BUILD=\n"
    );
    assert!(
        !dir.path().join(".seaworthy/target").exists(),
        "the tool builds outside the checkout"
    );
    assert!(
        dir.path()
            .join("seaworthy/tool-target/release/seaworthy")
            .is_file()
    );
    // The template's cached target directory, wherever it says.
    let elsewhere = dir.path().join("cache/tool");
    let out = prepare(&[("SEAWORTHY_TOOL_TARGET", elsewhere.to_str().unwrap())]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(elsewhere.join("release/seaworthy").is_file());
    // A cargo configuration above the private copy (TMPDIR's tree) would
    // join seaworthy's build: refused.
    let tmpdir = dir.path().join("tmp/inner");
    std::fs::create_dir_all(&tmpdir).unwrap();
    std::fs::create_dir_all(dir.path().join("tmp/.cargo")).unwrap();
    std::fs::write(dir.path().join("tmp/.cargo/config.toml"), "").unwrap();
    let out = prepare(&[("TMPDIR", tmpdir.to_str().unwrap())]);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("would join seaworthy's own build"),
        "{}",
        said(&out)
    );
    // The product's build-metadata command runs before anything is staged:
    // what it does to the checkout never reaches the scripts handed on.
    let tamper = format!(
        "echo '# changed by product code' >> {}; echo cafe12",
        checkout.join("scripts/ci/seaworthy.sh").display()
    );
    let out = prepare(&[("SEAWORTHY_BUILD_COMMAND", tamper.as_str())]);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        std::fs::read(dir.path().join("seaworthy/scripts/seaworthy.sh")).unwrap(),
        std::fs::read(repo_root().join("scripts/ci/seaworthy.sh")).unwrap(),
        "staged from the copy made before the command ran"
    );
    std::fs::copy(
        repo_root().join("scripts/ci/seaworthy.sh"),
        checkout.join("scripts/ci/seaworthy.sh"),
    )
    .unwrap();
    // A release compiles seaworthy in a new directory of its own, never the
    // cached one, and refuses the CI test-key switch.
    let out = prepare(&[
        ("SEAWORTHY_RELEASE", "1"),
        ("CI_COMMIT_TAG", "v1.2.3"),
        ("CI_PIPELINE_IID", "5"),
    ]);
    assert!(out.status.success(), "{}", said(&out));
    let target = std::fs::read_to_string(&seen)
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("target=").map(str::to_owned))
        .unwrap();
    assert!(
        !Path::new(&target).starts_with(&project),
        "a release's tool never builds in the cached target directory: {target}"
    );
    assert!(
        said(&out).contains("never comes from a cache"),
        "{}",
        said(&out)
    );
    let out = prepare(&[
        ("SEAWORTHY_RELEASE", "1"),
        ("CI_COMMIT_TAG", "v1.2.3"),
        ("CI_PIPELINE_IID", "5"),
        ("SEAWORTHY_ALLOW_CI_TEST_KEYS", "1"),
    ]);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("a release never trusts the CI test keys"),
        "{}",
        said(&out)
    );
    // The release-ordering lint: a server that needs the publication
    // passes (the template's include read through --include, not warned
    // about); one that doesn't fails the job.
    let out = prepare(&[("SEAWORTHY_SERVER_JOBS", "deploy")]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        said(&out).contains("release order: deploy waits for seaworthy-publish"),
        "{}",
        said(&out)
    );
    assert!(!said(&out).contains("include not read"), "{}", said(&out));
    let out = prepare(&[("SEAWORTHY_SERVER_JOBS", "deploy,lazy")]);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("\"lazy\" can deploy before client job \"seaworthy-publish\""),
        "{}",
        said(&out)
    );
    // A checkout of another revision than the included template's.
    let out = prepare(&[("SEAWORTHY_TEMPLATE", "0000000000000000")]);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("isn't the included template's revision"),
        "{}",
        said(&out)
    );
    // A release tag the package job would refuse fails here, before the
    // builds.
    let out = prepare(&[
        ("SEAWORTHY_RELEASE", "1"),
        ("CI_COMMIT_TAG", "v1.2.3-pre"),
        ("CI_PIPELINE_IID", "5"),
    ]);
    assert!(!out.status.success(), "{}", said(&out));
    // The version file (the template's version-file) names every
    // pipeline outside a release and a release without a tag (one from a
    // branch); a release tag must name the same version.
    let release_env = || std::fs::read_to_string(dir.path().join("seaworthy/release.env")).unwrap();
    std::fs::write(
        dir.path().join("server.toml"),
        "[package]\nname = \"server\"\nversion = \"2.1.0-beta.3\" # the contract's\n\n\
         [dependencies]\nversion = \"9.9.9\"\n",
    )
    .unwrap();
    let file = ("SEAWORTHY_VERSION_FILE", "server.toml");
    let out = prepare(&[file, ("CI_COMMIT_SHORT_SHA", "0a1b2c3d")]);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        release_env(),
        "SEAWORTHY_RELEASE_VERSION=2.1.0-beta.3\nSEAWORTHY_RELEASE_BUILD=0a1b2c3d\n"
    );
    let branch_release = [
        file,
        ("SEAWORTHY_RELEASE", "1"),
        ("CI_PIPELINE_IID", "5"),
        ("CI_COMMIT_SHORT_SHA", "0a1b2c3d"),
    ];
    let out = prepare(&branch_release);
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        said(&out).contains("the release: 2.1.0-beta.3+0a1b2c3d"),
        "{}",
        said(&out)
    );
    let mut tagged = branch_release.to_vec();
    tagged.push(("CI_COMMIT_TAG", "v2.1.0-beta.3"));
    let out = prepare(&tagged);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        release_env(),
        "SEAWORTHY_RELEASE_VERSION=2.1.0-beta.3\nSEAWORTHY_RELEASE_BUILD=0a1b2c3d\n"
    );
    let mut mistagged = branch_release.to_vec();
    mistagged.push(("CI_COMMIT_TAG", "v2.1.0"));
    let out = prepare(&mistagged);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("the tag v2.1.0 names 2.1.0, but server.toml declares 2.1.0-beta.3"),
        "{}",
        said(&out)
    );
    // SEAWORTHY_VERSION still wins over both.
    let mut explicit = mistagged.clone();
    explicit.push(("SEAWORTHY_VERSION", "3.0.0"));
    let out = prepare(&explicit);
    assert!(out.status.success(), "{}", said(&out));
    assert!(release_env().starts_with("SEAWORTHY_RELEASE_VERSION=3.0.0\n"));
    // Read as TOML (seaworthy manifest-version): a `version = …` line
    // inside a multi-line string isn't the version; a version inherited
    // from the workspace is the root's; an inherited one without a root, a
    // missing file and a version seaworthy doesn't package are refused —
    // on every pipeline, before the builds.
    std::fs::write(
        dir.path().join("server.toml"),
        "[package]\nname = \"server\"\ndescription = \"\"\"\nversion = \"6.6.6\"\n\"\"\"\nversion = \"2.1.0-beta.3\"\n",
    )
    .unwrap();
    let out = prepare(&[file]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(release_env().starts_with("SEAWORTHY_RELEASE_VERSION=2.1.0-beta.3\n"));
    std::fs::create_dir_all(dir.path().join("ws/member")).unwrap();
    std::fs::write(
        dir.path().join("ws/Cargo.toml"),
        "[workspace]\nmembers = [\"member\"]\n[workspace.package]\nversion = \"3.1.0-rc.2\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("ws/member/Cargo.toml"),
        "[package]\nname = \"member\"\nversion.workspace = true\n",
    )
    .unwrap();
    let out = prepare(&[("SEAWORTHY_VERSION_FILE", "ws/member/Cargo.toml")]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(release_env().starts_with("SEAWORTHY_RELEASE_VERSION=3.1.0-rc.2\n"));
    std::fs::write(
        dir.path().join("server.toml"),
        "[package]\nname = \"server\"\nversion.workspace = true\n",
    )
    .unwrap();
    let out = prepare(&[file]);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("inherits its version but no workspace root above it"),
        "{}",
        said(&out)
    );
    std::fs::write(
        dir.path().join("server.toml"),
        "[package]\nname = \"server\"\nversion = \"2.0.0-dev\"\n",
    )
    .unwrap();
    let out = prepare(&[file]);
    assert!(!out.status.success(), "a version seaworthy won't package");
    assert!(
        said(&out).contains("isn't one seaworthy packages"),
        "{}",
        said(&out)
    );
    let out = prepare(&[("SEAWORTHY_VERSION_FILE", "missing.toml")]);
    assert!(!out.status.success());
    assert!(said(&out).contains("the version file"), "{}", said(&out));
    // The build metadata from the product's command (template input
    // build-metadata): a product that composes its own version token names
    // the build part; the output must be build metadata, the command must
    // succeed.
    let out = prepare(&[
        (
            "SEAWORTHY_BUILD_COMMAND",
            "echo 4367cb33a097.lib-da9560db93ef",
        ),
        ("CI_COMMIT_SHORT_SHA", "0a1b2c3d"),
    ]);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        release_env(),
        "SEAWORTHY_RELEASE_VERSION=0.0.0-alpha\nSEAWORTHY_RELEASE_BUILD=4367cb33a097.lib-da9560db93ef\n"
    );
    for (command, says) in [
        ("echo 'not metadata!'", "build metadata is dot-separated"),
        ("printf ''", "build metadata is dot-separated"),
        ("echo a..b", "build metadata is dot-separated"),
        ("echo .lib-1", "build metadata is dot-separated"),
        ("echo é", "build metadata is dot-separated"),
        // At most 64 characters (the length check below).
        ("printf '%065d' 0", "build metadata is dot-separated"),
        ("exit 3", "the build-metadata command failed"),
        // pipefail: a failing first stage isn't hidden by the last.
        ("false | echo abc", "the build-metadata command failed"),
    ] {
        let out = prepare(&[("SEAWORTHY_BUILD_COMMAND", command)]);
        assert!(!out.status.success(), "{command}");
        assert!(said(&out).contains(says), "{command}: {}", said(&out));
    }
    // 64 characters is the most build metadata may hold.
    let out = prepare(&[("SEAWORTHY_BUILD_COMMAND", "printf '%064d' 0")]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        release_env().ends_with(&format!("SEAWORTHY_RELEASE_BUILD={}\n", "0".repeat(64))),
        "{}",
        release_env()
    );
    // A release with neither a tag nor a version file has no version.
    let out = prepare(&[("SEAWORTHY_RELEASE", "1"), ("CI_PIPELINE_IID", "5")]);
    assert!(!out.status.success());
    assert!(
        said(&out)
            .contains("a release needs a tag (SEAWORTHY_TAG, CI_COMMIT_TAG), the version file"),
        "{}",
        said(&out)
    );
    // No checkout.
    std::fs::remove_dir_all(&checkout).unwrap();
    let out = prepare(&[]);
    assert!(
        said(&out).contains("the seaworthy checkout"),
        "{}",
        said(&out)
    );
}

#[test]
fn the_build_step_names_the_release_for_the_product_s_build_scripts() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("seaworthy");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(
        work.join("plan-x86_64-unknown-linux-gnu.tsv"),
        "build\tbase\t-\t--bin tool\ncopy\tbase/x86_64-unknown-linux-gnu/release/tool\tx86_64-unknown-linux-gnu/launcher/tool\n",
    )
    .unwrap();
    let bin = dir.path().join("stub-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let seen = dir.path().join("seen");
    script_at(
        &bin.join("cargo"),
        &format!(
            "#!/bin/bash\nenv | grep '^SEAWORTHY_RELEASE_' | sort > '{}'\n\
             while [ $# -gt 0 ]; do [ \"$1\" = --target-dir ] && dir=\"$2\"; shift; done\n\
             mkdir -p \"$dir/x86_64-unknown-linux-gnu/release\" && echo bin > \"$dir/x86_64-unknown-linux-gnu/release/tool\"\n",
            seen.display()
        ),
    );
    let path = path_with(&bin);
    let build = |env: &[(&str, &str)]| {
        let mut all = vec![("PATH", path.as_str())];
        all.extend_from_slice(env);
        step(dir.path(), &["build", "x86_64-unknown-linux-gnu"], &all)
    };
    // No release.env (a local run): computed as the package step computes it.
    let out = build(&[
        ("SEAWORTHY_VERSION", "1.4.0-rc.2"),
        ("CI_COMMIT_SHORT_SHA", "0a1b2c3"),
    ]);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        std::fs::read_to_string(&seen).unwrap(),
        "SEAWORTHY_RELEASE_BUILD=0a1b2c3\nSEAWORTHY_RELEASE_VERSION=1.4.0-rc.2\n"
    );
    assert!(
        said(&out).contains("building release 1.4.0-rc.2+0a1b2c3"),
        "{}",
        said(&out)
    );
    // Prepare's record wins (a build job isn't told it's a release).
    std::fs::write(
        work.join("release.env"),
        "SEAWORTHY_RELEASE_VERSION=2.0.0\nSEAWORTHY_RELEASE_BUILD=deadbee\n",
    )
    .unwrap();
    let out = build(&[("CI_COMMIT_SHORT_SHA", "0a1b2c3")]);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        std::fs::read_to_string(&seen).unwrap(),
        "SEAWORTHY_RELEASE_BUILD=deadbee\nSEAWORTHY_RELEASE_VERSION=2.0.0\n"
    );
    // A record without a version, with a value twice, or with values the
    // steps don't take, is refused: it's data, read strictly.
    for (record, why) in [
        (
            "SEAWORTHY_RELEASE_BUILD=x\n",
            "must name SEAWORTHY_RELEASE_VERSION once",
        ),
        (
            "SEAWORTHY_RELEASE_VERSION=2.0.0\nSEAWORTHY_RELEASE_VERSION=3.0.0\n",
            "must name SEAWORTHY_RELEASE_VERSION once",
        ),
        (
            "SEAWORTHY_RELEASE_VERSION=2.0.0 $(id)\nSEAWORTHY_RELEASE_BUILD=x\n",
            "isn't one",
        ),
        (
            "SEAWORTHY_RELEASE_VERSION=2.0.0\nSEAWORTHY_RELEASE_BUILD=a..b\n",
            "isn't build metadata",
        ),
    ] {
        std::fs::write(work.join("release.env"), record).unwrap();
        let out = build(&[]);
        assert!(!out.status.success(), "{record}");
        assert!(said(&out).contains(why), "{record}: {}", said(&out));
    }
    // seaworthy-formats' CI test-key switch reaches a build outside a
    // release (a test lane's helper trusts the test keys), and fails every
    // step of a release, whatever its value but empty or 0.
    std::fs::write(
        work.join("release.env"),
        "SEAWORTHY_RELEASE_VERSION=2.0.0\nSEAWORTHY_RELEASE_BUILD=deadbee\n",
    )
    .unwrap();
    let out = build(&[("SEAWORTHY_ALLOW_CI_TEST_KEYS", "1")]);
    assert!(out.status.success(), "{}", said(&out));
    for value in ["1", "yes"] {
        let out = build(&[
            ("SEAWORTHY_RELEASE", "1"),
            ("SEAWORTHY_ALLOW_CI_TEST_KEYS", value),
        ]);
        assert!(!out.status.success(), "{value}");
        assert!(
            said(&out).contains("on a release: a release never trusts the CI test keys"),
            "{}",
            said(&out)
        );
    }
    for value in ["", "0"] {
        let out = build(&[
            ("SEAWORTHY_RELEASE", "1"),
            ("SEAWORTHY_ALLOW_CI_TEST_KEYS", value),
        ]);
        assert!(out.status.success(), "{value:?}: {}", said(&out));
    }
}

/// Off GitLab the release is named by SEAWORTHY_TAG, SEAWORTHY_SEQUENCE
/// and SEAWORTHY_COMMIT (the GitHub workflow sets them), and prepare
/// installs a seaworthy already built from the checkout
/// (SEAWORTHY_TOOL_BIN) instead of building one. A sequence that isn't a
/// positive integer is refused.
#[test]
fn off_gitlab_the_release_comes_from_seaworthy_variables() {
    let dir = tempfile::tempdir().unwrap();
    let checkout = dir.path().join(".seaworthy");
    for file in [
        "scripts/ci/seaworthy.sh",
        "scripts/ci/seaworthy-build.ps1",
        "scripts/ci/seaworthy-msi.ps1",
        "scripts/ci/azure-sign.sh",
        "scripts/ci/install-nfpm.sh",
        "scripts/ci/install-osslsigncode.sh",
        "ci/gitlab/seaworthy.yml",
    ] {
        let to = checkout.join(file);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(repo_root().join(file), &to).unwrap();
    }
    std::fs::write(checkout.join("Cargo.toml"), "[workspace]\n").unwrap();
    // No cargo may run: the tool is already built.
    let bin = dir.path().join("stub-bin");
    std::fs::create_dir_all(&bin).unwrap();
    script_at(
        &bin.join("cargo"),
        "#!/bin/bash\necho 'cargo ran' >&2\nexit 1\n",
    );
    std::fs::write(dir.path().join("seaworthy.toml"), WINDOWS_PRODUCT).unwrap();
    let path = path_with(&bin);
    let tool = env!("CARGO_BIN_EXE_seaworthy");
    let prepare = |extra: &[(&str, &str)]| {
        let mut env = vec![("PATH", path.as_str()), ("SEAWORTHY_TOOL_BIN", tool)];
        env.extend_from_slice(extra);
        step(dir.path(), &["prepare"], &env)
    };
    let out = prepare(&[
        ("SEAWORTHY_RELEASE", "1"),
        ("SEAWORTHY_TAG", "v1.4.0-rc.2"),
        ("SEAWORTHY_SEQUENCE", "812"),
        ("SEAWORTHY_COMMIT", "0a1b2c3d"),
    ]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(!said(&out).contains("cargo ran"), "{}", said(&out));
    assert!(
        said(&out).contains(&format!("seaworthy from {tool}")),
        "{}",
        said(&out)
    );
    assert_eq!(
        std::fs::read(dir.path().join("seaworthy/bin/seaworthy")).unwrap(),
        std::fs::read(tool).unwrap()
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("seaworthy/release.env")).unwrap(),
        "SEAWORTHY_RELEASE_VERSION=1.4.0-rc.2\nSEAWORTHY_RELEASE_BUILD=0a1b2c3d\n"
    );
    assert!(
        dir.path()
            .join("seaworthy/plan-x86_64-unknown-linux-gnu.tsv")
            .is_file()
    );
    // The neutral variables win over GitLab's.
    let out = prepare(&[
        ("SEAWORTHY_RELEASE", "1"),
        ("SEAWORTHY_TAG", "v2.0.0"),
        ("CI_COMMIT_TAG", "v9.9.9"),
        ("SEAWORTHY_SEQUENCE", "9"),
        ("CI_PIPELINE_IID", "1"),
    ]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        std::fs::read_to_string(dir.path().join("seaworthy/release.env"))
            .unwrap()
            .starts_with("SEAWORTHY_RELEASE_VERSION=2.0.0\n")
    );
    // A release with no tag, version file or version is refused, by the
    // variables' names.
    let out = prepare(&[("SEAWORTHY_RELEASE", "1"), ("SEAWORTHY_SEQUENCE", "9")]);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("a release needs a tag (SEAWORTHY_TAG"),
        "{}",
        said(&out)
    );
    for sequence in ["0", "-3", "12a", "1.5"] {
        let out = prepare(&[
            ("SEAWORTHY_RELEASE", "1"),
            ("SEAWORTHY_TAG", "v1.0.0"),
            ("SEAWORTHY_SEQUENCE", sequence),
        ]);
        assert!(!out.status.success(), "{sequence}");
        assert!(
            said(&out).contains("isn't a positive integer"),
            "{sequence}: {}",
            said(&out)
        );
    }
    // A missing prebuilt tool is named.
    let out = step(
        dir.path(),
        &["prepare"],
        &[
            ("PATH", path.as_str()),
            ("SEAWORTHY_TOOL_BIN", "/nonexistent/seaworthy"),
        ],
    );
    assert!(!out.status.success());
    assert!(said(&out).contains("SEAWORTHY_TOOL_BIN"), "{}", said(&out));
}

/// A product with a launcher, a helper and two cores, for the caller's
/// extra rustflags.
const EXTRA_FLAGS_PRODUCT: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[product.console]
display-name = "Acme Console"
description = "The Acme console."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
kind = "desktop"
windows-directory = "Console"
outputs = ["deb", "zip"]
"#;

/// The rustflags each build got, by its target directory's name: the
/// `target.<triple>.rustflags=[…]` argument of every call a stub cargo
/// recorded (one `.args` file per call, one argument per line).
fn rustflags_by_target_dir(log: &Path, triple: &str) -> std::collections::BTreeMap<String, String> {
    let prefix = format!("target.{triple}.rustflags=");
    let mut seen = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(log).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "args") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let dir = lines
            .iter()
            .position(|l| *l == "--target-dir")
            .map(|at| lines[at + 1])
            .unwrap();
        let name = Path::new(dir)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let flags = lines
            .iter()
            .find_map(|l| l.strip_prefix(prefix.as_str()))
            .unwrap_or("")
            .to_owned();
        // The launcher and helper share `base`: both builds must agree.
        if let Some(earlier) = seen.insert(name.clone(), flags.clone()) {
            assert_eq!(earlier, flags, "{name}'s builds got different flags");
        }
    }
    seen
}

/// The caller's extra rustflags (`SEAWORTHY_RUSTFLAGS` for every build,
/// `SEAWORTHY_CORE_RUSTFLAGS` for the cores alone: PGO's `-Cprofile-use`,
/// say) join each build's `target.<triple>.rustflags` after the plan's
/// per-CPU flags, with `{workspace}` (absolute), `{triple}` and `{cpu}`
/// expanded. Refused: a flag choosing the CPU or its features, a quote, an
/// unknown placeholder, and `{workspace}` without the workspace manifest.
#[test]
fn the_build_step_adds_the_caller_s_rustflags_after_the_plan_s() {
    let triple = "x86_64-unknown-linux-gnu";
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("seaworthy.toml"), EXTRA_FLAGS_PRODUCT).unwrap();
    std::fs::write(dir.path().join("Cargo.toml"), "[workspace]\n").unwrap();
    std::fs::create_dir_all(dir.path().join("seaworthy")).unwrap();
    // This build's seaworthy, run in place: the build step needs no copy.
    let plan = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
        .current_dir(dir.path())
        .args(["build-plan", "--triple", triple])
        .output()
        .unwrap();
    assert!(plan.status.success(), "{}", said(&plan));
    std::fs::write(
        dir.path().join(format!("seaworthy/plan-{triple}.tsv")),
        &plan.stdout,
    )
    .unwrap();
    let bin = dir.path().join("stub-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = dir.path().join("log");
    std::fs::create_dir_all(&log).unwrap();
    script_at(
        &bin.join("cargo"),
        &format!(
            "#!/bin/bash\nprintf '%s\\n' \"$@\" > \"{log}/$(date +%s%N).args\"\n\
             dir=\"\" name=\"\" kind=\"\"\n\
             while [ $# -gt 0 ]; do case \"$1\" in --target-dir) dir=\"$2\"; shift ;; --bin) name=\"$2\"; kind=bin; shift ;; -p) name=\"$2\"; kind=lib; shift ;; esac; shift; done\n\
             release=\"$dir/{triple}/release\"; mkdir -p \"$release\"\n\
             if [ \"$kind\" = bin ]; then echo bin > \"$release/$name\"; else echo so > \"$release/lib$name.so\"; fi\n",
            log = log.display()
        ),
    );
    let path = path_with(&bin);
    let build = |env: &[(&str, &str)]| {
        for entry in std::fs::read_dir(&log).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        let mut all = vec![("PATH", path.as_str())];
        all.extend_from_slice(env);
        step(dir.path(), &["build", triple], &all)
    };
    let workspace = dir.path().canonicalize().unwrap();
    let out = build(&[
        (
            "SEAWORTHY_RUSTFLAGS",
            "--cfg every_build -Cdebuginfo=line-tables-only",
        ),
        (
            "SEAWORTHY_CORE_RUSTFLAGS",
            "-Cprofile-use={workspace}/pgo/{triple}-{cpu}.profdata  -Cllvm-args=-pgo-warn-mismatch=false",
        ),
    ]);
    assert!(out.status.success(), "{}", said(&out));
    let flags = rustflags_by_target_dir(&log, triple);
    assert_eq!(
        flags["base"], "['--cfg','every_build','-Cdebuginfo=line-tables-only']",
        "the launcher and helper get every build's flags, never the cores'"
    );
    for cpu in ["x86-64-v3", "x86-64-v2"] {
        assert_eq!(
            flags[cpu],
            format!(
                "['-C','target-cpu={cpu}','--cfg','every_build','-Cdebuginfo=line-tables-only',\
                 '-Cprofile-use={}/pgo/{triple}-{cpu}.profdata','-Cllvm-args=-pgo-warn-mismatch=false']",
                workspace.display()
            ),
            "{cpu}: the plan's flags first, then every build's, then the cores'"
        );
    }
    // Without extra flags the launcher's build gets none at all.
    let out = build(&[]);
    assert!(out.status.success(), "{}", said(&out));
    let flags = rustflags_by_target_dir(&log, triple);
    assert_eq!(flags["base"], "");
    assert_eq!(flags["x86-64-v3"], "['-C','target-cpu=x86-64-v3']");
    for (variable, value, why) in [
        (
            "SEAWORTHY_CORE_RUSTFLAGS",
            "-Ctarget-cpu=native",
            "may not choose the CPU or its features",
        ),
        (
            "SEAWORTHY_RUSTFLAGS",
            "-C target-feature=+avx2",
            "may not choose the CPU or its features",
        ),
        (
            "SEAWORTHY_CORE_RUSTFLAGS",
            "--cfg=feature='x'",
            "may not hold a quote",
        ),
        (
            "SEAWORTHY_RUSTFLAGS",
            "-Cprofile-use={workspce}/a",
            "unknown placeholder {workspce}",
        ),
    ] {
        let out = build(&[(variable, value)]);
        assert!(!out.status.success(), "{value}: {}", said(&out));
        assert!(said(&out).contains(why), "{value}: {}", said(&out));
    }
    std::fs::remove_file(dir.path().join("Cargo.toml")).unwrap();
    let out = build(&[(
        "SEAWORTHY_CORE_RUSTFLAGS",
        "-Cprofile-use={workspace}/a.profdata",
    )]);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("{workspace} names the workspace manifest's directory"),
        "{}",
        said(&out)
    );
}

/// `build <triple> <target dir>` carries out one target directory's steps
/// alone (one CI job per CPU): its build and its copies, nothing of the
/// others'; an unknown directory is refused. The PowerShell build does the
/// same, the first CPU's job also copying the sidecars beside every core.
#[test]
fn one_target_directory_builds_alone_for_a_job_per_cpu() {
    let triple = "x86_64-unknown-linux-gnu";
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("seaworthy.toml"), EXTRA_FLAGS_PRODUCT).unwrap();
    std::fs::write(dir.path().join("Cargo.toml"), "[workspace]\n").unwrap();
    std::fs::create_dir_all(dir.path().join("seaworthy")).unwrap();
    let plan = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
        .current_dir(dir.path())
        .args(["build-plan", "--triple", triple])
        .output()
        .unwrap();
    assert!(plan.status.success(), "{}", said(&plan));
    std::fs::write(
        dir.path().join(format!("seaworthy/plan-{triple}.tsv")),
        &plan.stdout,
    )
    .unwrap();
    let bin = dir.path().join("stub-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = dir.path().join("log");
    std::fs::create_dir_all(&log).unwrap();
    script_at(
        &bin.join("cargo"),
        &format!(
            "#!/bin/bash\nprintf '%s\\n' \"$@\" > \"{log}/$(date +%s%N).args\"\n\
             dir=\"\" name=\"\" kind=\"\"\n\
             while [ $# -gt 0 ]; do case \"$1\" in --target-dir) dir=\"$2\"; shift ;; --bin) name=\"$2\"; kind=bin; shift ;; -p) name=\"$2\"; kind=lib; shift ;; esac; shift; done\n\
             release=\"$dir/{triple}/release\"; mkdir -p \"$release\"\n\
             if [ \"$kind\" = bin ]; then echo bin > \"$release/$name\"; else echo so > \"$release/lib$name.so\"; fi\n",
            log = log.display()
        ),
    );
    let path = path_with(&bin);
    let artifacts = dir.path().join("seaworthy/artifacts").join(triple);
    let files = || -> Vec<String> {
        let mut found = Vec::new();
        for entry in walk(&artifacts) {
            found.push(
                entry
                    .strip_prefix(&artifacts)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        found.sort();
        found
    };
    let out = step(
        dir.path(),
        &["build", triple, "x86-64-v2"],
        &[("PATH", path.as_str())],
    );
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        said(&out).contains("the x86-64-v2 build alone"),
        "{}",
        said(&out)
    );
    assert_eq!(files(), ["cores/x86-64-v2/libacme_core.so"]);
    assert_eq!(rustflags_by_target_dir(&log, triple).len(), 1);
    let out = step(
        dir.path(),
        &["build", triple, "base"],
        &[("PATH", path.as_str())],
    );
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        files(),
        [
            "cores/x86-64-v2/libacme_core.so",
            "helper/AcmeToolUpdate",
            "launcher/AcmeTool",
        ]
    );
    assert!(
        !dir.path()
            .join(format!("seaworthy/plan-{triple}.base.tsv"))
            .exists(),
        "the partial plan is removed"
    );
    for bad in ["x86-64-v9", "../x86-64-v2"] {
        let out = step(
            dir.path(),
            &["build", triple, bad],
            &[("PATH", path.as_str())],
        );
        assert!(!out.status.success(), "{bad}");
        assert!(
            said(&out).contains("has no target directory")
                || said(&out).contains("isn't a target directory"),
            "{bad}: {}",
            said(&out)
        );
    }

    // Windows: the first CPU's job copies the sidecars beside every core.
    let have_pwsh = pwsh()
        .args(["-NoProfile", "-Command", "exit 0"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !have_pwsh {
        eprintln!("SKIPPED: pwsh is not installed");
        return;
    }
    let windows = "x86_64-pc-windows-msvc";
    let wdir = tempfile::tempdir().unwrap();
    std::fs::write(wdir.path().join("seaworthy.toml"), WINDOWS_PRODUCT).unwrap();
    std::fs::create_dir_all(wdir.path().join("seaworthy")).unwrap();
    let plan = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
        .current_dir(wdir.path())
        .args(["build-plan", "--triple", windows])
        .output()
        .unwrap();
    assert!(plan.status.success(), "{}", said(&plan));
    std::fs::write(
        wdir.path().join(format!("seaworthy/plan-{windows}.tsv")),
        &plan.stdout,
    )
    .unwrap();
    let wbin = wdir.path().join("stub-bin");
    std::fs::create_dir_all(&wbin).unwrap();
    script_at(&wbin.join("cargo"), &windows_cargo_stub(wdir.path()));
    let script = repo_root().join("scripts/ci/seaworthy-build.ps1");
    let run = |target_dir: &str| {
        pwsh()
            .current_dir(wdir.path())
            .args(["-NoProfile", "-NonInteractive", "-File"])
            .arg(&script)
            .args(["-TargetDir", target_dir])
            .env("PATH", path_with(&wbin))
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_BUILD_RUSTFLAGS")
            .output()
            .unwrap()
    };
    let wartifacts = wdir.path().join("seaworthy/artifacts").join(windows);
    let out = run("x86-64-v2");
    assert!(out.status.success(), "{}", said(&out));
    assert!(wartifacts.join("cores/x86-64-v2/acme_core.dll").is_file());
    assert!(
        !wartifacts
            .join("cores/x86-64-v2/aws_lc_fips_0_13_crypto.dll")
            .exists(),
        "the sidecars come from the first CPU's build"
    );
    let out = run("x86-64-v3");
    assert!(out.status.success(), "{}", said(&out));
    for file in [
        "cores/x86-64-v3/acme_core.dll",
        "cores/x86-64-v3/aws_lc_fips_0_13_crypto.dll",
        "cores/x86-64-v2/aws_lc_fips_0_13_crypto.dll",
        "cores/x86-64-v2/aws_lc_fips_0_13_rust_wrapper.dll",
    ] {
        assert!(wartifacts.join(file).is_file(), "{file}");
    }
    assert!(!wartifacts.join("launcher").exists());
    let out = run("x86-64-v9");
    assert!(!out.status.success());
    assert!(
        said(&out).contains("has no target directory"),
        "{}",
        said(&out)
    );
}

/// Every file under `dir`, recursively.
fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// `SEAWORTHY_PRODUCTS` narrows prepare's plans to the products named
/// (each step once), dropping a triple none of them needs; an id that
/// isn't one is refused.
#[test]
fn prepare_plans_the_selected_products_alone() {
    let dir = tempfile::tempdir().unwrap();
    let checkout = dir.path().join(".seaworthy");
    for file in [
        "scripts/ci/seaworthy.sh",
        "scripts/ci/seaworthy-build.ps1",
        "scripts/ci/seaworthy-msi.ps1",
        "scripts/ci/azure-sign.sh",
        "scripts/ci/install-nfpm.sh",
        "scripts/ci/install-osslsigncode.sh",
        "ci/gitlab/seaworthy.yml",
    ] {
        let to = checkout.join(file);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(repo_root().join(file), &to).unwrap();
    }
    std::fs::write(checkout.join("Cargo.toml"), "[workspace]\n").unwrap();
    let two = format!(
        "{WINDOWS_PRODUCT}\n[product.tool]\ndisplay-name = \"Acme Tool\"\ndescription = \"A tool.\"\n\
         executable = \"AcmeCli\"\ncore = \"acme_cli_core\"\nkind = \"tool\"\noutputs = [\"tar\"]\n\
         updates.default = \"off\"\n"
    );
    std::fs::write(dir.path().join("seaworthy.toml"), two).unwrap();
    let tool = env!("CARGO_BIN_EXE_seaworthy");
    let prepare = |products: &str| {
        step(
            dir.path(),
            &["prepare"],
            &[
                ("SEAWORTHY_TOOL_BIN", tool),
                ("SEAWORTHY_PRODUCTS", products),
            ],
        )
    };
    let plan = |triple: &str| {
        std::fs::read_to_string(dir.path().join(format!("seaworthy/plan-{triple}.tsv")))
            .unwrap_or_default()
    };
    let out = prepare("tool");
    assert!(out.status.success(), "{}", said(&out));
    let linux = plan("x86_64-unknown-linux-gnu");
    assert!(
        linux.contains("--bin AcmeCli") && !linux.contains("AcmeTool"),
        "{linux}"
    );
    assert!(
        said(&out).contains("x86_64-pc-windows-msvc: no product needs it"),
        "{}",
        said(&out)
    );
    let out = prepare("console, tool");
    assert!(out.status.success(), "{}", said(&out));
    let linux = plan("x86_64-unknown-linux-gnu");
    assert!(
        linux.contains("--bin AcmeCli") && linux.contains("--bin AcmeTool"),
        "{linux}"
    );
    // Each step once, even where both products' plans have it.
    let lines: Vec<&str> = linux.lines().collect();
    let unique: BTreeSet<&str> = lines.iter().copied().collect();
    assert_eq!(lines.len(), unique.len(), "{linux}");
    assert!(plan("x86_64-pc-windows-msvc").contains("--bin AcmeTool"));
    let out = prepare("Tool");
    assert!(!out.status.success());
    assert!(said(&out).contains("isn't a product id"), "{}", said(&out));
    // Two selected products building one binary differently: refused,
    // though the products aren't selected together otherwise.
    let clashing = format!(
        "{}\n[product.other]\ndisplay-name = \"Acme Other\"\ndescription = \"Another.\"\n\
         launcher = \"crates/other\"\nexecutable = \"AcmeTool\"\ncore = \"acme_core\"\nkind = \"tool\"\n\
         outputs = [\"tar\"]\nupdates.default = \"off\"\n",
        std::fs::read_to_string(dir.path().join("seaworthy.toml")).unwrap()
    );
    std::fs::write(dir.path().join("seaworthy.toml"), clashing).unwrap();
    let out = prepare("tool");
    assert!(out.status.success(), "{}", said(&out));
    let out = prepare("console,other");
    assert!(!out.status.success());
    assert!(
        said(&out).contains("the selected products build base --bin AcmeTool differently"),
        "{}",
        said(&out)
    );
    let out = prepare("missing");
    assert!(!out.status.success());
    assert!(said(&out).contains("missing"), "{}", said(&out));
}

/// The Windows build adds the caller's extra rustflags as the Linux step
/// does: after the plan's (static C runtime included), the cores' on the
/// cores alone, `{workspace}` absolute (a path with a space stays one
/// argument), and the same refusals.
#[test]
fn the_windows_build_adds_the_caller_s_rustflags_after_the_plan_s() {
    let have_pwsh = pwsh()
        .args(["-NoProfile", "-Command", "exit 0"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !have_pwsh {
        eprintln!(
            "SKIPPED: pwsh is not installed (Windows PowerShell 5.1 runs this script on the runner)"
        );
        return;
    }
    let triple = "x86_64-pc-windows-msvc";
    let top = tempfile::tempdir().unwrap();
    // A workspace whose path holds a space.
    let dir = top.path().join("acme product");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("seaworthy.toml"), EXTRA_FLAGS_PRODUCT).unwrap();
    std::fs::write(dir.join("Cargo.toml"), "[workspace]\n").unwrap();
    std::fs::create_dir_all(dir.join("seaworthy")).unwrap();
    let plan = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
        .current_dir(&dir)
        .args(["build-plan", "--triple", triple])
        .output()
        .unwrap();
    assert!(plan.status.success(), "{}", said(&plan));
    std::fs::write(
        dir.join(format!("seaworthy/plan-{triple}.tsv")),
        &plan.stdout,
    )
    .unwrap();
    let bin = dir.join("stub-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = dir.join("log");
    std::fs::create_dir_all(&log).unwrap();
    script_at(&bin.join("cargo"), &windows_cargo_stub(&log));
    let script = repo_root().join("scripts/ci/seaworthy-build.ps1");
    let run = |env: &[(&str, &str)]| {
        for entry in std::fs::read_dir(&log).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                std::fs::remove_file(path).unwrap();
            }
        }
        let _ = std::fs::remove_dir_all(dir.join("seaworthy/target"));
        let mut command = pwsh();
        command
            .current_dir(&dir)
            .args(["-NoProfile", "-NonInteractive", "-File"])
            .arg(&script)
            .env("PATH", path_with(&bin))
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_BUILD_RUSTFLAGS")
            .env_remove("SEAWORTHY_RUSTFLAGS")
            .env_remove("SEAWORTHY_CORE_RUSTFLAGS");
        for (key, value) in env {
            command.env(key, value);
        }
        command.output().unwrap()
    };
    let out = run(&[
        ("SEAWORTHY_RUSTFLAGS", "--cfg every_build"),
        (
            "SEAWORTHY_CORE_RUSTFLAGS",
            "-Cprofile-use={workspace}/pgo/{triple}-{cpu}.profdata",
        ),
    ]);
    assert!(out.status.success(), "{}", said(&out));
    let flags = rustflags_by_target_dir(&log, triple);
    assert_eq!(
        flags["base"],
        "['-C','target-feature=+crt-static','-C','link-arg=/DEPENDENTLOADFLAG:0xA00','--cfg','every_build']"
    );
    let workspace = dir.canonicalize().unwrap();
    for cpu in ["x86-64-v3", "x86-64-v2"] {
        assert_eq!(
            flags[cpu],
            format!(
                "['-C','target-cpu={cpu}','-C','target-feature=+crt-static','--cfg','every_build',\
                 '-Cprofile-use={}/pgo/{triple}-{cpu}.profdata']",
                workspace.display()
            )
        );
    }
    for (variable, value, why) in [
        (
            "SEAWORTHY_CORE_RUSTFLAGS",
            "-Ctarget-cpu=native",
            "may not choose the CPU or its features",
        ),
        (
            "SEAWORTHY_RUSTFLAGS",
            "--cfg=feature='x'",
            "may not hold a quote",
        ),
        (
            "SEAWORTHY_CORE_RUSTFLAGS",
            "-Cprofile-use={workspce}/a",
            "unknown placeholder {workspce}",
        ),
    ] {
        let out = run(&[(variable, value)]);
        assert!(!out.status.success(), "{value}: {}", said(&out));
        assert!(said(&out).contains(why), "{value}: {}", said(&out));
    }
}

// ---------------------------------------------------------------------------
// The MSI jobs

/// No-op stand-ins for the tools a step checks for, first on `PATH`.
fn stub_tools(dir: &Path, tools: &[&str]) -> String {
    let stubs = dir.join("stubs");
    std::fs::create_dir_all(&stubs).unwrap();
    for tool in tools {
        script_at(&stubs.join(tool), "#!/usr/bin/env bash\nexit 0\n");
    }
    path_with(&stubs)
}

#[test]
fn the_adopt_step_adopts_each_msi_into_a_copy_the_repo_step_publishes() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let log = dir.join("calls.log");
    // A stand-in seaworthy, as a job builds it for itself (SEAWORTHY_TOOL_BIN).
    let bin = dir.join("stub-tool");
    std::fs::create_dir_all(&bin).unwrap();
    script_at(
        &bin.join("seaworthy"),
        &format!(
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> {}\n",
            log.display()
        ),
    );
    let path = stub_tools(
        dir,
        &[
            "msiextract",
            "msiinfo",
            "dpkg-scanpackages",
            "dpkg-deb",
            "createrepo_c",
            "repo-add",
            "bsdtar",
            "rpmkeys",
            "gpg",
        ],
    );
    // The package job's output: one product with a .wxs, one without.
    common::write(dir, "seaworthy/dist/viewer/packages.json", b"{}");
    common::write(
        dir,
        "seaworthy/dist/viewer/packages/acme-viewer-1-1-windows-x86_64.wxs",
        b"<Wix/>",
    );
    common::write(dir, "seaworthy/dist/tool/packages.json", b"{}");
    common::write(
        dir,
        "seaworthy/dist/tool/packages/acme-tool-1-1-windows-x86_64.zip",
        b"zip",
    );
    std::fs::write(dir.join("seaworthy.toml"), "").unwrap();
    let calls = || std::fs::read_to_string(&log).unwrap_or_default();
    let stub_tool = bin.join("seaworthy");
    let env = [
        ("PATH", path.as_str()),
        ("SOURCE_DATE_EPOCH", "1700000000"),
        ("SEAWORTHY_TOOL_BIN", stub_tool.to_str().unwrap()),
    ];

    // The MSI job left none for the product with a .wxs, or two.
    let out = step(dir, &["adopt-msi"], &env);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("product viewer has a .wxs but the MSI job left 0 MSI(s)"),
        "{}",
        said(&out)
    );
    common::write(
        dir,
        "seaworthy/msi/viewer/acme-viewer-1-1-windows-x86_64.msi",
        b"msi",
    );
    common::write(dir, "seaworthy/msi/viewer/stray.msi", b"msi");
    let out = step(dir, &["adopt-msi"], &env);
    assert!(said(&out).contains("left 2 MSI(s)"), "{}", said(&out));
    std::fs::remove_file(dir.join("seaworthy/msi/viewer/stray.msi")).unwrap();
    assert!(calls().is_empty(), "nothing adopted: {}", calls());

    // Each MSI adopted into a copy of everything, unsigned outside a release.
    let out = step(dir, &["adopt-msi"], &env);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        calls().trim(),
        "adopt-msi --config seaworthy.toml --out seaworthy/adopted --product viewer --msi seaworthy/msi/viewer/acme-viewer-1-1-windows-x86_64.msi"
    );
    assert!(dir.join("seaworthy/adopted/tool/packages.json").is_file());
    assert!(said(&out).contains("1 MSI(s) adopted"), "{}", said(&out));

    // A release signs with the package job's signing.toml.
    std::fs::write(
        dir.join("signing.toml"),
        "[openpgp]\nhome = \"g\"\nkey = \"k\"\n",
    )
    .unwrap();
    std::fs::remove_file(&log).unwrap();
    let release = [
        ("PATH", path.as_str()),
        ("SOURCE_DATE_EPOCH", "1700000000"),
        ("SEAWORTHY_RELEASE", "1"),
        ("CI_PIPELINE_IID", "9"),
        ("SEAWORTHY_TOOL_BIN", stub_tool.to_str().unwrap()),
        TRUSTED_CHECKOUT,
    ];
    let out = step(dir, &["adopt-msi"], &release);
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        calls().trim().ends_with("--signing signing.toml"),
        "{}",
        calls()
    );

    // The repo step publishes the adopted copy, else the package job's.
    let url = serve(404, Vec::new());
    std::fs::write(
        dir.join("publish.toml"),
        format!("endpoint = \"http://127.0.0.1:9\"\nbucket = \"b\"\nregion = \"auto\"\nprefix = \"packages\"\npublic-url = \"{url}\"\n"),
    )
    .unwrap();
    std::fs::remove_file(&log).unwrap();
    let out = step(dir, &["repo"], &release);
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        calls().contains(
            "repo --config seaworthy.toml --packages seaworthy/adopted --out seaworthy/repo"
        ),
        "{}",
        calls()
    );
    std::fs::remove_dir_all(dir.join("seaworthy/adopted")).unwrap();
    std::fs::remove_file(&log).unwrap();
    let url = serve(404, Vec::new());
    std::fs::write(
        dir.join("publish.toml"),
        format!("endpoint = \"http://127.0.0.1:9\"\nbucket = \"b\"\nregion = \"auto\"\nprefix = \"packages\"\npublic-url = \"{url}\"\n"),
    )
    .unwrap();
    let out = step(dir, &["repo"], &release);
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        calls().contains("--packages seaworthy/dist "),
        "{}",
        calls()
    );
    // The last plan is read bounded (64 MiB, as publish reads plans back),
    // and from https or a loopback address only.
    std::fs::remove_file(&log).unwrap();
    for (url, refusal) in [
        (
            serve_claiming(64 * 1024 * 1024 + 1),
            "/publish-plan.json is larger than 67108864 bytes",
        ),
        (
            "http://files.example.com/packages".to_owned(),
            "https only (http only to a loopback address)",
        ),
        (
            "http://127.0.0.1.example.com/packages".to_owned(),
            "https only (http only to a loopback address)",
        ),
    ] {
        std::fs::write(
            dir.join("publish.toml"),
            format!("endpoint = \"http://127.0.0.1:9\"\nbucket = \"b\"\nregion = \"auto\"\nprefix = \"packages\"\npublic-url = \"{url}\"\n"),
        )
        .unwrap();
        let out = step(dir, &["repo"], &release);
        assert!(!out.status.success(), "{url}");
        assert!(said(&out).contains(refusal), "{url}: {}", said(&out));
    }
    assert!(calls().is_empty(), "repo never ran: {}", calls());
}

/// A dev build (the template's dev-sign-if): package and adopt-msi
/// sign with signing.toml's [authenticode] alone (`--authenticode-only`),
/// under the dev secrets prefix and on a protected ref only; a release
/// overrides it; and a publish dry run passes `--dry-run`.
#[test]
fn a_dev_build_signs_with_authenticode_alone_on_a_protected_ref() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let log = dir.join("calls.log");
    // A stand-in seaworthy, as a job builds it for itself (SEAWORTHY_TOOL_BIN).
    let bin = dir.join("stub-tool");
    std::fs::create_dir_all(&bin).unwrap();
    script_at(
        &bin.join("seaworthy"),
        &format!(
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> {}\n",
            log.display()
        ),
    );
    let stub_tool = bin.join("seaworthy");
    // [authenticode] needs osslsigncode: a stand-in, as the tools step
    // builds it before any secret is around (SEAWORTHY_OSSLSIGNCODE).
    script_at(&dir.join("osslsigncode"), "#!/bin/sh\nexit 0\n");
    let osslsigncode = dir.join("osslsigncode");
    // Each secrets prefix notes which one ran.
    let prefix = |name: &str| {
        let path = dir.join(name);
        script_at(
            &path,
            &format!("#!/bin/sh\necho {name} >> {}\nexec \"$@\"\n", log.display()),
        );
        path.to_str().unwrap().to_owned()
    };
    let (release_secrets, dev_secrets) = (prefix("release-secrets"), prefix("dev-secrets"));
    let path = stub_tools(
        dir,
        &[
            "dpkg-deb",
            "rpmsign",
            "gpg",
            "bsdtar",
            "curl",
            "desktop-file-validate",
            "cmake",
            "msiextract",
            "msiinfo",
            "nfpm",
        ],
    );
    std::fs::write(dir.join("seaworthy.toml"), "").unwrap();
    std::fs::write(
        dir.join("signing.toml"),
        "[authenticode]\ncommand = [\"sign\"]\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.join("seaworthy/artifacts")).unwrap();
    // The package job's output, which the package step clears first.
    let packaged = || {
        common::write(dir, "seaworthy/dist/viewer/packages.json", b"{}");
        common::write(
            dir,
            "seaworthy/dist/viewer/packages/acme-viewer-1-1-windows-x86_64.wxs",
            b"<Wix/>",
        );
    };
    packaged();
    common::write(
        dir,
        "seaworthy/msi/viewer/acme-viewer-1-1-windows-x86_64.msi",
        b"msi",
    );
    let nfpm = dir.join("stubs/nfpm");
    let calls = || std::fs::read_to_string(&log).unwrap_or_default();
    let env = [
        ("PATH", path.as_str()),
        ("NFPM", nfpm.to_str().unwrap()),
        ("SOURCE_DATE_EPOCH", "1700000000"),
        ("CI_PIPELINE_IID", "21"),
        ("CI_COMMIT_SHORT_SHA", "0a1b2c3"),
        ("SEAWORTHY_DEV_SIGN", "1"),
        ("SEAWORTHY_SECRETS", release_secrets.as_str()),
        ("SEAWORTHY_DEV_SECRETS", dev_secrets.as_str()),
        ("GITLAB_CI", "true"),
        ("SEAWORTHY_TOOL_BIN", stub_tool.to_str().unwrap()),
        ("SEAWORTHY_OSSLSIGNCODE", osslsigncode.to_str().unwrap()),
        TRUSTED_CHECKOUT,
    ];

    // In GitLab, a dev build on an unprotected ref is refused, before any
    // signer runs.
    for command in ["package", "adopt-msi"] {
        let mut unprotected = env.to_vec();
        unprotected.push(("CI_COMMIT_REF_PROTECTED", "false"));
        let out = step(dir, &[command], &unprotected);
        assert!(!out.status.success(), "{command}");
        assert!(
            said(&out).contains("a dev build runs on a protected ref only"),
            "{command}: {}",
            said(&out)
        );
    }
    assert!(calls().is_empty(), "{}", calls());

    // On a protected ref: Authenticode alone, under the dev prefix.
    let mut protected = env.to_vec();
    protected.push(("CI_COMMIT_REF_PROTECTED", "true"));
    let out = step(dir, &["package"], &protected);
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        said(&out).contains("a dev build: Authenticode-signed Windows binaries"),
        "{}",
        said(&out)
    );
    let lines: Vec<String> = calls().lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0], "dev-secrets");
    assert!(
        lines[1].starts_with("package --config seaworthy.toml"),
        "{lines:?}"
    );
    assert!(
        lines[1].ends_with(
            "--build 0a1b2c3 --platforms linux,windows --signing signing.toml --authenticode-only"
        ),
        "{lines:?}"
    );
    std::fs::remove_file(&log).unwrap();
    packaged();
    let out = step(dir, &["adopt-msi"], &protected);
    assert!(out.status.success(), "{}", said(&out));
    assert!(said(&out).contains("a dev build: the MSIs are Authenticode-signed"));
    assert_eq!(
        calls(),
        "dev-secrets\nadopt-msi --config seaworthy.toml --out seaworthy/adopted --product viewer --msi seaworthy/msi/viewer/acme-viewer-1-1-windows-x86_64.msi --signing signing.toml --authenticode-only\n"
    );

    // A release overrides it: fully signed, under the release's prefix.
    std::fs::remove_file(&log).unwrap();
    let mut release = protected.clone();
    release.extend([("SEAWORTHY_RELEASE", "1"), ("CI_COMMIT_TAG", "v2.1.0")]);
    let out = step(dir, &["adopt-msi"], &release);
    assert!(out.status.success(), "{}", said(&out));
    assert!(calls().starts_with("release-secrets\n"), "{}", calls());
    assert!(
        calls().trim_end().ends_with("--signing signing.toml"),
        "{}",
        calls()
    );

    // Neither: unsigned, under no prefix.
    std::fs::remove_file(&log).unwrap();
    let mut neither = protected.clone();
    neither.retain(|(k, _)| *k != "SEAWORTHY_DEV_SIGN");
    let out = step(dir, &["adopt-msi"], &neither);
    assert!(out.status.success(), "{}", said(&out));
    assert!(said(&out).contains("not a release: the MSIs stay unsigned"));
    assert!(calls().starts_with("adopt-msi "), "{}", calls());
    assert!(!calls().contains("--signing"), "{}", calls());

    // A publish dry run checks everything and uploads nothing.
    std::fs::remove_file(&log).unwrap();
    common::write(dir, "seaworthy/repo/publish-plan.json", b"{}");
    std::fs::write(dir.join("publish.toml"), "").unwrap();
    let mut dry = release.clone();
    dry.push(("SEAWORTHY_PUBLISH_DRY_RUN", "1"));
    let out = step(dir, &["publish"], &dry);
    assert!(out.status.success(), "{}", said(&out));
    assert!(said(&out).contains("a dry run (SEAWORTHY_PUBLISH_DRY_RUN=1)"));
    assert_eq!(
        calls(),
        "release-secrets\npublish --repo seaworthy/repo --target publish.toml --dry-run\n"
    );
    std::fs::remove_file(&log).unwrap();
    let out = step(dir, &["publish"], &release);
    assert!(out.status.success(), "{}", said(&out));
    assert!(calls().ends_with("--target publish.toml\n"), "{}", calls());
}

#[test]
fn the_msi_job_builds_and_validates_each_wxs_with_the_pinned_wix() {
    // pwsh stands in for Windows PowerShell (not a package tool: CI's
    // image has none, so this skips there as the other script tests do).
    let have_pwsh = pwsh()
        .args(["-NoProfile", "-Command", "exit 0"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !have_pwsh {
        eprintln!(
            "SKIPPED: pwsh is not installed (Windows PowerShell 5.1 runs this script on the runner)"
        );
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let log = dir.join("wix.log");
    // WiX v5.0.2 where its MSI installs it, as a recording stand-in.
    let program_files = dir.join("ProgramFiles");
    let wix_bin = program_files.join("WiX Toolset v5.0").join("bin");
    std::fs::create_dir_all(&wix_bin).unwrap();
    let wix = |validate_exit: u8| {
        script_at(
            &wix_bin.join("wix.exe"),
            &format!(
                "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> {log}\ncase \"$1\" in\n  --version) echo 5.0.2+aa65968c ;;\n  build) while [ $# -gt 0 ]; do [ \"$1\" = -o ] && : > \"$2\"; shift; done ;;\n  msi) exit {validate_exit} ;;\nesac\n",
                log = log.display()
            ),
        );
    };
    wix(0);
    common::write(dir, "seaworthy/dist/viewer/packages.json", b"{}");
    common::write(
        dir,
        "seaworthy/dist/viewer/packages/acme-viewer-1-1-windows-x86_64.wxs",
        b"<Wix/>",
    );
    common::write(
        dir,
        "seaworthy/dist/viewer/x86_64-pc-windows-msvc/tree/Acme/Viewer/x.exe",
        b"x",
    );
    common::write(dir, "seaworthy/dist/tool/packages.json", b"{}");
    let run = || {
        pwsh()
            .current_dir(dir)
            .env("ProgramFiles", &program_files)
            .env_remove("ProgramFiles(x86)")
            .env("SEAWORTHY_WORK", dir.join("seaworthy"))
            .args(["-NoProfile", "-File"])
            .arg(repo_root().join("scripts/ci/seaworthy-msi.ps1"))
            .output()
            .unwrap()
    };
    let out = run();
    assert!(out.status.success(), "{}", said(&out));
    let msi = dir.join("seaworthy/msi/viewer/acme-viewer-1-1-windows-x86_64.msi");
    assert!(msi.is_file(), "{}", said(&out));
    let calls = std::fs::read_to_string(&log).unwrap();
    let tree = dir.join("seaworthy/dist/viewer/x86_64-pc-windows-msvc/tree");
    assert!(
        calls.contains(&format!(
            "build -arch x64 -bindpath tree={} -o {}",
            tree.display(),
            msi.display()
        )),
        "{calls}"
    );
    assert!(
        calls.contains(&format!("msi validate {}", msi.display())),
        "{calls}"
    );
    assert!(
        said(&out).contains("1 MSI(s) built and validated"),
        "{}",
        said(&out)
    );
    // An ICE error fails the job (pwsh wraps and colours the error: compare
    // without its escapes, line breaks and margins).
    wix(1);
    let out = run();
    assert!(!out.status.success());
    let squeezed: String = said(&out)
        .split('\u{1b}')
        .map(|part| {
            part.find('m')
                .filter(|&at| at < 8 && part.starts_with('['))
                .map_or(part, |at| &part[at + 1..])
        })
        .collect::<String>()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '|')
        .collect();
    assert!(
        squeezed.contains("WindowsInstaller'svalidation(ICE)refusedviewer'sMSI"),
        "{}",
        said(&out)
    );
}

#[test]
fn azure_sign_keeps_the_secret_and_the_token_off_every_command_line() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    // curl: Microsoft Entra's token answer (the secret read from stdin), or
    // a jsign download that isn't jsign.
    script_at(
        &bin.join("curl"),
        &format!(
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> {dir}/curl.args\nif [[ \"$*\" == *audience=* ]]; then cat > {dir}/oidc.stdin; echo '{{\"count\":1,\"value\":\"aGVhZGVy.cGF5bG9hZA.c2ln\"}}'; elif [[ \"$*\" == *login.microsoftonline.com* ]]; then cat > {dir}/curl.stdin; echo '{{\"token_type\":\"Bearer\",\"access_token\":\"tok-123\"}}'; else printf 'download secret=%s\\n' \"${{AZURE_CLIENT_SECRET:-unset}}\" >> {dir}/curl.env; while [ $# -gt 0 ]; do [ \"$1\" = -o ] && echo 'not jsign' > \"$2\"; shift; done; fi\n",
            dir = dir.display()
        ),
    );
    // java: jsign, failing as many times as asked.
    script_at(
        &bin.join("java"),
        &format!(
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> {dir}/java.args\nprintf 'token=%s secret=%s\\n' \"$SEAWORTHY_AZURE_ACCESS_TOKEN\" \"${{AZURE_CLIENT_SECRET:-unset}}\" >> {dir}/java.env\nn=$(cat {dir}/fail 2>/dev/null || echo 0)\nif [ \"$n\" -gt 0 ]; then echo $((n - 1)) > {dir}/fail; exit 1; fi\n",
            dir = dir.display()
        ),
    );
    let file = dir.join("app.exe");
    std::fs::write(&file, b"MZ").unwrap();
    let tools = dir.join("tools");
    let sign = |extra: &[(&str, &str)], args: &[&str]| {
        let mut command = Command::new("bash");
        command
            .arg(repo_root().join("scripts/ci/azure-sign.sh"))
            .args(args)
            .env("PATH", path_with(&bin))
            .env("SEAWORTHY_AZURE_SIGN_TOOLS", &tools)
            .env("SEAWORTHY_AZURE_SIGN_RETRY_SECONDS", "0")
            .env("AZURE_TENANT_ID", "11111111-2222-4333-8444-555555555555")
            .env("AZURE_CLIENT_ID", "66666666-7777-4888-9999-000000000000")
            .env("AZURE_CLIENT_SECRET", "s3cr3t-value")
            .env_remove("AZURE_FEDERATED_TOKEN_FILE")
            .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL")
            .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
        for (key, value) in extra {
            command.env(key, value);
        }
        command.output().unwrap()
    };
    let good = [
        "--endpoint",
        "eus.codesigning.azure.net",
        "--account",
        "Acme-Signing",
        "--profile",
        "Acme-Release",
        file.to_str().unwrap(),
    ];
    // The jar must be the pinned one: a download with other bytes refused.
    let out = sign(&[], &good);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("the download's SHA-256 isn't the pinned one"),
        "{}",
        said(&out)
    );
    assert!(
        !tools.join("jsign-7.5.jar").exists(),
        "a refused download isn't kept"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("curl.env")).unwrap(),
        "download secret=unset\n",
        "the download runs without the client secret"
    );
    // With the pinned jar in place (a sha256sum stand-in accepting it).
    std::fs::create_dir_all(&tools).unwrap();
    std::fs::write(tools.join("jsign-7.5.jar"), b"jar").unwrap();
    script_at(&bin.join("sha256sum"), "#!/usr/bin/env bash\nexit 0\n");
    script_at(
        &bin.join("sleep"),
        &format!(
            "#!/usr/bin/env bash\necho \"$1\" >> {}/sleep.args\n",
            dir.display()
        ),
    );
    std::fs::write(dir.join("fail"), "2").unwrap();
    let out = sign(&[("SEAWORTHY_AZURE_SIGN_RETRY_SECONDS", "3")], &good);
    assert!(out.status.success(), "{}", said(&out));
    let java = std::fs::read_to_string(dir.join("java.args")).unwrap();
    assert_eq!(java.lines().count(), 3, "two retries: {java}");
    assert_eq!(
        std::fs::read_to_string(dir.join("sleep.args")).unwrap(),
        "3\n6\n",
        "the pause doubles"
    );
    assert_eq!(
        java.lines().last().unwrap(),
        format!(
            "-jar {}/jsign-7.5.jar --storetype TRUSTEDSIGNING --keystore eus.codesigning.azure.net --storepass env:SEAWORTHY_AZURE_ACCESS_TOKEN --alias Acme-Signing/Acme-Release --alg SHA-256 --tsaurl http://timestamp.acs.microsoft.com --tsmode RFC3161 --replace {}",
            tools.display(),
            file.display()
        )
    );
    // The token reached jsign through its environment, the secret through
    // curl's standard input; neither through any command line, and jsign
    // never saw the secret.
    let env = std::fs::read_to_string(dir.join("java.env")).unwrap();
    assert!(
        env.lines().all(|l| l == "token=tok-123 secret=unset"),
        "{env}"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("curl.stdin")).unwrap(),
        "s3cr3t-value"
    );
    let curl = std::fs::read_to_string(dir.join("curl.args")).unwrap();
    for text in [&curl, &java] {
        assert!(
            !text.contains("s3cr3t-value") && !text.contains("tok-123"),
            "{text}"
        );
    }
    // No stored secret: GitHub Actions' OIDC, a fresh token for Entra's
    // audience per signature, its request token in curl's config on stdin
    // and the token as the client assertion, neither on a command line.
    std::fs::remove_file(dir.join("curl.args")).unwrap();
    let out = sign(
        &[
            ("AZURE_CLIENT_SECRET", ""),
            (
                "ACTIONS_ID_TOKEN_REQUEST_URL",
                "https://token.example/oidc?api-version=2.0",
            ),
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "req-tok-456"),
        ],
        &good,
    );
    assert!(out.status.success(), "{}", said(&out));
    let curl = std::fs::read_to_string(dir.join("curl.args")).unwrap();
    assert!(
        curl.lines().any(|l| l.contains("--config -")
            && l.ends_with(" https://token.example/oidc?api-version=2.0&audience=api%3A%2F%2FAzureADTokenExchange")),
        "{curl}"
    );
    assert!(
        curl.contains(
            "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        ) && curl.contains("client_assertion@-")
            && !curl.contains("client_secret"),
        "{curl}"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("oidc.stdin")).unwrap(),
        "header = \"Authorization: bearer req-tok-456\"\n"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("curl.stdin")).unwrap(),
        "aGVhZGVy.cGF5bG9hZA.c2ln"
    );
    assert!(
        !curl.contains("req-tok-456") && !curl.contains("aGVhZGVy"),
        "{curl}"
    );
    // A federated token in a file (workload identity federation).
    let token = dir.join("federated.jwt");
    std::fs::write(&token, "ZmlsZQ.dG9rZW4.c2ln\n").unwrap();
    let out = sign(
        &[
            ("AZURE_CLIENT_SECRET", ""),
            ("AZURE_FEDERATED_TOKEN_FILE", token.to_str().unwrap()),
        ],
        &good,
    );
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        std::fs::read_to_string(dir.join("curl.stdin")).unwrap(),
        "ZmlsZQ.dG9rZW4.c2ln"
    );
    std::fs::write(&token, "not a token").unwrap();
    let out = sign(
        &[
            ("AZURE_CLIENT_SECRET", ""),
            ("AZURE_FEDERATED_TOKEN_FILE", token.to_str().unwrap()),
        ],
        &good,
    );
    assert!(!out.status.success());
    assert!(said(&out).contains("isn't a JWT"), "{}", said(&out));
    // Three failures in a row fail the signing.
    std::fs::write(dir.join("fail"), "3").unwrap();
    let out = sign(&[], &good);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("jsign failed to sign"),
        "{}",
        said(&out)
    );
    // What it refuses before anything runs.
    for (args, env, mentions) in [
        (
            vec![
                "--endpoint",
                "evil.example.com",
                "--account",
                "A-1",
                "--profile",
                "P-1",
            ],
            vec![],
            "--endpoint must be a Trusted Signing endpoint host",
        ),
        (
            vec![
                "--endpoint",
                "eus.codesigning.azure.net",
                "--account",
                "a/b",
                "--profile",
                "P-1",
            ],
            vec![],
            "--account must be a Trusted Signing account name",
        ),
        (
            vec![
                "--endpoint",
                "eus.codesigning.azure.net",
                "--account",
                "A-1",
                "--profile",
                "P-1",
            ],
            vec![("AZURE_CLIENT_SECRET", "")],
            "AZURE_CLIENT_SECRET is unset",
        ),
        (
            vec![
                "--endpoint",
                "eus.codesigning.azure.net",
                "--account",
                "A-1",
                "--profile",
                "P-1",
            ],
            vec![("AZURE_TENANT_ID", "not-a-guid")],
            "AZURE_TENANT_ID must be the tenant's GUID",
        ),
    ] {
        let mut args = args;
        args.push(file.to_str().unwrap());
        let out = sign(&env, &args);
        assert!(!out.status.success());
        assert!(said(&out).contains(mentions), "{mentions}: {}", said(&out));
    }
}

/// Credentials in the job's environment — the GitHub workflow's store and
/// signing secrets, the runner's OIDC request variables, cloud
/// credentials, GitLab's job token, an id token under any name, the
/// key-env variables signing.toml names, SEAWORTHY_HELD_ENV's — reach the
/// seaworthy call alone: git (and every other program the step runs) sees
/// none of them.
#[test]
fn credentials_reach_the_seaworthy_call_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let seen_git = dir.join("git.env");
    let seen_tool = dir.join("tool.env");
    let path = stub_tools(
        dir,
        &[
            "dpkg-deb",
            "rpmsign",
            "gpg",
            "bsdtar",
            "curl",
            "desktop-file-validate",
            "nfpm",
        ],
    );
    script_at(
        &dir.join("stubs/git"),
        &format!(
            "#!/usr/bin/env bash\nenv > {}\n[ \"$1\" = log ] && echo 1700000000\nexit 0\n",
            seen_git.display()
        ),
    );
    let tool = dir.join("stub-tool/seaworthy");
    std::fs::create_dir_all(tool.parent().unwrap()).unwrap();
    script_at(
        &tool,
        &format!("#!/usr/bin/env bash\nenv > {}\n", seen_tool.display()),
    );
    std::fs::write(dir.join("seaworthy.toml"), "").unwrap();
    std::fs::write(
        dir.join("signing.toml"),
        "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey-env = \"ACME_RELEASE_KEY_HEX\"\n\n[openpgp]\nsecret-key-env = 'ACME_REPO_KEY_ASC'\nkey = \"0123456789ABCDEF0123456789ABCDEF01234567\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.join("seaworthy/artifacts")).unwrap();
    let nfpm = dir.join("stubs/nfpm");
    let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwcm9qZWN0In0.c2lnbmF0dXJl";
    let credentials = [
        ("SEAWORTHY_S3_SECRET_ACCESS_KEY", "s3-secret"),
        ("SEAWORTHY_RELEASE_MANIFEST_KEY", "manifest-key"),
        ("SEAWORTHY_GH_AUTHENTICODE_PASSWORD", "pfx-password"),
        ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "oidc-request"),
        ("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example.com"),
        ("AZURE_CLIENT_SECRET", "azure-secret"),
        ("AWS_SECRET_ACCESS_KEY", "aws-secret"),
        ("CI_JOB_TOKEN", "job-token"),
        ("SECRET_STORE_ID_TOKEN", jwt),
        ("ACME_RELEASE_KEY_HEX", "acme-manifest"),
        ("ACME_REPO_KEY_ASC", "acme-openpgp"),
        ("ACME_VAULT_TOKEN", "acme-vault"),
    ];
    let mut env = vec![
        ("PATH", path.as_str()),
        ("NFPM", nfpm.to_str().unwrap()),
        ("CI_PIPELINE_IID", "3"),
        ("CI_COMMIT_SHORT_SHA", "0a1b2c3"),
        ("SEAWORTHY_TOOL_BIN", tool.to_str().unwrap()),
        ("SEAWORTHY_HELD_ENV", "ACME_VAULT_TOKEN"),
        ("ACME_PLAIN", "not-a-secret"),
    ];
    env.extend(credentials);
    let out = step(dir, &["package"], &env);
    assert!(out.status.success(), "{}", said(&out));
    let git = std::fs::read_to_string(&seen_git).unwrap();
    let tool = std::fs::read_to_string(&seen_tool).unwrap();
    for (name, value) in credentials {
        assert!(!git.contains(value), "git was given {name}:\n{git}");
        assert!(
            tool.contains(&format!("{name}={value}\n")),
            "seaworthy wasn't given {name}:\n{tool}"
        );
    }
    assert!(git.contains("ACME_PLAIN=not-a-secret"), "{git}");
    assert!(!said(&out).contains("s3-secret"), "never printed");
}
