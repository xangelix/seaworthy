//! seaworthy's reusable GitHub workflow (`.github/workflows/dist.yml`) and
//! its glue (`scripts/ci/github.sh`, `.github/actions/setup-seaworthy`):
//! the workflow read as YAML and held to the repository's Actions baseline
//! (every job its own permissions but the two that take the calling job's
//! grant for Azure's OIDC, every action pinned by
//! commit, no credentials kept, no expression in a script, harden-runner on
//! Linux, no organization default, every script step one the scripts
//! have), and github.sh carried out: the build matrix from real build
//! plans, the caller's build environment, the generated `signing.toml`
//! (loaded by seaworthy as a release would), and the packages artifact
//! checked against its listings.
//!
//! A missing tool (jq, openssl) is skipped loudly, unless
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
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use yaml_rust2::{Yaml, YamlLoader};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn yaml(path: &str) -> (String, Yaml) {
    let text = std::fs::read_to_string(repo_root().join(path)).unwrap();
    let doc = YamlLoader::load_from_str(&text).unwrap().remove(0);
    (text, doc)
}

fn key<'a>(node: &'a Yaml, name: &str) -> &'a Yaml {
    &node[name]
}

fn string(node: &Yaml) -> Option<&str> {
    node.as_str()
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Whether `uses` is a full-SHA pin (`owner/repo[/path]@<40 hex>`).
fn pinned(uses: &str) -> bool {
    let Some((name, sha)) = uses.split_once('@') else {
        return false;
    };
    name.split('/').count() >= 2
        && sha.len() == 40
        && sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Every step of every job, with the job's id.
fn steps(workflow: &Yaml) -> Vec<(String, Yaml)> {
    let mut out = Vec::new();
    for (id, job) in workflow["jobs"].as_hash().unwrap() {
        for step in job["steps"].as_vec().unwrap() {
            out.push((id.as_str().unwrap().to_owned(), step.clone()));
        }
    }
    out
}

/// Every action pinned by commit with its version beside it (but the
/// workflow's own, from `./.seaworthy/`), no checkout keeping credentials,
/// no expression in a script.
fn steps_follow_the_baseline(text: &str, workflow: &Yaml) {
    for (job, step) in steps(workflow) {
        if let Some(uses) = string(&step["uses"]) {
            if !uses.starts_with("./.seaworthy/") {
                assert!(pinned(uses), "{job}: {uses} isn't pinned by commit");
                // The pinned version in a comment beside it.
                let line = text.lines().find(|l| l.contains(uses)).unwrap();
                assert!(line.contains(" # v"), "{job}: {line}");
            }
            if uses.starts_with("actions/checkout@") {
                assert_eq!(
                    step["with"]["persist-credentials"].as_bool(),
                    Some(false),
                    "{job}: a checkout keeps no credentials"
                );
            }
        }
        if let Some(run) = string(&step["run"]) {
            assert!(
                !run.contains("${{"),
                "{job}: an expression in a script (pass it through env):\n{run}"
            );
        }
    }
}

#[test]
fn the_reusable_workflow_follows_the_actions_baseline() {
    let (text, workflow) = yaml(".github/workflows/dist.yml");
    // A reusable workflow, and nothing else.
    let on = key(&workflow, "on").as_hash().unwrap();
    assert_eq!(on.len(), 1);
    assert!(on.contains_key(&Yaml::from_str("workflow_call")));
    // No default permissions: the two jobs that Authenticode-sign (package,
    // adopt-msi) declare none and take the calling job's grant, so only a
    // caller that signs through Azure grants id-token: write. Every other
    // job declares contents: read alone, and no job declares id-token.
    assert!(
        key(&workflow, "permissions").is_badvalue(),
        "a default would cap the signing jobs too"
    );
    let jobs = key(&workflow, "jobs").as_hash().unwrap();
    let mut inheriting = BTreeSet::new();
    for (id, job) in jobs {
        let id = id.as_str().unwrap();
        assert!(
            job["timeout-minutes"].as_i64().is_some(),
            "{id}: timeout-minutes"
        );
        match job["permissions"].as_hash() {
            None => {
                assert!(job["permissions"].is_badvalue(), "{id}: permissions");
                inheriting.insert(id.to_owned());
                // Its grant is checked before anything else runs.
                let steps = job["steps"].as_vec().unwrap();
                let grant = steps
                    .iter()
                    .position(|step| {
                        string(&step["run"])
                            == Some("bash .seaworthy/scripts/ci/github.sh oidc-grant")
                    })
                    .unwrap_or_else(|| panic!("{id}: the oidc-grant check"));
                let setup = steps
                    .iter()
                    .position(|step| {
                        string(&step["uses"])
                            == Some("./.seaworthy/.github/actions/setup-seaworthy")
                    })
                    .unwrap();
                assert!(grant < setup, "{id}: the grant is checked first");
                for name in [
                    "SEAWORTHY_GH_AZURE_ENDPOINT",
                    "SEAWORTHY_GH_AZURE_ACCOUNT",
                    "SEAWORTHY_GH_AZURE_PROFILE",
                    "AZURE_TENANT_ID",
                    "AZURE_CLIENT_ID",
                ] {
                    assert!(string(&steps[grant]["env"][name]).is_some(), "{id}: {name}");
                }
            }
            Some(permissions) => {
                assert_eq!(permissions.len(), 1, "{id}: {permissions:?}");
                assert_eq!(
                    string(&job["permissions"]["contents"]),
                    Some("read"),
                    "{id}"
                );
            }
        }
        // Linux jobs start with harden-runner (audit mode).
        if string(&job["runs-on"]) == Some("${{ inputs.linux-runner }}") {
            let first = &job["steps"][0];
            assert!(
                string(&first["uses"])
                    .is_some_and(|u| u.starts_with("step-security/harden-runner@")),
                "{id}: harden-runner first"
            );
            assert_eq!(
                string(&first["with"]["egress-policy"]),
                Some("audit"),
                "{id}"
            );
        }
    }
    assert_eq!(
        inheriting,
        BTreeSet::from(["adopt-msi".to_owned(), "package".to_owned()])
    );
    // The self-test calls it as an unsigned caller does: contents: read
    // alone.
    let (_, selftest) = yaml(".github/workflows/dist-selftest.yml");
    let grant = selftest["jobs"]["dist"]["permissions"].as_hash().unwrap();
    assert_eq!(grant.len(), 1);
    assert_eq!(
        string(&selftest["jobs"]["dist"]["permissions"]["contents"]),
        Some("read")
    );
    steps_follow_the_baseline(&text, &workflow);
    // The seaworthy checkout is the workflow's own commit.
    assert!(text.contains("repository: ${{ job.workflow_repository }}"));
    assert!(text.contains("ref: ${{ job.workflow_sha }}"));
    // The MSI jobs get the signed Windows tree and its layout.json, which
    // adopt-msi checks each MSI's payload against.
    for path in [
        "seaworthy-work/dist/*/x86_64-pc-windows-msvc/tree/",
        "seaworthy-work/dist/*/x86_64-pc-windows-msvc/layout.json",
    ] {
        assert!(text.contains(path), "{path}");
    }
    // A release's tool is compiled, never restored from a cache.
    assert!(
        text.contains("cache: ${{ (inputs.release || inputs.dev-sign) && 'false' || 'true' }}")
    );
}

/// delete-artifacts.yml: a reusable workflow alone, its one job capped at
/// `actions: write`, held to dist.yml's baseline (harden-runner first,
/// every action pinned, no credentials kept, no expression in a script) and
/// running `github.sh delete-artifacts` from seaworthy's checkout at the
/// workflow's own commit. The self-test calls it as a caller does, after
/// the job that downloads the packages.
#[test]
fn the_artifact_deletion_workflow_follows_the_actions_baseline() {
    let (text, workflow) = yaml(".github/workflows/delete-artifacts.yml");
    let on = key(&workflow, "on").as_hash().unwrap();
    assert_eq!(on.len(), 1);
    let inputs = workflow["on"]["workflow_call"]["inputs"].as_hash().unwrap();
    let defaults: Vec<(&str, &str)> = inputs
        .iter()
        .map(|(name, input)| {
            let name = name.as_str().unwrap();
            assert!(string(&input["description"]).is_some(), "{name}: described");
            (name, string(&input["default"]).unwrap())
        })
        .collect();
    assert_eq!(
        defaults,
        [("pattern", "*"), ("linux-runner", "ubuntu-24.04")]
    );
    assert!(key(&workflow, "permissions").is_badvalue());
    assert_eq!(key(&workflow, "jobs").as_hash().unwrap().len(), 1);
    let job = &workflow["jobs"]["delete"];
    assert!(job["timeout-minutes"].as_i64().is_some());
    assert_eq!(job["permissions"].as_hash().unwrap().len(), 1);
    assert_eq!(string(&job["permissions"]["actions"]), Some("write"));
    assert_eq!(string(&job["runs-on"]), Some("${{ inputs.linux-runner }}"));
    let job_steps = job["steps"].as_vec().unwrap();
    assert!(
        string(&job_steps[0]["uses"])
            .is_some_and(|u| u.starts_with("step-security/harden-runner@")),
        "harden-runner first"
    );
    assert_eq!(
        string(&job_steps[0]["with"]["egress-policy"]),
        Some("audit")
    );
    steps_follow_the_baseline(&text, &workflow);
    assert!(text.contains("repository: ${{ job.workflow_repository }}"));
    assert!(text.contains("ref: ${{ job.workflow_sha }}"));
    let runs: Vec<&str> = job_steps.iter().filter_map(|s| string(&s["run"])).collect();
    assert_eq!(
        runs,
        ["bash .seaworthy/scripts/ci/github.sh delete-artifacts \"$PATTERN\""]
    );
    let (_, selftest) = yaml(".github/workflows/dist-selftest.yml");
    let call = &selftest["jobs"]["delete-builds"];
    assert_eq!(
        string(&call["uses"]),
        Some("./.github/workflows/delete-artifacts.yml")
    );
    assert_eq!(call["permissions"].as_hash().unwrap().len(), 1);
    assert_eq!(string(&call["permissions"]["actions"]), Some("write"));
    assert_eq!(string(&call["needs"]), Some("check"));
}

#[test]
fn no_input_defaults_to_an_organization_and_every_secret_is_optional() {
    let (_, workflow) = yaml(".github/workflows/dist.yml");
    let call = &workflow["on"]["workflow_call"];
    let inputs = call["inputs"].as_hash().unwrap();
    for (name, input) in inputs {
        let name = name.as_str().unwrap();
        assert!(string(&input["description"]).is_some(), "{name}: described");
        let default = match &input["default"] {
            Yaml::String(s) => s.clone(),
            Yaml::Boolean(b) => b.to_string(),
            Yaml::Integer(i) => i.to_string(),
            other => panic!("{name}: default {other:?}"),
        };
        match name {
            // GitHub-hosted runner labels.
            "linux-runner" => assert_eq!(default, "ubuntu-24.04"),
            "windows-runner" => assert_eq!(default, "windows-2025"),
            "macos-runner" => assert_eq!(default, "macos-15"),
            // The official Rust image, digest-pinned: the GitLab template's.
            "linux-build-image" => {
                assert!(
                    default.starts_with("rust:") && default.contains("@sha256:"),
                    "{default}"
                );
                let gitlab =
                    std::fs::read_to_string(repo_root().join("ci/gitlab/seaworthy.yml")).unwrap();
                assert!(
                    gitlab.contains(&default),
                    "the GitLab template's build image"
                );
            }
            "config" => assert_eq!(default, "seaworthy.toml"),
            "manifest" => assert_eq!(default, "Cargo.toml"),
            "platforms" => assert_eq!(default, "linux,windows,macos"),
            "artifact-prefix" => assert_eq!(default, "seaworthy"),
            "retention-days" => assert_eq!(default, "14"),
            "release" | "dev-sign" | "publish-dry-run" | "allow-unsigned" | "ci-test-keys" => {
                assert_eq!(default, "false")
            }
            // Source paths are remapped unless a caller says otherwise.
            "remap-paths" => assert_eq!(default, "true"),
            // Everything else (accounts, endpoints, identities, stores,
            // signing settings) has no default.
            _ => assert_eq!(default, "", "{name}"),
        }
    }
    for (name, secret) in call["secrets"].as_hash().unwrap() {
        assert_eq!(
            secret["required"].as_bool(),
            Some(false),
            "{}",
            name.as_str().unwrap()
        );
    }
}

#[test]
fn the_workflow_runs_steps_the_scripts_have() {
    let (text, _) = yaml(".github/workflows/dist.yml");
    let script = std::fs::read_to_string(repo_root().join("scripts/ci/seaworthy.sh")).unwrap();
    let glue = std::fs::read_to_string(repo_root().join("scripts/ci/github.sh")).unwrap();
    let mut seen = 0;
    // The commands (a step's name or a comment can name a script too).
    for line in text
        .lines()
        .filter(|l| l.contains("bash ") && !l.trim_start().starts_with('#'))
    {
        for (needle, source) in [("seaworthy.sh", &script), ("github.sh", &glue)] {
            let Some(at) = line.find(needle) else {
                continue;
            };
            let rest = line[at + needle.len()..].trim_start_matches('"');
            if !rest.starts_with(' ') {
                continue;
            }
            let step = rest.split_whitespace().next().unwrap();
            assert!(
                source.contains(&format!("\n    {step})")),
                "{line}: no step {step}"
            );
            seen += 1;
            // github.sh signed <step> runs seaworthy.sh <step>.
            if step == "signed" {
                let inner = rest.split_whitespace().nth(1).unwrap();
                assert!(script.contains(&format!("\n    {inner})")), "{line}");
            }
        }
    }
    assert!(seen >= 10, "{seen}");
    for file in ["seaworthy-build.ps1", "seaworthy-msi.ps1"] {
        assert!(text.contains(file));
        assert!(repo_root().join("scripts/ci").join(file).is_file());
    }
    // Prepare hands github.sh on with the other scripts.
    assert!(
        text.contains(
            "install -m 0755 .seaworthy/scripts/ci/github.sh \"$SEAWORTHY_WORK/scripts/\""
        )
    );
    let (action_text, action) = yaml(".github/actions/setup-seaworthy/action.yml");
    for step in action["runs"]["steps"].as_vec().unwrap() {
        if let Some(uses) = string(&step["uses"]) {
            assert!(pinned(uses), "{uses}");
            let line = action_text.lines().find(|l| l.contains(uses)).unwrap();
            assert!(line.contains(" # v"), "{line}");
        }
        if let Some(run) = string(&step["run"]) {
            assert!(!run.contains("${{"), "{run}");
        }
    }
}

/// The jobs that hold secrets run no product code and trust nothing the
/// prepare job handed on but data: seaworthy comes from seaworthy's own
/// checkout at the workflow's commit, built in the job (never from a cache
/// on a release or a dev build), and so do the scripts; the third-party
/// tools are installed by a step that holds no secret, before the one step
/// that does, whose script hands the secrets to the seaworthy call alone; no
/// signing configuration travels through GITHUB_ENV.
#[test]
fn the_signing_jobs_trust_only_data_from_prepare() {
    let (text, workflow) = yaml(".github/workflows/dist.yml");
    assert!(
        !text.contains("SEAWORTHY_SIGNING=$SIGNING_TOML"),
        "signing.toml never travels through GITHUB_ENV"
    );
    let jobs = workflow["jobs"].as_hash().unwrap();
    for id in ["package", "adopt-msi", "package-macos", "publish"] {
        let job = &jobs[&Yaml::String(id.to_owned())];
        let steps = job["steps"].as_vec().unwrap();
        let workflow_checkout = steps.iter().position(|step| {
            string(&step["with"]["ref"]) == Some("${{ job.workflow_sha }}")
                && string(&step["with"]["path"]) == Some(".seaworthy")
        });
        let setup = steps.iter().position(|step| {
            string(&step["uses"]) == Some("./.seaworthy/.github/actions/setup-seaworthy")
        });
        assert!(
            workflow_checkout.is_some() && setup > workflow_checkout,
            "{id}: seaworthy from the workflow's own commit, built in the job"
        );
        let cache = string(&steps[setup.unwrap()]["with"]["cache"]).unwrap();
        assert!(
            cache == "false"
                || cache.contains("(inputs.release || inputs.dev-sign) && 'false'")
                || cache == "${{ inputs.release && 'false' || 'true' }}",
            "{id}: {cache}"
        );
        let mut secret_steps = Vec::new();
        for (index, step) in steps.iter().enumerate() {
            let run = string(&step["run"]).unwrap_or_default();
            if run.contains("seaworthy.sh") || run.contains("github.sh") {
                assert!(
                    run.contains(".seaworthy/scripts/ci/")
                        && !run.contains("$SEAWORTHY_WORK/scripts"),
                    "{id}: the checkout's scripts, never the prepare job's copies:\n{run}"
                );
            }
            assert!(
                !run.contains("$SEAWORTHY_WORK/bin"),
                "{id}: never the prepare job's seaworthy"
            );
            let holds_secret = step["env"].as_hash().is_some_and(|env| {
                env.values()
                    .any(|v| string(v).is_some_and(|v| v.contains("secrets.")))
            });
            if holds_secret {
                secret_steps.push(index);
                assert!(
                    run.starts_with("bash .seaworthy/scripts/ci/github.sh signed ")
                        || run == "bash .seaworthy/scripts/ci/seaworthy.sh publish",
                    "{id}: a step holding secrets runs the signing script alone:\n{run}"
                );
            }
            if run.contains("apt-get") || run.contains("brew install") || run.contains(" tools ") {
                assert!(!holds_secret, "{id}: a tool install holds no secret");
                assert!(
                    secret_steps.is_empty(),
                    "{id}: tools are installed before any step holds a secret"
                );
            }
        }
        assert!(
            !secret_steps.is_empty(),
            "{id}: some step signs or publishes"
        );
        // The always-run cleanup removes whatever a killed step left.
        assert!(
            steps
                .iter()
                .any(|step| string(&step["if"]) == Some("always()")
                    && string(&step["run"]).is_some_and(|r| r.contains("seaworthy-signing."))),
            "{id}: the always-run cleanup"
        );
    }
    // The tools step installs nFPM and osslsigncode into GITHUB_ENV, never
    // with the OIDC request variables in its environment.
    for (id, step) in [("package", "package"), ("adopt-msi", "adopt-msi")] {
        let job = &jobs[&Yaml::String(id.to_owned())];
        let tools = job["steps"]
            .as_vec()
            .unwrap()
            .iter()
            .filter_map(|s| string(&s["run"]))
            .find(|r| r.contains(" tools "))
            .unwrap_or_else(|| panic!("{id}: a tools step"));
        assert!(
            tools.contains(&format!(
                "bash .seaworthy/scripts/ci/seaworthy.sh tools {step} \"$GITHUB_ENV\""
            )),
            "{tools}"
        );
        assert!(
            tools.contains("unset ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        );
    }
    // The MSI job and the assembly run the checkout's scripts too.
    assert!(text.contains("-File .seaworthy\\scripts\\ci\\seaworthy-msi.ps1"));
    assert!(text.contains("bash .seaworthy/scripts/ci/github.sh assemble"));
    // The CI test-key switch: an input, off by default, given to the
    // builds (the Linux build's container too), refused on a release by
    // every step.
    assert!(text.contains("SEAWORTHY_ALLOW_CI_TEST_KEYS: ${{ inputs.ci-test-keys && '1' || '' }}"));
    assert!(text.contains("-e SEAWORTHY_ALLOW_CI_TEST_KEYS"));
    assert!(text.contains("SEAWORTHY_ALLOW_UNSIGNED: ${{ inputs.allow-unsigned && '1' || '0' }}"));
    // The tool's own build sees nothing of the product's.
    let (action, _) = yaml(".github/actions/setup-seaworthy/action.yml");
    assert!(action.contains("git -C \"$SOURCE\" archive --format=tar HEAD | tar -x -C \"$src\""));
    assert!(action.contains("would join seaworthy's own build"));
    assert!(
        !action.contains("working-directory"),
        "never in the product's tree"
    );
}

// ---------------------------------------------------------------------------
// github.sh, carried out

fn have(tool: &str, probe: &[&str]) -> bool {
    common::have(tool, probe)
}

fn glue(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new("bash");
    command
        .arg(repo_root().join("scripts/ci/github.sh"))
        .args(args)
        .env_remove("GITHUB_OUTPUT")
        .env_remove("GITHUB_ENV");
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy();
        if k.starts_with("SEAWORTHY_")
            || k.starts_with("AZURE_")
            || k.starts_with("ACTIONS_ID_TOKEN_")
        {
            command.env_remove(&*k);
        }
    }
    for (k, v) in env {
        command.env(k, v);
    }
    command.output().unwrap()
}

/// The caller's data artifact: both inputs, checked by the prepare job
/// before anything builds and by each packaging job before it downloads the
/// data, which lands where data-path says before the signing step reads it.
#[test]
fn the_data_artifact_lands_where_data_path_says_after_its_check() {
    let (text, workflow) = yaml(".github/workflows/dist.yml");
    let inputs = &workflow["on"]["workflow_call"]["inputs"];
    for input in ["data-artifact", "data-path"] {
        assert_eq!(string(&inputs[input]["default"]), Some(""), "{input}");
    }
    assert!(text.contains("SEAWORTHY_DATA_ARTIFACT: ${{ inputs.data-artifact }}"));
    assert!(text.contains("SEAWORTHY_DATA_PATH: ${{ inputs.data-path }}"));
    let jobs = workflow["jobs"].as_hash().unwrap();
    let steps_of = |id: &str| {
        jobs[&Yaml::String(id.to_owned())]["steps"]
            .as_vec()
            .unwrap()
            .clone()
    };
    let check = "bash .seaworthy/scripts/ci/github.sh data-path";
    let prepare = steps_of("prepare");
    let checked = prepare
        .iter()
        .position(|s| string(&s["run"]) == Some(check))
        .expect("prepare checks the data artifact");
    let prepared = prepare
        .iter()
        .position(|s| string(&s["run"]).is_some_and(|r| r.contains("seaworthy.sh prepare")))
        .unwrap();
    assert!(checked < prepared, "checked before the plans are made");
    for id in ["package", "package-macos"] {
        let steps = steps_of(id);
        let checked = steps
            .iter()
            .position(|s| string(&s["run"]) == Some(check))
            .unwrap_or_else(|| panic!("{id}: the data check"));
        let downloaded = steps
            .iter()
            .position(|s| string(&s["with"]["name"]) == Some("${{ inputs.data-artifact }}"))
            .unwrap_or_else(|| panic!("{id}: the data's download"));
        let signed = steps
            .iter()
            .position(|s| {
                string(&s["run"])
                    .is_some_and(|r| r.starts_with("bash .seaworthy/scripts/ci/github.sh signed "))
            })
            .unwrap();
        assert!(checked < downloaded && downloaded < signed, "{id}");
        let download = &steps[downloaded];
        assert_eq!(string(&download["if"]), Some("inputs.data-artifact != ''"));
        assert_eq!(
            string(&steps[checked]["if"]),
            Some("inputs.data-artifact != ''")
        );
        assert_eq!(
            string(&download["with"]["path"]),
            Some("${{ inputs.data-path }}")
        );
        assert!(pinned(string(&download["uses"]).unwrap()), "{id}");
    }
}

/// `github.sh data-path`: both inputs or neither; a plain relative path not
/// there yet, whose existing part resolves inside the workspace and outside
/// seaworthy's checkout and work directory, however it is spelled or linked.
#[test]
fn data_path_keeps_the_data_off_seaworthy_s_own_directories() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path();
    for dir in [".seaworthy/scripts/ci", "seaworthy-work", "docs", "target"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    std::fs::write(root.join("README"), "x").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.join(".seaworthy/scripts"), root.join("shortcut")).unwrap();
        std::os::unix::fs::symlink("/tmp", root.join("outside")).unwrap();
    }
    let run = |artifact: &str, path: &str| {
        let mut command = Command::new("bash");
        command
            .arg(repo_root().join("scripts/ci/github.sh"))
            .arg("data-path")
            .current_dir(root);
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("SEAWORTHY_") {
                command.env_remove(k);
            }
        }
        command
            .env("SEAWORTHY_DATA_ARTIFACT", artifact)
            .env("SEAWORTHY_DATA_PATH", path)
            .env("SEAWORTHY_CHECKOUT", ".seaworthy")
            .env("SEAWORTHY_WORK", "seaworthy-work");
        command.output().unwrap()
    };
    let accepted = |artifact: &str, path: &str| {
        let out = run(artifact, path);
        assert!(out.status.success(), "{path}: {}", said(&out));
    };
    let refused = |artifact: &str, path: &str, why: &str| {
        let out = run(artifact, path);
        assert!(!out.status.success(), "{path} must be refused");
        assert!(said(&out).contains(why), "{path}: {}", said(&out));
    };
    accepted("", "");
    accepted("web-build", "web");
    accepted("web-build", "target/web");
    accepted("web-build", "docs/built/web");
    refused("web-build", "", "without data-path");
    refused("", "web", "without data-artifact");
    refused("web build", "web", "isn't an artifact's name");
    for path in ["/tmp/web", "web/", "a//b", "web dir", "a\\b"] {
        refused("web-build", path, "isn't a plain relative path");
    }
    refused("web-build", "docs/../web", "holds a `..` segment");
    refused("web-build", "./web", "holds a `.` segment");
    refused("web-build", "docs", "in the repository already");
    refused("web-build", "README/web", "isn't a directory");
    for path in [
        ".seaworthy/web",
        ".SeaWorthy/web",
        "seaworthy-work/artifacts/x",
        "Seaworthy-Work",
    ] {
        refused("web-build", path, "lands in seaworthy's own");
    }
    #[cfg(unix)]
    {
        refused("web-build", "shortcut/web", "lands in seaworthy's own");
        refused("web-build", "outside/web", "leads out of the workspace");
    }
}

#[test]
fn the_oidc_grant_is_azure_s_alone() {
    let token = [
        ("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token"),
        ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "oidc"),
    ];
    let azure = [
        ("SEAWORTHY_GH_AZURE_ENDPOINT", "eus.codesigning.azure.net"),
        ("SEAWORTHY_GH_AZURE_ACCOUNT", "acme"),
        ("SEAWORTHY_GH_AZURE_PROFILE", "acme-public"),
        ("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000"),
        ("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000001"),
    ];
    let release = [("SEAWORTHY_RELEASE", "1")];
    let run = |sets: &[&[(&str, &str)]]| {
        let env: Vec<(&str, &str)> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        glue(&["oidc-grant"], &env)
    };
    // No Azure, no grant: an unsigned or PKCS#12 caller.
    assert!(run(&[&release]).status.success());
    // Azure with the grant, on a release or not.
    assert!(run(&[&azure, &token, &release]).status.success());
    assert!(run(&[&azure, &token]).status.success());
    // A grant without Azure: refused, whatever the run.
    for sets in [&[&token[..]][..], &[&token[..], &release[..]]] {
        let out = run(sets);
        assert!(!out.status.success());
        assert!(said(&out).contains("remove it"), "{}", said(&out));
    }
    // Azure without the grant: refused when the run signs, else harmless.
    let out = run(&[&azure, &release]);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("grant id-token: write"),
        "{}",
        said(&out)
    );
    assert!(run(&[&azure, &[("SEAWORTHY_DEV_SIGN", "1")]]).status.code() == Some(1));
    assert!(run(&[&azure]).status.success());
}

/// delete-artifacts lists the run's artifacts once, then deletes the ones
/// whose names match the pattern (every one by default) by id, and fails
/// when a call fails; an empty pattern, and a run or repository that isn't
/// one, are refused before any call. A stub gh records its calls.
#[test]
fn delete_artifacts_deletes_the_run_s_matching_artifacts() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let calls = dir.path().join("calls");
    let listing = dir.path().join("listing");
    std::fs::write(
        &listing,
        "11\tseaworthy-build-linux-base\n12\tseaworthy-packages\n13\tseaworthy-build-windows-znver4\n",
    )
    .unwrap();
    let gh = bin.join("gh");
    std::fs::write(
        &gh,
        format!(
            r#"#!/usr/bin/env bash
echo "$*" >> {calls}
if [ "$2" = --paginate ]; then cat {listing}; exit "${{STUB_LIST_EXIT:-0}}"; fi
case "$*" in *"/artifacts/${{STUB_DELETE_FAIL:-none}}") exit 1 ;; esac
"#,
            calls = calls.display(),
            listing = listing.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let run = |args: &[&str], extra: &[(&str, &str)]| {
        let _ = std::fs::remove_file(&calls);
        let mut env = vec![
            ("PATH", path.as_str()),
            ("GITHUB_REPOSITORY", "acme/viewer"),
            ("GITHUB_RUN_ID", "42"),
        ];
        env.extend_from_slice(extra);
        let out = glue(&[&["delete-artifacts"][..], args].concat(), &env);
        (out, std::fs::read_to_string(&calls).unwrap_or_default())
    };

    // A pattern: the matching artifacts alone, by id, after one listing.
    let (out, made) = run(&["seaworthy-build-*"], &[]);
    assert!(out.status.success(), "{}", said(&out));
    let made: Vec<&str> = made.lines().collect();
    assert_eq!(made.len(), 3, "{made:?}");
    assert!(
        made[0].starts_with("api --paginate repos/acme/viewer/actions/runs/42/artifacts --jq "),
        "{}",
        made[0]
    );
    assert!(made[0].contains("select(.expired | not)"), "{}", made[0]);
    assert_eq!(
        made[1..],
        [
            "api --silent -X DELETE repos/acme/viewer/actions/artifacts/11",
            "api --silent -X DELETE repos/acme/viewer/actions/artifacts/13",
        ]
    );
    assert!(
        said(&out).contains("deleted 2 artifact(s) of run 42; kept 1"),
        "{}",
        said(&out)
    );

    // No pattern: every artifact.
    let (out, made) = run(&[], &[]);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(made.lines().filter(|l| l.contains(" DELETE ")).count(), 3);

    // A failed listing or deletion fails the step.
    let (out, _) = run(&[], &[("STUB_LIST_EXIT", "1")]);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("couldn't list run 42's artifacts"),
        "{}",
        said(&out)
    );
    let (out, _) = run(&[], &[("STUB_DELETE_FAIL", "12")]);
    assert!(!out.status.success());
    assert!(
        said(&out).contains("couldn't delete seaworthy-packages"),
        "{}",
        said(&out)
    );

    // Refused before any call.
    for (args, extra, why) in [
        (vec![""], vec![], "an empty pattern"),
        (vec![], vec![("GITHUB_RUN_ID", "42; rm")], "isn't a run id"),
        (
            vec![],
            vec![("GITHUB_REPOSITORY", "acme")],
            "isn't owner/name",
        ),
    ] {
        let (out, made) = run(&args, &extra);
        assert!(!out.status.success(), "{why}");
        assert!(said(&out).contains(why), "{}", said(&out));
        assert!(made.is_empty(), "{why}: {made}");
    }
}

const TWO_PLATFORMS: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[product.viewer]
display-name = "Acme Viewer"
description = "Views things."
executable = "AcmeViewer"
core = "acme_core"
kind = "desktop"
windows-directory = "Viewer"
outputs = ["deb", "zip"]
updates.default = "off"
"#;

#[test]
fn the_matrix_has_one_entry_per_target_directory() {
    if !have("jq", &["--version"]) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("seaworthy.toml"), TWO_PLATFORMS).unwrap();
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    for triple in ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"] {
        let plan = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
            .current_dir(dir.path())
            .args(["build-plan", "--triple", triple])
            .output()
            .unwrap();
        assert!(plan.status.success(), "{}", said(&plan));
        std::fs::write(work.join(format!("plan-{triple}.tsv")), &plan.stdout).unwrap();
    }
    let work_arg = work.to_str().unwrap();
    let out = glue(&["matrix", work_arg], &[]);
    assert!(out.status.success(), "{}", said(&out));
    let text = String::from_utf8_lossy(&out.stdout);
    for want in [
        "linux=[\"base\",\"x86-64-v3\",\"x86-64-v2\"]",
        "windows=[\"base\",\"x86-64-v3\",\"x86-64-v2\"]",
        "macos=[]",
    ] {
        assert!(text.lines().any(|l| l == want), "{want}\n{text}");
    }
    // Into $GITHUB_OUTPUT, narrowed to the platforms asked for.
    let outputs = dir.path().join("outputs");
    let out = glue(
        &["matrix", work_arg],
        &[
            ("SEAWORTHY_PLATFORMS", "windows"),
            ("GITHUB_OUTPUT", outputs.to_str().unwrap()),
        ],
    );
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        std::fs::read_to_string(&outputs).unwrap(),
        "linux=[]\nwindows=[\"base\",\"x86-64-v3\",\"x86-64-v2\"]\nmacos=[]\n"
    );
    let out = glue(
        &["matrix", work_arg],
        &[("SEAWORTHY_PLATFORMS", "linux,bsd")],
    );
    assert!(!out.status.success());
    assert!(
        said(&out).contains("unknown platform(s) bsd"),
        "{}",
        said(&out)
    );
}

#[test]
fn build_env_merges_a_target_s_entries_and_refuses_what_it_must() {
    if !have("jq", &["--version"]) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("build.env");
    let file_arg = file.to_str().unwrap();
    let run = |json: &str| {
        glue(
            &["build-env", "x86_64-pc-windows-msvc", file_arg],
            &[("SEAWORTHY_BUILD_ENV", json)],
        )
    };
    let out = run(
        r#"{"*": {"CC": "clang", "CFLAGS": "-O2 -g"}, "x86_64-pc-windows-msvc": {"CC": "clang-cl"}, "aarch64-apple-darwin": {"X": "y"}}"#,
    );
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "CC=clang-cl\nCFLAGS=-O2 -g\n"
    );
    let out = run("");
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "");
    for (json, why) in [
        (
            r#"{"*": {"RUSTFLAGS": "-Ctarget-cpu=native"}}"#,
            "may not set RUSTFLAGS",
        ),
        (
            r#"{"*": {"LD_PRELOAD": "/x.so"}}"#,
            "may not set LD_PRELOAD",
        ),
        (
            r#"{"*": {"GITHUB_TOKEN": "x"}}"#,
            "may not set GITHUB_TOKEN",
        ),
        (
            r#"{"*": {"SEAWORTHY_WORK": "x"}}"#,
            "may not set SEAWORTHY_WORK",
        ),
        (r#"{"*": {"A": "one\ntwo"}}"#, "control character"),
        (r#"{"*": {"A B": "x"}}"#, "isn't a variable name"),
        (r#"{"linux": {"A": "x"}}"#, "nor a target seaworthy builds"),
        (r#"{"*": {"A": 1}}"#, "a JSON object of objects of strings"),
        ("[]", "a JSON object of objects of strings"),
    ] {
        let out = run(json);
        assert!(!out.status.success(), "{json}");
        assert!(said(&out).contains(why), "{json}: {}", said(&out));
    }
}

#[test]
fn signing_toml_names_each_signer_it_was_handed() {
    if !have("openssl", &["version"]) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let scripts = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::write(scripts.join("azure-sign.sh"), "").unwrap();
    let signing = dir.path().join("signing/signing.toml");
    let env_file = dir.path().join("github.env");
    let run = |extra: &[(&str, &str)]| {
        let _ = std::fs::remove_file(&env_file);
        let mut env = vec![
            ("SEAWORTHY_GH_SCRIPTS", scripts.to_str().unwrap()),
            ("GITHUB_ENV", env_file.to_str().unwrap()),
        ];
        env.extend_from_slice(extra);
        glue(&["signing-toml", signing.to_str().unwrap()], &env)
    };
    let fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567";
    // A manifest key, an OpenPGP key and Azure Artifact Signing.
    let out = run(&[
        ("SEAWORTHY_RELEASE_MANIFEST_KEY", "00"),
        ("SEAWORTHY_GH_MANIFEST_ALGORITHM", "ed25519"),
        (
            "SEAWORTHY_OPENPGP_SECRET_KEY",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        ),
        ("SEAWORTHY_GH_OPENPGP_FINGERPRINT", fingerprint),
        ("SEAWORTHY_GH_AZURE_ENDPOINT", "eus.codesigning.azure.net"),
        ("SEAWORTHY_GH_AZURE_ACCOUNT", "Acme-Signing"),
        ("SEAWORTHY_GH_AZURE_PROFILE", "Acme-Release"),
        ("AZURE_TENANT_ID", "11111111-2222-4333-8444-555555555555"),
        ("AZURE_CLIENT_ID", "66666666-7777-4888-9999-000000000000"),
    ]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(!said(&out).contains("BEGIN PGP"), "no secret printed");
    let text = std::fs::read_to_string(&signing).unwrap();
    assert!(
        !text.contains("BEGIN PGP") && !text.contains("\"00\""),
        "names, never values:\n{text}"
    );
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&signing).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{mode:o}");
    }
    assert_eq!(
        std::fs::read_to_string(&env_file).unwrap(),
        format!("SEAWORTHY_SIGNING={}\n", signing.display())
    );
    let (file, _) = seaworthy::sign::SigningConfig::load(&signing).unwrap();
    assert_eq!(file.manifest.len(), 1);
    assert_eq!(
        file.manifest[0].key_env.as_deref(),
        Some("SEAWORTHY_RELEASE_MANIFEST_KEY")
    );
    let openpgp = file.openpgp.as_ref().unwrap();
    assert_eq!(openpgp.key, fingerprint);
    assert_eq!(
        openpgp.secret_key_env.as_deref(),
        Some("SEAWORTHY_OPENPGP_SECRET_KEY")
    );
    assert_eq!(
        file.authenticode
            .as_ref()
            .unwrap()
            .command
            .as_deref()
            .unwrap(),
        [
            "bash",
            scripts.join("azure-sign.sh").to_str().unwrap(),
            "--endpoint",
            "eus.codesigning.azure.net",
            "--account",
            "Acme-Signing",
            "--profile",
            "Acme-Release",
            "{file}"
        ]
    );
    assert!(file.apple.is_none());

    // A PKCS#12 certificate: PEM files for osslsigncode, private.
    let p12 = dir.path().join("codesign.p12");
    let key = dir.path().join("k.pem");
    let cert = dir.path().join("c.pem");
    let req = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=Acme Code Signing",
            "-days",
            "2",
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .unwrap();
    assert!(req.status.success(), "{}", said(&req));
    let export = Command::new("openssl")
        .args(["pkcs12", "-export", "-passout", "pass:pfx-pass"])
        .arg("-inkey")
        .arg(&key)
        .arg("-in")
        .arg(&cert)
        .arg("-out")
        .arg(&p12)
        .output()
        .unwrap();
    assert!(export.status.success(), "{}", said(&export));
    // Encoded here: macOS's base64 has no -w0, and an empty secret means no
    // PKCS#12 at all.
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(std::fs::read(&p12).unwrap());
    let out = run(&[
        ("SEAWORTHY_GH_AUTHENTICODE_PFX", &encoded),
        ("SEAWORTHY_GH_AUTHENTICODE_PASSWORD", "pfx-pass"),
        (
            "SEAWORTHY_GH_TIMESTAMP_URL",
            "http://timestamp.example.com/rfc3161",
        ),
    ]);
    assert!(out.status.success(), "{}", said(&out));
    let (file, _) = seaworthy::sign::SigningConfig::load(&signing).unwrap();
    let authenticode = file.authenticode.as_ref().unwrap();
    let chain = authenticode.certificate.as_ref().unwrap();
    let private = authenticode.key.as_ref().unwrap();
    assert!(
        std::fs::read_to_string(chain)
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
    assert!(
        std::fs::read_to_string(private)
            .unwrap()
            .contains("PRIVATE KEY")
    );
    {
        use std::os::unix::fs::PermissionsExt as _;
        for file in [chain, private] {
            let mode = std::fs::metadata(file).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "{}: {mode:o}", file.display());
        }
    }
    assert!(
        !dir.path()
            .join("signing/authenticode/identity.p12")
            .exists(),
        "the PKCS#12 copy is removed"
    );
    assert_eq!(
        authenticode.timestamp_url.as_deref(),
        Some("http://timestamp.example.com/rfc3161")
    );
    let out = run(&[
        ("SEAWORTHY_GH_AUTHENTICODE_PFX", &encoded),
        ("SEAWORTHY_GH_AUTHENTICODE_PASSWORD", "wrong"),
        ("SEAWORTHY_GH_TIMESTAMP_URL", "http://timestamp.example.com"),
    ]);
    assert!(!out.status.success());
    assert!(said(&out).contains("doesn't open"), "{}", said(&out));

    // The Developer ID apple-keychain left.
    let out = run(&[
        (
            "SEAWORTHY_GH_APPLE_IDENTITY",
            "Developer ID Application: Acme Inc (ABCDE12345)",
        ),
        (
            "SEAWORTHY_GH_APPLE_INSTALLER_IDENTITY",
            "Developer ID Installer: Acme Inc (ABCDE12345)",
        ),
        ("SEAWORTHY_GH_APPLE_KEYCHAIN", "/tmp/acme.keychain-db"),
        ("SEAWORTHY_GH_APPLE_NOTARY_PROFILE", "seaworthy-notary"),
    ]);
    assert!(out.status.success(), "{}", said(&out));
    let (file, base) = seaworthy::sign::SigningConfig::load(&signing).unwrap();
    let id = file.apple.as_ref().unwrap().developer_id(&base).unwrap();
    assert_eq!(
        id.identity,
        "Developer ID Application: Acme Inc (ABCDE12345)"
    );
    assert_eq!(
        id.keychain.as_deref(),
        Some(Path::new("/tmp/acme.keychain-db"))
    );
    assert_eq!(id.notary_profile, "seaworthy-notary");

    // No signer at all: an unsigned build, said so for the later steps.
    let out = run(&[]);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        std::fs::read_to_string(&env_file).unwrap(),
        "SEAWORTHY_UNSIGNED=1\n"
    );
    // On a release or a dev build that's refused, unless allow-unsigned
    // means it (and then it's a warning).
    for kind in ["SEAWORTHY_RELEASE", "SEAWORTHY_DEV_SIGN"] {
        let out = run(&[(kind, "1")]);
        assert!(!out.status.success(), "{kind}");
        assert!(
            said(&out).contains("no signer was handed to this job, on a release or a dev build"),
            "{}",
            said(&out)
        );
        let out = run(&[(kind, "1"), ("SEAWORTHY_ALLOW_UNSIGNED", "1")]);
        assert!(out.status.success(), "{}", said(&out));
        assert!(said(&out).contains("::warning::"), "{}", said(&out));
        assert_eq!(
            std::fs::read_to_string(&env_file).unwrap(),
            "SEAWORTHY_UNSIGNED=1\n"
        );
    }
    // What it refuses.
    for (env, why) in [
        (
            vec![("SEAWORTHY_RELEASE_MANIFEST_KEY", "00")],
            "needs the release-manifest-algorithm input",
        ),
        (
            vec![
                ("SEAWORTHY_RELEASE_MANIFEST_KEY", "00"),
                ("SEAWORTHY_GH_MANIFEST_ALGORITHM", "rsa"),
            ],
            "ml-dsa-87, ecdsa-p256 or ed25519",
        ),
        (
            vec![
                ("SEAWORTHY_OPENPGP_SECRET_KEY", "k"),
                ("SEAWORTHY_GH_OPENPGP_FINGERPRINT", "acme@example.com"),
            ],
            "openpgp-key-fingerprint",
        ),
        (
            vec![
                ("SEAWORTHY_GH_AUTHENTICODE_PFX", "eA=="),
                ("SEAWORTHY_GH_AZURE_ENDPOINT", "eus.codesigning.azure.net"),
            ],
            "not both",
        ),
        (
            vec![
                ("SEAWORTHY_GH_AZURE_ENDPOINT", "evil.example.com"),
                ("SEAWORTHY_GH_AZURE_ACCOUNT", "Acme-Signing"),
                ("SEAWORTHY_GH_AZURE_PROFILE", "Acme-Release"),
            ],
            "azure-endpoint",
        ),
        (
            vec![("SEAWORTHY_GH_AUTHENTICODE_PFX", "eA==")],
            "authenticode-timestamp-url",
        ),
        (
            vec![(
                "SEAWORTHY_GH_APPLE_IDENTITY",
                "Developer ID Application: \"x\" (ABCDE12345)",
            )],
            "a quote",
        ),
    ] {
        let out = run(&env);
        assert!(!out.status.success(), "{env:?}");
        assert!(said(&out).contains(why), "{env:?}: {}", said(&out));
    }
}

#[test]
fn assemble_copies_every_listed_artifact_checked_against_its_listing() {
    if !have("jq", &["--version"]) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let dist = dir.path().join("dist/viewer");
    std::fs::create_dir_all(dist.join("packages")).unwrap();
    let bytes = b"a package";
    std::fs::write(dist.join("packages/acme-viewer_1.0.0-3_amd64.deb"), bytes).unwrap();
    std::fs::write(dist.join("packages/stray.txt"), b"unlisted").unwrap();
    std::fs::create_dir_all(dist.join("x86_64-pc-windows-msvc/tree")).unwrap();
    std::fs::write(
        dist.join("x86_64-pc-windows-msvc/tree/AcmeViewer.exe"),
        b"MZ",
    )
    .unwrap();
    let sha = seaworthy_crypto::digest::sha256_hex(bytes);
    let listing = |file: &str, sha: &str| {
        format!(
            r#"{{"product":"viewer","artifacts":[{{"kind":"deb","file":"{file}","target":"x86_64-unknown-linux-gnu","sha256":"{sha}"}}]}}"#
        )
    };
    std::fs::write(
        dist.join("packages.json"),
        listing("packages/acme-viewer_1.0.0-3_amd64.deb", &sha),
    )
    .unwrap();
    let out_dir = dir.path().join("out");
    let dist_arg = format!("packages={}", dir.path().join("dist").display());
    let mac_arg = format!("packages-macos={}", dir.path().join("none").display());
    let out = glue(
        &["assemble", out_dir.to_str().unwrap(), &dist_arg, &mac_arg],
        &[],
    );
    assert!(out.status.success(), "{}", said(&out));
    let mut files: Vec<String> = Vec::new();
    let mut stack = vec![out_dir.clone()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(
                    path.strip_prefix(&out_dir)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    files.sort();
    assert_eq!(
        files,
        [
            "SHA256SUMS",
            "packages/viewer/packages.json",
            "packages/viewer/packages/acme-viewer_1.0.0-3_amd64.deb",
        ],
        "listed files only"
    );
    let sums = std::fs::read_to_string(out_dir.join("SHA256SUMS")).unwrap();
    assert!(
        sums.contains(&format!(
            "{sha}  packages/viewer/packages/acme-viewer_1.0.0-3_amd64.deb"
        )),
        "{sums}"
    );
    // Another file than the one listed, a path out of the listing's
    // directory, an existing output: refused.
    for (file, sha, why) in [
        (
            "packages/acme-viewer_1.0.0-3_amd64.deb",
            "0".repeat(64),
            "but the listing says",
        ),
        ("../../etc/passwd", sha.clone(), "not a plain relative path"),
        ("packages/missing.deb", sha.clone(), "which isn't there"),
    ] {
        std::fs::write(dist.join("packages.json"), listing(file, &sha)).unwrap();
        let fresh = dir.path().join(format!("out-{}", why.len()));
        let out = glue(&["assemble", fresh.to_str().unwrap(), &dist_arg], &[]);
        assert!(!out.status.success(), "{file}");
        assert!(said(&out).contains(why), "{file}: {}", said(&out));
    }
    let out = glue(&["assemble", out_dir.to_str().unwrap(), &dist_arg], &[]);
    assert!(!out.status.success());
    assert!(said(&out).contains("exists"), "{}", said(&out));
}

/// `github.sh signed <step>`: on a release, the signing material is made in
/// a private directory for that step alone — signing.toml and the PEM
/// files the PKCS#12 opens to — the PKCS#12 and its password leave the
/// environment before seaworthy.sh starts, and the directory is shredded
/// when the step ends, passed or failed. Outside a release or a dev build
/// nothing is made. A stub seaworthy.sh beside a copy of github.sh records
/// what it was given.
#[test]
fn signed_makes_the_signing_material_for_its_step_alone() {
    if !have("openssl", &["version"]) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let scripts = dir.path().join("scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::copy(
        repo_root().join("scripts/ci/github.sh"),
        scripts.join("github.sh"),
    )
    .unwrap();
    std::fs::write(scripts.join("azure-sign.sh"), "").unwrap();
    let record = dir.path().join("record");
    std::fs::write(
        scripts.join("seaworthy.sh"),
        format!(
            r#"#!/usr/bin/env bash
{{
  echo "step=$1"
  echo "signing=${{SEAWORTHY_SIGNING:-}}"
  echo "unsigned=${{SEAWORTHY_UNSIGNED:-}}"
  echo "pfx=${{SEAWORTHY_GH_AUTHENTICODE_PFX:-}}"
  echo "password=${{SEAWORTHY_GH_AUTHENTICODE_PASSWORD:-}}"
  echo "manifest=${{SEAWORTHY_RELEASE_MANIFEST_KEY:-}}"
  if [ -n "${{SEAWORTHY_SIGNING:-}}" ]; then
    cat "$SEAWORTHY_SIGNING"
    find "$(dirname "$SEAWORTHY_SIGNING")" -type f | sort
  fi
}} > {record}
exit "${{STUB_EXIT:-0}}"
"#,
            record = record.display()
        ),
    )
    .unwrap();
    let runner_temp = dir.path().join("runner-temp");
    std::fs::create_dir_all(&runner_temp).unwrap();
    // A PKCS#12 identity.
    let key = dir.path().join("k.pem");
    let cert = dir.path().join("c.pem");
    let p12 = dir.path().join("codesign.p12");
    let req = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=Acme Code Signing",
            "-days",
            "2",
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .unwrap();
    assert!(req.status.success(), "{}", said(&req));
    let export = Command::new("openssl")
        .args(["pkcs12", "-export", "-passout", "pass:pfx-pass"])
        .arg("-inkey")
        .arg(&key)
        .arg("-in")
        .arg(&cert)
        .arg("-out")
        .arg(&p12)
        .output()
        .unwrap();
    assert!(export.status.success(), "{}", said(&export));
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(std::fs::read(&p12).unwrap());
    let signed = |extra: &[(&str, &str)]| {
        let _ = std::fs::remove_file(&record);
        let mut command = Command::new("bash");
        command
            .arg(scripts.join("github.sh"))
            .args(["signed", "package"])
            .env("RUNNER_TEMP", &runner_temp)
            .env_remove("GITHUB_OUTPUT")
            .env_remove("GITHUB_ENV");
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy();
            if k.starts_with("SEAWORTHY_") || k.starts_with("AZURE_") || k == "SIGNING_TOML" {
                command.env_remove(&*k);
            }
        }
        for (k, v) in extra {
            command.env(k, v);
        }
        command.output().unwrap()
    };
    let leftovers = || {
        std::fs::read_dir(&runner_temp)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
    };
    let release = [
        ("SEAWORTHY_RELEASE", "1"),
        ("SEAWORTHY_RELEASE_MANIFEST_KEY", "00"),
        ("SEAWORTHY_GH_MANIFEST_ALGORITHM", "ed25519"),
        ("SEAWORTHY_GH_AUTHENTICODE_PFX", encoded.as_str()),
        ("SEAWORTHY_GH_AUTHENTICODE_PASSWORD", "pfx-pass"),
        ("SEAWORTHY_GH_TIMESTAMP_URL", "http://timestamp.example.com"),
    ];
    let out = signed(&release);
    assert!(out.status.success(), "{}", said(&out));
    let seen = std::fs::read_to_string(&record).unwrap();
    assert!(seen.contains("step=package\n"), "{seen}");
    assert!(
        seen.contains("pfx=\n") && seen.contains("password=\n"),
        "the PKCS#12 left the environment:\n{seen}"
    );
    assert!(
        seen.contains("manifest=00\n"),
        "seaworthy.sh hands the key on itself:\n{seen}"
    );
    let signing = seen
        .lines()
        .find_map(|l| l.strip_prefix("signing="))
        .unwrap()
        .to_owned();
    assert!(
        signing.starts_with(&format!("{}/seaworthy-signing.", runner_temp.display())),
        "{seen}"
    );
    assert!(
        seen.contains("[authenticode]") && seen.contains("authenticode/key.pem"),
        "{seen}"
    );
    assert!(leftovers().is_empty(), "shredded: {:?}", leftovers());
    // A failing step: the same cleanup, its exit status kept.
    let mut failing = release.to_vec();
    failing.push(("STUB_EXIT", "7"));
    let out = signed(&failing);
    assert_eq!(out.status.code(), Some(7), "{}", said(&out));
    assert!(leftovers().is_empty(), "shredded: {:?}", leftovers());
    // A release with no signer: refused before the step; allowed, unsigned.
    let out = signed(&[("SEAWORTHY_RELEASE", "1")]);
    assert!(!out.status.success());
    assert!(!record.exists(), "the step never ran");
    assert!(leftovers().is_empty(), "{:?}", leftovers());
    let out = signed(&[
        ("SEAWORTHY_RELEASE", "1"),
        ("SEAWORTHY_ALLOW_UNSIGNED", "1"),
    ]);
    assert!(out.status.success(), "{}", said(&out));
    let seen = std::fs::read_to_string(&record).unwrap();
    assert!(
        seen.contains("unsigned=1\n") && seen.contains("signing=\n"),
        "{seen}"
    );
    // The caller's own signing.toml, as given.
    let out = signed(&[
        ("SEAWORTHY_RELEASE", "1"),
        ("SIGNING_TOML", "ci/signing.toml"),
    ]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        std::fs::read_to_string(&record)
            .unwrap()
            .contains("signing=ci/signing.toml\n")
    );
    // Not a release: the step as it is, nothing made.
    let out = signed(&[("SEAWORTHY_GH_AUTHENTICODE_PFX", encoded.as_str())]);
    assert!(out.status.success(), "{}", said(&out));
    let seen = std::fs::read_to_string(&record).unwrap();
    assert!(
        seen.contains("signing=\n") && seen.contains("unsigned=\n"),
        "{seen}"
    );
    assert!(leftovers().is_empty(), "{:?}", leftovers());
}
