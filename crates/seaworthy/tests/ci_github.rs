//! seaworthy's reusable GitHub workflow (`.github/workflows/dist.yml`) and
//! its glue (`scripts/ci/github.sh`, `.github/actions/setup-seaworthy`):
//! the workflow read as YAML and held to the repository's Actions baseline
//! (no permissions by default, every job its own, every action pinned by
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

#[test]
fn the_reusable_workflow_follows_the_actions_baseline() {
    let (text, workflow) = yaml(".github/workflows/dist.yml");
    // A reusable workflow, and nothing else.
    let on = key(&workflow, "on").as_hash().unwrap();
    assert_eq!(on.len(), 1);
    assert!(on.contains_key(&Yaml::from_str("workflow_call")));
    // No permissions by default; each job grants its own, id-token only to
    // the two jobs that sign Windows code (Azure OIDC).
    assert!(
        key(&workflow, "permissions")
            .as_hash()
            .is_some_and(|h| h.is_empty())
    );
    let jobs = key(&workflow, "jobs").as_hash().unwrap();
    let mut id_token = BTreeSet::new();
    for (id, job) in jobs {
        let id = id.as_str().unwrap();
        assert!(
            job["timeout-minutes"].as_i64().is_some(),
            "{id}: timeout-minutes"
        );
        let permissions = job["permissions"]
            .as_hash()
            .unwrap_or_else(|| panic!("{id}: permissions"));
        assert_eq!(
            string(&job["permissions"]["contents"]),
            Some("read"),
            "{id}"
        );
        for (scope, level) in permissions {
            let scope = scope.as_str().unwrap();
            match (scope, level.as_str()) {
                ("contents", Some("read")) => {}
                ("id-token", Some("write")) => {
                    id_token.insert(id.to_owned());
                }
                _ => panic!("{id}: {scope}: {level:?}"),
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
        id_token,
        BTreeSet::from(["adopt-msi".to_owned(), "package".to_owned()])
    );
    for (job, step) in steps(&workflow) {
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
        if k.starts_with("SEAWORTHY_") || k.starts_with("AZURE_") {
            command.env_remove(&*k);
        }
    }
    for (k, v) in env {
        command.env(k, v);
    }
    command.output().unwrap()
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
    let encoded = String::from_utf8(
        Command::new("base64")
            .arg("-w0")
            .arg(&p12)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
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
