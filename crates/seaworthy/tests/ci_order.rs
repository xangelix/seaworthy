//! `seaworthy ci-order`: the release-ordering lint, over CI
//! configurations written to temporary repositories — every way a server
//! deploy can get ahead of a client publication refused, every way GitLab
//! assembles a configuration (local includes and globs, nested includes,
//! inputs, `extends`, anchors and `<<`, `!reference`) read as GitLab reads
//! it, and the command's output and exit codes.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use seaworthy::ci_order::{Report, check, load};

/// A repository holding `files` (path, text).
fn repo(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (path, text) in files {
        let path = dir.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    dir
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// The lint over `.gitlab-ci.yml` in `dir` with `extra` files.
fn lint_with(dir: &Path, extra: &[PathBuf], servers: &[&str], clients: &[&str]) -> Report {
    let pipeline = load(dir, &dir.join(".gitlab-ci.yml"), extra).unwrap();
    check(&pipeline, &names(servers), &names(clients))
}

fn lint(dir: &Path, servers: &[&str], clients: &[&str]) -> Report {
    lint_with(dir, &[], servers, clients)
}

fn ok(report: &Report) {
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
}

fn refused(report: &Report, mentions: &str) {
    assert!(
        report.findings.iter().any(|f| f.contains(mentions)),
        "{mentions:?} in {:#?}",
        report.findings
    );
}

const CLIENTS: [&str; 2] = ["publish", "web"];

#[test]
fn a_server_that_needs_every_client_passes() {
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "stages: [build, publish, deploy]\n\
         build: {stage: build, script: [make]}\n\
         publish: {stage: publish, needs: [build], script: [p]}\n\
         web: {stage: publish, needs: [build], script: [w]}\n\
         server: {stage: deploy, needs: [publish, web], script: [d]}\n",
    )]);
    let report = lint(dir.path(), &["server"], &CLIENTS);
    ok(&report);
    assert_eq!(report.ordered, vec![("server".to_owned(), names(&CLIENTS))]);
}

#[test]
fn needs_of_needs_count_and_stage_order_doesnt() {
    // Through a verify job that needs both: still ordered.
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "publish: {script: [p]}\nweb: {script: [w]}\n\
         verify: {needs: [publish, {job: web, artifacts: false}], script: [v]}\n\
         server: {stage: deploy, needs: [verify], script: [d]}\n",
    )]);
    ok(&lint(dir.path(), &["server"], &CLIENTS));
    // Stage order alone (no needs): refused, naming why.
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "stages: [publish, deploy]\npublish: {stage: publish, script: [p]}\n\
         web: {stage: publish, script: [w]}\nserver: {stage: deploy, script: [d]}\n",
    )]);
    refused(
        &lint(dir.path(), &["server"], &CLIENTS),
        "has no needs, so it waits only by stage order",
    );
    // A path through a stage-ordered job doesn't count either.
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "stages: [publish, verify, deploy]\npublish: {stage: publish, script: [p]}\n\
         web: {stage: publish, script: [w]}\nverify: {stage: verify, script: [v]}\n\
         server: {stage: deploy, needs: [verify], script: [d]}\n",
    )]);
    refused(
        &lint(dir.path(), &["server"], &CLIENTS),
        "server job \"server\" can deploy before client job \"publish\": it doesn't need it, directly or through its needs",
    );
}

#[test]
fn every_gap_a_server_can_slip_through_is_refused() {
    for (case, server, mentions) in [
        (
            "missing",
            "server: {needs: [publish], script: [d]}",
            "before client job \"web\": it doesn't need it",
        ),
        (
            "empty",
            "server: {needs: [], script: [d]}",
            "it has needs: [], so it starts at once",
        ),
        (
            "optional",
            "server: {needs: [publish, {job: web, optional: true}], script: [d]}",
            "it needs it only with optional: true",
        ),
        (
            "partial",
            "server: {needs: [publish, {job: web, parallel: {matrix: [{X: a}]}}], script: [d]}",
            "it needs only some of its parallel: matrix jobs",
        ),
        (
            "other-pipeline",
            "server: {needs: [publish, {pipeline: $PARENT, job: web}], script: [d]}",
            "before client job \"web\"",
        ),
        (
            "other-project",
            "server: {needs: [publish, {project: acme/web, job: web, ref: main}], script: [d]}",
            "before client job \"web\"",
        ),
        (
            "when-always",
            "server: {needs: [publish, web], when: always, script: [d]}",
            "runs when: always",
        ),
        (
            "rule-on-failure",
            "server: {needs: [publish, web], rules: [{if: $CI_COMMIT_TAG, when: on_failure}], script: [d]}",
            "runs when: always or on_failure (in the job or a rule)",
        ),
    ] {
        let dir = repo(&[(
            ".gitlab-ci.yml",
            &format!("publish: {{script: [p]}}\nweb: {{script: [w]}}\n{server}\n"),
        )]);
        refused(&lint(dir.path(), &["server"], &CLIENTS), mentions);
        assert!(!mentions.is_empty(), "{case}");
    }
}

#[test]
fn clients_that_can_fail_without_stopping_the_server_are_refused() {
    for (client, mentions) in [
        (
            "web: {allow_failure: true, script: [w]}",
            "is allowed to fail",
        ),
        (
            "web: {allow_failure: {exit_codes: [3]}, script: [w]}",
            "is allowed to fail",
        ),
        (
            "web: {when: manual, script: [w]}",
            "is manual, and a manual job outside rules is allowed to fail by default",
        ),
        (
            "web: {rules: [{if: $X, allow_failure: true}], script: [w]}",
            "has a rule that allows it to fail",
        ),
        (
            "web: {trigger: {project: a/b}}",
            "triggers a pipeline without strategy: depend",
        ),
        (
            "web: {trigger: a/b}",
            "triggers a pipeline without strategy: depend",
        ),
        (
            "web: {trigger: {project: a/b, strategy: later}}",
            "triggers a pipeline without strategy: depend",
        ),
    ] {
        let dir = repo(&[(
            ".gitlab-ci.yml",
            &format!(
                "publish: {{script: [p]}}\n{client}\nserver: {{needs: [publish, web], script: [d]}}\n"
            ),
        )]);
        refused(&lint(dir.path(), &["server"], &CLIENTS), mentions);
    }
    // A manual client that may not fail, and a trigger that waits: fine.
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "publish: {when: manual, allow_failure: false, script: [p]}\n\
         web: {trigger: {project: a/b, strategy: depend}}\n\
         server: {needs: [publish, web], script: [d]}\n",
    )]);
    ok(&lint(dir.path(), &["server"], &CLIENTS));
}

#[test]
fn unknown_jobs_are_findings() {
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "include: [{project: acme/seaworthy, file: ci/gitlab/seaworthy.yml}]\n\
         web: {script: [w]}\nserver: {needs: [seaworthy-publish, web], script: [d]}\n\
         .hidden: {script: [h]}\n.deploy: {needs: [web], script: [d]}\n",
    )]);
    // A hidden job (defined, never run) is no job.
    let report = lint(
        dir.path(),
        &["server", "absent", ".deploy"],
        &["seaworthy-publish", "web", ".hidden"],
    );
    refused(
        &report,
        "no client job \"seaworthy-publish\" in the configuration (includes not read: project: acme/seaworthy (ci/gitlab/seaworthy.yml); pass the file defining it)",
    );
    refused(&report, "no client job \".hidden\"");
    refused(&report, "no server job \"absent\"");
    refused(&report, "no server job \".deploy\"");
}

#[test]
fn local_includes_globs_and_nesting_merge_as_gitlab_merges() {
    // The server's needs live in a globbed include, a client in a nested
    // one; the root file overrides an included key.
    let dir = repo(&[
        (
            ".gitlab-ci.yml",
            "include:\n  - local: .gitlab/ci/*.yml\n  - /.gitlab/more/web.yml\n\
             publish: {script: [overridden]}\n",
        ),
        (
            ".gitlab/ci/deploy.yml",
            "server: {stage: deploy, needs: [publish, web], script: [d]}\n",
        ),
        (
            ".gitlab/ci/publish.yml",
            "include: [{local: .gitlab/nested/**/base.yml}]\npublish: {needs: [build]}\n",
        ),
        (".gitlab/nested/deep/er/base.yml", "build: {script: [b]}\n"),
        (".gitlab/more/web.yml", "web: {script: [w]}\n"),
    ]);
    let pipeline = load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[]).unwrap();
    assert!(pipeline.jobs.contains_key("build"), "the nested ** include");
    ok(&check(&pipeline, &names(&["server"]), &names(&CLIENTS)));
    // An include that matches nothing, leaves the repository, or loops.
    for (case, include, mentions) in [
        ("none", "include: ci/absent.yml", "matches no file"),
        (
            "escape",
            "include: ../outside.yml",
            "isn't a path inside the repository",
        ),
        ("loop", "include: .gitlab-ci.yml", "includes itself"),
    ] {
        let dir = repo(&[(".gitlab-ci.yml", include)]);
        let err = load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains(mentions), "{case}: {err}");
    }
    // Unix only: creating a symlink on Windows needs a privilege.
    #[cfg(unix)]
    {
        // A symlinked include reaching outside the repository.
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("evil.yml"), "x: {script: [x]}\n").unwrap();
        let dir = repo(&[(".gitlab-ci.yml", "include: ci/link.yml\n")]);
        std::fs::create_dir_all(dir.path().join("ci")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("evil.yml"),
            dir.path().join("ci/link.yml"),
        )
        .unwrap();
        let err = load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("outside the repository"), "{err}");
    }
}

#[test]
fn extends_anchors_merge_keys_and_references_resolve() {
    let dir = repo(&[(
        ".gitlab-ci.yml",
        ".needs: &needs [publish, web]\n\
         .deploy: {stage: deploy, needs: [publish], script: [d]}\n\
         .rules: {rules: [{if: $CI_COMMIT_TAG}]}\n\
         publish: {script: [p]}\nweb: {script: [w]}\n\
         # extends merges in order; the job's own needs replace the parent's\n\
         server: {extends: [.deploy, .rules], needs: *needs}\n\
         # a child that drops a need through extends\n\
         lazy: {extends: .deploy}\n\
         # <<, and !reference\n\
         merged: {<<: *base, needs: !reference [server, needs]}\n\
         .base: &base {stage: deploy, script: [m]}\n",
    )]);
    // `*base` is used before its anchor: YAML refuses that.
    assert!(load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[]).is_err());
    let dir = repo(&[(
        ".gitlab-ci.yml",
        ".base: &base {stage: deploy, script: [m]}\n\
         .needs: &needs [publish, web]\n\
         .deploy: {stage: deploy, needs: [publish], script: [d]}\n\
         publish: {script: [p]}\nweb: {script: [w]}\n\
         server: {extends: [.deploy], needs: *needs}\n\
         lazy: {extends: .deploy}\n\
         merged: {<<: *base, needs: !reference [server, needs]}\n\
         spliced: {needs: [!reference [.deploy, needs], web], script: [s]}\n",
    )]);
    let pipeline = load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[]).unwrap();
    ok(&check(
        &pipeline,
        &names(&["server", "merged", "spliced"]),
        &names(&CLIENTS),
    ));
    refused(
        &check(&pipeline, &names(&["lazy"]), &names(&CLIENTS)),
        "server job \"lazy\" can deploy before client job \"web\"",
    );
    // An extends loop, an unknown parent, a reference to nothing.
    for (text, mentions) in [
        ("a: {extends: b}\nb: {extends: a}\n", "extends itself"),
        ("a: {extends: .gone}\n", "isn't defined"),
        ("a: {needs: !reference [.gone, needs]}\n", "names nothing"),
    ] {
        let dir = repo(&[(".gitlab-ci.yml", text)]);
        let err = load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains(mentions), "{text}: {err}");
    }
}

#[test]
fn an_included_template_s_inputs_take_their_defaults_or_the_values_given() {
    let template = "spec:\n  inputs:\n    stage:\n      default: publish\n    after:\n      type: array\n      default: [build]\n---\n\
                    seaworthy-publish:\n  stage: $[[ inputs.stage ]]\n  needs: $[[ inputs.after ]]\n  script: [p]\n";
    let dir = repo(&[
        ("ci/template.yml", template),
        (
            ".gitlab-ci.yml",
            "stages: [build, publish, deploy]\nbuild: {stage: build, script: [b]}\n\
             web: {script: [w]}\nserver: {stage: deploy, needs: [seaworthy-publish, web], script: [d]}\n",
        ),
    ]);
    // Passed as an extra file (an include: project the lint can't fetch).
    let report = lint_with(
        dir.path(),
        &[dir.path().join("ci/template.yml")],
        &["server"],
        &["seaworthy-publish", "web"],
    );
    ok(&report);
    // Included locally with inputs.
    let dir = repo(&[
        ("ci/template.yml", template),
        (
            ".gitlab-ci.yml",
            "include: [{local: ci/template.yml, inputs: {stage: deploy, after: [web]}}]\n\
             web: {script: [w]}\nserver: {needs: [seaworthy-publish], script: [d]}\n",
        ),
    ]);
    let pipeline = load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[]).unwrap();
    // Through the template job's needs (the given input), the server waits
    // for web too.
    ok(&check(
        &pipeline,
        &names(&["server"]),
        &names(&["seaworthy-publish", "web"]),
    ));
    // An unknown input, a required one missing, inputs to a file without a
    // spec.
    for (root, mentions) in [
        (
            "include: [{local: ci/template.yml, inputs: {nope: 1}}]\n",
            "no input \"nope\" in its spec",
        ),
        (
            "include: [{local: ci/plain.yml, inputs: {a: 1}}]\n",
            "given inputs, but it has no spec: header",
        ),
        (
            "include: [{local: ci/required.yml}]\n",
            "input \"need\" has no default and isn't given",
        ),
    ] {
        let dir = repo(&[
            ("ci/template.yml", template),
            ("ci/plain.yml", "x: {script: [x]}\n"),
            (
                "ci/required.yml",
                "spec:\n  inputs:\n    need: {}\n---\nx: {script: [\"$[[ inputs.need ]]\"]}\n",
            ),
            (".gitlab-ci.yml", root),
        ]);
        let err = load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains(mentions), "{root}: {err}");
    }
}

/// A file given beside the CI file stands for an include whose inputs the
/// lint can't see (a template from another project, with the product's
/// images and runner tags): its required inputs read as empty, while the
/// same file included locally without them is refused, as GitLab refuses
/// it. A file it includes in turn gets no such leniency.
#[test]
fn a_stand_in_template_s_required_inputs_read_as_empty() {
    let required = "spec:\n  inputs:\n    image: {}\n    tags: {type: array}\n---\n\
                    seaworthy-publish:\n  image: $[[ inputs.image ]]\n  tags: $[[ inputs.tags ]]\n  script: [p]\n";
    let dir = repo(&[
        ("ci/template.yml", required),
        (
            ".gitlab-ci.yml",
            "web: {script: [w]}\nserver: {needs: [seaworthy-publish, web], script: [d]}\n",
        ),
    ]);
    let report = lint_with(
        dir.path(),
        &[dir.path().join("ci/template.yml")],
        &["server"],
        &["seaworthy-publish", "web"],
    );
    ok(&report);
    let pipeline = load(
        dir.path(),
        &dir.path().join(".gitlab-ci.yml"),
        &[dir.path().join("ci/template.yml")],
    )
    .unwrap();
    let publish = pipeline.jobs.get("seaworthy-publish").unwrap();
    assert_eq!(publish.get("image").and_then(|i| i.text()), Some(""));
    // Included locally, the product must give them.
    let dir = repo(&[
        ("ci/template.yml", required),
        (
            ".gitlab-ci.yml",
            "include: [{local: ci/template.yml}]\nserver: {needs: [seaworthy-publish], script: [d]}\n",
        ),
    ]);
    let err = load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("input \"image\" has no default and isn't given"),
        "{err}"
    );
    // A stand-in's own include is read as written.
    let dir = repo(&[
        ("ci/inner.yml", required),
        ("ci/outer.yml", "include: [{local: ci/inner.yml}]\n"),
        (".gitlab-ci.yml", "server: {script: [d]}\n"),
    ]);
    let err = load(
        dir.path(),
        &dir.path().join(".gitlab-ci.yml"),
        &[dir.path().join("ci/outer.yml")],
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("has no default and isn't given"), "{err}");
}

#[test]
fn the_seaworthy_template_orders_itself_and_a_product_that_needs_it_passes() {
    // seaworthy's own template, as a product's server deploy would include it.
    let template = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ci/gitlab/seaworthy.yml");
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "stages: [check, build, package, publish, deploy]\n\
         web: {stage: publish, script: [w]}\n\
         server: {stage: deploy, needs: [seaworthy-publish, web], script: [d]}\n\
         early: {stage: deploy, needs: [seaworthy-package], script: [d]}\n",
    )]);
    let pipeline = load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[template]).unwrap();
    ok(&check(
        &pipeline,
        &names(&["server"]),
        &names(&["seaworthy-publish", "web"]),
    ));
    refused(
        &check(
            &pipeline,
            &names(&["early"]),
            &names(&["seaworthy-publish"]),
        ),
        "server job \"early\" can deploy before client job \"seaworthy-publish\"",
    );
}

#[test]
fn files_that_arent_ci_configurations_are_refused() {
    for (text, mentions) in [
        ("a: [unclosed\n", "not YAML"),
        ("- a\n- b\n", "isn't a mapping"),
        ("a: 1\n---\nb: 2\n", "more than one YAML document"),
        ("a: *nowhere\n", "not YAML"),
    ] {
        let dir = repo(&[(".gitlab-ci.yml", text)]);
        let err = load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains(mentions), "{text:?}: {err}");
        assert!(err.starts_with("CI configuration: "), "{err}");
    }
}

#[test]
fn the_command_reports_and_exits_like_every_command() {
    let run = |dir: &Path, args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
            .current_dir(dir)
            .arg("ci-order")
            .args(args)
            .output()
            .unwrap();
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "include: [{remote: 'https://example.com/x.yml'}]\n\
         publish: {script: [p]}\nweb: {script: [w]}\n\
         server: {needs: [publish, web], script: [d]}\nlazy: {needs: [publish], script: [d]}\n",
    )]);
    let (code, text) = run(
        dir.path(),
        &[
            "--ci",
            ".gitlab-ci.yml",
            "--server",
            "server",
            "--client",
            "publish, web",
        ],
    );
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("release order: server waits for publish, web"),
        "{text}"
    );
    assert!(
        text.contains("warning: include not read (remote: https://example.com/x.yml)"),
        "{text}"
    );
    let (code, text) = run(
        dir.path(),
        &[
            "--ci",
            ".gitlab-ci.yml",
            "--server",
            "server,lazy",
            "--client",
            "publish,web",
        ],
    );
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("release order: 1 problem(s)"), "{text}");
    assert!(
        text.contains("\"lazy\" can deploy before client job \"web\""),
        "{text}"
    );
    let (code, text) = run(
        dir.path(),
        &[
            "--ci",
            ".gitlab-ci.yml",
            "--server",
            "",
            "--client",
            "publish",
        ],
    );
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("no server deploy job named"), "{text}");
    let (code, text) = run(
        dir.path(),
        &["--ci", ".gitlab-ci.yml", "--client", "publish"],
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("ci-order needs --server and --client"),
        "{text}"
    );
    let (code, text) = run(
        dir.path(),
        &["--ci", "absent.yml", "--server", "s", "--client", "c"],
    );
    assert_eq!(code, Some(1), "{text}");
}

#[test]
fn later_parents_and_the_including_file_win() {
    // extends: each parent in order, the later winning; the job's own keys
    // last.
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "publish: {script: [p]}\nweb: {script: [w]}\n\
         .early: {needs: [publish]}\n.late: {needs: [publish, web]}\n\
         server: {extends: [.early, .late], script: [d]}\n\
         backwards: {extends: [.late, .early], script: [d]}\n",
    )]);
    let pipeline = load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[]).unwrap();
    ok(&check(&pipeline, &names(&["server"]), &names(&CLIENTS)));
    refused(
        &check(&pipeline, &names(&["backwards"]), &names(&CLIENTS)),
        "\"backwards\" can deploy before client job \"web\"",
    );
    // The including file's keys win over an include's; a later include's
    // over an earlier one's.
    let dir = repo(&[
        (
            ".gitlab-ci.yml",
            "include: [a.yml, b.yml]\npublish: {script: [p]}\nweb: {script: [w]}\n\
             server: {needs: [publish, web]}\n",
        ),
        (
            "a.yml",
            "server: {needs: [publish], script: [d]}\nother: {needs: [publish, web], script: [o]}\n",
        ),
        ("b.yml", "other: {needs: [publish], script: [o]}\n"),
    ]);
    let pipeline = load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[]).unwrap();
    ok(&check(&pipeline, &names(&["server"]), &names(&CLIENTS)));
    refused(
        &check(&pipeline, &names(&["other"]), &names(&CLIENTS)),
        "\"other\" can deploy before client job \"web\"",
    );
    // `needs:` with no value is no needs at all.
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "publish: {script: [p]}\nweb: {script: [w]}\nserver:\n  needs:\n  script: [d]\n",
    )]);
    refused(
        &lint(dir.path(), &["server"], &CLIENTS),
        "it has needs: [], so it starts at once",
    );
}

#[test]
fn gitlab_s_limits_bound_every_walk() {
    // 151 included files.
    let mut files: Vec<(String, String)> = (0..151)
        .map(|n| {
            (
                format!("ci/{n:03}.yml"),
                format!("job{n}: {{script: [x]}}\n"),
            )
        })
        .collect();
    files.push((".gitlab-ci.yml".into(), "include: ci/*.yml\n".into()));
    let borrowed: Vec<(&str, &str)> = files
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let dir = repo(&borrowed);
    let err = load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[])
        .unwrap_err()
        .to_string();
    assert!(err.contains("more than 150 CI files included"), "{err}");
    // 150 is fine (the root and 149 includes).
    let mut files: Vec<(String, String)> = (0..149)
        .map(|n| {
            (
                format!("ci/{n:03}.yml"),
                format!("job{n}: {{script: [x]}}\n"),
            )
        })
        .collect();
    files.push((".gitlab-ci.yml".into(), "include: ci/*.yml\n".into()));
    let borrowed: Vec<(&str, &str)> = files
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let dir = repo(&borrowed);
    assert_eq!(
        load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[])
            .unwrap()
            .jobs
            .len(),
        149
    );
    // An extends chain 12 deep; 11 is fine.
    for (depth, refused) in [(12, true), (11, false)] {
        let mut text = String::from(".j0: {script: [x]}\n");
        for n in 1..depth {
            text.push_str(&format!(".j{n}: {{extends: .j{}}}\n", n - 1));
        }
        text.push_str(&format!("job: {{extends: .j{}}}\n", depth - 1));
        let dir = repo(&[(".gitlab-ci.yml", &text)]);
        let result = load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[]);
        assert_eq!(result.is_err(), refused, "depth {depth}: {result:?}");
        if let Err(e) = result {
            assert!(
                e.to_string().contains("extends nested past 11 levels"),
                "{e}"
            );
        }
    }
}

#[test]
fn a_rule_s_needs_replace_the_job_s() {
    // A tag pipeline's rule empties the server's needs: it starts at once.
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "publish: {script: [p]}\nweb: {script: [w]}\n\
         server:\n  needs: [publish, web]\n  rules:\n    - if: $CI_COMMIT_TAG\n      needs: []\n    - when: on_success\n  script: [d]\n",
    )]);
    refused(
        &lint(dir.path(), &["server"], &CLIENTS),
        "has needs: [], so it starts at once (counting every rule's needs",
    );
    // A later rule that drops a client, the first one complete.
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "publish: {script: [p]}\nweb: {script: [w]}\n\
         server:\n  rules:\n    - if: $CI_COMMIT_TAG\n      needs: [publish, web]\n\
         \x20   - if: $CI_COMMIT_BRANCH\n      needs: [publish]\n  script: [d]\n",
    )]);
    refused(
        &lint(dir.path(), &["server"], &CLIENTS),
        "server job \"server\" can deploy before client job \"web\"",
    );
    // Every runnable rule's needs reach the clients (a `when: never` rule
    // doesn't run, and a rule without needs keeps the job's).
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "publish: {script: [p]}\nweb: {script: [w]}\n\
         server:\n  needs: [publish, web]\n  rules:\n    - if: $SKIP\n      when: never\n      needs: []\n\
         \x20   - if: $CI_COMMIT_TAG\n      needs: [web, publish, other]\n    - when: on_success\n  script: [d]\n\
         other: {script: [o]}\n",
    )]);
    ok(&lint(dir.path(), &["server"], &CLIENTS));
    // An intermediate job's rule that drops a client.
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "publish: {script: [p]}\nweb: {script: [w]}\n\
         verify:\n  needs: [publish, web]\n  rules: [{if: $CI_COMMIT_TAG, needs: [publish]}]\n  script: [v]\n\
         server: {needs: [verify], script: [d]}\n",
    )]);
    refused(
        &lint(dir.path(), &["server"], &CLIENTS),
        "server job \"server\" can deploy before client job \"web\"",
    );
}

#[test]
fn yaml_reads_as_gitlab_s_parser_reads_it() {
    // YAML 1.1 booleans and !!bool, as GitLab reads them.
    for (client, needs, mentions) in [
        (
            "web: {script: [w]}",
            "[publish, {job: web, optional: yes}]",
            "needs it only with optional: true",
        ),
        (
            "web: {allow_failure: on, script: [w]}",
            "[publish, web]",
            "is allowed to fail",
        ),
        (
            "web: {allow_failure: !!bool \"true\", script: [w]}",
            "[publish, web]",
            "is allowed to fail",
        ),
        (
            "web: {allow_failure: YES, script: [w]}",
            "[publish, web]",
            "is allowed to fail",
        ),
    ] {
        let dir = repo(&[(
            ".gitlab-ci.yml",
            &format!(
                "publish: {{script: [p]}}\n{client}\nserver: {{needs: {needs}, script: [d]}}\n"
            ),
        )]);
        refused(&lint(dir.path(), &["server"], &CLIENTS), mentions);
    }
    // A string "true" is no boolean.
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "publish: {script: [p]}\nweb: {allow_failure: !!str yes, script: [w]}\nserver: {needs: [publish, web], script: [d]}\n",
    )]);
    ok(&lint(dir.path(), &["server"], &CLIENTS));
    // A merge after the needs overwrites them (Psych's document order).
    let dir = repo(&[(
        ".gitlab-ci.yml",
        ".nostart: &nostart {needs: []}\npublish: {script: [p]}\nweb: {script: [w]}\n\
         server:\n  needs: [publish, web]\n  <<: *nostart\n  script: [d]\n",
    )]);
    refused(
        &lint(dir.path(), &["server"], &CLIENTS),
        "has needs: [], so it starts at once",
    );
    // A key given twice keeps its last value.
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "publish: {script: [p]}\nweb: {script: [w]}\n\
         server: {needs: [publish, web]}\nserver: {stage: deploy, script: [d]}\n",
    )]);
    refused(&lint(dir.path(), &["server"], &CLIENTS), "has no needs");
    // A spec separator with a comment.
    let dir = repo(&[
        (
            "ci/t.yml",
            "spec:\n  inputs:\n    after: {default: web}\n--- # the configuration\n\
             publish:\n  needs:\n    - $[[ inputs.after ]]\n  script: [p]\n",
        ),
        (
            ".gitlab-ci.yml",
            "include: ci/t.yml\nweb: {script: [w]}\nserver: {needs: [publish], script: [d]}\n",
        ),
    ]);
    ok(&lint(dir.path(), &["server"], &CLIENTS));
}

#[test]
fn a_job_that_runs_past_failures_is_no_path() {
    for intermediate in [
        "verify: {needs: [publish, web], when: always, script: [v]}",
        "verify: {needs: [publish, web], rules: [{when: on_failure}], script: [v]}",
    ] {
        let dir = repo(&[(
            ".gitlab-ci.yml",
            &format!(
                "publish: {{script: [p]}}\nweb: {{script: [w]}}\n{intermediate}\nserver: {{needs: [verify], script: [d]}}\n"
            ),
        )]);
        refused(
            &lint(dir.path(), &["server"], &CLIENTS),
            "waits for it only through a job that runs when: always or on_failure",
        );
    }
    // A server that runs past failures is one finding: its own needs still
    // count (it reaches every client), only the `when` is wrong.
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "publish: {script: [p]}\nweb: {script: [w]}\nserver: {needs: [publish, web], when: always, script: [d]}\n",
    )]);
    let report = lint(dir.path(), &["server"], &CLIENTS);
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
    refused(&report, "server job \"server\" runs when: always");
    assert_eq!(report.ordered, vec![("server".to_owned(), names(&CLIENTS))]);
    // A trigger that mirrors its child's status waits for it.
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "publish: {trigger: {project: a/b, strategy: mirror}}\nweb: {script: [w]}\nserver: {needs: [publish, web], script: [d]}\n",
    )]);
    ok(&lint(dir.path(), &["server"], &CLIENTS));
}

#[test]
fn extends_resolve_before_references() {
    // `.base` gets its needs through extends; the reference sees them.
    let dir = repo(&[(
        ".gitlab-ci.yml",
        "publish: {script: [p]}\nweb: {script: [w]}\n\
         .needs: {needs: [publish, web]}\n.base: {extends: .needs, stage: deploy}\n\
         server: {needs: !reference [.base, needs], script: [d]}\n",
    )]);
    ok(&lint(dir.path(), &["server"], &CLIENTS));
}

#[test]
fn includes_gitlab_wouldn_t_read_never_count() {
    // An include with rules: refused (the lint can't tell when it applies).
    let dir = repo(&[
        (
            ".gitlab-ci.yml",
            "include: [{local: a.yml, rules: [{if: $X}]}]\n",
        ),
        ("a.yml", "x: {script: [x]}\n"),
    ]);
    let err = load(dir.path(), &dir.path().join(".gitlab-ci.yml"), &[])
        .unwrap_err()
        .to_string();
    assert!(err.contains("an include with rules"), "{err}");
    // In a git repository, a glob matches tracked files only: GitLab reads
    // the commit, not the working tree.
    if !have_git() {
        return;
    }
    let dir = repo(&[
        (
            ".gitlab-ci.yml",
            "include: ci/*.yml\npublish: {script: [p]}\nweb: {script: [w]}\n",
        ),
        (
            "ci/deploy.yml",
            "server: {needs: [publish, web], script: [d]}\n",
        ),
        ("ci/untracked.yml", "server: {needs: [], script: [d]}\n"),
    ]);
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .current_dir(dir.path())
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["add", ".gitlab-ci.yml", "ci/deploy.yml"]);
    ok(&lint(dir.path(), &["server"], &CLIENTS));
}

fn have_git() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}
