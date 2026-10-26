//! `seaworthy build-plan`: the build each target triple
//! needs, from `seaworthy.toml` — what's built where, with which flags, and
//! where each binary lands in the artifact directory — and its text form.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::process::Command;

use seaworthy::build_plan::{Step, plan, plan_for, render};
use seaworthy::config::Config;

const CONFIG: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
maintainer = "Acme Packaging <pkg@acme.test>"
license = "MIT"

[product.agent]
display-name = "Acme Agent"
description = "Collects things for Acme."
launcher = "crates/agent/launcher"
executable = "AcmeTool"
core = "acme_agent_core"
helper = "AcmeToolUpdate"
windows-directory = "Agent"
sidecars.windows = ["aws_lc_fips_*_crypto.dll", "aws_lc_fips_*_rust_wrapper.dll"]
outputs = ["msi", "zip", "deb", "tar"]

[product.agent.service]
name = "AcmeAgent"
account = "virtual"
arguments = ["service"]
state-directory = "acme/agent"

[product.agent.service.sandbox]
user = "acme-agent"

[product.console]
display-name = "Acme Console"
description = "The Acme console."
launcher = "crates/agent/launcher"
executable = "AcmeTool"
core = "acme_agent_core"
helper = "AcmeToolUpdate"
kind = "desktop"
windows-directory = "Console"
outputs = ["deb"]
"#;

fn build(dir: &str, flags: &[&str], args: &[&str]) -> Step {
    Step::Build {
        target_dir: dir.to_owned(),
        rustflags: flags.iter().map(|s| (*s).to_owned()).collect(),
        args: args.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn copy(from: &str, to: &str) -> Step {
    Step::Copy {
        from: from.to_owned(),
        to: to.to_owned(),
    }
}

#[test]
fn linux_builds_the_launcher_and_helper_once_and_each_core_per_cpu() {
    let config = Config::parse(CONFIG).unwrap();
    let linux = "x86_64-unknown-linux-gnu";
    // Two products sharing a launcher, a helper and a core: each step once.
    assert_eq!(
        plan(&config, linux, None).unwrap(),
        [
            build(
                "base",
                &[],
                &[
                    "--bin",
                    "AcmeTool",
                    "--manifest-path",
                    "crates/agent/launcher/Cargo.toml"
                ]
            ),
            copy(
                "base/x86_64-unknown-linux-gnu/release/AcmeTool",
                "x86_64-unknown-linux-gnu/launcher/AcmeTool"
            ),
            build("base", &[], &["--bin", "AcmeToolUpdate"]),
            copy(
                "base/x86_64-unknown-linux-gnu/release/AcmeToolUpdate",
                "x86_64-unknown-linux-gnu/helper/AcmeToolUpdate"
            ),
            build(
                "x86-64-v3",
                &["-C", "target-cpu=x86-64-v3"],
                &["-p", "acme_agent_core"]
            ),
            copy(
                "x86-64-v3/x86_64-unknown-linux-gnu/release/libacme_agent_core.so",
                "x86_64-unknown-linux-gnu/cores/x86-64-v3/libacme_agent_core.so"
            ),
            build(
                "x86-64-v2",
                &["-C", "target-cpu=x86-64-v2"],
                &["-p", "acme_agent_core"]
            ),
            copy(
                "x86-64-v2/x86_64-unknown-linux-gnu/release/libacme_agent_core.so",
                "x86_64-unknown-linux-gnu/cores/x86-64-v2/libacme_agent_core.so"
            ),
        ]
    );
}

#[test]
fn windows_adds_the_extension_and_the_sidecars_beside_each_core() {
    let config = Config::parse(CONFIG).unwrap();
    let windows = "x86_64-pc-windows-msvc";
    let steps = plan(&config, windows, None).unwrap();
    // Only the agent has Windows outputs.
    assert!(steps.contains(&copy(
        "base/x86_64-pc-windows-msvc/release/AcmeTool.exe",
        "x86_64-pc-windows-msvc/launcher/AcmeTool.exe"
    )));
    assert!(steps.contains(&copy(
        "x86-64-v3/x86_64-pc-windows-msvc/release/acme_agent_core.dll",
        "x86_64-pc-windows-msvc/cores/x86-64-v3/acme_agent_core.dll"
    )));
    // Every core gets the module DLL of the FIRST CPU target's build (one
    // module binary per release: MSVC builds aren't byte-reproducible across
    // target directories); nothing copies from another CPU's build.
    for (cpu, pattern) in [
        ("x86-64-v3", "aws_lc_fips_*_crypto.dll"),
        ("x86-64-v3", "aws_lc_fips_*_rust_wrapper.dll"),
        ("x86-64-v2", "aws_lc_fips_*_crypto.dll"),
        ("x86-64-v2", "aws_lc_fips_*_rust_wrapper.dll"),
    ] {
        assert!(
            steps.contains(&Step::Sidecars {
                directory: "x86-64-v3/x86_64-pc-windows-msvc/release/build".to_owned(),
                pattern: pattern.to_owned(),
                to: format!("x86_64-pc-windows-msvc/cores/{cpu}"),
            }),
            "{cpu} {pattern}"
        );
    }
    assert!(
        !steps.iter().any(
            |s| matches!(s, Step::Sidecars { directory, .. } if directory.starts_with("x86-64-v2/"))
        ),
        "{steps:#?}"
    );
    // Every Windows build links the C runtime statically (verify refuses
    // vcruntime imports): the launcher's, the helper's and each core's.
    let builds: Vec<&Vec<String>> = steps
        .iter()
        .filter_map(|s| match s {
            Step::Build { rustflags, .. } => Some(rustflags),
            _ => None,
        })
        .collect();
    assert!(builds.len() >= 3, "{steps:#?}");
    for flags in &builds {
        assert!(
            flags
                .windows(2)
                .any(|w| w == ["-C", "target-feature=+crt-static"]),
            "{flags:?}"
        );
    }
    assert!(
        steps.contains(&build(
            "x86-64-v3",
            &[
                "-C",
                "target-cpu=x86-64-v3",
                "-C",
                "target-feature=+crt-static"
            ],
            &["-p", "acme_agent_core"]
        )),
        "{steps:#?}"
    );
    // The launcher and helper (target directory `base`) link with their
    // imports restricted to their directory and System32; the cores, which
    // the launcher loads with explicit search flags, don't need it.
    for step in &steps {
        if let Step::Build {
            target_dir,
            rustflags,
            ..
        } = step
        {
            let restricted = rustflags
                .windows(2)
                .any(|w| w == ["-C", "link-arg=/DEPENDENTLOADFLAG:0xA00"]);
            assert_eq!(restricted, target_dir == "base", "{step:?}");
        }
    }
    // Linux builds don't take it (glibc's static linking is another matter).
    for step in plan(&config, "x86_64-unknown-linux-gnu", None).unwrap() {
        if let Step::Build { rustflags, .. } = step {
            assert!(
                !rustflags
                    .iter()
                    .any(|f| f.contains("crt-static") || f.contains("DEPENDENTLOADFLAG")),
                "{rustflags:?}"
            );
        }
    }
    // Sidecars come after their core's copy.
    let core = steps
        .iter()
        .position(
            |s| matches!(s, Step::Copy { to, .. } if to.ends_with("x86-64-v3/acme_agent_core.dll")),
        )
        .unwrap();
    let sidecar = steps
        .iter()
        .position(|s| matches!(s, Step::Sidecars { to, .. } if to.ends_with("x86-64-v3")))
        .unwrap();
    assert!(core < sidecar);
}

/// Products share the per-CPU target directories (and the artifacts'
/// `cores/<cpu>`): the FIPS DLL pair is copied once per CPU, after EVERY
/// product's core built there, so the copy's one-set-of-bytes check sees
/// each product's build (found with Acme's collector and console:
/// the pair was copied after the first product's core alone).
#[test]
fn the_sidecars_are_copied_once_after_every_product_s_cores() {
    let two = CONFIG
        .replace(
            "outputs = [\"deb\"]\n",
            "outputs = [\"zip\"]\nsidecars.windows = [\"aws_lc_fips_*_crypto.dll\", \"aws_lc_fips_*_rust_wrapper.dll\"]\n",
        )
        .replace(
            "executable = \"AcmeTool\"\ncore = \"acme_agent_core\"\nhelper = \"AcmeToolUpdate\"\nkind = \"desktop\"",
            "executable = \"AcmeConsole\"\ncore = \"acme_console_core\"\nkind = \"desktop\"\nupdates.default = \"off\"",
        )
        .replace(
            "description = \"The Acme console.\"\nlauncher = \"crates/agent/launcher\"",
            "description = \"The Acme console.\"\nlauncher = \"crates/console/launcher\"",
        );
    let config = Config::parse(&two).unwrap();
    let steps = plan(&config, "x86_64-pc-windows-msvc", None).unwrap();
    let last_core_build = steps
        .iter()
        .rposition(
            |s| matches!(s, Step::Build { args, .. } if args.first().is_some_and(|a| a == "-p")),
        )
        .unwrap();
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, Step::Build { args, .. } if args == &["-p", "acme_console_core"])),
        "both products' cores are built"
    );
    let sidecars: Vec<usize> = steps
        .iter()
        .enumerate()
        .filter(|(_, s)| matches!(s, Step::Sidecars { .. }))
        .map(|(i, _)| i)
        .collect();
    // Two CPUs × two patterns, each once, all after the last core build.
    assert_eq!(sidecars.len(), 4, "{steps:#?}");
    assert!(sidecars.iter().all(|&i| i > last_core_build), "{steps:#?}");
}

#[test]
fn a_triple_no_product_needs_has_no_plan_and_one_product_can_be_chosen() {
    let config = Config::parse(&CONFIG.replace(
        "outputs = [\"msi\", \"zip\", \"deb\", \"tar\"]",
        "outputs = [\"deb\", \"tar\"]",
    ))
    .unwrap();
    assert!(
        plan(&config, "x86_64-pc-windows-msvc", None)
            .unwrap()
            .is_empty()
    );
    let err = plan(&config, "x86_64-pc-windows-msvc", Some("agent"))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("product \"agent\" has no x86_64-pc-windows-msvc output"),
        "{err}"
    );
    let err = plan(&config, "x86_64-unknown-linux-gnu", Some("nope"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("no product \"nope\""), "{err}");
    let err = plan(&config, "aarch64-unknown-linux-gnu", None)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("no build plan for \"aarch64-unknown-linux-gnu\""),
        "{err}"
    );
    // A product without a helper or a launcher path.
    let bare = Config::parse(
        &CONFIG
            .replace("launcher = \"crates/agent/launcher\"\n", "")
            .replace(
                "helper = \"AcmeToolUpdate\"\n",
                "updates.default = \"off\"\n",
            ),
    )
    .unwrap();
    let steps = plan(&bare, "x86_64-unknown-linux-gnu", Some("console")).unwrap();
    assert_eq!(steps[0], build("base", &[], &["--bin", "AcmeTool"]));
    // `--product` builds that product's binaries alone.
    let two = Config::parse(&CONFIG.replace(
        "executable = \"AcmeTool\"\ncore = \"acme_agent_core\"\nhelper = \"AcmeToolUpdate\"\nkind = \"desktop\"",
        "executable = \"AcmeConsole\"\ncore = \"acme_console_core\"\nhelper = \"AcmeToolUpdate\"\nkind = \"desktop\"",
    ))
    .unwrap();
    let console = plan(&two, "x86_64-unknown-linux-gnu", Some("console")).unwrap();
    assert!(
        console
            .iter()
            .all(|s| !format!("{s:?}").contains("AcmeTool\"")
                && !format!("{s:?}").contains("acme_agent_core")),
        "{console:#?}"
    );
    assert_eq!(
        plan(&two, "x86_64-unknown-linux-gnu", None).unwrap().len(),
        14
    );
    assert!(
        !steps
            .iter()
            .any(|s| matches!(s, Step::Copy { to, .. } if to.contains("/helper/")))
    );
}

/// The helper's crate (`helper-crate`): built from its own manifest, so it
/// gets its own features alone, not every workspace member's (a
/// helper beside a job server enabling reqwest's unstable `http3`); a path
/// that isn't plain is refused like the launcher's.
#[test]
fn the_helper_builds_from_its_crate_when_dist_toml_names_it() {
    let named = CONFIG.replacen(
        "helper = \"AcmeToolUpdate\"\n",
        "helper = \"AcmeToolUpdate\"\nhelper-crate = \"crates/agent/update\"\n",
        2,
    );
    let config = Config::parse(&named).unwrap();
    let steps = plan(&config, "x86_64-unknown-linux-gnu", None).unwrap();
    assert!(
        steps.contains(&build(
            "base",
            &[],
            &[
                "--bin",
                "AcmeToolUpdate",
                "--manifest-path",
                "crates/agent/update/Cargo.toml"
            ]
        )),
        "{steps:#?}"
    );
    // A crate for a helper that doesn't ship is refused.
    let off = named.replace(
        "helper = \"AcmeToolUpdate\"\nhelper-crate",
        "updates.default = \"off\"\nhelper-crate",
    );
    let err = Config::parse(&off).unwrap_err().to_string();
    assert!(err.contains("helper-crate"), "{err}");
    for bad in ["/abs/update", "../update", "crates/my update"] {
        let config = Config::parse(&named.replace("crates/agent/update", bad)).unwrap();
        let err = plan(&config, "x86_64-unknown-linux-gnu", None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("product.agent.helper-crate") && err.contains("plain segments"),
            "{bad}: {err}"
        );
    }
}

/// `seaworthy.toml`'s crate paths are relative to the workspace root, the
/// workspace manifest's directory, and the plan names them through it: the
/// builds run where that manifest is named from: a template built from
/// its repository's root (`templates/acme/Cargo.toml`) misses a bare
/// `crates/acme-device`.
#[test]
fn crate_paths_are_relative_to_the_workspace_manifest_s_directory() {
    let config = Config::parse(&CONFIG.replacen(
        "helper = \"AcmeToolUpdate\"\n",
        "helper = \"AcmeToolUpdate\"\nhelper-crate = \"crates/agent/update\"\n",
        2,
    ))
    .unwrap();
    let linux = "x86_64-unknown-linux-gnu";
    let manifests = |manifest: &str| -> Vec<String> {
        plan_for(&config, linux, None, std::path::Path::new(manifest))
            .unwrap()
            .into_iter()
            .filter_map(|step| match step {
                Step::Build { args, .. } => args
                    .iter()
                    .position(|a| a == "--manifest-path")
                    .map(|i| args[i + 1].clone()),
                Step::Copy { .. } | Step::Sidecars { .. } => None,
            })
            .collect()
    };
    for (manifest, root) in [
        ("Cargo.toml", ""),
        ("./Cargo.toml", ""),
        ("templates/acme/Cargo.toml", "templates/acme/"),
        ("../product/Cargo.toml", "../product/"),
        ("/builds/acme/product/Cargo.toml", "/builds/acme/product/"),
        ("/Cargo.toml", "/"),
    ] {
        assert_eq!(
            manifests(manifest),
            [
                format!("{root}crates/agent/launcher/Cargo.toml"),
                format!("{root}crates/agent/update/Cargo.toml"),
            ],
            "{manifest}"
        );
    }
    // `plan` is the current directory's workspace.
    assert_eq!(
        plan(&config, linux, None).unwrap(),
        plan_for(&config, linux, None, std::path::Path::new("Cargo.toml")).unwrap()
    );
    // A directory the plan's space-separated text can't carry is refused,
    // but only when a crate path needs it.
    for bad in [
        "my product/Cargo.toml",
        "product\t/Cargo.toml",
        "pr$oduct/Cargo.toml",
    ] {
        let err = plan_for(&config, linux, None, std::path::Path::new(bad))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("is in a directory the build plan can't name"),
            "{bad}: {err}"
        );
    }
    let bare =
        Config::parse(&CONFIG.replace("launcher = \"crates/agent/launcher\"\n", "")).unwrap();
    assert!(
        plan_for(
            &bare,
            linux,
            None,
            std::path::Path::new("my product/Cargo.toml")
        )
        .is_ok()
    );
}

#[test]
fn launcher_paths_that_arent_plain_are_refused() {
    for bad in [
        "/abs/launcher",
        "../launcher",
        "crates/my launcher",
        "a/./b",
    ] {
        let config = Config::parse(&CONFIG.replace("crates/agent/launcher", bad)).unwrap();
        let err = plan(&config, "x86_64-unknown-linux-gnu", None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("must be a relative path of plain segments"),
            "{bad}: {err}"
        );
    }
}

#[test]
fn the_text_form_is_one_tab_separated_step_per_line() {
    let steps = [
        build("base", &[], &["--bin", "AcmeTool"]),
        build(
            "x86-64-v3",
            &["-C", "target-cpu=x86-64-v3"],
            &["-p", "core"],
        ),
        copy("a/b", "c/d"),
        Step::Sidecars {
            directory: "x/build".into(),
            pattern: "*.dll".into(),
            to: "t/cores/x".into(),
        },
    ];
    assert_eq!(
        render(&steps),
        "build\tbase\t-\t--bin AcmeTool\n\
         build\tx86-64-v3\t-C target-cpu=x86-64-v3\t-p core\n\
         copy\ta/b\tc/d\n\
         sidecars\tx/build\t*.dll\tt/cores/x\n"
    );
}

// Unix only: the plan names the workspace's paths in a shell-safe alphabet,
// which an absolute Windows path (a drive, backslashes, an 8.3 `~` name)
// never is; the reusable workflow plans on Linux, and the Windows lab plans
// from a relative checkout path.
#[cfg(unix)]
#[test]
fn the_command_prints_the_plan() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("seaworthy.toml"), CONFIG).unwrap();
    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
            .arg("build-plan")
            .arg("--config")
            .arg(dir.path().join("seaworthy.toml"))
            .arg("--manifest")
            .arg(dir.path().join("Cargo.toml"))
            .args(args)
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (code, stdout, stderr) = run(&["--triple", "x86_64-unknown-linux-gnu"]);
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(stdout.lines().count(), 8, "{stdout}");
    // The crate's manifest through the workspace manifest's directory.
    assert!(
        stdout.starts_with(&format!(
            "build\tbase\t-\t--bin AcmeTool --manifest-path {}/crates/agent/launcher/Cargo.toml\n",
            dir.path().display()
        )),
        "{stdout}"
    );
    let (code, _, stderr) = run(&[]);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("build-plan needs --triple"), "{stderr}");
    let (code, _, stderr) = run(&["--triple", "x86_64-pc-windows-msvc", "--product", "console"]);
    assert_eq!(code, Some(1), "{stderr}");
    // A product whose cargo configuration sets build.rustflags.
    std::fs::create_dir_all(dir.path().join(".git")).unwrap();
    std::fs::create_dir_all(dir.path().join(".cargo")).unwrap();
    std::fs::write(
        dir.path().join(".cargo/config.toml"),
        "[build]\nrustflags = [\"-Dwarnings\"]\n",
    )
    .unwrap();
    let (code, _, stderr) = run(&["--triple", "x86_64-unknown-linux-gnu"]);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("sets build.rustflags"), "{stderr}");
}

#[test]
fn two_products_building_one_artifact_differently_are_refused() {
    // The same executable from two launcher crates: the second's build would
    // overwrite the first's after its copy.
    let text = CONFIG.replacen(
        "launcher = \"crates/agent/launcher\"",
        "launcher = \"crates/console/launcher\"",
        2,
    );
    let text = text.replacen(
        "launcher = \"crates/console/launcher\"",
        "launcher = \"crates/agent/launcher\"",
        1,
    );
    let config = Config::parse(&text).unwrap();
    let err = plan(&config, "x86_64-unknown-linux-gnu", None)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(
            "two products build base/x86_64-unknown-linux-gnu/release/AcmeTool differently"
        ),
        "{err}"
    );
}

#[test]
fn a_helper_that_doesnt_ship_isnt_built() {
    // Named, but updates are off: the helper doesn't ship (inputs.rs).
    let config = Config::parse(&CONFIG.replacen(
        "outputs = [\"deb\"]\n",
        "outputs = [\"deb\"]\nupdates.default = \"off\"\n",
        1,
    ))
    .unwrap();
    let steps = plan(&config, "x86_64-unknown-linux-gnu", Some("console")).unwrap();
    assert!(
        !steps
            .iter()
            .any(|s| matches!(s, Step::Copy { to, .. } if to.contains("/helper/"))),
        "{steps:#?}"
    );
}

#[test]
fn a_product_s_build_rustflags_are_refused() {
    use seaworthy::build_plan::check_cargo_config;
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let crate_dir = repo.join("product");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::create_dir_all(crate_dir.join(".cargo")).unwrap();
    std::fs::write(crate_dir.join("Cargo.toml"), "[workspace]\n").unwrap();
    let manifest = crate_dir.join("Cargo.toml");
    // No configuration, or target flags (which join the per-CPU ones): fine.
    check_cargo_config(&manifest).unwrap();
    std::fs::write(
        crate_dir.join(".cargo/config.toml"),
        "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"--cfg\", \"x\"]\n",
    )
    .unwrap();
    check_cargo_config(&manifest).unwrap();
    // build.rustflags, beside the manifest or at the repository's root.
    std::fs::write(
        crate_dir.join(".cargo/config.toml"),
        "[build]\nrustflags = [\"--cfg\", \"x\"]\n",
    )
    .unwrap();
    let err = check_cargo_config(&manifest).unwrap_err().to_string();
    assert!(err.contains("sets build.rustflags"), "{err}");
    std::fs::remove_file(crate_dir.join(".cargo/config.toml")).unwrap();
    std::fs::create_dir_all(repo.join(".cargo")).unwrap();
    std::fs::write(
        repo.join(".cargo/config"),
        "build.rustflags = [\"-Dwarnings\"]\n",
    )
    .unwrap();
    // The path as the platform prints it, compared with `/` separators.
    let err = check_cargo_config(&manifest)
        .unwrap_err()
        .to_string()
        .replace('\\', "/");
    assert!(
        err.contains("repo/.cargo/config sets build.rustflags"),
        "{err}"
    );
    // Above the repository's root: the build image's, not read.
    std::fs::remove_file(repo.join(".cargo/config")).unwrap();
    std::fs::create_dir_all(dir.path().join(".cargo")).unwrap();
    std::fs::write(
        dir.path().join(".cargo/config.toml"),
        "[build]\nrustflags = [\"-Dwarnings\"]\n",
    )
    .unwrap();
    check_cargo_config(&manifest).unwrap();
    // A configuration that isn't TOML.
    std::fs::write(crate_dir.join(".cargo/config.toml"), "[build\n").unwrap();
    assert!(check_cargo_config(&manifest).is_err());
}
