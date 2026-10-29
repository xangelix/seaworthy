//! Several programs in one product (`[[product.<id>.programs]]`): what the
//! single-program keys mean in the new model, every rule refusing what it
//! should, the build plan (each program's launcher and per-CPU cores, each
//! core built with its program's features in a target directory of its
//! own), `verify` and `layout` over every program, the Linux packages'
//! links and menu entry, and the MSI's service and shortcuts.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::path::Path;

use common::{CPUS, Elf, LOADER, Pe, V2, cpulist, record, write};
use seaworthy::build_plan::{Step, plan, render};
use seaworthy::config::{Config, Program, Role};
use seaworthy::inputs::{LINUX, WINDOWS};
use seaworthy::layout::Role as FileRole;

const DEFAULTS: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
maintainer = "Acme Packaging <packages@example.com>"
license = "MIT"
"#;

/// A desktop product with a command-line program and an app, each core
/// built with its own features.
const TROVE: &str = r#"
[product.trove]
display-name = "Acme Trove"
description = "Packs and unpacks Trove archives."
kind = "desktop"
windows-directory = "Trove"
outputs = ["deb", "tar", "zip", "msi"]
updates.default = "off"
upgrade-code = "{2B4E6A80-1C3D-4F5E-8A7B-9C0D1E2F3A4B}"

[[product.trove.programs]]
executable = "trove"
launcher = "crates/trove/cli"
core = "trove_cli_core"
role = "cli"
features = ["fips"]
default-features = false

[[product.trove.programs]]
executable = "TroveGui"
launcher = "crates/trove/gui"
core = "trove_gui_core"
role = "gui"
features = ["gui", "fips"]

[product.trove.desktop]
categories = ["Utility"]
desktop-shortcut = true
"#;

fn parse(products: &str) -> Config {
    Config::parse(&format!("{DEFAULTS}{products}")).unwrap()
}

fn refused(products: &str, mentions: &str) {
    let err = Config::parse(&format!("{DEFAULTS}{products}"))
        .expect_err("must be refused")
        .to_string();
    assert!(err.contains(mentions), "expected {mentions:?} in: {err}");
}

fn edit(from: &str, to: &str) -> String {
    assert!(TROVE.contains(from), "{from:?} not in the fixture");
    TROVE.replacen(from, to, 1)
}

#[test]
fn programs_resolve_in_order_with_their_roles_commands_and_features() {
    let config = parse(TROVE);
    let programs = config.products["trove"].programs();
    assert_eq!(
        programs,
        [
            Program {
                executable: "trove".into(),
                launcher: Some("crates/trove/cli".into()),
                // Its cargo binary is its executable unless named apart.
                launcher_bin: "trove".into(),
                core: "trove_cli_core".into(),
                role: Role::Cli,
                // A cli program is on PATH as its executable.
                linux_command: Some("trove".into()),
                macos_command: Some("trove".into()),
                features: vec!["fips".into()],
                default_features: false,
                bundled: false,
            },
            Program {
                executable: "TroveGui".into(),
                launcher: Some("crates/trove/gui".into()),
                launcher_bin: "TroveGui".into(),
                core: "trove_gui_core".into(),
                role: Role::Gui,
                // A gui program only when it names a command.
                linux_command: None,
                macos_command: None,
                // Sorted: the build's identity, whatever the order written.
                features: vec!["fips".into(), "gui".into()],
                default_features: true,
                bundled: true,
            },
        ]
    );
    let product = &config.products["trove"];
    assert_eq!(product.gui_program().unwrap().executable, "TroveGui");
    assert_eq!(product.service_program().unwrap().executable, "trove");
    assert_eq!(product.bundled_program().unwrap().executable, "TroveGui");
    // A command of its own.
    let named = parse(&edit(
        "role = \"gui\"",
        "role = \"gui\"\ncommand = \"trove-gui\"",
    ));
    let gui = named.products["trove"].gui_program().unwrap();
    assert_eq!(gui.linux_command.as_deref(), Some("trove-gui"));
    assert_eq!(gui.macos_command.as_deref(), Some("trove-gui"));
}

/// The single-program keys are one program: a gui program for a desktop
/// app, a cli program otherwise; `linux.command` stays Linux's link alone,
/// and the program stays in the macOS bundle (but a tool's, which has
/// none); its core builds with the crate's default features.
#[test]
fn the_single_program_keys_are_one_program() {
    let one = |kind: &str, extra: &str| {
        parse(&format!(
            "[product.one]\ndisplay-name = \"Acme One\"\ndescription = \"One.\"\nexecutable = \"AcmeOne\"\ncore = \"acme_one_core\"\nlauncher = \"crates/one\"\nkind = \"{kind}\"\noutputs = [\"deb\"]\nupdates.default = \"off\"\n{extra}"
        ))
        .products["one"]
            .programs()
    };
    let desktop = one("desktop", "linux.command = \"acme-one\"\n");
    assert_eq!(
        desktop,
        [Program {
            executable: "AcmeOne".into(),
            launcher: Some("crates/one".into()),
            launcher_bin: "AcmeOne".into(),
            core: "acme_one_core".into(),
            role: Role::Gui,
            linux_command: Some("acme-one".into()),
            macos_command: None,
            features: vec![],
            default_features: true,
            bundled: true,
        }]
    );
    assert!(desktop[0].default_build());
    assert_eq!(desktop[0].build_dir("x86-64-v3"), "x86-64-v3");
    assert!(desktop[0].feature_args().is_empty());
    let tool = one("tool", "");
    assert_eq!(tool[0].role, Role::Cli);
    assert_eq!(tool[0].linux_command, None);
    assert!(!tool[0].bundled);
    let service = one(
        "service",
        "[product.one.service]\nname = \"AcmeOne\"\naccount = \"local-system\"\n",
    );
    assert_eq!(service[0].role, Role::Cli);
    assert!(service[0].bundled);
}

#[test]
fn programs_are_validated() {
    // The two forms don't mix.
    for (key, line) in [
        ("executable", "executable = \"trove\""),
        ("core", "core = \"trove_core\""),
        ("launcher", "launcher = \"crates/trove\""),
        ("launcher-bin", "launcher-bin = \"trove-launcher\""),
        ("linux.command", "linux.command = \"trove\""),
    ] {
        refused(
            &edit(
                "windows-directory = \"Trove\"",
                &format!("windows-directory = \"Trove\"\n{line}"),
            ),
            &format!("product.trove.{key}: the single-program form's key"),
        );
    }
    // Without [[programs]], executable and core are required.
    refused(
        "[product.x]\ndisplay-name = \"X\"\ndescription = \"X.\"\ncore = \"x_core\"\nkind = \"tool\"\noutputs = [\"tar\"]\nupdates.default = \"off\"\n",
        "product.x.executable: required",
    );
    refused(
        "[product.x]\ndisplay-name = \"X\"\ndescription = \"X.\"\nexecutable = \"x\"\nkind = \"tool\"\noutputs = [\"tar\"]\nupdates.default = \"off\"\n",
        "product.x.core: required",
    );
    for (from, to, mentions) in [
        (
            "executable = \"TroveGui\"",
            "executable = \"TROVE\"",
            "programs[1].executable: \"TROVE\" is another program's executable too",
        ),
        (
            "core = \"trove_gui_core\"",
            "core = \"Trove_Cli_Core\"",
            "programs[1].core: \"Trove_Cli_Core\" is another program's core too",
        ),
        (
            "executable = \"TroveGui\"",
            "executable = \"NUL\"",
            "programs[1].executable: a file stem",
        ),
        (
            "core = \"trove_cli_core\"",
            "core = \"trove-cli\"",
            "programs[0].core: a crate name",
        ),
        (
            "role = \"cli\"",
            "role = \"gui\"",
            "programs[1].role: programs[0] is the product's gui program already",
        ),
        (
            "role = \"cli\"",
            "role = \"daemon\"",
            "unknown variant `daemon`",
        ),
        // A cli program's default command is its executable, which must
        // then be a command name.
        (
            "executable = \"trove\"",
            "executable = \"Trove\"",
            "programs[0].command: a cli program is put on PATH as its executable, and \"Trove\" isn't a command name",
        ),
        (
            "role = \"cli\"",
            "role = \"cli\"\ncommand = \"Trove\"",
            "programs[0].command: a command name",
        ),
        (
            "role = \"gui\"",
            "role = \"gui\"\ncommand = \"trove\"",
            "programs[1].command: \"trove\" is another program's command too",
        ),
        (
            "features = [\"fips\"]",
            "features = [\"fips,gui\"]",
            "programs[0].features: \"fips,gui\" isn't a cargo feature",
        ),
        (
            "features = [\"fips\"]",
            "features = [\"--all-features\"]",
            "isn't a cargo feature",
        ),
        (
            "features = [\"fips\"]",
            "features = [\"fips\", \"fips\"]",
            "programs[0].features: \"fips\" is listed twice",
        ),
        (
            "role = \"cli\"",
            "role = \"cli\"\nflavour = \"x\"",
            "unknown field `flavour`",
        ),
        // A launcher's cargo binary: a name cargo and the plan take, one
        // program's alone (each launcher names its own core), never the
        // helper's.
        (
            "role = \"cli\"",
            "role = \"cli\"\nlauncher-bin = \"trove launcher\"",
            "programs[0].launcher-bin: a cargo binary's name",
        ),
        (
            "role = \"cli\"",
            "role = \"cli\"\nlauncher-bin = \"CON\"",
            "programs[0].launcher-bin: a cargo binary's name",
        ),
        (
            "role = \"gui\"",
            "role = \"gui\"\nlauncher-bin = \"Trove\"",
            "programs[1].launcher-bin: \"Trove\" is another program's launcher binary too",
        ),
    ] {
        refused(&edit(from, to), mentions);
    }
    // `pkg/feature` and the full feature grammar are fine.
    parse(&edit(
        "features = [\"fips\"]",
        "features = [\"seaworthy-crypto/fips\", \"a_b+c.d-e\"]",
    ));
    // The helper is neither program.
    let err = Config::parse(&format!(
        "{}{}",
        DEFAULTS.replace(
            "[defaults]",
            "[defaults]\nrelease-signatures = [\"ml-dsa-87\"]"
        ),
        edit("updates.default = \"off\"", "helper = \"TROVEGUI\"")
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("different from every program's executable"),
        "{err}"
    );
    let err = Config::parse(&format!(
        "{}{}",
        DEFAULTS.replace(
            "[defaults]",
            "[defaults]\nrelease-signatures = [\"ml-dsa-87\"]"
        ),
        edit("updates.default = \"off\"", "helper = \"TroveUpdate\"").replace(
            "role = \"cli\"",
            "role = \"cli\"\nlauncher-bin = \"troveupdate\""
        )
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("programs[0].launcher-bin: the update helper's binary too"),
        "{err}"
    );
}

/// A launcher whose cargo binary is named apart from its executable (a
/// workspace whose development binary already holds that name): the plan
/// builds that binary and ships it as the executable, in either form.
#[test]
fn a_launcher_binary_named_apart_ships_as_the_executable() {
    let config = parse(&edit(
        "role = \"gui\"",
        "role = \"gui\"\nlauncher-bin = \"trove-gui-launcher\"",
    ));
    let gui = config.products["trove"].gui_program().unwrap();
    assert_eq!(gui.launcher_bin, "trove-gui-launcher");
    assert_eq!(gui.executable, "TroveGui");
    let steps = plan(&config, WINDOWS, None).unwrap();
    let launcher = steps
        .iter()
        .position(|step| matches!(step, Step::Build { args, .. } if args.contains(&"trove-gui-launcher".to_owned())))
        .expect("the gui launcher's build");
    let Step::Build { args, .. } = &steps[launcher] else {
        unreachable!()
    };
    assert_eq!(&args[..2], ["--bin", "trove-gui-launcher"]);
    assert_eq!(
        steps[launcher + 1],
        copy(
            "base/x86_64-pc-windows-msvc/release/trove-gui-launcher.exe",
            "x86_64-pc-windows-msvc/launcher/TroveGui.exe",
        )
    );
    // The single-program form's key alike.
    let one = parse(
        "[product.one]\ndisplay-name = \"Acme One\"\ndescription = \"One.\"\nexecutable = \"acme-one\"\nlauncher-bin = \"acme-one-launcher\"\ncore = \"acme_one_core\"\nkind = \"tool\"\noutputs = [\"deb\"]\nupdates.default = \"off\"\n",
    );
    let steps = plan(&one, LINUX, None).unwrap();
    assert_eq!(
        steps[..2],
        [
            build("base", &[], &["--bin", "acme-one-launcher"]),
            copy(
                "base/x86_64-unknown-linux-gnu/release/acme-one-launcher",
                "x86_64-unknown-linux-gnu/launcher/acme-one",
            ),
        ]
    );
}

/// The menu entry and the shortcuts are the gui program's: a product
/// without one has none, whatever its kind; a desktop app may hold a cli
/// program, and a tool a gui program.
#[test]
fn the_desktop_section_needs_a_gui_program_whatever_the_kind() {
    refused(
        &edit("role = \"gui\"", "role = \"cli\"\ncommand = \"trove-gui\""),
        "product.trove.desktop: only a desktop app",
    );
    let tool = parse(&edit("kind = \"desktop\"", "kind = \"tool\""));
    assert_eq!(
        tool.products["trove"].gui_program().unwrap().executable,
        "TroveGui"
    );
    // A desktop app of cli programs alone, without a menu entry.
    let cli_only = parse(
        &edit("role = \"gui\"", "role = \"cli\"\ncommand = \"trove-gui\"").replace(
            "[product.trove.desktop]\ncategories = [\"Utility\"]\ndesktop-shortcut = true\n",
            "",
        ),
    );
    assert!(cli_only.products["trove"].gui_program().is_none());
}

/// Two products putting one command on PATH collide, whichever form names
/// it.
#[test]
fn a_command_is_one_products() {
    refused(
        &format!(
            "{TROVE}\n[product.legacy]\ndisplay-name = \"Acme Legacy\"\ndescription = \"x\"\nexecutable = \"Legacy\"\ncore = \"legacy_core\"\nkind = \"tool\"\noutputs = [\"deb\"]\nupdates.default = \"off\"\nlinux.command = \"trove\"\n"
        ),
        "share linux.command \"trove\"",
    );
}

/// A cli program on macOS installs from a pkg (its tool directory, its
/// link): the dmg holds the app bundle alone.
#[test]
fn a_cli_program_ships_on_macos_in_a_pkg() {
    let macos = |outputs: &str| {
        edit(
            "outputs = [\"deb\", \"tar\", \"zip\", \"msi\"]",
            &format!("outputs = [{outputs}]"),
        ) + "\n[product.trove.macos]\nbundle-id = \"com.example.trove\"\n"
    };
    refused(
        &macos("\"dmg\""),
        "its cli programs, and their PATH links, need a pkg",
    );
    parse(&macos("\"pkg\""));
}

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

/// Each program's launcher once in `base`; each core once per CPU, built
/// with its program's features in its own target directory (named for the
/// CPU and the feature set), landing in that directory under `cores/`.
#[test]
fn the_plan_builds_each_programs_launcher_and_cores_with_its_features() {
    let config = parse(TROVE);
    let programs = config.products["trove"].programs();
    let cli = programs[0].build_dir("x86-64-v3");
    let gui = programs[1].build_dir("x86-64-v3");
    assert!(
        cli.starts_with("x86-64-v3.f") && cli.len() == "x86-64-v3.f".len() + 8,
        "{cli}"
    );
    assert_ne!(cli, gui, "two feature sets, two target directories");
    // The digest is the feature set's: the order written doesn't count.
    assert_eq!(
        programs[1].build_dir("x86-64-v2"),
        parse(&edit("[\"gui\", \"fips\"]", "[\"fips\", \"gui\"]")).products["trove"].programs()[1]
            .build_dir("x86-64-v2")
    );
    let dir = |program: usize, cpu: &str| programs[program].build_dir(cpu);
    let steps = plan(&config, LINUX, None).unwrap();
    let mut expected = vec![
        build(
            "base",
            &[],
            &[
                "--bin",
                "trove",
                "--manifest-path",
                "crates/trove/cli/Cargo.toml",
            ],
        ),
        copy(
            "base/x86_64-unknown-linux-gnu/release/trove",
            "x86_64-unknown-linux-gnu/launcher/trove",
        ),
        build(
            "base",
            &[],
            &[
                "--bin",
                "TroveGui",
                "--manifest-path",
                "crates/trove/gui/Cargo.toml",
            ],
        ),
        copy(
            "base/x86_64-unknown-linux-gnu/release/TroveGui",
            "x86_64-unknown-linux-gnu/launcher/TroveGui",
        ),
    ];
    for (program, core, features) in [
        (
            0,
            "trove_cli_core",
            &["--no-default-features", "--features", "fips"][..],
        ),
        (1, "trove_gui_core", &["--features", "fips,gui"][..]),
    ] {
        for cpu in CPUS {
            let d = dir(program, cpu);
            let mut args = vec!["-p", core];
            args.extend(features);
            expected.push(build(&d, &["-C", &format!("target-cpu={cpu}")], &args));
            expected.push(copy(
                &format!("{d}/x86_64-unknown-linux-gnu/release/lib{core}.so"),
                &format!("x86_64-unknown-linux-gnu/cores/{d}/lib{core}.so"),
            ));
        }
    }
    assert_eq!(steps, expected);
    // The text form carries the feature flags as words of the cargo
    // arguments; the target directory is one word the scripts take as is.
    let text = render(&steps);
    assert!(
        text.contains(&format!(
            "build\t{}\t-C target-cpu=x86-64-v3\t-p trove_cli_core --no-default-features --features fips\n",
            dir(0, "x86-64-v3")
        )),
        "{text}"
    );
}

/// Three profile products of one CLI: the launcher builds once (the same
/// binary), each profile's core once per CPU in its feature set's
/// directory; two products building a core alike build it once.
#[test]
fn profiles_share_the_launcher_and_build_each_feature_set_once() {
    let profile = |id: &str, features: &str| {
        format!(
            "[product.{id}]\ndisplay-name = \"Acme Trove {id}\"\ndescription = \"x\"\nkind = \"tool\"\noutputs = [\"tar\"]\nupdates.default = \"off\"\n\n[[product.{id}.programs]]\nexecutable = \"trove\"\nlauncher = \"crates/trove/cli\"\ncore = \"trove_cli_core\"\nrole = \"cli\"\nfeatures = [{features}]\ndefault-features = false\n"
        )
    };
    // One installation can't hold two products' commands of one name
    // (`conflicts` lets profiles share one): distinct commands here.
    let text = [
        profile("fips", "\"fips\"")
            .replace("role = \"cli\"", "role = \"cli\"\ncommand = \"trove-fips\""),
        profile("aws-lc", "\"aws-lc\"").replace(
            "role = \"cli\"",
            "role = \"cli\"\ncommand = \"trove-aws-lc\"",
        ),
        profile("again", "\"aws-lc\"").replace(
            "role = \"cli\"",
            "role = \"cli\"\ncommand = \"trove-again\"",
        ),
    ]
    .join("\n");
    let config = parse(&text);
    let steps = plan(&config, LINUX, None).unwrap();
    let builds: Vec<&Step> = steps
        .iter()
        .filter(|s| matches!(s, Step::Build { .. }))
        .collect();
    // One launcher build, and two feature sets times two CPUs.
    assert_eq!(builds.len(), 1 + 2 * 2, "{steps:#?}");
    let fips = config.products["fips"].programs()[0].build_dir("x86-64-v2");
    let aws = config.products["aws-lc"].programs()[0].build_dir("x86-64-v2");
    assert_eq!(
        aws,
        config.products["again"].programs()[0].build_dir("x86-64-v2")
    );
    for d in [&fips, &aws] {
        assert!(steps.contains(&copy(
            &format!("{d}/x86_64-unknown-linux-gnu/release/libtrove_cli_core.so"),
            &format!("x86_64-unknown-linux-gnu/cores/{d}/libtrove_cli_core.so"),
        )));
    }
}

/// The FIPS module's DLL ships beside every core of the product, all
/// from its first program's first CPU build: one module binary, which
/// `verify` holds every copy to.
#[test]
fn the_sidecars_come_from_the_first_programs_first_build() {
    let config = parse(&edit(
        "updates.default = \"off\"",
        "updates.default = \"off\"\nsidecars.windows = [\"aws_lc_fips_*_crypto.dll\"]",
    ));
    let programs = config.products["trove"].programs();
    let steps = plan(&config, WINDOWS, None).unwrap();
    let sidecars: Vec<&Step> = steps
        .iter()
        .filter(|s| matches!(s, Step::Sidecars { .. }))
        .collect();
    let first = programs[0].build_dir("x86-64-v3");
    let mut expected = Vec::new();
    for program in &programs {
        for cpu in CPUS {
            expected.push(Step::Sidecars {
                directory: format!("{first}/x86_64-pc-windows-msvc/release/build"),
                pattern: "aws_lc_fips_*_crypto.dll".into(),
                to: format!("x86_64-pc-windows-msvc/cores/{}", program.build_dir(cpu)),
            });
        }
    }
    assert_eq!(sidecars, expected.iter().collect::<Vec<_>>());
    // After every core build.
    let last_build = steps
        .iter()
        .rposition(|s| matches!(s, Step::Build { .. }))
        .unwrap();
    let first_sidecar = steps
        .iter()
        .position(|s| matches!(s, Step::Sidecars { .. }))
        .unwrap();
    assert!(last_build < first_sidecar);
}

/// Every program's binaries in the artifact directory, for Linux and
/// Windows: each launcher's `.cpulist` names its own core (or `wrong`'s
/// core for `wrong_core`), each core sits in its build's directory.
fn artifacts(config: &Config, id: &str, root: &Path, wrong_core: Option<&str>) {
    for program in config.products[id].programs() {
        let core = wrong_core
            .filter(|_| program.role == Role::Gui)
            .unwrap_or(&program.core);
        let list = cpulist(core, &CPUS);
        write(
            root,
            &format!("{LINUX}/launcher/{}", program.executable),
            &Elf {
                sections: vec![(".cpulist".into(), list.clone())],
                needed: vec!["libc.so.6".into()],
                interp: Some(LOADER.into()),
                ..Elf::default()
            }
            .build(),
        );
        write(
            root,
            &format!("{WINDOWS}/launcher/{}.exe", program.executable),
            &Pe {
                sections: vec![(".cpulist".into(), list)],
                imports: vec!["kernel32.dll".into()],
                executable: true,
            }
            .build(),
        );
        for cpu in CPUS {
            let dir = program.build_dir(cpu);
            write(
                root,
                &format!("{LINUX}/cores/{dir}/lib{}.so", program.core),
                &Elf {
                    sections: vec![(".cpureq".into(), record(LINUX, cpu, V2))],
                    needed: vec!["libc.so.6".into()],
                    symbols: vec![("seaworthy_core_main".into(), true)],
                    ..Elf::default()
                }
                .build(),
            );
            write(
                root,
                &format!("{WINDOWS}/cores/{dir}/{}.dll", program.core),
                &Pe {
                    sections: vec![(".cpureq".into(), record(WINDOWS, cpu, V2))],
                    imports: vec!["kernel32.dll".into()],
                    executable: false,
                }
                .build(),
            );
        }
    }
}

fn lay_out(config: &Config, id: &str, dir: &Path) -> Vec<seaworthy::layout::Layout> {
    let input = dir.join("artifacts");
    artifacts(config, id, &input, None);
    let verified = seaworthy::verify::verify(config, id, &input).expect("verifies");
    assert_eq!(verified.platforms()[0].inputs.programs.len(), 2);
    seaworthy::layout::layout(
        config,
        id,
        &verified,
        &dir.join("dist"),
        seaworthy::layout::Options {
            strip: false,
            ..seaworthy::layout::Options::default()
        },
    )
    .expect("lays out")
}

/// `verify` checks every program: a launcher whose `.cpulist` names
/// another core, and a program's missing core, are findings.
#[test]
fn verify_checks_every_programs_launcher_and_cores() {
    let config = parse(TROVE);
    let dir = tempfile::tempdir().unwrap();
    artifacts(&config, "trove", dir.path(), Some("trove_cli_core"));
    let gui = config.products["trove"].programs()[1].clone();
    std::fs::remove_file(dir.path().join(format!(
        "{LINUX}/cores/{}/libtrove_gui_core.so",
        gui.build_dir("x86-64-v2")
    )))
    .unwrap();
    let err = seaworthy::verify::verify(&config, "trove", dir.path())
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("TroveGui: its .cpulist names core \"trove_cli_core\", seaworthy.toml says \"trove_gui_core\""),
        "{err}"
    );
    let missing = std::path::Path::new(&gui.build_dir("x86-64-v2")).join("libtrove_gui_core.so");
    assert!(err.contains(&missing.display().to_string()), "{err}");
}

#[test]
fn every_program_installs_beside_the_others() {
    let config = parse(TROVE);
    let dir = tempfile::tempdir().unwrap();
    let layouts = lay_out(&config, "trove", dir.path());
    let linux = layouts.iter().find(|l| l.triple == LINUX).unwrap();
    let files: Vec<(&str, &FileRole, Option<&str>)> = linux
        .files
        .iter()
        .map(|f| (f.install_path.as_str(), &f.role, f.program.as_deref()))
        .collect();
    let v3 = FileRole::Core {
        cpu: "x86-64-v3".into(),
    };
    let v2 = FileRole::Core {
        cpu: "x86-64-v2".into(),
    };
    assert_eq!(
        files,
        [
            ("/opt/acme/trove/trove", &FileRole::Launcher, Some("trove")),
            (
                "/opt/acme/trove/TroveGui",
                &FileRole::Launcher,
                Some("TroveGui")
            ),
            (
                "/opt/acme/trove/lib/libtrove_cli_core_x86-64-v3.so",
                &v3,
                Some("trove")
            ),
            (
                "/opt/acme/trove/lib/libtrove_cli_core_x86-64-v2.so",
                &v2,
                Some("trove")
            ),
            (
                "/opt/acme/trove/lib/libtrove_gui_core_x86-64-v3.so",
                &v3,
                Some("TroveGui")
            ),
            (
                "/opt/acme/trove/lib/libtrove_gui_core_x86-64-v2.so",
                &v2,
                Some("TroveGui")
            ),
        ]
    );
    assert_eq!(
        linux.launcher_of("TroveGui").unwrap().install_path,
        "/opt/acme/trove/TroveGui"
    );
    assert_eq!(linux.launchers().count(), 2);
    let windows = layouts.iter().find(|l| l.triple == WINDOWS).unwrap();
    let paths: Vec<&str> = windows
        .files
        .iter()
        .map(|f| f.install_path.as_str())
        .collect();
    assert_eq!(
        paths,
        [
            "Acme\\Trove\\trove.exe",
            "Acme\\Trove\\TroveGui.exe",
            "Acme\\Trove\\trove_cli_core_x86-64-v3.dll",
            "Acme\\Trove\\trove_cli_core_x86-64-v2.dll",
            "Acme\\Trove\\trove_gui_core_x86-64-v3.dll",
            "Acme\\Trove\\trove_gui_core_x86-64-v2.dll",
        ]
    );
    // layout.json names each launcher's and core's program.
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(windows.tree.parent().unwrap().join("layout.json")).unwrap(),
    )
    .unwrap();
    let programs: Vec<&str> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["program"].as_str().unwrap())
        .collect();
    assert_eq!(
        programs,
        [
            "trove", "TroveGui", "trove", "trove", "TroveGui", "TroveGui"
        ]
    );
}

/// The Linux packages link each cli program onto PATH and start the gui
/// program from the menu.
#[test]
fn the_linux_packages_link_each_command_and_the_menu_starts_the_gui_program() {
    let config = parse(&edit(
        "role = \"gui\"",
        "role = \"gui\"\ncommand = \"trove-gui\"",
    ));
    let dir = tempfile::tempdir().unwrap();
    let layouts = lay_out(&config, "trove", dir.path());
    let linux = layouts.iter().find(|l| l.triple == LINUX).unwrap();
    let package = seaworthy::linux::linux_package(&config, "trove", linux).unwrap();
    let links: Vec<(&str, &str)> = package
        .links
        .iter()
        .map(|l| (l.dst.as_str(), l.target.as_str()))
        .collect();
    assert_eq!(
        links,
        [
            ("/usr/bin/trove", "/opt/acme/trove/trove"),
            ("/usr/bin/trove-gui", "/opt/acme/trove/TroveGui"),
        ]
    );
    let entry = package
        .files
        .iter()
        .find(|f| f.dst == "/usr/share/applications/acme-trove.desktop")
        .unwrap();
    let seaworthy::linux::Source::Generated(text) = &entry.source else {
        panic!("generated");
    };
    assert!(
        text.contains("\nExec=/opt/acme/trove/TroveGui\nTryExec=/opt/acme/trove/TroveGui\n"),
        "{text}"
    );
}

/// The MSI's shortcuts start the gui program; every program's files are
/// components; adopt-msi's model reads the `.wxs` as it reads any.
#[test]
fn the_msi_shortcuts_start_the_gui_program() {
    let config = parse(TROVE);
    let dir = tempfile::tempdir().unwrap();
    let layouts = lay_out(&config, "trove", dir.path());
    let windows = layouts.iter().find(|l| l.triple == WINDOWS).unwrap();
    let wxs = seaworthy::wix::wxs(&config, "trove", windows, &common::release()).unwrap();
    seaworthy::msi_check::expected_from_wxs(&wxs).unwrap();
    let shortcuts: Vec<String> = wxs
        .lines()
        .filter(|l| l.contains("<Shortcut "))
        .map(str::to_owned)
        .collect();
    assert_eq!(shortcuts.len(), 2, "{shortcuts:#?}");
    let gui_file = wxs
        .lines()
        .find(|l| l.contains("<File ") && l.contains("TroveGui.exe"))
        .and_then(|l| l.split("Id=\"").nth(1))
        .and_then(|l| l.split('"').next())
        .unwrap()
        .to_owned();
    for shortcut in &shortcuts {
        assert!(
            shortcut.contains(&format!("Target=\"[#{gui_file}]\"")),
            "{shortcut}"
        );
    }
    for name in [
        "trove.exe",
        "TroveGui.exe",
        "trove_cli_core_x86-64-v3.dll",
        "trove_gui_core_x86-64-v2.dll",
    ] {
        assert!(wxs.contains(&format!("\\Acme\\Trove\\{name}\"")), "{name}");
    }
}

/// A service product's service runs its first program; the second is a
/// plain file beside it.
#[test]
fn a_services_first_program_is_the_service() {
    let config = parse(
        r#"
[product.agent]
display-name = "Acme Agent"
description = "Collects things."
windows-directory = "Agent"
outputs = ["msi", "deb"]
updates.default = "off"

[[product.agent.programs]]
executable = "AcmeAgent"
core = "acme_agent_core"
role = "cli"
command = "acme-agent"

[[product.agent.programs]]
executable = "AcmeCtl"
core = "acme_ctl_core"
role = "cli"
command = "acmectl"

[product.agent.service]
name = "AcmeAgent"
account = "local-system"
arguments = ["serve"]
"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let layouts = lay_out(&config, "agent", dir.path());
    let windows = layouts.iter().find(|l| l.triple == WINDOWS).unwrap();
    let wxs = seaworthy::wix::wxs(&config, "agent", windows, &common::release()).unwrap();
    seaworthy::msi_check::expected_from_wxs(&wxs).unwrap();
    // The service's component is the first program's launcher's.
    let component: Vec<&str> = wxs
        .split("<Component ")
        .filter(|c| c.contains("<ServiceInstall "))
        .collect();
    assert_eq!(
        component.len(),
        1,
        "{:#?}",
        common::wxs_lines(&wxs, &["<Component ", "<ServiceInstall "])
    );
    assert!(
        component[0].contains("\\Acme\\Agent\\AcmeAgent.exe\""),
        "{}",
        component[0]
    );
    let linux = layouts.iter().find(|l| l.triple == LINUX).unwrap();
    let package = seaworthy::linux::linux_package(&config, "agent", linux).unwrap();
    let unit = package
        .files
        .iter()
        .find(|f| f.dst == "/usr/lib/systemd/system/AcmeAgent.service")
        .unwrap();
    let seaworthy::linux::Source::Generated(text) = &unit.source else {
        panic!("generated");
    };
    assert!(
        text.contains("ExecStart=/opt/acme/agent/AcmeAgent serve"),
        "{text}"
    );
}
