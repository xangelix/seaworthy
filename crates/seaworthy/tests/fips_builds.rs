//! FIPS builds: a product's own `fips` (one `seaworthy.toml` listing a
//! product per crypto build), checked by `verify` as what it is.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::path::Path;

use common::{CPUS, Elf, LOADER, Pe, V2, cpulist, record, write};
use seaworthy::DistError;
use seaworthy::config::Config;
use seaworthy::inputs::{LINUX, WINDOWS};

/// Three profiles of one tool: the FIPS module, AWS-LC without it, and a
/// portable build, each a product whose cores build with its features.
fn profiles(defaults_fips: bool, extra_defaults: &str) -> String {
    let product = |id: &str, fips: &str, sidecars: &str| {
        format!(
            "[product.{id}]\ndisplay-name = \"Acme Trove ({id})\"\ndescription = \"Packs Trove archives.\"\nkind = \"tool\"\nwindows-directory = \"Trove{}\"\noutputs = [\"deb\", \"zip\"]\nupdates.default = \"off\"\n{fips}{sidecars}\n[[product.{id}.programs]]\nexecutable = \"trove\"\ncore = \"trove_core\"\nrole = \"cli\"\ncommand = \"trove-{id}\"\nfeatures = [\"{id}\"]\ndefault-features = false\n\n",
            id.replace('-', "")
        )
    };
    format!(
        "[defaults]\nvendor = \"Acme\"\ntargets = [\"x86-64-v3\", \"x86-64-v2\"]\nchannel = \"stable\"\nmaintainer = \"Acme <packages@example.com>\"\nlicense = \"MIT\"\nfips = {defaults_fips}\n{extra_defaults}\n{}{}{}",
        product(
            "fips",
            if defaults_fips { "" } else { "fips = true\n" },
            "sidecars.windows = [\"aws_lc_fips_*_crypto.dll\"]\n"
        ),
        product(
            "aws-lc",
            if defaults_fips { "fips = false\n" } else { "" },
            ""
        ),
        product(
            "portable",
            if defaults_fips { "fips = false\n" } else { "" },
            ""
        ),
    )
}

/// Every product's artifacts: the FIPS product's cores link the module
/// whose symbols carry `prefix` (and import its DLL on Windows, which its
/// sidecar ships); the others' link nothing of it.
fn artifacts(config: &Config, root: &Path, prefix: &str) {
    for (id, product) in &config.products {
        let fips = config.fips(product);
        for program in product.programs() {
            let list = cpulist(&program.core, &CPUS);
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
                let symbols = if fips {
                    vec![
                        (format!("{prefix}awslc_version_string"), true),
                        (format!("{prefix}RAND_bytes"), true),
                        ("seaworthy_core_main".to_owned(), true),
                    ]
                } else {
                    vec![("seaworthy_core_main".to_owned(), true)]
                };
                write(
                    root,
                    &format!("{LINUX}/cores/{dir}/lib{}.so", program.core),
                    &Elf {
                        sections: vec![(".cpureq".into(), record(LINUX, cpu, V2))],
                        needed: vec!["libc.so.6".into()],
                        symbols,
                        ..Elf::default()
                    }
                    .build(),
                );
                let mut imports = vec!["kernel32.dll".to_owned()];
                if fips {
                    imports.insert(0, format!("{prefix}crypto.dll"));
                    write(
                        root,
                        &format!("{WINDOWS}/cores/{dir}/{prefix}crypto.dll"),
                        &Pe {
                            sections: vec![(".text".into(), b"crypto".to_vec())],
                            imports: vec!["kernel32.dll".into()],
                            executable: false,
                        }
                        .build(),
                    );
                }
                write(
                    root,
                    &format!("{WINDOWS}/cores/{dir}/{}.dll", program.core),
                    &Pe {
                        sections: vec![(".cpureq".into(), record(WINDOWS, cpu, V2))],
                        imports,
                        executable: false,
                    }
                    .build(),
                );
            }
        }
        let _ = id;
    }
}

fn findings(config: &Config, id: &str, root: &Path) -> Vec<String> {
    match seaworthy::verify::verify(config, id, root) {
        Ok(_) => Vec::new(),
        Err(DistError::Verify(findings)) => findings,
        Err(other) => panic!("not a verify error: {other}"),
    }
}

/// A product's `fips` overrides `defaults.fips` both ways: only the FIPS
/// profile's binaries are held to the module.
#[test]
fn a_products_fips_decides_its_checks() {
    for defaults_fips in [false, true] {
        let config = Config::parse(&profiles(defaults_fips, "")).unwrap();
        let fips = |id: &str| config.fips(&config.products[id]);
        assert!(fips("fips"));
        assert!(!fips("aws-lc") && !fips("portable"));
        let dir = tempfile::tempdir().unwrap();
        artifacts(
            &config,
            dir.path(),
            seaworthy_crypto::module::FIPS_SYMBOL_PREFIX,
        );
        for id in ["fips", "aws-lc", "portable"] {
            assert_eq!(
                findings(&config, id, dir.path()),
                Vec::<String>::new(),
                "{id}"
            );
        }
        // The non-FIPS profiles' cores in the FIPS product's place: refused.
        let fips_program = config.products["fips"].programs()[0].clone();
        let portable = config.products["portable"].programs()[0].clone();
        for cpu in CPUS {
            std::fs::copy(
                dir.path().join(format!(
                    "{LINUX}/cores/{}/libtrove_core.so",
                    portable.build_dir(cpu)
                )),
                dir.path().join(format!(
                    "{LINUX}/cores/{}/libtrove_core.so",
                    fips_program.build_dir(cpu)
                )),
            )
            .unwrap();
        }
        let found = findings(&config, "fips", dir.path());
        assert!(
            found
                .iter()
                .any(|f| f.contains("the pinned AWS-LC FIPS module is not linked")),
            "{found:#?}"
        );
    }
}

/// The module releases `defaults.fips-module` accepts: the pinned one is
/// among them, its prefix the one `seaworthy-crypto` pins.
#[test]
fn the_known_modules_include_the_pinned_one() {
    use seaworthy::config::{FIPS_MODULES, fips_module, pinned_fips_module};
    let pinned = pinned_fips_module();
    assert!(FIPS_MODULES.contains(&pinned));
    assert_eq!(
        pinned.sys,
        seaworthy_crypto::module::EXPECTED_FIPS_SYS_VERSION
    );
    assert_eq!(
        pinned.module,
        seaworthy_crypto::module::EXPECTED_FIPS_MODULE_VERSION
    );
    assert_eq!(
        pinned.symbol_prefix(),
        seaworthy_crypto::module::FIPS_SYMBOL_PREFIX
    );
    let older = fips_module("0.14.2").unwrap();
    assert_eq!(older.module, "4.2.0");
    assert_eq!(older.symbol_prefix(), "aws_lc_fips_0_14_2_");
    for unknown in ["0.13.0", "0.14.4", "0.14", "latest", ""] {
        assert!(fips_module(unknown).is_none(), "{unknown}");
    }
}

/// `fips-module` names a known release, and only where a product carries
/// the module.
#[test]
fn the_fips_module_is_a_known_release_of_a_fips_build() {
    let config = Config::parse(&profiles(false, "fips-module = \"0.14.2\"")).unwrap();
    assert_eq!(config.fips_module().sys, "0.14.2");
    assert_eq!(config.fips_symbol_prefix(), "aws_lc_fips_0_14_2_");
    let pinned = Config::parse(&profiles(false, "")).unwrap();
    assert_eq!(
        pinned.fips_symbol_prefix(),
        seaworthy_crypto::module::FIPS_SYMBOL_PREFIX
    );
    for unknown in ["0.13.0", "0.14.4", "4.2.0"] {
        let err = Config::parse(&profiles(false, &format!("fips-module = \"{unknown}\"")))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&format!(
                "defaults.fips-module \"{unknown}\" isn't an aws-lc-fips-sys release"
            )) && err.contains("0.14.2 builds AWS-LC FIPS 4.2.0")
                && err.contains("0.14.3 builds AWS-LC FIPS 4.2.0"),
            "{err}"
        );
    }
    let err =
        Config::parse(&profiles(false, "fips-module = \"0.14.2\"").replace("fips = true\n", ""))
            .unwrap_err()
            .to_string();
    assert!(err.contains("no product carries the FIPS module"), "{err}");
}

/// `verify` holds the FIPS product to the module `fips-module` names: its
/// symbols on Linux, its DLL on Windows; another release's are refused.
#[test]
fn verify_follows_the_chosen_module() {
    let older = Config::parse(&profiles(false, "fips-module = \"0.14.2\"")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    artifacts(&older, dir.path(), "aws_lc_fips_0_14_2_");
    assert_eq!(findings(&older, "fips", dir.path()), Vec::<String>::new());
    // The same binaries against the default (the pinned 0.14.3).
    let pinned = Config::parse(&profiles(false, "")).unwrap();
    let found = findings(&pinned, "fips", dir.path());
    for needle in [
        "no aws_lc_fips_0_14_3_* symbols",
        "AWS-LC FIPS symbols of a version other than aws_lc_fips_0_14_3_",
        "does not import aws_lc_fips_0_14_3_crypto.dll",
    ] {
        assert!(
            found.iter().any(|f| f.contains(needle)),
            "{needle}: {found:#?}"
        );
    }
    // And 0.14.3's binaries against fips-module = "0.14.2".
    let dir = tempfile::tempdir().unwrap();
    artifacts(&pinned, dir.path(), "aws_lc_fips_0_14_3_");
    assert_eq!(findings(&pinned, "fips", dir.path()), Vec::<String>::new());
    let found = findings(&older, "fips", dir.path());
    assert!(
        found
            .iter()
            .any(|f| f.contains("does not import aws_lc_fips_0_14_2_crypto.dll")),
        "{found:#?}"
    );
}

/// `fips-check --module` checks one binary against a known release.
#[test]
fn fips_check_takes_the_module_release() {
    let dir = tempfile::tempdir().unwrap();
    let binary = write(
        dir.path(),
        "core.so",
        &Elf {
            sections: vec![(".cpureq".into(), record(LINUX, "x86-64-v2", V2))],
            symbols: vec![
                ("aws_lc_fips_0_14_2_awslc_version_string".to_owned(), true),
                ("aws_lc_fips_0_14_2_RAND_bytes".to_owned(), true),
            ],
            ..Elf::default()
        }
        .build(),
    );
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_seaworthy"))
            .arg("fips-check")
            .args(args)
            .arg(&binary)
            .output()
            .unwrap()
    };
    let ok = run(&["--module", "0.14.2"]);
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(String::from_utf8_lossy(&ok.stdout).contains("aws_lc_fips_0_14_2_*"));
    let pinned = run(&[]);
    assert_eq!(pinned.status.code(), Some(1));
    let unknown = run(&["--module", "0.13.0"]);
    assert_eq!(unknown.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("0.14.2, 0.14.3"));
}
