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
