//! The FIPS allowlist's parser and the build graph's verdict, exercised
//! directly: `build/allowlist.rs` is pure, so the build script's rules are
//! tested here in every profile (a `--features fips` build proves the script
//! runs over the real graph).

#[path = "../build/allowlist.rs"]
#[allow(
    dead_code,
    reason = "shared with build.rs; not every item is asserted here"
)]
mod allowlist;

fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

#[allow(
    clippy::expect_used,
    reason = "a test helper: a malformed fixture is a bug in the test, and a panic fails it"
)]
fn list() -> allowlist::Allowlist {
    allowlist::parse(include_str!("../fips-allowlist.txt")).expect("the allowlist parses")
}

/// The metadata a `fips` build with aws-lc-rs `rs` over aws-lc-fips-sys
/// `sys` hands this crate's build script.
fn fips_graph(rs: &str, sys: &str, bound: &str) -> Vec<(String, String)> {
    let rs = rs.replace('.', "_");
    let sys = sys.replace('.', "_");
    vars(&[
        (&format!("DEP_AWS_LC_RS_{rs}_SYS_INCLUDE"), "/out/include"),
        (&format!("DEP_AWS_LC_RS_{rs}_SYS_LIBCRYPTO"), bound),
        (&format!("DEP_AWS_LC_RS_{rs}_SYS_CONF"), "OPENSSL_NO_ASYNC"),
        (&format!("DEP_AWS_LC_FIPS_{sys}_INCLUDE"), "/out/include"),
        (&format!("DEP_AWS_LC_FIPS_{sys}_LIBCRYPTO"), "x"),
        ("DEP_OTHER_1_2_3_INCLUDE", "/elsewhere"),
        ("CARGO_FEATURE_FIPS", "1"),
    ])
}

#[test]
fn the_shipped_allowlist_parses() {
    let list = list();
    let modules: Vec<(&str, &str, u32)> = list
        .modules
        .iter()
        .map(|m| (m.sys.as_str(), m.module.as_str(), m.branch))
        .collect();
    assert_eq!(
        modules,
        [
            ("0.14.2", "4.2.0", 4),
            ("0.14.3", "4.2.0", 4),
            ("0.14.4", "4.2.0", 4)
        ]
    );
    let rs: Vec<(&str, &str)> = list
        .aws_lc_rs
        .iter()
        .map(|r| (r.version.as_str(), r.binds.as_str()))
        .collect();
    assert_eq!(rs, [("1.18.2", "0.14"), ("1.19.0", "0.14")]);
    let generated = list.rust();
    assert!(generated.contains("FipsModule { sys: \"0.14.4\", module: \"4.2.0\", branch: 4 },"));
    assert!(generated.contains("AwsLcRsRelease { version: \"1.19.0\", binds: \"0.14\" },"));
}

#[test]
fn malformed_allowlists_are_refused() {
    let ok = "module 0.14.4 4.2.0 4\naws-lc-rs 1.19.0 0.14\n";
    assert!(allowlist::parse(ok).is_ok());
    for (text, why) in [
        ("", "empty"),
        ("module 0.14.4 4.2.0 4\n", "no aws-lc-rs"),
        ("aws-lc-rs 1.19.0 0.14\n", "no module"),
        (
            "module 0.14 4.2.0 4\naws-lc-rs 1.19.0 0.14\n",
            "a two-part release",
        ),
        (
            "module 0.14.04 4.2.0 4\naws-lc-rs 1.19.0 0.14\n",
            "a leading zero",
        ),
        (
            "module 0.14.4 4.2.0 0\naws-lc-rs 1.19.0 0.14\n",
            "branch zero",
        ),
        (
            "module 0.14.4 4.2.0 x\naws-lc-rs 1.19.0 0.14\n",
            "a non-numeric branch",
        ),
        (
            "module 0.14.4 4.2.0 4 extra\naws-lc-rs 1.19.0 0.14\n",
            "an extra field",
        ),
        (
            "module 0.14.4 4.2.0 4 # note\naws-lc-rs 1.19.0 0.14\n",
            "a trailing comment",
        ),
        (
            "modules 0.14.4 4.2.0 4\naws-lc-rs 1.19.0 0.14\n",
            "an unknown kind",
        ),
        (
            "module 0.14.4 4.2.0 4\nmodule 0.14.4 4.2.0 4\naws-lc-rs 1.19.0 0.14\n",
            "a duplicate",
        ),
        (
            "module 0.14.4 4.2.0 4\nmodule 0.14.3 4.2.0 4\naws-lc-rs 1.19.0 0.14\n",
            "descending",
        ),
        (
            "module 0.14.4 4.2.0 4\naws-lc-rs 1.19.0 0.14.2\n",
            "a release as the series",
        ),
        (
            "module 0.14.4 4.2.0 4\naws-lc-rs 1.19.0 0.15\n",
            "aws-lc-rs binds no module",
        ),
        (
            "module 0.14.4 4.2.0 4\nmodule 0.15.0 5.0.0 5\naws-lc-rs 1.19.0 0.14\n",
            "a module no aws-lc-rs binds",
        ),
    ] {
        assert!(allowlist::parse(text).is_err(), "{why}: {text:?}");
    }
    // Comments and blank lines are ignored.
    assert!(allowlist::parse(&format!("# header\n\n  {ok}\n# tail\n")).is_ok());
}

#[test]
fn the_graph_names_the_releases_the_build_resolved() {
    let graph = allowlist::graph(&fips_graph("1.19.0", "0.14.4", "aws_lc_fips_0_14_4_crypto"));
    assert_eq!(graph.aws_lc_rs.iter().collect::<Vec<_>>(), ["1.19.0"]);
    assert_eq!(graph.fips_sys.iter().collect::<Vec<_>>(), ["0.14.4"]);
    assert_eq!(
        graph.bound_libcrypto.iter().collect::<Vec<_>>(),
        ["aws_lc_fips_0_14_4_crypto"]
    );
    // Every variable read is a rerun trigger; others are not read.
    assert_eq!(graph.names.len(), 5);
    assert!(!graph.names.iter().any(|n| n.contains("OTHER")));
    // A non-FIPS build: aws-lc-rs over aws-lc-sys, no direct sys crate.
    let graph = allowlist::graph(&vars(&[
        ("DEP_AWS_LC_RS_1_18_2_SYS_INCLUDE", "/i"),
        ("DEP_AWS_LC_RS_1_18_2_SYS_LIBCRYPTO", "aws_lc_0_46_0_crypto"),
    ]));
    assert_eq!(graph.aws_lc_rs.iter().collect::<Vec<_>>(), ["1.18.2"]);
    assert!(graph.fips_sys.is_empty());
    // Malformed names are not releases.
    let graph = allowlist::graph(&vars(&[
        ("DEP_AWS_LC_RS_1_19_SYS_INCLUDE", "/i"),
        ("DEP_AWS_LC_FIPS_0_14_INCLUDE", "/i"),
        ("DEP_AWS_LC_FIPS_X_14_4_INCLUDE", "/i"),
    ]));
    assert_eq!(graph, allowlist::Graph::default());
}

#[test]
fn every_allowlisted_pair_builds() {
    let list = list();
    for rs in &list.aws_lc_rs {
        for module in &list.modules {
            let bound = format!("aws_lc_fips_{}_crypto", module.sys.replace('.', "_"));
            let graph = allowlist::graph(&fips_graph(&rs.version, &module.sys, &bound));
            let verdict = allowlist::evaluate(&list, &graph, true);
            assert_eq!(
                verdict.errors,
                Vec::<String>::new(),
                "{} {}",
                rs.version,
                module.sys
            );
            assert_eq!(verdict.warnings, Vec::<String>::new());
            assert_eq!(verdict.aws_lc_rs, rs.version);
            assert_eq!(verdict.fips_sys, module.sys);
        }
    }
}

#[test]
fn a_fips_build_of_anything_else_is_refused() {
    let list = list();
    let refused = |graph: Vec<(String, String)>, needle: &str| {
        let verdict = allowlist::evaluate(&list, &allowlist::graph(&graph), true);
        assert!(
            verdict.errors.iter().any(|e| e.contains(needle)),
            "{needle}: {:?}",
            verdict.errors
        );
    };
    // An unlisted module release, even of the same module.
    refused(
        fips_graph("1.19.0", "0.14.5", "aws_lc_fips_0_14_5_crypto"),
        "aws-lc-fips-sys 0.14.5 is not on the FIPS allowlist",
    );
    refused(
        fips_graph("1.19.0", "0.14.1", "aws_lc_fips_0_14_1_crypto"),
        "aws-lc-fips-sys 0.14.1 is not on the FIPS allowlist",
    );
    // aws-lc-rs binding another series than the crate depends on (a future
    // aws-lc-rs over aws-lc-fips-sys 0.15 next to this crate's 0.14).
    refused(
        fips_graph("1.20.0", "0.14.4", "aws_lc_fips_0_15_0_crypto"),
        "binds",
    );
    // aws-lc-rs binding the NON-FIPS library.
    refused(
        fips_graph("1.19.0", "0.14.4", "aws_lc_0_47_0_crypto"),
        "binds",
    );
    // No module at all, or two.
    refused(
        vars(&[(
            "DEP_AWS_LC_RS_1_19_0_SYS_LIBCRYPTO",
            "aws_lc_fips_0_14_4_crypto",
        )]),
        "0 aws-lc-fips-sys releases",
    );
    let mut two = fips_graph("1.19.0", "0.14.4", "aws_lc_fips_0_14_4_crypto");
    two.extend(vars(&[("DEP_AWS_LC_FIPS_0_14_3_INCLUDE", "/i")]));
    refused(two, "2 aws-lc-fips-sys releases");
    // Two aws-lc-rs releases.
    let mut two = fips_graph("1.19.0", "0.14.4", "aws_lc_fips_0_14_4_crypto");
    two.extend(vars(&[("DEP_AWS_LC_RS_1_18_2_SYS_INCLUDE", "/i")]));
    refused(two, "2 aws-lc-rs releases");
}

#[test]
fn an_unlisted_aws_lc_rs_over_a_listed_module_is_reported_not_refused() {
    let list = list();
    let graph = allowlist::graph(&fips_graph("1.19.1", "0.14.4", "aws_lc_fips_0_14_4_crypto"));
    let verdict = allowlist::evaluate(&list, &graph, true);
    assert_eq!(verdict.errors, Vec::<String>::new());
    assert!(
        verdict
            .warnings
            .iter()
            .any(|w| w.contains("aws-lc-rs 1.19.1 is not on")),
        "{:?}",
        verdict.warnings
    );
}

#[test]
fn a_non_fips_build_reads_aws_lc_rs_only() {
    let list = list();
    let graph = allowlist::graph(&vars(&[(
        "DEP_AWS_LC_RS_1_19_0_SYS_LIBCRYPTO",
        "aws_lc_0_47_0_crypto",
    )]));
    let verdict = allowlist::evaluate(&list, &graph, false);
    assert_eq!(verdict.errors, Vec::<String>::new());
    assert_eq!(verdict.aws_lc_rs, "1.19.0");
    assert_eq!(verdict.fips_sys, "");
    // Nothing to read is not an error without `fips`.
    let verdict = allowlist::evaluate(&list, &allowlist::Graph::default(), false);
    assert!(verdict.errors.is_empty() && verdict.aws_lc_rs.is_empty());
}
