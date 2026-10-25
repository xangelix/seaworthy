//! The release version's order, proven against the real package managers: for
//! every pair in a corpus of releases, `dpkg --compare-versions`, rpm's
//! `rpm.vercmp` and pacman's `vercmp` order the spellings
//! `seaworthy::version` produces exactly as the update helper's floor
//! orders the releases.
//!
//! A tool that isn't installed is skipped loudly, unless
//! `SEAWORTHY_REQUIRE_VERSION_TOOLS=1` (the Linux conformance lane sets
//! it, with all three installed), which turns a skip into a failure.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::cmp::Ordering;
use std::process::Command;

use seaworthy::version::Release;

/// Every shape the grammar allows, with ties broken by the sequence.
const CORPUS: &[(&str, u64)] = &[
    ("0.0.1", 1),
    ("0.9.9", 7),
    ("0.10.0", 1),
    ("1.0.0-alpha", 1),
    ("1.0.0-alpha", 2),
    ("1.0.0-alpha.1", 1),
    ("1.0.0-alpha.2", 1),
    ("1.0.0-alpha.10", 1),
    ("1.0.0-beta", 1),
    ("1.0.0-beta.2", 1),
    ("1.0.0-beta.11", 1),
    ("1.0.0-rc", 1),
    ("1.0.0-rc.1", 1),
    ("1.0.0-rc.1", 9),
    ("1.0.0", 1),
    ("1.0.0", 2),
    ("1.0.0", 10),
    ("1.0.1-rc.1", 1),
    ("1.0.1", 1),
    ("1.0.10", 1),
    ("1.1.0", 1),
    ("1.10.0", 1),
    ("2.0.0-alpha", 1),
    ("2.0.0-alpha.99", 1),
    ("2.0.0-beta.0", 1),
    ("2.0.0-rc.1", 1),
    ("2.0.0-rc.4294967296", 1),
    ("2.0.0", 1),
    ("10.0.0", 1),
];

fn required() -> bool {
    std::env::var_os("SEAWORTHY_REQUIRE_VERSION_TOOLS").is_some_and(|v| v == "1")
}

fn available(tool: &str, probe: &[&str]) -> bool {
    let ok = Command::new(tool)
        .args(probe)
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        assert!(
            !required(),
            "{tool} is required (SEAWORTHY_REQUIRE_VERSION_TOOLS=1) but not runnable"
        );
        eprintln!("SKIP: {tool} not installed — its ordering is unverified on this host");
    }
    ok
}

fn releases() -> Vec<Release> {
    CORPUS
        .iter()
        .map(|(v, s)| Release::new(v, *s).unwrap_or_else(|e| panic!("{v}: {e}")))
        .collect()
}

#[test]
fn the_corpus_is_in_floor_order() {
    let releases = releases();
    for pair in releases.windows(2) {
        assert_eq!(
            pair[0].cmp(&pair[1]),
            Ordering::Less,
            "{:?} vs {:?}",
            pair[0],
            pair[1]
        );
    }
}

/// Every ordered pair (i < j), compared with `compare`, must say Less, and
/// every reversed pair Greater.
fn check_all_pairs(tool: &str, compare: impl Fn(&Release, &Release) -> Ordering) {
    let releases = releases();
    let mut failures = Vec::new();
    for i in 0..releases.len() {
        for j in 0..releases.len() {
            let want = releases[i].cmp(&releases[j]);
            let got = compare(&releases[i], &releases[j]);
            if want != got {
                failures.push(format!(
                    "{} vs {}: floor {want:?}, {tool} {got:?}",
                    CORPUS[i].0, CORPUS[j].0
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{tool} disagrees with the floor:\n{}",
        failures.join("\n")
    );
}

#[test]
fn dpkg_orders_like_the_floor() {
    if !available("dpkg", &["--version"]) {
        return;
    }
    check_all_pairs("dpkg", |a, b| {
        let (a, b) = (
            a.package_versions().expect("deb").deb,
            b.package_versions().expect("deb").deb,
        );
        let op = |op: &str| {
            Command::new("dpkg")
                .args(["--compare-versions", &a, op, &b])
                .status()
                .expect("dpkg runs")
                .success()
        };
        if op("lt") {
            Ordering::Less
        } else if op("eq") {
            Ordering::Equal
        } else {
            Ordering::Greater
        }
    });
}

/// `rpm.vercmp` parses full EVR strings from rpm 4.16 on; older rpms would
/// misreport version-release pairs.
fn rpm_new_enough() -> bool {
    let Ok(out) = Command::new("rpm").arg("--version").output() else {
        return false;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let version = text.split_whitespace().last().unwrap_or("");
    let mut parts = version.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let (major, minor) = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    let ok = (major, minor) >= (4, 16);
    if !ok {
        assert!(
            !required(),
            "rpm {version} is older than 4.16 (SEAWORTHY_REQUIRE_VERSION_TOOLS=1)"
        );
        eprintln!("SKIP: rpm {version} is older than 4.16 — rpm.vercmp can't compare EVRs");
    }
    ok
}

#[test]
fn rpm_orders_like_the_floor() {
    if !available("rpm", &["--version"]) || !rpm_new_enough() {
        return;
    }
    // One rpm process for the whole matrix: rpm.vercmp over
    // version-release strings, as rpm compares packages (EVR, no epoch).
    let releases = releases();
    let evr: Vec<String> = releases
        .iter()
        .map(|r| {
            let v = r.package_versions().expect("rpm");
            format!("{}-{}", v.rpm_version, v.rpm_release)
        })
        .collect();
    let mut lua = String::from("%{lua: local v = {");
    for e in &evr {
        lua.push_str(&format!("'{e}',"));
    }
    lua.push_str("} for i = 1, #v do local row = {} for j = 1, #v do row[#row+1] = rpm.vercmp(v[i], v[j]) end print(table.concat(row, ' ') .. '\\n') end}");
    let out = Command::new("rpm")
        .args(["--eval", &lua])
        .output()
        .expect("rpm runs");
    assert!(
        out.status.success(),
        "rpm --eval failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let matrix: Vec<Vec<i32>> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            l.split_whitespace()
                .map(|n| n.parse().expect("rpm.vercmp result"))
                .collect()
        })
        .collect();
    assert_eq!(
        matrix.len(),
        releases.len(),
        "rpm printed {} rows",
        matrix.len()
    );
    let index = |r: &Release| releases.iter().position(|x| x == r).expect("in corpus");
    check_all_pairs("rpm", |a, b| matrix[index(a)][index(b)].cmp(&0));
}

#[test]
fn pacman_orders_like_the_floor() {
    if !available("vercmp", &["1", "1"]) {
        return;
    }
    check_all_pairs("vercmp", |a, b| {
        let full = |r: &Release| {
            let v = r.package_versions().expect("pacman");
            format!("{}-{}", v.pacman_pkgver, v.pacman_pkgrel)
        };
        let out = Command::new("vercmp")
            .args([full(a), full(b)])
            .output()
            .expect("vercmp runs");
        let n: i32 = String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("vercmp prints a number");
        n.cmp(&0)
    });
}

/// Why the tag set is closed: dpkg ranks a letter below `.`, so it orders a
/// tag after its own extension (`rc.1` after `rcx.1`), where semver, rpm and
/// pacman order it before. This pins the reason the grammar refuses such
/// tags; if dpkg ever changes, the closed set can be revisited.
#[test]
fn dpkg_misorders_prefix_tags_which_is_why_they_are_refused() {
    if !available("dpkg", &["--version"]) {
        return;
    }
    let lt = |a: &str, b: &str| {
        Command::new("dpkg")
            .args(["--compare-versions", a, "lt", b])
            .status()
            .expect("dpkg runs")
            .success()
    };
    assert!(
        !lt("1.0.0~rc.1-1", "1.0.0~rcx.1-1"),
        "dpkg now orders rc.1 before rcx.1"
    );
    assert!(lt("1.0.0~rcx.1-1", "1.0.0~rc.1-1"));
    assert!(seaworthy::version::Version::parse("1.0.0-rcx.1").is_err());
}
