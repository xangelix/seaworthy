//! The FIPS allowlist and the AWS-LC crates of the build graph: pure logic,
//! shared by `build.rs` and `tests/allowlist.rs` (included by path; no crate
//! dependencies, no I/O).
//!
//! **The allowlist** (`fips-allowlist.txt`, beside the manifest) names the
//! `aws-lc-fips-sys` releases a FIPS build may link, each with the AWS-LC
//! FIPS module it builds and the module's branch, and the `aws-lc-rs`
//! releases that bind them. The manifest accepts a range of both crates;
//! the list decides which of them a FIPS build may link. The build script
//! turns it into `module::FIPS_MODULES` and `module::AWS_LC_RS_RELEASES`
//! (generated code, so the file is the one source of truth).
//!
//! **The build graph.** Cargo hands the build script of a package that
//! depends directly on a `links` crate that crate's metadata, as
//! `DEP_<links>_<key>` variables, and both AWS-LC crates name their release
//! in their `links` key: `aws-lc-fips-sys` 0.14.4 is
//! `aws_lc_fips_0_14_4` (`DEP_AWS_LC_FIPS_0_14_4_INCLUDE`, …), `aws-lc-rs`
//! 1.19.0 is `aws_lc_rs_1_19_0_sys` (`DEP_AWS_LC_RS_1_19_0_SYS_INCLUDE`, …).
//! `aws-lc-rs` re-exports the metadata of the sys crate it selected, so its
//! `LIBCRYPTO` names the library it binds (`aws_lc_fips_0_14_4_crypto`
//! under `fips`). [`graph`] reads the releases this build resolved;
//! [`evaluate`] holds a FIPS build to the allowlist: one `aws-lc-fips-sys`
//! release, on the list, and `aws-lc-rs` binding exactly that release (a
//! future `aws-lc-rs` that binds another series would pull a second sys
//! crate into the graph: refused here).

use std::collections::BTreeSet;
use std::fmt::Write as _;

/// The allowlist file, relative to the crate's manifest directory.
pub(crate) const FILE: &str = "fips-allowlist.txt";

/// One `module` entry: an `aws-lc-fips-sys` release and the module it
/// builds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ModuleEntry {
    /// The `aws-lc-fips-sys` release (`0.14.4`).
    pub(crate) sys: String,
    /// The AWS-LC FIPS module version it builds (`4.2.0`).
    pub(crate) module: String,
    /// The module's branch (`aws_lc_rs::fips_version()`, `4`).
    pub(crate) branch: u32,
}

/// One `aws-lc-rs` entry: a release and the `aws-lc-fips-sys` series it
/// binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RsEntry {
    /// The `aws-lc-rs` release (`1.19.0`).
    pub(crate) version: String,
    /// The `aws-lc-fips-sys` series it binds (`0.14`: `^0.14.x`).
    pub(crate) binds: String,
}

/// The parsed allowlist.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Allowlist {
    /// The `module` entries, in the file's (ascending) order.
    pub(crate) modules: Vec<ModuleEntry>,
    /// The `aws-lc-rs` entries, in the file's (ascending) order.
    pub(crate) aws_lc_rs: Vec<RsEntry>,
}

/// A release `x.y.z`: three decimal components, no sign, no leading zero.
pub(crate) fn release(text: &str) -> Option<(u64, u64, u64)> {
    let mut parts = text.split('.');
    let (Some(a), Some(b), Some(c), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    Some((number(a)?, number(b)?, number(c)?))
}

/// A series `x.y`.
fn series(text: &str) -> Option<(u64, u64)> {
    let mut parts = text.split('.');
    let (Some(a), Some(b), None) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    Some((number(a)?, number(b)?))
}

fn number(text: &str) -> Option<u64> {
    let canonical = !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if canonical { text.parse().ok() } else { None }
}

/// The series (`x.y`) of a release (`x.y.z`).
pub(crate) fn series_of(release_text: &str) -> Option<String> {
    let (major, minor, _) = release(release_text)?;
    Some(format!("{major}.{minor}"))
}

/// Parse `fips-allowlist.txt`. Strict: every line is a comment, blank, or
/// one well-formed entry; releases are unique and ascending; every module
/// is bound by a listed `aws-lc-rs` and every `aws-lc-rs` binds a listed
/// module.
///
/// # Errors
/// The first problem, with its line number.
pub(crate) fn parse(text: &str) -> Result<Allowlist, String> {
    let mut list = Allowlist::default();
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.as_slice() {
            ["module", sys, module, branch] => {
                let (Some(sys_release), Some(_)) = (release(sys), release(module)) else {
                    return Err(format!(
                        "line {number}: `module <aws-lc-fips-sys release> <module version> \
                         <branch>`, releases as x.y.z: {line:?}"
                    ));
                };
                let Some(branch) = number_u32(branch).filter(|b| *b > 0) else {
                    return Err(format!(
                        "line {number}: the module branch is a positive integer: {line:?}"
                    ));
                };
                if let Some(last) = list.modules.last()
                    && release(&last.sys) >= Some(sys_release)
                {
                    return Err(format!(
                        "line {number}: module {sys} is not after {} (unique, ascending)",
                        last.sys
                    ));
                }
                list.modules.push(ModuleEntry {
                    sys: (*sys).to_string(),
                    module: (*module).to_string(),
                    branch,
                });
            }
            ["aws-lc-rs", version, binds] => {
                let (Some(rs_release), Some(_)) = (release(version), series(binds)) else {
                    return Err(format!(
                        "line {number}: `aws-lc-rs <release x.y.z> <aws-lc-fips-sys series \
                         x.y>`: {line:?}"
                    ));
                };
                if let Some(last) = list.aws_lc_rs.last()
                    && release(&last.version) >= Some(rs_release)
                {
                    return Err(format!(
                        "line {number}: aws-lc-rs {version} is not after {} (unique, ascending)",
                        last.version
                    ));
                }
                list.aws_lc_rs.push(RsEntry {
                    version: (*version).to_string(),
                    binds: (*binds).to_string(),
                });
            }
            _ => {
                return Err(format!(
                    "line {number}: not an entry (`module …` or `aws-lc-rs …`): {line:?}"
                ));
            }
        }
    }
    if list.modules.is_empty() || list.aws_lc_rs.is_empty() {
        return Err("the allowlist names no module or no aws-lc-rs release".to_string());
    }
    for module in &list.modules {
        let series = series_of(&module.sys).unwrap_or_default();
        if !list.aws_lc_rs.iter().any(|rs| rs.binds == series) {
            return Err(format!(
                "module {}: no listed aws-lc-rs release binds aws-lc-fips-sys {series}",
                module.sys
            ));
        }
    }
    for rs in &list.aws_lc_rs {
        if !list
            .modules
            .iter()
            .any(|m| series_of(&m.sys).as_deref() == Some(rs.binds.as_str()))
        {
            return Err(format!(
                "aws-lc-rs {}: no listed module is in the aws-lc-fips-sys {} series it binds",
                rs.version, rs.binds
            ));
        }
    }
    Ok(list)
}

fn number_u32(text: &str) -> Option<u32> {
    number(text).and_then(|n| u32::try_from(n).ok())
}

impl Allowlist {
    /// The entry of `aws-lc-fips-sys` release `sys`, if listed.
    pub(crate) fn module(&self, sys: &str) -> Option<&ModuleEntry> {
        self.modules.iter().find(|m| m.sys == sys)
    }

    /// The entry of `aws-lc-rs` release `version`, if listed.
    pub(crate) fn aws_lc_rs(&self, version: &str) -> Option<&RsEntry> {
        self.aws_lc_rs.iter().find(|rs| rs.version == version)
    }

    /// `0.14.2 (AWS-LC FIPS 4.2.0), …`: the list, for messages.
    pub(crate) fn describe_modules(&self) -> String {
        self.modules
            .iter()
            .map(|m| format!("{} (AWS-LC FIPS {})", m.sys, m.module))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The Rust source of `module::FIPS_MODULES` and
    /// `module::AWS_LC_RS_RELEASES` (`include!`d by `src/module.rs`).
    pub(crate) fn rust(&self) -> String {
        let mut out = String::from(
            "// @generated by build.rs from fips-allowlist.txt: edit that file.\n\n\
             /// The FIPS allowlist's modules (`fips-allowlist.txt`), ascending.\n\
             pub const FIPS_MODULES: &[FipsModule] = &[\n",
        );
        for m in &self.modules {
            let _ = writeln!(
                out,
                "    FipsModule {{ sys: {:?}, module: {:?}, branch: {} }},",
                m.sys, m.module, m.branch
            );
        }
        out.push_str(
            "];\n\n/// The FIPS allowlist's `aws-lc-rs` releases (`fips-allowlist.txt`), \
             ascending.\npub const AWS_LC_RS_RELEASES: &[AwsLcRsRelease] = &[\n",
        );
        for rs in &self.aws_lc_rs {
            let _ = writeln!(
                out,
                "    AwsLcRsRelease {{ version: {:?}, binds: {:?} }},",
                rs.version, rs.binds
            );
        }
        out.push_str("];\n");
        out
    }
}

/// The AWS-LC crates of the build graph, as `DEP_*` metadata names them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Graph {
    /// `aws-lc-rs` releases (`DEP_AWS_LC_RS_<x>_<y>_<z>_SYS_*`).
    pub(crate) aws_lc_rs: BTreeSet<String>,
    /// The library `aws-lc-rs` binds (its re-exported `LIBCRYPTO`:
    /// `aws_lc_fips_0_14_4_crypto` under `fips`).
    pub(crate) bound_libcrypto: BTreeSet<String>,
    /// `aws-lc-fips-sys` releases this crate depends on directly
    /// (`DEP_AWS_LC_FIPS_<x>_<y>_<z>_*`).
    pub(crate) fips_sys: BTreeSet<String>,
    /// Every variable read (the build script's rerun triggers).
    pub(crate) names: Vec<String>,
}

/// `<x>_<y>_<z>_<rest>` → (`x.y.z`, `rest`).
fn versioned(name: &str) -> Option<(String, &str)> {
    let mut parts = name.splitn(4, '_');
    let (Some(a), Some(b), Some(c), Some(rest)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let version = format!("{a}.{b}.{c}");
    release(&version).map(|_| (version, rest))
}

/// Read the build graph's AWS-LC releases from the build script's
/// environment.
pub(crate) fn graph(vars: &[(String, String)]) -> Graph {
    let mut graph = Graph::default();
    for (name, value) in vars {
        if let Some(rest) = name.strip_prefix("DEP_AWS_LC_RS_")
            && let Some((version, key)) = versioned(rest)
            && let Some(key) = key.strip_prefix("SYS_")
        {
            graph.aws_lc_rs.insert(version);
            graph.names.push(name.clone());
            if key == "LIBCRYPTO" {
                graph.bound_libcrypto.insert(value.clone());
            }
        } else if let Some(rest) = name.strip_prefix("DEP_AWS_LC_FIPS_")
            && let Some((version, _)) = versioned(rest)
        {
            graph.fips_sys.insert(version);
            graph.names.push(name.clone());
        }
    }
    graph.names.sort();
    graph
}

/// The releases a build links, and what the allowlist says of them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Verdict {
    /// The `aws-lc-rs` release (empty when the graph does not say).
    pub(crate) aws_lc_rs: String,
    /// The `aws-lc-fips-sys` release a FIPS build links (empty otherwise).
    pub(crate) fips_sys: String,
    /// Refusals: a FIPS build with any fails.
    pub(crate) errors: Vec<String>,
    /// Findings that do not refuse the build.
    pub(crate) warnings: Vec<String>,
}

/// Hold the build graph to the allowlist. Without `fips` only the
/// `aws-lc-rs` release is read (no module is linked); with it, the build
/// must link exactly one `aws-lc-fips-sys` release, on the allowlist, and
/// `aws-lc-rs` must bind exactly that release.
pub(crate) fn evaluate(list: &Allowlist, graph: &Graph, fips: bool) -> Verdict {
    let mut verdict = Verdict::default();
    let rs: Vec<&String> = graph.aws_lc_rs.iter().collect();
    match rs.as_slice() {
        [one] => verdict.aws_lc_rs = (*one).clone(),
        [] if !fips => {}
        _ => verdict.errors.push(format!(
            "the build graph names {} aws-lc-rs releases ({rs:?}): exactly one is expected",
            rs.len()
        )),
    }
    if !fips {
        return verdict;
    }
    let sys: Vec<&String> = graph.fips_sys.iter().collect();
    let [sys] = sys.as_slice() else {
        verdict.errors.push(format!(
            "the build graph names {} aws-lc-fips-sys releases ({sys:?}): a FIPS build links \
             exactly one",
            sys.len()
        ));
        return verdict;
    };
    verdict.fips_sys = (*sys).clone();
    if list.module(sys).is_none() {
        let newest = list.modules.last().map_or("", |m| m.sys.as_str());
        verdict.errors.push(format!(
            "aws-lc-fips-sys {sys} is not on the FIPS allowlist ({}): lock an allowlisted \
             release in the application's Cargo.lock (`cargo update -p aws-lc-fips-sys --precise \
             {newest}`), or add {sys} to {FILE} once it has been built and checked",
            list.describe_modules()
        ));
    }
    let expected = format!("aws_lc_fips_{}_crypto", sys.replace('.', "_"));
    let bound: Vec<&String> = graph.bound_libcrypto.iter().collect();
    if bound.as_slice() != [&expected] {
        verdict.errors.push(format!(
            "aws-lc-rs {} binds {bound:?}, not aws-lc-fips-sys {sys} ({expected}): one module, \
             the one this crate depends on, or none",
            verdict.aws_lc_rs
        ));
    }
    if !verdict.aws_lc_rs.is_empty() {
        match list.aws_lc_rs(&verdict.aws_lc_rs) {
            Some(entry) if series_of(sys).as_deref() != Some(entry.binds.as_str()) => {
                verdict.errors.push(format!(
                    "aws-lc-rs {} is listed as binding aws-lc-fips-sys {}, but links {sys}",
                    entry.version, entry.binds
                ));
            }
            Some(_) => {}
            None => verdict.warnings.push(format!(
                "aws-lc-rs {} is not on the FIPS allowlist; the module ({sys}) is, and it binds \
                 it, but an application's lockfile check refuses an unlisted aws-lc-rs",
                verdict.aws_lc_rs
            )),
        }
    }
    verdict
}
