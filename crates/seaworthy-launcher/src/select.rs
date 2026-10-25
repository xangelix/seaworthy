//! Choosing a core: pure decision logic, apart from files and loading so
//! every branch is unit-tested.

use std::path::PathBuf;

use seaworthy_levels::{Assessment, Host, Requirement};

/// What probing one core's file found.
#[derive(Debug)]
pub(crate) enum Probe {
    /// No file at the expected path.
    Missing,
    /// A file whose record could not be read (the reason).
    Unreadable(String),
    /// The file's requirement record.
    Record(Requirement),
}

/// One core the launcher may load, in preference order.
#[derive(Debug)]
pub(crate) struct Candidate {
    /// The CPU name it was built for (from the launcher's list).
    pub(crate) cpu: String,
    /// Where it lives.
    pub(crate) path: PathBuf,
    /// What its file holds.
    pub(crate) probe: Probe,
}

/// The decision.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Load the candidate at this index.
    Load(usize),
    /// Every core is present and consistent, and the host runs none: the
    /// lowest one's CPU name and assessment.
    NoneSupported {
        /// The least demanding readable core.
        cpu: String,
        /// Why the host can't run it.
        assessment: Assessment,
    },
    /// Nothing loadable, and at least one core is missing, unreadable, or
    /// carries another build's (or another target's) record: a damaged or
    /// incomplete install — the missing core may be the one this CPU runs,
    /// so "this CPU is too old" would be the wrong diagnosis.
    Damaged,
}

/// Walks `candidates` in order and returns the first one the host fully
/// supports and `extra` accepts (the AMX permission on Linux). Every
/// skipped candidate gets one line in `report`. With nothing loadable, the
/// verdict is [`Outcome::NoneSupported`] only when every candidate was
/// present and consistent; otherwise [`Outcome::Damaged`].
pub(crate) fn choose(
    candidates: &[Candidate],
    host: &Host,
    target: &str,
    mut extra: impl FnMut(&Requirement) -> Result<(), String>,
    report: &mut Vec<String>,
) -> Outcome {
    let mut lowest: Option<(String, Assessment)> = None;
    let mut damaged = false;
    for (index, candidate) in candidates.iter().enumerate() {
        let record = match &candidate.probe {
            Probe::Missing => {
                report.push(format!(
                    "{}: missing ({})",
                    candidate.cpu,
                    candidate.path.display()
                ));
                damaged = true;
                continue;
            }
            Probe::Unreadable(reason) => {
                report.push(format!("{}: unreadable ({reason})", candidate.cpu));
                damaged = true;
                continue;
            }
            Probe::Record(record) => record,
        };
        if record.cpu != candidate.cpu {
            report.push(format!(
                "{}: the file carries the record of another build ({}) — damaged install",
                candidate.cpu, record.cpu
            ));
            damaged = true;
            continue;
        }
        if record.target != target {
            report.push(format!(
                "{}: built for another target ({}, this launcher is {target}) — damaged install",
                candidate.cpu, record.target
            ));
            damaged = true;
            continue;
        }
        let assessment = host.assess(record, target);
        if !assessment.is_supported() {
            report.push(format!("{}: {assessment}", candidate.cpu));
            lowest = Some((candidate.cpu.clone(), assessment));
            continue;
        }
        if let Err(reason) = extra(record) {
            report.push(format!("{}: {reason}", candidate.cpu));
            lowest = Some((
                candidate.cpu.clone(),
                Assessment {
                    missing: vec![reason],
                    ..Assessment::default()
                },
            ));
            continue;
        }
        return Outcome::Load(index);
    }
    match lowest {
        Some((cpu, assessment)) if !damaged => Outcome::NoneSupported { cpu, assessment },
        _ => Outcome::Damaged,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    const TARGET: &str = "x86_64-unknown-linux-gnu";

    fn record(cpu: &str, features: &[&str]) -> Probe {
        let mut features: Vec<String> = features.iter().map(|f| (*f).to_owned()).collect();
        features.sort();
        Probe::Record(Requirement {
            target: TARGET.into(),
            cpu: cpu.into(),
            features,
        })
    }

    fn candidate(cpu: &str, probe: Probe) -> Candidate {
        Candidate {
            cpu: cpu.into(),
            path: PathBuf::from(format!("/opt/demo/lib/libdemo_core_{cpu}.so")),
            probe,
        }
    }

    /// A host with SSE4.2 but no AVX: a v2 machine.
    fn v2_host() -> Host {
        let text = "seaworthy-cpuid:1\ncpuid 00000000.00000000 00000001 756e6547 6c65746e 49656e69\ncpuid 00000001.00000000 00000000 00000000 00982201 07800001\ncpuid 80000000.00000000 80000001 00000000 00000000 00000000\ncpuid 80000001.00000000 00000000 00000000 00000001 00000000\nxcr0 0000000000000000\n";
        Host::from_source(&seaworthy_levels::Snapshot::parse(text).expect("fixture"))
    }

    const V2: &[&str] = &[
        "cmpxchg16b",
        "fxsr",
        "lahfsahf",
        "popcnt",
        "sse",
        "sse2",
        "sse3",
        "sse4.1",
        "sse4.2",
        "ssse3",
        "x87",
    ];
    const V3_EXTRA: &[&str] = &[
        "avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "lzcnt", "movbe", "xsave",
    ];

    fn v3() -> Vec<&'static str> {
        V2.iter().chain(V3_EXTRA).copied().collect()
    }

    #[test]
    fn the_first_supported_core_in_order_wins() {
        let candidates = [
            candidate("x86-64-v3", record("x86-64-v3", &v3())),
            candidate("x86-64-v2", record("x86-64-v2", V2)),
        ];
        let mut report = Vec::new();
        let outcome = choose(&candidates, &v2_host(), TARGET, |_| Ok(()), &mut report);
        assert_eq!(outcome, Outcome::Load(1));
        assert_eq!(report.len(), 1);
        assert!(
            report[0].starts_with("x86-64-v3: needs avx, avx2"),
            "{report:?}"
        );
    }

    #[test]
    fn missing_and_unreadable_cores_are_skipped_with_a_note() {
        let candidates = [
            candidate("x86-64-v3", Probe::Missing),
            candidate(
                "x86-64-v2",
                Probe::Unreadable("no `.cpureq` section".into()),
            ),
            candidate("x86-64", record("x86-64", &["fxsr", "sse", "sse2", "x87"])),
        ];
        let mut report = Vec::new();
        assert_eq!(
            choose(&candidates, &v2_host(), TARGET, |_| Ok(()), &mut report),
            Outcome::Load(2)
        );
        assert_eq!(report.len(), 2);
        assert!(report[0].contains("missing (/opt/demo/lib/libdemo_core_x86-64-v3.so)"));
        assert!(report[1].contains("unreadable (no `.cpureq` section)"));
    }

    #[test]
    fn a_file_carrying_another_builds_record_is_damage() {
        let candidates = [candidate("x86-64-v2", record("x86-64-v3", &v3()))];
        let mut report = Vec::new();
        assert_eq!(
            choose(&candidates, &v2_host(), TARGET, |_| Ok(()), &mut report),
            Outcome::Damaged
        );
        assert!(report[0].contains("damaged install"));
    }

    #[test]
    fn nothing_supported_reports_the_lowest_core() {
        let candidates = [
            candidate("x86-64-v4", record("x86-64-v4", &["avx512f"])),
            candidate("x86-64-v3", record("x86-64-v3", &v3())),
        ];
        let mut report = Vec::new();
        match choose(&candidates, &v2_host(), TARGET, |_| Ok(()), &mut report) {
            Outcome::NoneSupported { cpu, assessment } => {
                assert_eq!(cpu, "x86-64-v3");
                assert_eq!(assessment.missing, V3_EXTRA);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_record_for_another_target_is_damage() {
        let mut probe = record("x86-64-v2", V2);
        if let Probe::Record(r) = &mut probe {
            r.target = "x86_64-pc-windows-msvc".into();
        }
        let mut report = Vec::new();
        let outcome = choose(
            &[candidate("x86-64-v2", probe)],
            &v2_host(),
            TARGET,
            |_| Ok(()),
            &mut report,
        );
        assert_eq!(outcome, Outcome::Damaged);
        assert!(
            report[0].contains("built for another target (x86_64-pc-windows-msvc"),
            "{report:?}"
        );
    }

    #[test]
    fn a_missing_lowest_core_is_damage_not_an_old_cpu() {
        // v4 and v3 present but beyond this v2 host; the v2 core — the one it
        // would run — is missing: repair the install, don't blame the CPU.
        let candidates = [
            candidate("x86-64-v4", record("x86-64-v4", &["avx512f"])),
            candidate("x86-64-v3", record("x86-64-v3", &v3())),
            candidate("x86-64-v2", Probe::Missing),
        ];
        let mut report = Vec::new();
        assert_eq!(
            choose(&candidates, &v2_host(), TARGET, |_| Ok(()), &mut report),
            Outcome::Damaged
        );
        assert_eq!(report.len(), 3, "{report:?}");
        assert!(report[1].starts_with("x86-64-v3: needs avx"), "{report:?}");
        assert!(report[2].starts_with("x86-64-v2: missing"), "{report:?}");
    }

    #[test]
    fn an_extra_refusal_falls_back() {
        let candidates = [
            candidate("amx", record("amx", &["sse"])),
            candidate("x86-64-v2", record("x86-64-v2", V2)),
        ];
        let mut report = Vec::new();
        let outcome = choose(
            &candidates,
            &v2_host(),
            TARGET,
            |r| {
                if r.cpu == "amx" {
                    Err("the kernel refused AMX".into())
                } else {
                    Ok(())
                }
            },
            &mut report,
        );
        assert_eq!(outcome, Outcome::Load(1));
        assert_eq!(report, ["amx: the kernel refused AMX"]);
    }

    #[test]
    fn no_candidates_is_damage() {
        let mut report = Vec::new();
        assert_eq!(
            choose(&[], &v2_host(), TARGET, |_| Ok(()), &mut report),
            Outcome::Damaged
        );
    }
}
