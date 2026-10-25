//! Recorded CPUID dumps: every leaf the detector reads, plus `XCR0`, in a
//! small text format — replayed through [`CpuidSource`] by tests (recorded
//! real and emulated CPUs as fixtures) and attached to support reports
//! ("why did the launcher pick that core?").
//!
//! ```text
//! seaworthy-cpuid:1
//! # AMD Ryzen 9 9950X3D, Linux 7.2
//! cpuid 00000000.00000000 00000010 68747541 444d4163 69746e65
//! cpuid 00000001.00000000 00b40f40 ...
//! xcr0 00000000000002e7
//! ```
//!
//! Lines: the magic first, then `#` comments, `cpuid <leaf>.<subleaf> <eax>
//! <ebx> <ecx> <edx>` (hex, eight digits each) and one `xcr0 <hex>`. A leaf
//! the dump does not hold reads as all zeros, like an unsupported leaf.

use std::collections::BTreeMap;

use crate::detect::CpuidSource;

/// The format's first line.
pub const SNAPSHOT_MAGIC: &str = "seaworthy-cpuid:1";

/// Every `(leaf, subleaf)` the detector reads (maximum-leaf queries
/// included), in recording order.
pub const LEAVES: [(u32, u32); 11] = [
    (0, 0),
    (1, 0),
    (7, 0),
    (7, 1),
    (0xD, 1),
    (0x19, 0),
    (0x1E, 0),
    (0x1E, 1),
    (0x24, 0),
    (0x8000_0000, 0),
    (0x8000_0001, 0),
];

/// A recorded CPU.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    comment: Vec<String>,
    leaves: BTreeMap<(u32, u32), [u32; 4]>,
    xcr0: u64,
}

/// A malformed dump.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotError {
    /// 1-based line number.
    pub line: usize,
    /// What is wrong with it.
    pub reason: &'static str,
}

impl core::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CPUID dump line {}: {}", self.line, self.reason)
    }
}

impl std::error::Error for SnapshotError {}

impl Snapshot {
    /// Records every leaf in [`LEAVES`] from `source` (leaves the CPU does
    /// not have are recorded as whatever it answers — the detector
    /// range-checks them on replay exactly as it does live). `XCR0` is read
    /// only when the CPU reports XSAVE and OSXSAVE.
    #[must_use]
    pub fn record<S: CpuidSource>(source: &S, comment: &[&str]) -> Self {
        let mut leaves = BTreeMap::new();
        for (leaf, subleaf) in LEAVES {
            leaves.insert((leaf, subleaf), source.cpuid(leaf, subleaf));
        }
        let ecx1 = leaves.get(&(1, 0)).map_or(0, |regs| regs[2]);
        // CPUID.1:ECX.XSAVE[26] and OSXSAVE[27].
        let osxsave = ecx1 & 0x0400_0000 != 0 && ecx1 & 0x0800_0000 != 0;
        Self {
            // One comment line per entry: control characters (a newline in a
            // description) would otherwise inject lines into the dump.
            comment: comment
                .iter()
                .map(|line| {
                    line.chars()
                        .map(|c| if c.is_control() { ' ' } else { c })
                        .collect()
                })
                .collect(),
            leaves,
            xcr0: if osxsave { source.xcr0() } else { 0 },
        }
    }

    /// Parses a dump.
    ///
    /// # Errors
    /// [`SnapshotError`] naming the first malformed line: a missing or wrong
    /// magic, a malformed `cpuid` or `xcr0` line, a repeated leaf or `xcr0`,
    /// or an unknown line.
    pub fn parse(text: &str) -> Result<Self, SnapshotError> {
        let mut lines = text.lines().enumerate();
        match lines.next() {
            Some((_, first)) if first == SNAPSHOT_MAGIC => {}
            _ => {
                return Err(SnapshotError {
                    line: 1,
                    reason: "the first line must be `seaworthy-cpuid:1`",
                });
            }
        }
        let mut snapshot = Self::default();
        let mut have_xcr0 = false;
        for (index, line) in lines {
            let number = index.saturating_add(1);
            let err = |reason| SnapshotError {
                line: number,
                reason,
            };
            if let Some(comment) = line.strip_prefix('#') {
                snapshot.comment.push(comment.trim().to_owned());
            } else if let Some(rest) = line.strip_prefix("cpuid ") {
                let mut words = rest.split(' ');
                let at = words.next().ok_or_else(|| err("missing leaf"))?;
                let (leaf, subleaf) = at
                    .split_once('.')
                    .ok_or_else(|| err("leaf must be <leaf>.<subleaf>"))?;
                let key = (
                    hex32(leaf).ok_or_else(|| err("bad leaf"))?,
                    hex32(subleaf).ok_or_else(|| err("bad sub-leaf"))?,
                );
                let mut regs = [0u32; 4];
                for reg in &mut regs {
                    *reg = words
                        .next()
                        .and_then(hex32)
                        .ok_or_else(|| err("expected four 8-digit hex registers"))?;
                }
                if words.next().is_some() {
                    return Err(err("trailing data after the four registers"));
                }
                if snapshot.leaves.insert(key, regs).is_some() {
                    return Err(err("a leaf is recorded twice"));
                }
            } else if let Some(rest) = line.strip_prefix("xcr0 ") {
                if have_xcr0 {
                    return Err(err("xcr0 is recorded twice"));
                }
                snapshot.xcr0 = hex64(rest).ok_or_else(|| err("xcr0 must be 16 hex digits"))?;
                have_xcr0 = true;
            } else if !line.is_empty() {
                return Err(err("unknown line"));
            }
        }
        Ok(snapshot)
    }

    /// The dump in the text format (round-trips through [`Snapshot::parse`]).
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::from(SNAPSHOT_MAGIC);
        out.push('\n');
        for line in &self.comment {
            out.push_str("# ");
            out.push_str(line);
            out.push('\n');
        }
        for ((leaf, subleaf), [eax, ebx, ecx, edx]) in &self.leaves {
            out.push_str(&format!(
                "cpuid {leaf:08x}.{subleaf:08x} {eax:08x} {ebx:08x} {ecx:08x} {edx:08x}\n"
            ));
        }
        out.push_str(&format!("xcr0 {:016x}\n", self.xcr0));
        out
    }

    /// The dump's comment lines (the CPU model, the OS, how it was taken).
    #[must_use]
    pub fn comment(&self) -> &[String] {
        &self.comment
    }
}

fn hex32(text: &str) -> Option<u32> {
    (text.len() == 8 && text.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(text, 16).ok())
        .flatten()
}

/// Exactly 16 hex digits (`from_str_radix` alone would also take a sign).
fn hex64(text: &str) -> Option<u64> {
    (text.len() == 16 && text.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| u64::from_str_radix(text, 16).ok())
        .flatten()
}

impl CpuidSource for Snapshot {
    fn cpuid(&self, leaf: u32, subleaf: u32) -> [u32; 4] {
        self.leaves.get(&(leaf, subleaf)).copied().unwrap_or([0; 4])
    }

    fn xcr0(&self) -> u64 {
        self.xcr0
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const SAMPLE: &str = "seaworthy-cpuid:1\n# a test CPU\ncpuid 00000000.00000000 00000007 756e6547 6c65746e 49656e69\ncpuid 00000001.00000000 00000000 00000000 1c800201 07800001\nxcr0 0000000000000007\n";

    #[test]
    fn a_dump_round_trips() {
        let snapshot = Snapshot::parse(SAMPLE).expect("parses");
        assert_eq!(snapshot.render(), SAMPLE);
        assert_eq!(snapshot.comment(), ["a test CPU"]);
        assert_eq!(snapshot.cpuid(0, 0)[0], 7);
        assert_eq!(
            snapshot.cpuid(0x42, 0),
            [0; 4],
            "unrecorded leaves read as zeros"
        );
        assert_eq!(snapshot.xcr0(), 7);
    }

    #[test]
    fn a_comment_cannot_inject_lines() {
        let snapshot = Snapshot::record(
            &Snapshot::default(),
            &["evil\ncpuid 00000000.00000000 ffffffff 0 0 0"],
        );
        let text = snapshot.render();
        assert_eq!(
            text.lines()
                .filter(|l| l.starts_with("cpuid 00000000.00000000 ffffffff"))
                .count(),
            0,
            "{text}"
        );
        assert_eq!(Snapshot::parse(&text).expect("parses"), snapshot);
    }

    #[test]
    fn malformed_dumps_name_their_line() {
        let cases = [
            (
                "not-a-dump\n",
                1,
                "the first line must be `seaworthy-cpuid:1`",
            ),
            ("seaworthy-cpuid:1\ncpuid 0.0 1 2 3 4\n", 2, "bad leaf"),
            (
                "seaworthy-cpuid:1\ncpuid 00000000.00000000 00000001\n",
                2,
                "expected four 8-digit hex registers",
            ),
            (
                "seaworthy-cpuid:1\ncpuid 00000000.00000000 00000001 00000002 00000003 00000004 5\n",
                2,
                "trailing data after the four registers",
            ),
            (
                "seaworthy-cpuid:1\ncpuid 00000000.00000000 00000001 00000002 00000003 00000004\ncpuid 00000000.00000000 00000001 00000002 00000003 00000004\n",
                3,
                "a leaf is recorded twice",
            ),
            (
                "seaworthy-cpuid:1\nxcr0 7\n",
                2,
                "xcr0 must be 16 hex digits",
            ),
            // A sign is not a hex digit.
            (
                "seaworthy-cpuid:1\nxcr0 +000000000000007\n",
                2,
                "xcr0 must be 16 hex digits",
            ),
            (
                "seaworthy-cpuid:1\nxcr0 0000000000000007\nxcr0 0000000000000007\n",
                3,
                "xcr0 is recorded twice",
            ),
            ("seaworthy-cpuid:1\nbogus\n", 2, "unknown line"),
        ];
        for (text, line, reason) in cases {
            assert_eq!(
                Snapshot::parse(text),
                Err(SnapshotError { line, reason }),
                "{text:?}"
            );
        }
    }
}
