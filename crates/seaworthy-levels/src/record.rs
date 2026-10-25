//! The two records a launcher layout carries in linker sections:
//!
//! - **The requirement record** (`.cpureq`, in every core) — what the
//!   compiler enabled for that core:
//!
//!   ```text
//!   seaworthy-cpureq:1
//!   target=x86_64-unknown-linux-gnu
//!   cpu=x86-64-v3
//!   features=avx,avx2,bmi1,...,xsave
//!   ```
//!
//! - **The CPU list** (`.cpulist`, in the launcher) — the core's file stem
//!   and the preference order the launcher tries:
//!
//!   ```text
//!   seaworthy-cpulist:1
//!   core=acme_core
//!   cpus=x86-64-v4,x86-64-v3,x86-64-v2
//!   ```
//!
//! Both parsers are strict — fixed line order, `\n` endings, every value
//! shape-checked, at most [`MAX_RECORD_BYTES`] — and tolerate only trailing
//! NUL padding (a PE section's raw size is rounded up to the file
//! alignment).

use crate::table::is_feature_name;

/// The requirement record's first line (format version 1).
pub const RECORD_MAGIC: &str = "seaworthy-cpureq:1";
/// The CPU list's first line (format version 1).
pub const CPULIST_MAGIC: &str = "seaworthy-cpulist:1";
/// The largest record either parser accepts.
pub const MAX_RECORD_BYTES: usize = 4096;

/// A core's requirement record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requirement {
    /// The target triple the core was compiled for.
    pub target: String,
    /// The rustc CPU name it was compiled for (`-C target-cpu`).
    pub cpu: String,
    /// Every target feature that compiler enabled, sorted and unique.
    pub features: Vec<String>,
}

/// A launcher's CPU list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuList {
    /// The core's file stem (`acme_core`): the cores are
    /// `<core>_<cpu>.dll` on Windows and `lib/lib<core>_<cpu>.so` on Linux.
    pub core: String,
    /// The CPU names to try, most preferred first.
    pub cpus: Vec<String>,
}

/// A malformed record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Larger than [`MAX_RECORD_BYTES`].
    TooLarge(usize),
    /// Not UTF-8, or containing a carriage return or an interior NUL.
    NotText,
    /// The first line is not the expected magic (its text, truncated).
    WrongFormat(String),
    /// A field is missing or out of order (the field expected).
    Expected(&'static str),
    /// A field's value is malformed.
    BadValue {
        /// The field.
        field: &'static str,
        /// Why.
        reason: &'static str,
    },
    /// Lines after the last field.
    TrailingData,
}

impl core::fmt::Display for RecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge(len) => write!(f, "record of {len} bytes exceeds {MAX_RECORD_BYTES}"),
            Self::NotText => f.write_str("record is not LF-terminated UTF-8 text"),
            Self::WrongFormat(first) => write!(f, "unknown record format {first:?}"),
            Self::Expected(field) => write!(f, "expected the `{field}=` line"),
            Self::BadValue { field, reason } => write!(f, "`{field}`: {reason}"),
            Self::TrailingData => f.write_str("data after the last field"),
        }
    }
}

impl std::error::Error for RecordError {}

/// The record's lines after the trailing-NUL and size checks.
fn lines<'a>(bytes: &'a [u8], magic: &'static str) -> Result<Vec<&'a str>, RecordError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(RecordError::TooLarge(bytes.len()));
    }
    let end = bytes
        .iter()
        .rposition(|b| *b != 0)
        .map_or(0, |i| i.saturating_add(1));
    let text = bytes.get(..end).ok_or(RecordError::NotText)?;
    let text = core::str::from_utf8(text).map_err(|_| RecordError::NotText)?;
    if text.contains('\r') || text.contains('\0') {
        return Err(RecordError::NotText);
    }
    let text = text.strip_suffix('\n').unwrap_or(text);
    let lines: Vec<&str> = text.split('\n').collect();
    match lines.first() {
        Some(first) if *first == magic => Ok(lines),
        Some(first) => Err(RecordError::WrongFormat(first.chars().take(40).collect())),
        None => Err(RecordError::WrongFormat(String::new())),
    }
}

fn field<'a>(line: Option<&&'a str>, name: &'static str) -> Result<&'a str, RecordError> {
    line.and_then(|line| line.strip_prefix(name))
        .and_then(|rest| rest.strip_prefix('='))
        .ok_or(RecordError::Expected(name))
}

/// A target triple: lower-case ASCII letters, digits, `_`, `.` and `-`.
fn is_triple(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        })
}

/// A rustc CPU name or a core stem: ASCII letters, digits, `_`, `.` and `-`,
/// starting with a letter.
fn is_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

impl Requirement {
    /// Parses a requirement record (the bytes of a `.cpureq` section).
    ///
    /// # Errors
    /// [`RecordError`] for any deviation from the format.
    pub fn parse(bytes: &[u8]) -> Result<Self, RecordError> {
        let lines = lines(bytes, RECORD_MAGIC)?;
        let target = field(lines.get(1), "target")?;
        if !is_triple(target) {
            return Err(RecordError::BadValue {
                field: "target",
                reason: "not a target triple",
            });
        }
        let cpu = field(lines.get(2), "cpu")?;
        if !is_name(cpu) {
            return Err(RecordError::BadValue {
                field: "cpu",
                reason: "not a CPU name",
            });
        }
        let features = field(lines.get(3), "features")?;
        let features: Vec<String> = if features.is_empty() {
            Vec::new()
        } else {
            features.split(',').map(str::to_owned).collect()
        };
        if features.iter().any(|name| !is_feature_name(name)) {
            return Err(RecordError::BadValue {
                field: "features",
                reason: "a malformed feature name",
            });
        }
        if features
            .windows(2)
            .any(|pair| matches!(pair, [a, b] if a >= b))
        {
            return Err(RecordError::BadValue {
                field: "features",
                reason: "not sorted and unique",
            });
        }
        if lines.len() > 4 {
            return Err(RecordError::TrailingData);
        }
        Ok(Self {
            target: target.to_owned(),
            cpu: cpu.to_owned(),
            features,
        })
    }

    /// The record in its on-disk form (round-trips through
    /// [`Requirement::parse`]; `features` must already be sorted and unique).
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "{RECORD_MAGIC}\ntarget={}\ncpu={}\nfeatures={}\n",
            self.target,
            self.cpu,
            self.features.join(",")
        )
    }
}

impl CpuList {
    /// Parses a CPU list (the bytes of a `.cpulist` section).
    ///
    /// # Errors
    /// [`RecordError`] for any deviation from the format, including an
    /// empty or repeated CPU name.
    pub fn parse(bytes: &[u8]) -> Result<Self, RecordError> {
        let lines = lines(bytes, CPULIST_MAGIC)?;
        let core = field(lines.get(1), "core")?;
        if !is_name(core) {
            return Err(RecordError::BadValue {
                field: "core",
                reason: "not a core file stem",
            });
        }
        let cpus: Vec<String> = field(lines.get(2), "cpus")?
            .split(',')
            .map(str::to_owned)
            .collect();
        if cpus.iter().any(|cpu| !is_name(cpu)) {
            return Err(RecordError::BadValue {
                field: "cpus",
                reason: "an empty or malformed CPU name",
            });
        }
        let unique: std::collections::BTreeSet<&String> = cpus.iter().collect();
        if unique.len() != cpus.len() {
            return Err(RecordError::BadValue {
                field: "cpus",
                reason: "a CPU name is listed twice",
            });
        }
        if lines.len() > 3 {
            return Err(RecordError::TrailingData);
        }
        Ok(Self {
            core: core.to_owned(),
            cpus,
        })
    }

    /// The list in its on-disk form.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "{CPULIST_MAGIC}\ncore={}\ncpus={}\n",
            self.core,
            self.cpus.join(",")
        )
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const V3: &str = "seaworthy-cpureq:1\ntarget=x86_64-unknown-linux-gnu\ncpu=x86-64-v3\nfeatures=avx,avx2,bmi1,bmi2,cmpxchg16b,f16c,fma,fxsr,lahfsahf,lzcnt,movbe,popcnt,sse,sse2,sse3,sse4.1,sse4.2,ssse3,x87,xsave\n";

    #[test]
    fn a_record_round_trips_and_tolerates_nul_padding() {
        let record = Requirement::parse(V3.as_bytes()).expect("parses");
        assert_eq!(record.cpu, "x86-64-v3");
        assert_eq!(record.features.len(), 20);
        assert_eq!(record.render(), V3);
        let mut padded = V3.as_bytes().to_vec();
        padded.resize(512, 0);
        assert_eq!(Requirement::parse(&padded), Ok(record));
    }

    #[test]
    fn malformed_records_are_refused() {
        let cases: [(&str, RecordError); 9] = [
            (
                "seaworthy-cpureq:2\n",
                RecordError::WrongFormat("seaworthy-cpureq:2".into()),
            ),
            (
                "seaworthy-cpureq:1\ncpu=x\n",
                RecordError::Expected("target"),
            ),
            (
                "seaworthy-cpureq:1\ntarget=X86\ncpu=a\nfeatures=\n",
                RecordError::BadValue {
                    field: "target",
                    reason: "not a target triple",
                },
            ),
            (
                "seaworthy-cpureq:1\ntarget=t\ncpu=-v3\nfeatures=\n",
                RecordError::BadValue {
                    field: "cpu",
                    reason: "not a CPU name",
                },
            ),
            (
                "seaworthy-cpureq:1\ntarget=t\ncpu=a\nfeatures=sse,AVX\n",
                RecordError::BadValue {
                    field: "features",
                    reason: "a malformed feature name",
                },
            ),
            (
                "seaworthy-cpureq:1\ntarget=t\ncpu=a\nfeatures=sse2,sse\n",
                RecordError::BadValue {
                    field: "features",
                    reason: "not sorted and unique",
                },
            ),
            (
                "seaworthy-cpureq:1\ntarget=t\ncpu=a\nfeatures=sse,sse\n",
                RecordError::BadValue {
                    field: "features",
                    reason: "not sorted and unique",
                },
            ),
            (
                "seaworthy-cpureq:1\ntarget=t\ncpu=a\nfeatures=sse\nextra\n",
                RecordError::TrailingData,
            ),
            ("seaworthy-cpureq:1\r\ntarget=t\n", RecordError::NotText),
        ];
        for (text, err) in cases {
            assert_eq!(Requirement::parse(text.as_bytes()), Err(err), "{text:?}");
        }
        assert_eq!(
            Requirement::parse(&[b'a'; 5000]),
            Err(RecordError::TooLarge(5000))
        );
        assert_eq!(
            Requirement::parse(b"seaworthy-cpureq:1\0x\n"),
            Err(RecordError::NotText),
            "interior NUL"
        );
    }

    #[test]
    fn an_empty_feature_list_is_well_formed() {
        let record = Requirement::parse(b"seaworthy-cpureq:1\ntarget=t\ncpu=a\nfeatures=\n")
            .expect("parses");
        assert!(record.features.is_empty());
    }

    #[test]
    fn a_cpu_list_round_trips_and_refuses_repeats() {
        let text = "seaworthy-cpulist:1\ncore=acme_core\ncpus=x86-64-v4,x86-64-v3,x86-64-v2\n";
        let list = CpuList::parse(text.as_bytes()).expect("parses");
        assert_eq!(list.cpus, ["x86-64-v4", "x86-64-v3", "x86-64-v2"]);
        assert_eq!(list.render(), text);
        assert_eq!(
            CpuList::parse(b"seaworthy-cpulist:1\ncore=c\ncpus=a,a\n"),
            Err(RecordError::BadValue {
                field: "cpus",
                reason: "a CPU name is listed twice"
            })
        );
        assert_eq!(
            CpuList::parse(b"seaworthy-cpulist:1\ncore=c\ncpus=\n"),
            Err(RecordError::BadValue {
                field: "cpus",
                reason: "an empty or malformed CPU name"
            })
        );
        assert_eq!(
            CpuList::parse(b"seaworthy-cpulist:1\ncore=../x\ncpus=a\n"),
            Err(RecordError::BadValue {
                field: "core",
                reason: "not a core file stem"
            })
        );
    }
}
