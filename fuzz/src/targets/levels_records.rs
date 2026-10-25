//! `levels_records` — seaworthy-levels' parsers, which read a core's file
//! before anything of it runs: the requirement record (`.cpureq`), the CPU
//! list (`.cpulist`), the CPUID dump format, and the ELF/PE/Mach-O section
//! reader over arbitrary bytes.
//!
//! Input: `[mode][bytes]`. Mode 0: `Requirement::parse`; mode 1:
//! `CpuList::parse`; mode 2: `Snapshot::parse` (and detection over the
//! dump); mode 3: the section readers over the bytes as a binary image.
//! Invariants: nothing panics; anything a parser accepts renders back to a
//! form the same parser reads identically.

use seaworthy_levels::{
    CpuList, Host, Requirement, Snapshot, cpu_list_from_bytes, requirement_from_bytes,
};

/// Runs one input (see the module docs for its layout).
pub fn run(data: &[u8]) {
    let Some((&mode, bytes)) = data.split_first() else {
        return;
    };
    match mode % 4 {
        0 => {
            if let Ok(record) = Requirement::parse(bytes) {
                let again = Requirement::parse(record.render().as_bytes());
                assert_eq!(
                    again.as_ref(),
                    Ok(&record),
                    "a record re-parses identically"
                );
                // Assessment over an arbitrary accepted record never panics.
                let _ = Host::detect()
                    .assess(&record, "x86_64-unknown-linux-gnu")
                    .to_string();
            }
        }
        1 => {
            if let Ok(list) = CpuList::parse(bytes) {
                let again = CpuList::parse(list.render().as_bytes());
                assert_eq!(
                    again.as_ref(),
                    Ok(&list),
                    "a CPU list re-parses identically"
                );
            }
        }
        2 => {
            let text = String::from_utf8_lossy(bytes);
            if let Ok(snapshot) = Snapshot::parse(&text) {
                let again = Snapshot::parse(&snapshot.render());
                assert_eq!(
                    again.as_ref(),
                    Ok(&snapshot),
                    "a dump re-parses identically"
                );
                // Detection over any dump: range checks, never a panic.
                let host = Host::from_source(&snapshot);
                let _ = host.names().count();
            }
        }
        _ => {
            let _ = requirement_from_bytes(bytes);
            let _ = cpu_list_from_bytes(bytes);
        }
    }
}
