//! Prints this machine's CPUID dump in `seaworthy-levels`' snapshot format,
//! followed by the features the launcher would consider present.
//!
//! ```text
//! cargo run -p seaworthy-levels --example cpuid_dump -- "AMD Ryzen 9 9950X3D, Linux 7.2"
//! ```
//!
//! Attach the dump to a support report ("why did the launcher pick that
//! core?") — `Snapshot::parse` replays it exactly — or add it to
//! `tests/fixtures/` as a recorded CPU. Under qemu-user
//! (`qemu-x86_64 -cpu Haswell target/debug/examples/cpuid_dump`) it records
//! the emulated model.

#[cfg(target_arch = "x86_64")]
fn main() {
    let comment: Vec<String> = std::env::args().skip(1).collect();
    let comment: Vec<&str> = comment.iter().map(String::as_str).collect();
    let snapshot = seaworthy_levels::Snapshot::record(&seaworthy_levels::Native, &comment);
    print!("{}", snapshot.render());
    let host = seaworthy_levels::Host::from_source(&snapshot);
    eprintln!("features: {}", host.names().collect::<Vec<_>>().join(","));
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {
    eprintln!("cpuid_dump: x86-64 only");
    std::process::exit(2);
}
