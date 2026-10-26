//! The Windows lab's service launcher: plain x86-64, the fixture's three
//! cores in preference order (`targets` in seaworthy.toml). The products
//! are Windows-only (MSIs); elsewhere it builds and runs as any launcher.

#[cfg(not(target_os = "macos"))]
seaworthy_launcher::launcher_main!(
    core = "scm_core",
    cpus = ["x86-64-v4", "x86-64-v3", "x86-64-v2"],
);

#[cfg(target_os = "macos")]
fn main() {
    eprintln!("the SCM fixture has no macOS build");
    std::process::exit(2);
}
