//! The fixture's launcher: plain x86-64, three cores in preference order.
//! On Apple Silicon macOS, an `apple-m4` core — whose record carries
//! `v8.5a` and later, which macOS reports nothing for, so the launcher
//! skips it — and the `apple-m1` baseline it falls back to.

#[cfg(not(target_os = "macos"))]
seaworthy_launcher::launcher_main!(
    core = "demo_core",
    cpus = ["x86-64-v4", "x86-64-v3", "x86-64-v2"],
);

#[cfg(target_os = "macos")]
seaworthy_launcher::launcher_main!(core = "demo_core", cpus = ["apple-m4", "apple-m1"]);
