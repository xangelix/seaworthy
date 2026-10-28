//! A desktop program's launcher. `windows_subsystem = "windows"` makes it a
//! GUI-subsystem program on Windows, so starting it opens no console window;
//! with no console (or terminal) to report to, the launcher shows its own
//! failures in a dialog as well as on stderr (`ENV_NO_DIALOG` and the
//! crate's docs have the rules).
//!
//! Run without a core beside it, it exits 74 (a damaged install) after
//! saying so: `tests/windows_dialog.rs` runs it that way on Windows.

#![windows_subsystem = "windows"]

seaworthy_launcher::launcher_main!(
    core = "acme_desktop_core",
    cpus = ["x86-64-v3", "x86-64-v2"],
);
