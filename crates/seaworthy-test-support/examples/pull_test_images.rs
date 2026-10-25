//! The pre-pull step's entry point: pulls the digest-pinned test images
//! serially, retrying transient registry failures, before the container
//! suites run. Run it through `scripts/pull-test-images.sh`, which pins the
//! toolchain and the lockfile; `--help` lists the options. The logic lives
//! in `seaworthy_test_support::prepull` (unit-tested there).

use std::process::ExitCode;

#[cfg(unix)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    seaworthy_test_support::prepull::run(std::env::args().skip(1)).await
}

/// The harness is unix-only (see the crate docs).
#[cfg(not(unix))]
fn main() -> ExitCode {
    eprintln!("pull-test-images: the container test harness is unix-only");
    ExitCode::from(2)
}
