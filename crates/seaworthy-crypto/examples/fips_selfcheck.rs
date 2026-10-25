//! The FIPS release-binary probe.
//!
//! Build this example in release with the `fips` feature and its symbols
//! kept, run `scripts/verify-fips-binary.sh` over it (the
//! `aws_lc_fips_0_14_2_*` symbols present, zero non-FIPS `aws_lc_0_*` /
//! `ring_core_*`), then run it with `--expect-fips`: the boot self-check (a
//! module-DRBG draw + the pinned-module assertion), then `is_fips()`, then
//! the build provenance, printed, so the log is the evidence of which
//! module and toolchain the release build used.
//!
//! ```text
//! CARGO_PROFILE_RELEASE_STRIP=false cargo build --release -p seaworthy-crypto \
//!     --features fips --example fips_selfcheck
//! scripts/verify-fips-binary.sh target/release/examples/fips_selfcheck
//! target/release/examples/fips_selfcheck --expect-fips
//! ```

use std::process::ExitCode;

fn main() -> ExitCode {
    let expect_fips = std::env::args().any(|arg| arg == "--expect-fips");
    // First thing: the self-check (the first DRBG draw: a CPU-jitter
    // health-test abort happens HERE, at boot).
    let check = match seaworthy_crypto::module::startup_self_check() {
        Ok(check) => check,
        Err(error) => {
            eprintln!("fips_selfcheck: startup self-check FAILED: {error}");
            return ExitCode::FAILURE;
        }
    };
    let fips = seaworthy_crypto::is_fips();
    println!("module:        {}", check.module.describe());
    println!("fips mode:     {}", check.module.fips_mode);
    println!("module branch: {:?}", check.module.fips_branch);
    println!("cpu jitter:    {}", check.module.cpu_jitter_entropy);
    println!("rng drawn:     {} bytes", check.rng_bytes_drawn);
    println!("is_fips():     {fips}");
    println!("cmvp:          {}", seaworthy_crypto::module::CMVP_STATUS);
    for (key, value) in seaworthy_crypto::module::build_provenance().fields() {
        println!("build.{key:<18} {value}");
    }
    if expect_fips && !(fips && check.module.fips_build && check.module.fips_mode) {
        eprintln!("fips_selfcheck: --expect-fips, but this process is not running FIPS");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
