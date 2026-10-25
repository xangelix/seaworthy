//! seaworthy fuzz targets: the logic behind every `fuzz_targets/<name>.rs`
//! libFuzzer binary, as plain functions (`targets::<name>::run(&[u8])`), so
//! the committed seeds and minimized regressions replay on stable
//! (`tests/replay.rs`) without libFuzzer.
//!
//! Every target prefers an INVARIANT over bare no-panic wherever one is
//! cheap: decode→encode round-trips, parse idempotence, independent oracles,
//! bounded allocation, and tamper detection (a flipped bit in a signed
//! input must fail verification). A violated invariant panics, and
//! libFuzzer reports it as a crash, exactly like an unexpected panic in the
//! parser.
//!
//! Adding a target `<name>` (fuzz/README.md):
//!
//! 1. `src/targets/<name>.rs` with `pub fn run(data: &[u8])`;
//! 2. `<name>,` in the `targets!` list below;
//! 3. a `[[bin]]` entry in `Cargo.toml` and the wrapper
//!    `fuzz_targets/<name>.rs`;
//! 4. at least one seed in `corpus/<name>/`.

#![forbid(unsafe_code)]
// Invariant checks panic on purpose: that is how a target reports a bug.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// One target: its binary name and its entry point.
pub type Target = (&'static str, fn(&[u8]));

/// Declares each target's module (`src/targets/<name>.rs`) and its entry
/// in [`TARGETS`] from one list, so the two cannot drift apart.
macro_rules! targets {
    ($($name:ident),* $(,)?) => {
        /// One module per fuzz target; each exposes `pub fn run(data: &[u8])`.
        pub mod targets {
            $(pub mod $name;)*
        }

        /// Every target, by its binary name: the `[[bin]]` entries in
        /// `Cargo.toml` and the `fuzz_targets/` wrappers match this list.
        pub const TARGETS: &[Target] = &[$((stringify!($name), targets::$name::run)),*];
    };
}

// The target list, one name per line, sorted.
#[rustfmt::skip]
targets![
    levels_records,
    service_unit,
    updater_manifest,
];

/// Drive a future to completion on the current thread. Fuzzed futures
/// (in-memory channels, cursor-backed codecs) never park on I/O, but the
/// waker is a real thread-unpark, so a future that does yield still
/// completes instead of spinning.
pub fn block_on<F: std::future::Future>(future: F) -> F::Output {
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct Unpark(std::thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::park(),
        }
    }
}

/// Split `data` at the first `sep` byte: `(before, after)`, or `(data, &[])`
/// when absent. The input convention of multi-field targets.
pub fn split_at_byte(data: &[u8], sep: u8) -> (&[u8], &[u8]) {
    match data.iter().position(|&b| b == sep) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[]),
    }
}

/// `data` as UTF-8, lossily: string-typed parsers see valid UTF-8, as they
/// do from their production callers.
pub fn text(data: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(data)
}
