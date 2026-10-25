#![no_main]
// libFuzzer wrapper — the target logic and its invariants live in
// `seaworthy_fuzz::targets::service_unit` (replayed on stable by tests/replay.rs).
libfuzzer_sys::fuzz_target!(|data: &[u8]| seaworthy_fuzz::targets::service_unit::run(data));
