#![no_main]
// libFuzzer wrapper: the logic and its invariants live in
// `seaworthy_fuzz::targets::mldsa_public_key` (replayed on stable by tests/replay.rs).
libfuzzer_sys::fuzz_target!(|data: &[u8]| seaworthy_fuzz::targets::mldsa_public_key::run(data));
