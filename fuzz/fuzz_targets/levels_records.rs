#![no_main]
// libFuzzer wrapper — the target logic and its invariants live in
// `seaworthy_fuzz::targets::levels_records` (replayed on stable by the fuzz
// crate's replay test).
libfuzzer_sys::fuzz_target!(|data: &[u8]| seaworthy_fuzz::targets::levels_records::run(data));
