# seaworthy fuzz targets

cargo-fuzz (libFuzzer + AddressSanitizer) targets over seaworthy's parsers of untrusted input:
release manifests and identifiers, CPU requirement records and CPU lists, CPUID dumps,
configuration, URL templates, package metadata readers and the S3 store's XML responses. Every such parser has a target
(the security baseline in [CONTRIBUTING.md](../CONTRIBUTING.md)).

## Layout

| Path | What |
|---|---|
| `Cargo.toml` | The `seaworthy-fuzz` crate. It is its **own workspace**, listed in the root `exclude`, with its own `Cargo.lock`. libFuzzer, `arbitrary` and the nightly sanitizer builds never touch the stable build, `cargo test --workspace`, clippy or cargo-deny's graph. |
| `rust-toolchain.toml` | The pinned nightly that `scripts/fuzz.sh` uses (Dependabot proposes newer ones). |
| `src/lib.rs` | The `targets!` list: one line per target. It declares each target's module and its entry in `TARGETS`. |
| `src/targets/<name>.rs` | The target logic: `pub fn run(data: &[u8])`, plus the invariants it asserts. |
| `fuzz_targets/<name>.rs` | One-line libFuzzer wrappers. |
| `corpus/<name>/` | Small committed seeds: real inputs, golden vectors, inputs from reviews. |
| `regressions/<name>/` | Minimized inputs from past crashes. Keep them forever. |
| `dicts/<name>.dict` | Optional libFuzzer dictionaries (grammar tokens, magic strings). |
| `tests/replay.rs` | Replays every seed and regression through its target on **stable**, without libFuzzer, and checks that the target list, the `[[bin]]` entries, the wrappers, the target modules and the seed directories agree. |

A crate reaches its private parsers through a doc-hidden `__fuzz` module behind its own `fuzzing`
feature (off by default, no extra dependencies), enabled in this crate's `Cargo.toml`. Keep each
such module a thin re-export: invariants belong here, not in the crate.

## Running

```sh
cargo test --manifest-path fuzz/Cargo.toml   # replay every seed and regression (stable)
scripts/fuzz.sh list                         # the targets
scripts/fuzz.sh run <target> 300             # one target for 5 min; the corpus grows under fuzz/work/
scripts/fuzz.sh smoke                        # every target for 60 s, seeds only
scripts/fuzz.sh nightly                      # a ~30 min budget across targets, persisted corpus
```

`scripts/fuzz.sh` installs the pinned nightly with rustup when it is missing and uses the
cargo-fuzz on `PATH` when it is the pinned version, otherwise the pinned release binary
(SHA-256 verified, `scripts/ci/install-tool.sh`). Every setting is listed in the script's header.

## Adding a target

For a target named `manifest_decode`:

1. Write `src/targets/manifest_decode.rs`:

   ```rust
   //! `manifest_decode`: what it feeds, and the invariants beyond "no panic".

   pub fn run(data: &[u8]) {
       // Parse `data`; assert round-trips and other invariants.
   }
   ```

2. Add `manifest_decode,` to the `targets!` list in `src/lib.rs` (sorted).
3. Add the binary to `Cargo.toml`, and the crate under test as a path dependency if it is new:

   ```toml
   [[bin]]
   name = "manifest_decode"
   path = "fuzz_targets/manifest_decode.rs"
   test = false
   doc = false
   bench = false
   ```

4. Add the wrapper `fuzz_targets/manifest_decode.rs`:

   ```rust
   #![no_main]
   // libFuzzer wrapper: the logic and its invariants live in
   // `seaworthy_fuzz::targets::manifest_decode` (replayed on stable by tests/replay.rs).
   libfuzzer_sys::fuzz_target!(|data: &[u8]| seaworthy_fuzz::targets::manifest_decode::run(data));
   ```

5. Commit at least one seed as `corpus/manifest_decode/seed-<what>`.

`cargo test --manifest-path fuzz/Cargo.toml` names whichever of these steps is missing.

## When a target crashes

1. Reproduce: `cargo +$(scripts/fuzz.sh toolchain) fuzz run --fuzz-dir fuzz <target> fuzz/artifacts/<target>/crash-…`.
   Minimize: `cargo +$(scripts/fuzz.sh toolchain) fuzz tmin --fuzz-dir fuzz <target> <file>`.
2. If the crate under test is wrong, fix it there with a failing unit test first. If the target's
   invariant is wrong, fix the invariant.
3. Copy the minimized input to `regressions/<target>/<short-description>`; `tests/replay.rs` then
   replays it on every CI run.

A crash in released code may be a vulnerability: report it privately (see
[SECURITY.md](../SECURITY.md)) before committing the reproducer.

## CI

- **Every change:** the stable replay (`cargo test --manifest-path fuzz/Cargo.toml`) runs in the
  CI workflow.
- **Weekly, on demand, and on pull requests that touch `fuzz/`:** `.github/workflows/fuzz.yml`
  builds every target on the pinned nightly and runs each one briefly (`scripts/fuzz.sh smoke`,
  one job per target). Crash inputs and logs are uploaded as workflow artifacts kept for 7 days.

Workflow logs and artifacts of a public repository are public. A crash found by the scheduled run
is therefore disclosed as soon as it is found: treat it as a potential vulnerability, triage it
in a private security advisory, and keep the fix and the regression input together.
