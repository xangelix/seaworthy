<!--
Security fixes: do not open a public pull request for an undisclosed vulnerability. Report it
privately first (SECURITY.md); the fix is coordinated in a private security advisory.
-->

## What and why

<!-- What this changes and the reason. Link the issue it resolves, if any. -->

## Checklist

- [ ] One logical change; the commit messages say what changed and why.
- [ ] Tests cover the change (a failing test first for a bug fix).
- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
      `cargo test --workspace --all-features`, `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`
      and `cargo deny check` pass locally.
- [ ] Public items are documented; errors are typed; library code cannot panic on input.
- [ ] A new parser of untrusted input has a fuzz target, with seeds (`fuzz/README.md`).
- [ ] New dependencies are in `[workspace.dependencies]` and justified below; cryptography and TLS
      go through `seaworthy-crypto` only.
- [ ] Every `unsafe` block has a `// SAFETY:` comment, or the crate forbids unsafe code.
- [ ] A changed signed or on-disk format has a new `seaworthy-<name>:<n>` tag version and a
      migration note.
- [ ] A change to a trust boundary, a default, or what is downloaded or executed updates
      [docs/threat-model.md](https://github.com/xangelix/seaworthy/blob/main/docs/threat-model.md).
- [ ] No organization defaults: examples use `example.com` and `Acme`; no secrets, keys or
      internal URLs.

## Notes for reviewers

<!-- New dependencies and why, MSRV or toolchain impact, anything that needs a careful look. -->
