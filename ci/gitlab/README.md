# GitLab CI templates

Include-able GitLab CI (GitLab 17.0 or later) that takes a product from a tag to verified, signed
packages and published APT, DNF and pacman repositories, through the `seaworthy` command.

| File | What |
|---|---|
| [`seaworthy.yml`](seaworthy.yml) | prepare (the `seaworthy` binary built from a seaworthy checkout, the build plans, the release-ordering lint), the Linux build, package, repo and publish |
| [`seaworthy-windows.yml`](seaworthy-windows.yml) | the native MSVC build, and for `msi` outputs the MSI built with WiX on Windows and adopted on Linux |
| [`seaworthy-macos.yml`](seaworthy-macos.yml) | the macOS build and its ad hoc-signed dmg or pkg on a Mac runner: a pipeline artifact, in a release only with a Developer ID (its `sign-if` input) |

Every job runs one step of [`scripts/ci/seaworthy.sh`](../../scripts/ci/seaworthy.sh) (Windows:
`seaworthy-build.ps1`, `seaworthy-msi.ps1`); the YAML only wires them.

No image, runner tag or secret source has a default: `tools-image`, `windows-image`,
`windows-tags`, `macos-image` and `macos-tags` are required inputs, and credentials reach the one
`seaworthy` call that needs them through the `*-secrets` command prefixes, on a release only. A
release's signing jobs build `seaworthy` from seaworthy's own checkout, fetched afresh, and restore
no cache; they trust nothing earlier jobs left them but data.

The guide, with every job and input, the release order, Windows signing and FIPS products:
[docs/ci-gitlab.md](../../docs/ci-gitlab.md).
