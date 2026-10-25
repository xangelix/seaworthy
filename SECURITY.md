# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/xangelix/seaworthy/security/advisories/new)
("Report a vulnerability" on the repository's Security tab). Do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect. You will get an
acknowledgement within three business days and a status update at least weekly until the issue
is resolved. Fixes are released as soon as they are ready and announced in a GitHub security
advisory, crediting the reporter unless they prefer otherwise.

## Supported versions

Before 1.0, only the latest release receives security fixes.

## Scope

In scope: every crate in this repository, the reusable CI workflows and templates, and the
formats they define (release manifests, release keys, CPU records, update memos). The threat
model is in [docs/threat-model.md](docs/threat-model.md).
