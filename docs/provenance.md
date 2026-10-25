# Provenance

seaworthy began as the distribution crates of the carpc project (CPU levels, the launcher,
packaging and signing, service definitions, the update helper), extracted on 2026-10-25 into a
standalone, general-purpose crate family. The extraction:

- renamed every format tag, environment variable and exported symbol to the `seaworthy` prefix
  and reset format versions to 1 (no release had shipped under the old names);
- removed every organization-specific default (registries, buckets, signing accounts, runner
  images);
- started a fresh history: the import commit is the first commit of this repository.
