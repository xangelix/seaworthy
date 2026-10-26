#!/usr/bin/env bash
# A `shell:` for workflow steps (`shell: bash scripts/ci/logged.sh {0}`):
# runs the step's script exactly as GitHub's `shell: bash` does
# (`bash --noprofile --norc -eo pipefail`), echoing its output to the job
# log and appending it to "$RUNNER_TEMP/step-output.log". When the job
# fails, .github/actions/annotate-failure publishes that file's tail as
# error annotations, which GitHub serves without signing in (job logs need
# a signed-in account, even on a public repository).
set -o pipefail
log="${RUNNER_TEMP:-/tmp}/step-output.log"
{
    printf '\n===== step: %s =====\n' "${GITHUB_ACTION:-step}"
    bash --noprofile --norc -eo pipefail "$1" 2>&1
} | tee -a "$log"
