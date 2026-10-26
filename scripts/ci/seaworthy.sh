#!/usr/bin/env bash
# scripts/ci/seaworthy.sh — the steps of seaworthy's CI: the GitLab CI
# templates (ci/gitlab/seaworthy*.yml) and the reusable GitHub workflow
# (.github/workflows/dist.yml). Each job runs one step; the logic lives
# here, not in YAML. GitLab's variables name the release by default; the
# SEAWORTHY_* ones below name it on any CI.
#
#   seaworthy.sh prepare           seaworthy built from the seaworthy
#                                   checkout, seaworthy.toml checked, the
#                                   build plans, the release-ordering lint,
#                                   the scripts the later jobs run
#   seaworthy.sh build <triple> [<target dir>]
#                                  the build plan carried out (Linux, or
#                                   aarch64-apple-darwin on the Mac): every
#                                   binary into the artifact directory; with
#                                   a target directory (base, or a CPU) only
#                                   that build's steps, so one CI job per
#                                   CPU builds in parallel
#   seaworthy.sh package           seaworthy package, every platform but
#                                   macOS (signed on a release, Authenticode
#                                   alone on a dev build)
#   seaworthy.sh package-macos     on the Mac: seaworthy built there,
#                                   package --platforms macos (the dmg or
#                                   pkg: ad hoc-signed, or on a release with
#                                   SEAWORTHY_MACOS_SIGN=1 Developer
#                                   ID-signed and notarized), into
#                                   dist-macos/
#   seaworthy.sh adopt-msi         seaworthy adopt-msi for each MSI the
#                                   Windows MSI job built (signed on a
#                                   release or a dev build), into adopted/
#   seaworthy.sh repo              seaworthy repo after the published plan
#                                   (from adopted/ when the MSI jobs ran)
#   seaworthy.sh publish           seaworthy publish
#   seaworthy.sh tools <step> [<env file>]
#                                  the third-party tools <step> (package,
#                                   adopt-msi) runs, installed ahead of it
#                                   in a step that holds no secret: their
#                                   paths as NFPM= and SEAWORTHY_OSSLSIGNCODE=
#                                   lines appended to <env file> (GitHub's
#                                   $GITHUB_ENV), else printed
#
# On a release or a dev build the signing steps (package, adopt-msi,
# package-macos, repo, publish) trust nothing the prepare job handed on but
# data: this script must run from seaworthy's own checkout
# ($SEAWORTHY_CHECKOUT/scripts/ci/seaworthy.sh), which builds seaworthy
# afresh (or installs SEAWORTHY_TOOL_BIN, built in the same job), and the
# tool installers run from beside it. The prepare job ran the product's
# build-metadata command, so its bin/ and scripts/ could hold anything.
#
# Everything lives under $SEAWORTHY_WORK (default seaworthy), which the
# template passes from job to job as artifacts:
#
#   bin/seaworthy         the tool, built once (prepare), for the build jobs
#                         and the steps outside a release or a dev build
#   scripts/              this script and the tool scripts those jobs run
#   plan-<triple>.tsv     each target triple's build plan (seaworthy build-plan)
#   artifacts/<triple>/   the built binaries (build), seaworthy's input layout
#   dist/                 the packages (package)
#   dist-macos/           the macOS packages' listings and files (package-macos)
#   msi/<product>/        the MSIs WiX built on Windows (seaworthy-msi.ps1)
#   adopted/              dist/ with every MSI adopted (adopt-msi)
#   repo/                 the repositories and the publish plan (repo)
#   target/               the build's cargo target directories (cached, not passed on)
#
# Environment (the template sets it from its inputs):
#
#   SEAWORTHY_CONFIG          seaworthy.toml (default seaworthy.toml)
#   SEAWORTHY_SIGNING         signing.toml: package and adopt-msi on a
#                             release or a dev build, repo
#   SEAWORTHY_CI_SIGNING      outside a release: the CI test keys' signing
#                             configuration: package, adopt-msi and
#                             package-macos sign with it (--ci-test-signing),
#                             which repo refuses
#   SEAWORTHY_PUBLISH         publish.toml: repo (its public-url), publish
#   SEAWORTHY_CHECKOUT        prepare, package-macos, and every signing step
#                             of a release or a dev build: a seaworthy
#                             checkout (default .seaworthy)
#   SEAWORTHY_TARGET_DIR      build: the cargo target directories' root
#                             (default $SEAWORTHY_WORK/target)
#   SEAWORTHY_TOOL_TARGET     prepare, package-macos outside a release or a
#                             dev build: seaworthy's target directory
#                             (default $SEAWORTHY_WORK/tool-target; the
#                             template caches it). A release or a dev build
#                             compiles in a new, private directory instead
#   SEAWORTHY_MACOS_SCRATCH   package-macos: where seaworthy lays out and
#                             signs the bundle (default
#                             $SEAWORTHY_WORK/macos; the Mac template puts
#                             it on the VM's own disk)
#   SEAWORTHY_MANIFEST        build: the workspace manifest (default Cargo.toml)
#   SEAWORTHY_CARGO_ARGS      build: more cargo arguments for every build
#                             (word-split, e.g. --features fips)
#   SEAWORTHY_RUSTFLAGS       build: more rustflags for every build, after
#                             the plan's (word-split; {workspace}, {triple}
#                             and {cpu} expand: docs/packaging.md, "Extra
#                             build flags")
#   SEAWORTHY_CORE_RUSTFLAGS  build: more rustflags for the cores' builds
#                             alone (the plan's steps whose target directory
#                             isn't base), after SEAWORTHY_RUSTFLAGS', such
#                             as -Cprofile-use={workspace}/pgo/{triple}.profdata
#   SEAWORTHY_SERVER_JOBS     prepare: the server deploy jobs, comma-separated
#   SEAWORTHY_CLIENT_JOBS     prepare: client jobs beside the publish job
#                             (the web console's deploy), comma-separated
#   SEAWORTHY_RELEASE         1 on a release (the template's rules): signed,
#                             versioned from the tag; in GitLab, only on a
#                             protected ref (CI_COMMIT_REF_PROTECTED)
#   SEAWORTHY_DEV_SIGN        1 on a dev build outside a release (the
#                             template's dev-sign-if): package and
#                             adopt-msi sign with signing.toml's
#                             [authenticode] alone (--authenticode-only),
#                             which repo refuses; in GitLab, only on a
#                             protected ref
#   SEAWORTHY_VERSION         the release version (default: the tag, less a
#                             leading v; else SEAWORTHY_VERSION_FILE's;
#                             else 0.0.0-alpha outside a release)
#   SEAWORTHY_TAG             the release's tag (default CI_COMMIT_TAG)
#   SEAWORTHY_SEQUENCE        the release sequence, a counter that only grows
#                             (default CI_PIPELINE_IID)
#   SEAWORTHY_COMMIT          the commit's short SHA, the default build
#                             metadata (default CI_COMMIT_SHORT_SHA, or on
#                             GitHub Actions GITHUB_SHA's first 8 characters)
#   SEAWORTHY_PRODUCTS        prepare, package, package-macos: the products
#                             to build and package, comma-separated
#                             (default every product); the repository
#                             package is built only for every product
#   SEAWORTHY_TOOL_BIN        a seaworthy binary already built from the
#                             checkout in this job (the GitHub workflow's
#                             setup-seaworthy action), installed instead of
#                             building one; never one under the work
#                             directory (the prepare job's artifacts)
#   SEAWORTHY_OSSLSIGNCODE    an osslsigncode the tools step built from its
#                             pinned source, used instead of building it
#   SEAWORTHY_UNSIGNED        1: no signer was given (the GitHub workflow
#                             without signing secrets): package and
#                             adopt-msi sign nothing — refused on a release
#                             or a dev build unless SEAWORTHY_ALLOW_UNSIGNED
#                             is 1 too (still versioned from its tag; repo
#                             refuses it)
#   SEAWORTHY_ALLOW_UNSIGNED  1: let a release or a dev build without a
#                             signer go on, unsigned, with a warning
#   SEAWORTHY_ALLOW_CI_TEST_KEYS
#                             seaworthy-formats' build switch (1: the build
#                             trusts the product's CI test keys): any value
#                             but empty or 0 fails every step of a release,
#                             and a release's package step refuses a built
#                             binary carrying the test-key marker
#   SEAWORTHY_MACOS_SIGN      1: on a release, package-macos signs with
#                             SEAWORTHY_SIGNING (its [apple] Developer ID,
#                             then notarization), and its listing is the
#                             release's; else the macOS outputs stay ad
#                             hoc-signed, outside the release
#   SEAWORTHY_BUILD_COMMAND   prepare: a command (run with bash in the
#                             checkout) printing the release's build
#                             metadata — the build part of the product's
#                             version token, [A-Za-z0-9.-], at most 64
#                             characters (default: CI_COMMIT_SHORT_SHA). It
#                             runs in prepare alone, before anything is
#                             staged; the later steps read release.env
#   SEAWORTHY_VERSION_FILE    a Cargo.toml whose literal [package] version
#                             names a release that has no tag (one from a
#                             branch) and every pipeline outside a release;
#                             a release tag must name the same version
#   SEAWORTHY_SECRETS         a command prefix (words, no quoting) the
#                             seaworthy call runs under on a release: the
#                             credentials it gives never reach tool installs
#   SEAWORTHY_DEV_SECRETS     the same, on a dev build: the Authenticode
#                             signer's credentials alone
#   SEAWORTHY_HELD_ENV        more names of credentials in the job's
#                             environment (comma or space separated) that
#                             only the seaworthy call receives, beside
#                             those held anyway (below)
#   SEAWORTHY_PUBLISH_DRY_RUN
#                             1: publish checks everything (the files, the
#                             store, the public URL) and uploads nothing
#                             (seaworthy publish --dry-run)
#   SEAWORTHY_TEMPLATE        prepare: the included template's marker; the
#                             seaworthy checkout's template must carry the same
#   CI_PIPELINE_IID, CI_COMMIT_SHORT_SHA, CI_COMMIT_TAG, CI_CONFIG_PATH,
#   CI_PROJECT_DIR, CI_COMMIT_REF_PROTECTED, GITLAB_CI:
#                             GitLab's (the release sequence, build metadata,
#                             tag, CI file, repository, protection)
#
# The publish job's credentials (SEAWORTHY_S3_ACCESS_KEY_ID,
# SEAWORTHY_S3_SECRET_ACCESS_KEY) come from the template's secrets wrapper,
# never a file; this script never prints them.
#
# Credentials in the job's own environment (the GitHub workflow's signing
# and store secrets, the runner's OIDC request variables, cloud
# credentials, an id token, the key-env variables signing.toml names) are
# taken out of the environment as the script starts and handed back to the
# seaworthy call alone (and through it to signing commands alone), so
# nothing else it runs — git, curl, the tool installers, pacman — inherits
# them.
set -euo pipefail
# A command substitution inherits -e: a failing step inside one (a version,
# the build metadata) stops the step instead of yielding an empty value.
# That takes bash 4.4; macOS's /bin/bash is 3.2, so say so rather than run
# without it.
if [ "${BASH_VERSINFO[0]}" -lt 4 ] || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 4 ]; }; then
    echo "seaworthy: needs bash 4.4 or later (this is $BASH_VERSION; on macOS: brew install bash)" >&2
    exit 1
fi
shopt -s inherit_errexit

work="${SEAWORTHY_WORK:-seaworthy}"
config="${SEAWORTHY_CONFIG:-seaworthy.toml}"
tool="$work/bin/seaworthy"
linux=x86_64-unknown-linux-gnu
windows=x86_64-pc-windows-msvc
macos=aarch64-apple-darwin
# This script's own directory: the tool installers beside it are the ones
# run (prepare's staged copies, or on a release seaworthy's checkout's).
scripts="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

fail() { echo "seaworthy: FAIL: $*" >&2; exit 1; }
say() { echo "seaworthy: $*"; }
# A warning a CI log shows as one (GitHub's annotation, else plain).
warn() {
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
        echo "::warning::seaworthy: $*"
    else
        echo "seaworthy: WARNING: $*" >&2
    fi
}

# Private directories this run made (a fresh tool build, its source copy),
# removed when it ends, however it ends.
private_dirs=()
cleanup() {
    local dir
    for dir in "${private_dirs[@]}"; do
        [ -n "$dir" ] && rm -rf "$dir"
    done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
private_dir() { # sets `made` to a new private directory
    made="$(umask 077 && mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/seaworthy.XXXXXXXX")"
    private_dirs+=("$made")
}

# A release: the version from the tag, the signing configuration required.
release() { [ "${SEAWORTHY_RELEASE:-0}" = 1 ]; }

# The credentials this script holds back from everything but the seaworthy
# call (with_secrets): taken out of the environment here, before anything
# runs. By name: the GitHub workflow's signing and store secrets and its
# PKCS#12 inputs, any SEAWORTHY_*_KEY, the runner's OIDC request and
# runtime tokens, cloud credentials (AZURE_*, AWS_*, GOOGLE_*), GitLab's
# job token, the key-env and secret-key-env variables signing.toml names,
# SEAWORTHY_HELD_ENV's; by value: an id token (a JWT, as GitLab's id_tokens
# hand them over under any name).
declare -A held=()
hold_credentials() {
    local names=() name extra=() signing="${SEAWORTHY_SIGNING:-signing.toml}"
    mapfile -t names < <(compgen -e)
    local held_env="${SEAWORTHY_HELD_ENV:-}"
    read -r -a extra <<<"${held_env//,/ }"
    if [ -f "$signing" ]; then
        # signing.toml's key-env = "NAME" and secret-key-env = "NAME" lines.
        while IFS= read -r name; do extra+=("$name"); done < <(sed -n \
            's/^[[:space:]]*\(secret-\)\{0,1\}key-env[[:space:]]*=[[:space:]]*["'\'']\([A-Za-z_][A-Za-z0-9_]*\)["'\''].*/\2/p' \
            "$signing")
    fi
    for name in "${names[@]}"; do
        [[ "$name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
        local hold=0 wanted
        case "$name" in
            SEAWORTHY_RELEASE_MANIFEST_KEY | SEAWORTHY_OPENPGP_SECRET_KEY | SEAWORTHY_S3_* | \
                SEAWORTHY_GH_AUTHENTICODE_PFX | SEAWORTHY_GH_AUTHENTICODE_PASSWORD | \
                SEAWORTHY_GH_APPLE_P12 | SEAWORTHY_GH_APPLE_P12_PASSWORD | SEAWORTHY_GH_APPLE_NOTARY_KEY | \
                SEAWORTHY_*_KEY | ACTIONS_ID_TOKEN_REQUEST_* | ACTIONS_RUNTIME_TOKEN | \
                AZURE_* | AWS_* | GOOGLE_* | CI_JOB_TOKEN | CI_JOB_JWT* | GITHUB_TOKEN | GH_TOKEN)
                hold=1 ;;
        esac
        for wanted in "${extra[@]}"; do
            [ "$name" = "$wanted" ] && hold=1
        done
        if [ "$hold" = 0 ] && [[ "${!name}" =~ ^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$ ]]; then
            hold=1
        fi
        if [ "$hold" = 1 ]; then
            held[$name]="${!name}"
            unset "$name"
        fi
    done
}
hold_credentials

# A release never builds or packages binaries that trust the product's CI
# test keys: seaworthy-formats' switch (1 turns it on) must be off, in
# every step of a release.
check_test_keys_switch() {
    release || return 0
    case "${SEAWORTHY_ALLOW_CI_TEST_KEYS:-}" in
        "" | 0) ;;
        *) fail "SEAWORTHY_ALLOW_CI_TEST_KEYS is ${SEAWORTHY_ALLOW_CI_TEST_KEYS@Q} on a release: a release never trusts the CI test keys (unset it, or set it to 0)" ;;
    esac
}
check_test_keys_switch

# A job's image may run as another user than the one owning its checkout,
# and git then refuses the checkout as "dubious ownership": install-nfpm.sh
# and install-osslsigncode.sh find their directory with git, package and
# adopt-msi take SOURCE_DATE_EPOCH from it, a product's build-metadata
# command may use it. In GitLab CI the checkout is the job's own fresh
# clone, trusted as this script is: safe.directory for it, in git's command
# scope (GIT_CONFIG_COUNT), for this process tree only. No config file
# changes.
if [ "${GITLAB_CI:-}" = true ] && [ -n "${CI_PROJECT_DIR:-}" ]; then
    git_configs="${GIT_CONFIG_COUNT:-0}"
    [[ "$git_configs" =~ ^[0-9]+$ ]] || fail "GIT_CONFIG_COUNT isn't a count: ${git_configs@Q}"
    export "GIT_CONFIG_KEY_$git_configs=safe.directory" "GIT_CONFIG_VALUE_$git_configs=$CI_PROJECT_DIR"
    export GIT_CONFIG_COUNT=$((git_configs + 1))
fi

# The tools a step runs, installed with pacman when the image is Arch and
# one is missing (never with SEAWORTHY_NO_INSTALL=1), else named.
need_tools() { # <command:package>…
    local missing=() packages=() entry command package
    for entry in "$@"; do
        command="${entry%%:*}" package="${entry#*:}"
        command -v "$command" >/dev/null 2>&1 || { missing+=("$command"); packages+=("$package"); }
    done
    [ "${#missing[@]}" -eq 0 ] && return 0
    if command -v pacman >/dev/null 2>&1 && [ "${SEAWORTHY_NO_INSTALL:-0}" != 1 ]; then
        say "installing ${packages[*]}"
        local sudo=()
        [ "$(id -u)" -eq 0 ] || sudo=(sudo)
        "${sudo[@]}" pacman -Syu --noconfirm --needed "${packages[@]}" >/dev/null
        for command in "${missing[@]}"; do
            command -v "$command" >/dev/null 2>&1 || fail "$command still missing after installing ${packages[*]}"
        done
    else
        fail "missing ${missing[*]} (packages: ${packages[*]}); use an image that has them"
    fi
}

need_file() { # <path> <what>
    [ -f "$1" ] || fail "$2: $1 doesn't exist"
}

# Whether product <id> has outputs for any of <triple>s (its build plan
# there isn't refused as having none).
product_has() { # <id> <triple>...
    local id="$1" triple
    shift
    for triple in "$@"; do
        "$tool" build-plan --config "$config" --triple "$triple" --product "$id" \
            --manifest "${SEAWORTHY_MANIFEST:-Cargo.toml}" >/dev/null 2>&1 && return 0
    done
    return 1
}

# SEAWORTHY_PRODUCTS' ids in `products` (none: every product), each
# checked to be a product id. (Not a command substitution: a refusal must
# stop the step.)
products=()
selected_products() {
    local list="${SEAWORTHY_PRODUCTS:-}" id ids=()
    products=()
    list="${list//[[:space:]]/}"
    [ -n "$list" ] || return 0
    IFS=, read -r -a ids <<<"$list"
    for id in "${ids[@]}"; do
        [ -n "$id" ] || continue
        [[ "$id" =~ ^[a-z0-9][a-z0-9-]*$ ]] || fail "SEAWORTHY_PRODUCTS: ${id@Q} isn't a product id"
        products+=("$id")
    done
}

# No signer at all (SEAWORTHY_UNSIGNED=1). On a release or a dev build
# that's refused unless SEAWORTHY_ALLOW_UNSIGNED=1 says it's meant, and then
# said loudly: a misnamed secret must not quietly ship unsigned packages.
unsigned() {
    [ "${SEAWORTHY_UNSIGNED:-0}" = 1 ] || return 1
    if release || dev_sign; then
        local what=release
        release || what="dev build"
        [ "${SEAWORTHY_ALLOW_UNSIGNED:-0}" = 1 ] ||
            fail "a $what with no signer: no signing secret or signing.toml reached this job (allow an unsigned $what on purpose with SEAWORTHY_ALLOW_UNSIGNED=1, the GitHub workflow's allow-unsigned input)"
        warn "an UNSIGNED $what (SEAWORTHY_ALLOW_UNSIGNED=1): no manifests, no signatures; the repositories refuse it and no update helper installs it"
    fi
}

# A dev build: not a release, but its Windows binaries and MSIs
# carry the release's Authenticode signature (nothing else is signed, and
# repo refuses it).
dev_sign() { ! release && [ "${SEAWORTHY_DEV_SIGN:-0}" = 1 ]; }

# A CI test build: not a release, with SEAWORTHY_CI_SIGNING set: its
# manifests and package signatures are the CI test keys', which only the
# product's non-release builds trust (on a dev build, beside the release's
# Authenticode). A release never signs with them.
ci_test_signing=()
ci_test_sign() {
    ! release && [ -n "${SEAWORTHY_CI_SIGNING:-}" ] || return 1
    need_file "$SEAWORTHY_CI_SIGNING" "the CI test keys' signing configuration (the template's ci-signing-toml)"
    [ "${#ci_test_signing[@]}" -eq 0 ] || return 0
    # git checks the test keys out 0644, and seaworthy signs only with key
    # files no one else can read: the file's directory, keys beside it, goes
    # into a private copy first.
    local made
    private_dir
    cp -R "$(dirname "$SEAWORTHY_CI_SIGNING")/." "$made/"
    chmod -R go-rwx "$made"
    ci_test_signing=(--ci-test-signing "$made/$(basename "$SEAWORTHY_CI_SIGNING")")
}

# In GitLab, a release or a dev build runs on a protected ref only: a
# pipeline variable must not turn a branch pipeline into a signed one.
check_release_ref() {
    [ "${GITLAB_CI:-}" = true ] && [ "${CI_COMMIT_REF_PROTECTED:-}" != true ] || return 0
    if release; then
        fail "a release runs on a protected ref only (CI_COMMIT_REF_PROTECTED isn't true): protect the release tags"
    fi
    if dev_sign; then
        fail "a dev build runs on a protected ref only (CI_COMMIT_REF_PROTECTED isn't true): the template's dev-sign-if must name protected refs alone"
    fi
}

# Runs a seaworthy command, under the secrets prefix on a release, or the
# dev secrets prefix on a dev build (its words, never globbed or re-parsed),
# with the credentials held back at the start (hold_credentials) back in
# its environment: exported in a subshell that becomes the command, so no
# value is ever on a command line.
with_secrets() {
    local prefix=()
    if release && [ -n "${SEAWORTHY_SECRETS:-}" ]; then
        read -r -a prefix <<<"$SEAWORTHY_SECRETS"
    elif dev_sign && [ -n "${SEAWORTHY_DEV_SECRETS:-}" ]; then
        read -r -a prefix <<<"$SEAWORTHY_DEV_SECRETS"
    fi
    (
        local name
        for name in "${!held[@]}"; do
            export "$name=${held[$name]}"
        done
        exec "${prefix[@]}" "$@"
    )
}

# The nFPM binary: $NFPM, else the pinned release (a failed download stops
# here).
nfpm_path() {
    if [ -n "${NFPM:-}" ]; then
        echo "$NFPM"
        return
    fi
    local path
    path="$("$scripts/install-nfpm.sh")" || fail "installing nFPM failed"
    [ -x "$path" ] || fail "install-nfpm.sh left no nFPM at ${path@Q}"
    echo "$path"
}

# A Cargo.toml's [package] version, read as TOML by seaworthy (a version
# inherited from the workspace is the workspace root's).
package_version() { # <Cargo.toml>
    need_file "$1" "the version file (the template's version-file)"
    need_file "$tool" "seaworthy (built by the prepare job)"
    "$tool" manifest-version --manifest "$1" || fail "$1: no version to read (the template's version-file)"
}

# The release's version: SEAWORTHY_VERSION; else, on a release with a tag,
# the tag less its `v` (which must be the version file's, when one is
# named); else the version file's; else, outside a release, 0.0.0-alpha.
version() {
    if [ -n "${SEAWORTHY_VERSION:-}" ]; then
        echo "$SEAWORTHY_VERSION"
        return
    fi
    local declared=""
    [ -z "${SEAWORTHY_VERSION_FILE:-}" ] || declared="$(package_version "$SEAWORTHY_VERSION_FILE")" || exit 1
    local tag="${SEAWORTHY_TAG:-${CI_COMMIT_TAG:-}}"
    if release && [ -n "$tag" ]; then
        local tagged="${tag#v}"
        [ -z "$declared" ] || [ "$declared" = "$tagged" ] ||
            fail "the tag $tag names $tagged, but $SEAWORTHY_VERSION_FILE declares $declared: tag the version the product declares"
        echo "$tagged"
    elif [ -n "$declared" ]; then
        echo "$declared"
    elif release; then
        fail "a release needs a tag (SEAWORTHY_TAG, CI_COMMIT_TAG), the version file (the template's version-file), or SEAWORTHY_VERSION"
    else
        echo 0.0.0-alpha
    fi
}

# The release's build metadata, as the package step names it: the
# product's command's (the build part of its version token, when the
# product composes its own), else the commit's short SHA.
build_metadata() {
    if [ -z "${SEAWORTHY_BUILD_COMMAND:-}" ]; then
        echo "${SEAWORTHY_COMMIT:-${CI_COMMIT_SHORT_SHA:-${GITHUB_SHA:+${GITHUB_SHA:0:8}}}}"
        return
    fi
    local built
    built="$(bash -eo pipefail -c "$SEAWORTHY_BUILD_COMMAND")" ||
        fail "the build-metadata command failed: ${SEAWORTHY_BUILD_COMMAND@Q}"
    # SemVer build metadata (seaworthy's --build rule), whatever the locale.
    if ! build_ok "$built"; then
        fail "the build-metadata command printed ${built@Q}: build metadata is dot-separated, non-empty identifiers of A-Z a-z 0-9 -, at most 64 characters"
    fi
    echo "$built"
}

# The release's identity, as prepare records it for the build jobs (which
# aren't told whether the pipeline is a release): `<version> <build>`.
# A product compiles its version token from it (the build step exports
# SEAWORTHY_RELEASE_VERSION and SEAWORTHY_RELEASE_BUILD), so the token its
# gate names is the name the package step gives the release.
release_identity() {
    local version build
    if read_release_env; then
        version="$release_env_version" build="$release_env_build"
    else
        version="$(version)" || exit 1
        build="$(build_metadata)" || exit 1
    fi
    echo "$version $build"
}

# Build metadata as seaworthy's --build takes it (SemVer's), whatever the
# locale.
build_ok() { # <build>
    LC_ALL=C bash -c '[[ ${#1} -le 64 && $1 =~ ^[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*$ ]]' _ "$1"
}

# prepare's release.env, read strictly into release_env_version and
# release_env_build (each named once, each as the steps take it); returns 1
# when there is none. It's data: never sourced.
release_env_version="" release_env_build=""
read_release_env() {
    local file="$work/release.env" versions=() builds=()
    [ -f "$file" ] || return 1
    mapfile -t versions < <(sed -n 's/^SEAWORTHY_RELEASE_VERSION=//p' "$file")
    mapfile -t builds < <(sed -n 's/^SEAWORTHY_RELEASE_BUILD=//p' "$file")
    [ "${#versions[@]}" -eq 1 ] && [ "${#builds[@]}" -le 1 ] ||
        fail "$file must name SEAWORTHY_RELEASE_VERSION once and SEAWORTHY_RELEASE_BUILD at most once"
    release_env_version="${versions[0]}" release_env_build="${builds[0]:-}"
    [[ "$release_env_version" =~ ^[0-9A-Za-z.-]{1,128}$ ]] ||
        fail "$file names the version ${release_env_version@Q}, which isn't one"
    [ -z "$release_env_build" ] || build_ok "$release_env_build" ||
        fail "$file names the build ${release_env_build@Q}, which isn't build metadata"
}

sequence() {
    local sequence="${SEAWORTHY_SEQUENCE:-${CI_PIPELINE_IID:-}}"
    [ -n "$sequence" ] || fail "no release sequence: SEAWORTHY_SEQUENCE (or GitLab's CI_PIPELINE_IID) is unset"
    [[ "$sequence" =~ ^[1-9][0-9]{0,18}$ ]] || fail "the release sequence ${sequence@Q} isn't a positive integer"
    echo "$sequence"
}

# The template marker: the template's text without its marker line, hashed
# (macOS has shasum, not sha256sum).
template_marker() { # <template>
    local sum=(sha256sum)
    command -v sha256sum >/dev/null 2>&1 || sum=(shasum -a 256)
    grep -v 'SEAWORTHY_TEMPLATE:' "$1" | "${sum[@]}" | cut -c1-16
}

# The seaworthy checkout a job builds seaworthy from: there, and the included
# template's revision.
check_checkout() { # <checkout>
    local checkout="$1"
    need_file "$checkout/Cargo.toml" "the seaworthy checkout (the template's seaworthy-dir; seaworthy-fetch puts it there)"
    if [ -n "${SEAWORTHY_TEMPLATE:-}" ]; then
        local marker
        marker="$(template_marker "$checkout/ci/gitlab/seaworthy.yml")"
        [ "$marker" = "$SEAWORTHY_TEMPLATE" ] ||
            fail "the seaworthy checkout at $checkout isn't the included template's revision (marker $marker, the pipeline's $SEAWORTHY_TEMPLATE): fetch the include's ref"
    fi
}

# A path under the work directory: the prepare job's artifacts, which
# product code (its build-metadata command) could have changed.
under_work() { # <path>
    [ -d "$work" ] || return 1
    local root path
    root="$(cd "$work" && pwd -P)"
    path="$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
    case "$path" in "$root"/*) return 0 ;; esac
    return 1
}

# Refuses a cargo configuration file in a directory above <dir>: cargo reads
# every .cargo/config.toml from the directory it runs in upward, and one
# there would join seaworthy's own build. CARGO_HOME's (the image's) is read
# by every build, and allowed.
cargo_configs_above() { # <dir>
    local dir file cargo_home="${CARGO_HOME:-${HOME:-/nonexistent}/.cargo}"
    [ ! -d "$cargo_home" ] || cargo_home="$(cd "$cargo_home" && pwd -P)"
    dir="$(cd "$1" && pwd -P)"
    while [ "$dir" != / ]; do
        dir="$(dirname "$dir")"
        for file in "$dir/.cargo/config" "$dir/.cargo/config.toml"; do
            [ -e "$file" ] || continue
            [ "$(cd "$dir/.cargo" && pwd -P)" != "$cargo_home" ] || continue
            fail "$file would join seaworthy's own build (cargo reads every .cargo/config.toml above the directory it builds in): remove it, or point TMPDIR elsewhere"
        done
    done
}

# Runs <command> with the system's basics alone in its environment: no
# RUSTC_WRAPPER or compiler cache, no CARGO_* or RUSTFLAGS override, no
# RUSTUP_TOOLCHAIN, no CC or CFLAGS (which the crypto module's C build
# reads), nothing a product sets for its own builds. Unset in a subshell that
# becomes the command, so no value lands on a command line.
tool_build_env() { # <command>...
    (
        local name
        while IFS= read -r name; do
            case "$name" in
                PATH | HOME | USER | LOGNAME | LANG | TMPDIR | TZ | CARGO_HOME | RUSTUP_HOME | \
                    RUSTUP_DIST_SERVER | RUSTUP_UPDATE_ROOT | RUSTUP_MAX_RETRIES | CARGO_NET_RETRY | \
                    CARGO_TERM_COLOR | CARGO_HTTP_CAINFO | CARGO_HTTP_PROXY | CARGO_HTTP_TIMEOUT | \
                    SSL_CERT_FILE | SSL_CERT_DIR | http_proxy | https_proxy | no_proxy | HTTP_PROXY | \
                    HTTPS_PROXY | NO_PROXY | ALL_PROXY | all_proxy | DEVELOPER_DIR) ;;
                *) unset "$name" 2>/dev/null || true ;;
            esac
        done < <(compgen -e)
        export CARGO_INCREMENTAL=0
        exec "$@"
    )
}

# seaworthy, built from the checkout into <path> so that nothing of the
# product's reaches it: from a copy of the checkout outside the product's
# tree (cargo reads every .cargo/config.toml from the directory it runs in
# upward, rustup the nearest rust-toolchain.toml: the copy's own, seaworthy's
# pinned toolchain), in the environment tool_build_env leaves, and on a
# release or a dev build into a new target directory, never a cached one.
# Outside those, the target directory is SEAWORTHY_TOOL_TARGET (the
# template caches it; outside the checkout, so a restored cache can't make
# the checkout's directory exist). SEAWORTHY_TOOL_BIN names one already
# built from the checkout in this job (the GitHub workflow's
# setup-seaworthy action, which builds it the same way), installed as is.
build_tool() { # <checkout> <path>
    if [ -n "${SEAWORTHY_TOOL_BIN:-}" ]; then
        need_file "$SEAWORTHY_TOOL_BIN" "seaworthy (SEAWORTHY_TOOL_BIN)"
        ! under_work "$SEAWORTHY_TOOL_BIN" ||
            fail "SEAWORTHY_TOOL_BIN is under $work, the prepare job's artifacts: never a seaworthy to run"
        say "seaworthy from $SEAWORTHY_TOOL_BIN"
        mkdir -p "$(dirname "$2")"
        install -m 0755 "$SEAWORTHY_TOOL_BIN" "$2"
        return
    fi
    local made src target
    private_dir
    src="$made"
    # The checkout's files, without its target directory or git metadata.
    (cd "$1" && tar --exclude=./target --exclude=./.git -cf - .) | (cd "$src" && tar -xf -)
    cargo_configs_above "$src"
    if release || dev_sign; then
        private_dir
        target="$made"
        say "building seaworthy from $1, in a new target directory (a release's tool never comes from a cache)"
    else
        target="${SEAWORTHY_TOOL_TARGET:-$work/tool-target}"
        mkdir -p "$target"
        target="$(cd "$target" && pwd -P)"
        say "building seaworthy from $1"
    fi
    (
        cd "$src"
        # seaworthy's pinned toolchain (rustup installs it only when asked).
        if command -v rustup >/dev/null 2>&1 && { [ -f rust-toolchain.toml ] || [ -f rust-toolchain ]; }; then
            tool_build_env rustup toolchain install >/dev/null 2>&1 || true
        fi
        tool_build_env cargo build --quiet --release --locked -p seaworthy --target-dir "$target"
    )
    mkdir -p "$(dirname "$2")"
    install -m 0755 "$target/release/seaworthy" "$2"
}

# On a release or a dev build, a signing step must run from seaworthy's own
# checkout (its script and the tool installers beside it), never from the
# prepare job's copies.
require_own_checkout() {
    release || dev_sign || return 0
    local checkout="${SEAWORTHY_CHECKOUT:-.seaworthy}" own
    check_checkout "$checkout"
    own="$(cd "$checkout/scripts/ci" && pwd -P)"
    [ "$scripts" = "$own" ] ||
        fail "a release or a dev build runs $step from seaworthy's own checkout ($checkout/scripts/ci/seaworthy.sh), not $scripts/seaworthy.sh: the prepare job's copies could have been changed by product code"
}

# A signing step's seaworthy: on a release or a dev build built afresh from
# the checkout, never the prepare job's bin/seaworthy; on any build,
# SEAWORTHY_TOOL_BIN when a job built one for itself (the GitHub workflow's
# signing jobs).
trusted_tool() {
    if release || dev_sign; then
        require_own_checkout
    elif [ -z "${SEAWORTHY_TOOL_BIN:-}" ]; then
        return 0
    fi
    local made
    private_dir
    tool="$made/seaworthy"
    build_tool "${SEAWORTHY_CHECKOUT:-.seaworthy}" "$tool"
}

# A release's binaries never trust the CI test keys: none may carry the
# marker a build with seaworthy-formats' switch leaves in it (seaworthy
# verify refuses them too; this is the pipeline's own check).
check_no_test_key_marker() { # <dir>
    release || return 0
    [ -d "$1" ] || return 0
    local found
    found="$(grep -rlaF -- 'seaworthy-ci-test-keys:trusted:1' "$1" | head -n 5 || true)"
    [ -z "$found" ] ||
        fail "a release's binaries were built with the CI test-key switch (SEAWORTHY_ALLOW_CI_TEST_KEYS=1): $(tr '\n' ' ' <<<"$found")"
}

# The files prepare hands on beside the tool: what the build jobs run, the
# tool installers and the azure-sign.sh signer of the steps outside a
# release, and the template (the release-ordering lint's --include).
staged_scripts=(scripts/ci/seaworthy.sh scripts/ci/seaworthy-build.ps1 scripts/ci/install-nfpm.sh
    scripts/ci/install-osslsigncode.sh scripts/ci/seaworthy-msi.ps1 scripts/ci/azure-sign.sh)

prepare() {
    local checkout="${SEAWORTHY_CHECKOUT:-.seaworthy}"
    check_checkout "$checkout"
    need_file "$config" "seaworthy.toml (the template's seaworthy-toml)"
    check_release_ref
    # The tool and the scripts, built and copied into a private directory
    # first: the product's build-metadata command (below) runs in the
    # checkout, and they're staged from those copies only after it. (The
    # signing steps of a release or a dev build trust none of this job's
    # artifacts anyway: they build seaworthy from its own checkout.)
    local made staging file
    private_dir
    staging="$made"
    tool="$staging/bin/seaworthy"
    build_tool "$checkout" "$tool"
    mkdir -p "$staging/scripts"
    for file in "${staged_scripts[@]}"; do
        install -m 0755 "$checkout/$file" "$staging/scripts/"
    done
    install -m 0644 "$checkout/ci/gitlab/seaworthy.yml" "$staging/scripts/"
    "$tool" check --config "$config"
    local release_version release_build
    release_version="$(version)"
    release_build="$(build_metadata)"
    mkdir -p "$work"
    printf 'SEAWORTHY_RELEASE_VERSION=%s\nSEAWORTHY_RELEASE_BUILD=%s\n' "$release_version" "$release_build" \
        > "$work/release.env"
    say "the release: $release_version${release_build:++$release_build}"
    # A version the package job would refuse (a tag, a version file's
    # `2.0.0-dev`) fails here, before the builds — on every pipeline.
    local check_sequence="${SEAWORTHY_SEQUENCE:-${CI_PIPELINE_IID:-1}}"
    if release; then
        check_sequence="$(sequence)"
    fi
    "$tool" version --release "$release_version" --sequence "$check_sequence" >/dev/null ||
        fail "the release version $release_version isn't one seaworthy packages (MAJOR.MINOR.PATCH, optionally -alpha, -beta or -rc, each optionally .N)"
    local triple product
    selected_products
    for triple in "$linux" "$windows" "$macos"; do
        if [ "${#products[@]}" -eq 0 ]; then
            "$tool" build-plan --config "$config" --triple "$triple" \
                --manifest "${SEAWORTHY_MANIFEST:-Cargo.toml}" > "$work/plan-$triple.tsv"
        else
            # The selected products' plans, each step once, in order. A
            # product without this triple's outputs adds nothing; two that
            # build one binary (a target directory's --bin or -p) with other
            # arguments are refused, as the whole plan refuses them.
            : > "$work/plan-$triple.tsv.selected"
            for product in "${products[@]}"; do
                if ! "$tool" build-plan --config "$config" --triple "$triple" --product "$product" \
                    --manifest "${SEAWORTHY_MANIFEST:-Cargo.toml}" >> "$work/plan-$triple.tsv.selected" 2>"$work/plan.err"; then
                    grep -q "has no $triple output" "$work/plan.err" ||
                        fail "build-plan --product $product: $(cat "$work/plan.err")"
                fi
            done
            awk '!seen[$0]++' "$work/plan-$triple.tsv.selected" > "$work/plan-$triple.tsv"
            rm -f "$work/plan-$triple.tsv.selected" "$work/plan.err"
            local clash
            clash="$(awk -F'\t' '$1 == "build" {
                n = split($4, word, " "); unit = "";
                for (i = 1; i < n; i++) if (word[i] == "--bin" || word[i] == "-p") unit = unit " " word[i] " " word[i + 1];
                key = $2 unit;
                if (key in line && line[key] != $0) { print key; exit }
                line[key] = $0 }' "$work/plan-$triple.tsv")"
            [ -z "$clash" ] ||
                fail "$triple: the selected products build ${clash} differently: give their binaries different names"
        fi
        if [ -s "$work/plan-$triple.tsv" ]; then
            say "$triple: $(grep -c '^build' "$work/plan-$triple.tsv") build(s), $(grep -c '^copy' "$work/plan-$triple.tsv") binaries"
        else
            rm -f "$work/plan-$triple.tsv"
            say "$triple: no product needs it"
        fi
    done
    local servers="${SEAWORTHY_SERVER_JOBS:-}"
    if [ -n "$servers" ]; then
        local clients="seaworthy-publish"
        [ -z "${SEAWORTHY_CLIENT_JOBS:-}" ] || clients="$clients,$SEAWORTHY_CLIENT_JOBS"
        "$tool" ci-order --ci "${CI_CONFIG_PATH:-.gitlab-ci.yml}" --root "${CI_PROJECT_DIR:-.}" \
            --include "$staging/scripts/seaworthy.yml" --server "$servers" --client "$clients"
    else
        say "no server deploy job named (server-deploy-jobs): nothing to order"
    fi
    # Staged last, from the private copies.
    rm -rf "${work:?}/bin" "${work:?}/scripts"
    mkdir -p "$work/bin" "$work/scripts"
    install -m 0755 "$tool" "$work/bin/seaworthy"
    cp -p "$staging/scripts/"* "$work/scripts/"
}

build() { # <triple> [<target dir>]
    local triple="${1:-}" only="${2:-}"
    case "$triple" in
        "$linux") ;;
        "$macos") [ "$(uname -s)" = Darwin ] || fail "build: $macos builds on the Mac (the template's seaworthy-macos job)" ;;
        *) fail "build: this script builds $linux and $macos; $windows builds with seaworthy-build.ps1" ;;
    esac
    local plan="$work/plan-$triple.tsv"
    if [ ! -f "$plan" ]; then
        say "$triple: no product needs it"
        return 0
    fi
    if [ -n "$only" ]; then
        # One target directory's steps: its build, its copies, and the
        # sidecars its build leaves (the first CPU's, for every core).
        [[ "$only" =~ ^[A-Za-z0-9._-]+$ ]] || fail "build: ${only@Q} isn't a target directory"
        grep -q "^build"$'\t'"$only"$'\t' "$plan" || fail "build: the $triple plan has no target directory ${only@Q}"
        local part="$work/plan-$triple.$only.tsv"
        awk -F'\t' -v d="$only" '($1 == "build" && $2 == d) || (($1 == "copy" || $1 == "sidecars") && index($2, d "/") == 1)' \
            "$plan" > "$part"
        plan="$part"
        say "$triple: the $only build alone"
    fi
    # The per-CPU flags go in as target.<triple>.rustflags, which joins the
    # product's own config; RUSTFLAGS would replace both.
    [ -z "${RUSTFLAGS:-}" ] && [ -z "${CARGO_ENCODED_RUSTFLAGS:-}" ] && [ -z "${CARGO_BUILD_RUSTFLAGS:-}" ] ||
        fail "RUSTFLAGS (or CARGO_BUILD_RUSTFLAGS) is set: it would replace or drop the per-CPU flags (put product flags in .cargo/config.toml's target.<triple>.rustflags, or in SEAWORTHY_RUSTFLAGS / SEAWORTHY_CORE_RUSTFLAGS)"
    local identity
    identity="$(release_identity)"
    # The release's name, for the product's build scripts (its version
    # token): what the package step will call it.
    SEAWORTHY_RELEASE_VERSION="${identity%% *}"
    SEAWORTHY_RELEASE_BUILD="${identity#* }"
    export SEAWORTHY_RELEASE_VERSION SEAWORTHY_RELEASE_BUILD
    say "building release $SEAWORTHY_RELEASE_VERSION${SEAWORTHY_RELEASE_BUILD:++$SEAWORTHY_RELEASE_BUILD}"
    local target_root="${SEAWORTHY_TARGET_DIR:-$work/target}" artifacts="$work/artifacts"
    local manifest="${SEAWORTHY_MANIFEST:-Cargo.toml}"
    local kind a b c line=0 extra=()
    read -r -a extra <<<"${SEAWORTHY_CARGO_ARGS:-}"
    # {workspace} in the caller's flags: the workspace root, absolute, as
    # every crate's rustc needs it (cargo runs a dependency's rustc in that
    # dependency's own directory).
    local workspace=""
    case "${SEAWORTHY_RUSTFLAGS:-} ${SEAWORTHY_CORE_RUSTFLAGS:-}" in
        *"{workspace}"*)
            [ -f "$manifest" ] || fail "{workspace} names the workspace manifest's directory, but $manifest doesn't exist (SEAWORTHY_MANIFEST)"
            workspace="$(cd "$(dirname "$manifest")" && pwd -P)"
            ;;
    esac
    while IFS=$'\t' read -r kind a b c; do
        line=$((line + 1))
        case "$kind" in
            build)
                local args=() flags=() rustflags=()
                read -r -a args <<<"$c"
                [ "$b" = - ] || read -r -a flags <<<"$b"
                # The caller's flags after the plan's: every build's, then
                # (a core's step: its target directory is its CPU, never
                # base) the cores'.
                extra_flags "$a" "$triple" "$workspace" "${SEAWORTHY_RUSTFLAGS:-}"
                flags+=("${expanded[@]}")
                if [ "$a" != base ]; then
                    extra_flags "$a" "$triple" "$workspace" "${SEAWORTHY_CORE_RUSTFLAGS:-}"
                    flags+=("${expanded[@]}")
                fi
                if [ "${#flags[@]}" -gt 0 ]; then
                    # TOML literal strings (extra_flags refuses a quote):
                    # one word every shell passes as is.
                    local toml="" flag
                    for flag in "${flags[@]}"; do toml="$toml'$flag',"; done
                    rustflags=(--config "target.$triple.rustflags=[${toml%,}]")
                fi
                local manifest_args=(--manifest-path "$manifest")
                case " $c " in *" --manifest-path "*) manifest_args=() ;; esac
                say "cargo build ${args[*]} ($a${flags[*]:+, ${flags[*]}})"
                cargo build --quiet --release --locked --target "$triple" --target-dir "$target_root/$a" \
                    --config profile.release.strip=false "${rustflags[@]}" "${manifest_args[@]}" \
                    "${args[@]}" "${extra[@]}"
                ;;
            copy)
                [ -f "$target_root/$a" ] || fail "the build left no $target_root/$a"
                # Not GNU's `install -D`: BSD install (macOS) has no such
                # option, and macOS builds run this step too.
                mkdir -p "$(dirname "$artifacts/$b")"
                install -m 0755 "$target_root/$a" "$artifacts/$b"
                ;;
            sidecars)
                # macOS (the FIPS module's dylib): every file named like the
                # pattern under the first CPU build's build scripts' output,
                # one set of bytes per name, copied beside the core. Windows
                # builds with seaworthy-build.ps1.
                [ "$triple" = "$macos" ] || fail "plan line $line: sidecars are Windows' and macOS's: build $windows with seaworthy-build.ps1"
                local from="$target_root/$a" to="$artifacts/$c" found=() file name digest seen
                [ -d "$from" ] || fail "the core build left no $from"
                while IFS= read -r -d '' file; do found+=("$file"); done < <(find "$from" -type f -name "$b" -print0)
                [ "${#found[@]}" -gt 0 ] || fail "no sidecar matching $b under $from (is the core built with the module that ships it?)"
                mkdir -p "$to"
                declare -A digests=()
                for file in "${found[@]}"; do
                    name="$(basename "$file")"
                    digest="$(shasum -a 256 "$file" | cut -d' ' -f1)"
                    seen="${digests[$name]:-}"
                    [ -z "$seen" ] || [ "$seen" = "$digest" ] || fail "$name: builds with different bytes under $from"
                    digests[$name]="$digest"
                    install -m 0755 "$file" "$to/$name"
                done
                say "sidecar(s) ${!digests[*]} -> $to"
                unset digests
                ;;
            *) fail "plan line $line: unknown step ${kind@Q}" ;;
        esac
    done < "$plan"
    [ -z "$only" ] || rm -f "$plan"
    say "built: $(find "$artifacts/$triple" -type f | wc -l) file(s) under $artifacts/$triple"
}

# The caller's extra rustflags for one build step, in `expanded`: the
# words of <flags>, {workspace} (the workspace root, absolute), {triple}
# and {cpu} (the step's target directory: its CPU, or base for the
# launcher and helper) expanded. Refused: a flag choosing the CPU or its
# features (the plan's alone: each core's requirement record must name
# exactly what it was built for), a quote (the flags travel as TOML literal
# strings) and any other {placeholder}.
expanded=()
extra_flags() { # <target dir> <triple> <workspace> <flags>
    local cpu="$1" triple="$2" workspace="$3" words=() word
    expanded=()
    read -r -a words <<<"$4"
    for word in "${words[@]}"; do
        case "$word" in
            *target-cpu* | *target-feature*)
                fail "extra rustflags may not choose the CPU or its features (${word@Q}): the build plan sets them per core" ;;
        esac
        word="${word//\{workspace\}/$workspace}"
        word="${word//\{triple\}/$triple}"
        word="${word//\{cpu\}/$cpu}"
        case "$word" in
            *"'"*) fail "extra rustflags may not hold a quote: ${word@Q}" ;;
        esac
        if [[ "$word" =~ \{[A-Za-z_]+\} ]]; then
            fail "extra rustflags: unknown placeholder ${BASH_REMATCH[0]} in ${word@Q} ({workspace}, {triple} and {cpu} expand)"
        fi
        expanded+=("$word")
    done
}

# What this release is, before any setup: release_version,
# release_sequence and release_build, for package and package-macos.
packaging_release() {
    release_version="$(version)"
    release_sequence="$(sequence)"
    check_release_ref
    # The binaries were built for the release prepare named (their version
    # tokens, release.env): packaging them as another would ship a gate that
    # never matches its manifests. The product's build-metadata command
    # never runs here: a signing step runs no product code, it reads what
    # prepare recorded.
    if read_release_env; then
        [ "$release_env_version" = "$release_version" ] ||
            fail "the build jobs built release $release_env_version (prepare's release.env), but this is $release_version"
        release_build="$release_env_build"
    else
        [ -z "${SEAWORTHY_BUILD_COMMAND:-}" ] ||
            fail "no $work/release.env (the prepare job's): the build-metadata command runs in prepare alone, and this step reads what it printed there"
        release_build="$(build_metadata)"
    fi
}

source_date_epoch() {
    if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
        SOURCE_DATE_EPOCH="$(git log -1 --format=%ct 2>/dev/null || true)"
        [ -n "$SOURCE_DATE_EPOCH" ] || fail "SOURCE_DATE_EPOCH: no git history to take the commit time from"
        export SOURCE_DATE_EPOCH
    fi
}

package() {
    need_file "$config" "seaworthy.toml (the template's seaworthy-toml)"
    [ -d "$work/artifacts" ] || fail "no $work/artifacts (from the build jobs)"
    # A release or a dev build without a signer: refused here, before any
    # work, unless SEAWORTHY_ALLOW_UNSIGNED=1.
    local no_signer=0
    if unsigned; then no_signer=1; fi
    trusted_tool
    need_file "$tool" "seaworthy (from the prepare job)"
    local release_version release_sequence release_build
    packaging_release
    check_no_test_key_marker "$work/artifacts"
    # desktop-file-validate: package checks every desktop product's menu
    # entry with it.
    need_tools dpkg-deb:dpkg rpmsign:rpm-tools gpg:gnupg bsdtar:libarchive curl:curl git:git \
        desktop-file-validate:desktop-file-utils
    NFPM="$(nfpm_path)"
    export NFPM
    source_date_epoch
    local signing=()
    if [ "$no_signer" = 1 ] && { release || dev_sign; }; then
        say "no signer was given: unsigned packages, version $release_version (the repositories refuse them)"
    elif release; then
        local file="${SEAWORTHY_SIGNING:-signing.toml}"
        signing_tools "$file"
        signing=(--signing "$file")
    elif dev_sign; then
        local file="${SEAWORTHY_SIGNING:-signing.toml}"
        signing_tools "$file"
        signing=(--signing "$file" --authenticode-only)
        say "a dev build: Authenticode-signed Windows binaries (no manifests, no repository signatures), version $release_version"
    elif ! ci_test_sign; then
        say "not a release: unsigned packages, version $release_version"
    fi
    if ci_test_sign; then
        say "a CI test build: manifests and package signatures by the CI test keys, version $release_version"
        signing+=("${ci_test_signing[@]}")
    fi
    rm -rf "$work/dist"
    # macOS packages on the Mac (package-macos).
    local product
    selected_products
    [ "${#products[@]}" -gt 0 ] || products=("")
    for product in "${products[@]}"; do
        if [ -n "$product" ] && ! product_has "$product" "$linux" "$windows"; then
            say "product $product has no Linux or Windows outputs: packaged on the Mac alone"
            continue
        fi
        with_secrets "$tool" package --config "$config" --artifacts "$work/artifacts" --out "$work/dist" \
            --release "$release_version" --sequence "$release_sequence" --build "$release_build" \
            --platforms linux,windows ${product:+--product "$product"} "${signing[@]}"
    done
}

# On the Mac (codesign and hdiutil are macOS's own): seaworthy built from
# the seaworthy checkout, each product's macOS outputs packaged from the build
# step's artifacts and their listings and files copied into dist-macos/ for
# the pipeline's artifacts. Ad hoc-signed and outside the release, unless a
# release sets SEAWORTHY_MACOS_SIGN=1: then signing.toml's [apple] Developer
# ID signs them and the notary service notarizes them (under the secrets
# prefix, when one is set).
package_macos() {
    [ "$(uname -s)" = Darwin ] || fail "package-macos runs on the Mac (macOS's codesign and hdiutil)"
    local checkout="${SEAWORTHY_CHECKOUT:-.seaworthy}"
    check_checkout "$checkout"
    need_file "$config" "seaworthy.toml (the template's seaworthy-toml)"
    [ -d "$work/artifacts/$macos" ] || fail "no $work/artifacts/$macos (from the build step)"
    # A release that signs runs this script from seaworthy's own checkout.
    if release && [ "${SEAWORTHY_MACOS_SIGN:-0}" = 1 ]; then
        require_own_checkout
    fi
    # The Mac's own seaworthy (the prepare job's is a Linux binary), built
    # from the checkout into a private directory.
    local made
    private_dir
    tool="$made/seaworthy"
    build_tool "$checkout" "$tool"
    local release_version release_sequence release_build
    packaging_release
    check_no_test_key_marker "$work/artifacts/$macos"
    local signing=()
    if release && [ "${SEAWORTHY_MACOS_SIGN:-0}" = 1 ]; then
        local file="${SEAWORTHY_SIGNING:-signing.toml}"
        need_file "$file" "signing.toml (its [apple] Developer ID signs a release's macOS outputs)"
        signing=(--signing "$file")
        say "a release: the macOS outputs are Developer ID-signed and notarized ([apple] in $file)"
    elif release; then
        say "a release: its macOS outputs stay ad hoc-signed pipeline artifacts, outside the release"
    elif ci_test_sign; then
        say "a CI test build: manifests by the CI test keys"
        signing=("${ci_test_signing[@]}")
    fi
    source_date_epoch
    local scratch="${SEAWORTHY_MACOS_SCRATCH:-$work/macos}"
    rm -rf "$scratch/dist" "$work/dist-macos"
    local product
    selected_products
    [ "${#products[@]}" -gt 0 ] || products=("")
    for product in "${products[@]}"; do
        if [ -n "$product" ] && ! product_has "$product" "$macos"; then
            say "product $product has no macOS outputs"
            continue
        fi
        with_secrets "$tool" package --config "$config" --artifacts "$work/artifacts" --out "$scratch/dist" \
            --release "$release_version" --sequence "$release_sequence" --build "$release_build" \
            --platforms macos ${product:+--product "$product"} "${signing[@]}"
    done
    local listing product copied=0
    mkdir -p "$work/dist-macos"
    for listing in "$scratch/dist"/*/packages.json; do
        [ -f "$listing" ] || continue
        product="$(basename "$(dirname "$listing")")"
        mkdir -p "$work/dist-macos/$product"
        cp "$listing" "$work/dist-macos/$product/"
        cp -R "$scratch/dist/$product/packages" "$work/dist-macos/$product/"
        copied=$((copied + 1))
    done
    say "$copied product(s) packaged for macOS into $work/dist-macos"
}

# The tools signing.toml needs (a release's, or a dev build's
# [authenticode]): osslsigncode, which checks every
# Authenticode signature against seaworthy.toml's pins (built from its pinned
# source), and with the Azure Artifact Signing signer (azure-sign.sh)
# a Java runtime for jsign.
signing_tools() { # <signing.toml>
    local file="$1"
    need_file "$file" "signing.toml (the template's signing-toml; a release or a dev build is signed)"
    if grep -q '^\[authenticode\]' "$file"; then
        local osslsigncode="${SEAWORTHY_OSSLSIGNCODE:-}"
        if [ -n "$osslsigncode" ]; then
            # The tools step's (GitHub: built before any secret was here).
            ! under_work "$osslsigncode" ||
                fail "SEAWORTHY_OSSLSIGNCODE is under $work, the prepare job's artifacts"
        else
            need_tools cmake:cmake
            osslsigncode="$("$scripts/install-osslsigncode.sh")" || fail "building osslsigncode failed"
        fi
        [ -x "$osslsigncode" ] || fail "install-osslsigncode.sh left no osslsigncode at ${osslsigncode@Q}"
        PATH="$(dirname "$osslsigncode"):$PATH"
        export PATH
        if grep -q 'azure-sign\.sh' "$file"; then
            need_tools java:jre-openjdk-headless
        fi
    fi
}

# Every MSI the Windows MSI job built (msi/<product>/*.msi), adopted into a
# copy of the packages (adopted/): its payload checked against the signed
# tree, signed on a release (Authenticode alone on a dev build), listed with
# its manifest and SBOM. Every product
# with a .wxs must have exactly its one MSI.
adopt_msi() {
    [ -d "$work/dist" ] || fail "no $work/dist (from the package job)"
    check_release_ref
    local no_signer=0
    if unsigned; then no_signer=1; fi
    trusted_tool
    need_file "$tool" "seaworthy (from the prepare job)"
    need_tools msiextract:msitools msiinfo:msitools
    source_date_epoch
    local signing=()
    if [ "$no_signer" = 1 ] && { release || dev_sign; }; then
        say "no signer was given: the MSIs stay unsigned"
    elif release; then
        local file="${SEAWORTHY_SIGNING:-signing.toml}"
        signing_tools "$file"
        signing=(--signing "$file")
    elif dev_sign; then
        local file="${SEAWORTHY_SIGNING:-signing.toml}"
        signing_tools "$file"
        signing=(--signing "$file" --authenticode-only)
        say "a dev build: the MSIs are Authenticode-signed"
    elif ! ci_test_sign; then
        say "not a release: the MSIs stay unsigned"
    fi
    if ci_test_sign; then
        say "a CI test build: the MSIs' manifests by the CI test keys"
        signing+=("${ci_test_signing[@]}")
    fi
    rm -rf "$work/adopted"
    cp -a "$work/dist" "$work/adopted"
    local listing product file wxs msi adopted=0
    for listing in "$work/adopted"/*/packages.json; do
        [ -f "$listing" ] || continue
        product="$(basename "$(dirname "$listing")")"
        wxs=0 msi=()
        for file in "$work/adopted/$product/packages/"*.wxs; do [ -f "$file" ] && wxs=$((wxs + 1)); done
        [ "$wxs" -gt 0 ] || continue
        for file in "$work/msi/$product/"*.msi; do [ -f "$file" ] && msi+=("$file"); done
        [ "${#msi[@]}" -eq 1 ] ||
            fail "product $product has a .wxs but the MSI job left ${#msi[@]} MSI(s) in $work/msi/$product (expected one)"
        with_secrets "$tool" adopt-msi --config "$config" --out "$work/adopted" --product "$product" \
            --msi "${msi[0]}" "${signing[@]}"
        adopted=$((adopted + 1))
    done
    say "$adopted MSI(s) adopted"
}

# publish.toml's public-url (a plain `public-url = "…"` or '…' line).
public_url() {
    local file="${SEAWORTHY_PUBLISH:-publish.toml}" url
    need_file "$file" "publish.toml (the template's publish-toml)"
    url="$(sed -n -e 's/^[[:space:]]*public-url[[:space:]]*=[[:space:]]*"\([^"]*\)"[[:space:]]*\(#.*\)\{0,1\}$/\1/p' \
        -e "s/^[[:space:]]*public-url[[:space:]]*=[[:space:]]*'\\([^']*\\)'[[:space:]]*\\(#.*\\)\\{0,1\\}\$/\\1/p" "$file" | head -1)"
    [ -n "$url" ] || fail "$file sets no public-url: the repo job fetches the last plan from there and publish checks through it"
    echo "$url"
}

repo() {
    # The adopt job's copy when the Windows MSI jobs ran (it lists the MSIs).
    local packages_dir="$work/dist"
    [ -d "$work/adopted" ] && packages_dir="$work/adopted"
    [ -d "$packages_dir" ] || fail "no $work/dist (from the package job)"
    release || fail "repo runs on a release only (the template's rules)"
    check_release_ref
    trusted_tool
    need_file "$tool" "seaworthy (from the prepare job)"
    need_tools dpkg-scanpackages:dpkg dpkg-deb:dpkg createrepo_c:createrepo_c repo-add:pacman \
        bsdtar:libarchive rpmkeys:rpm-tools gpg:gnupg curl:curl
    local signing_file="${SEAWORTHY_SIGNING:-signing.toml}" url status previous=()
    need_file "$signing_file" "signing.toml (the template's signing-toml)"
    url="$(public_url)"
    # https, or http to a loopback address only (publish refuses anything
    # else as public-url too); redirects are never followed.
    local proto
    case "$url" in
        https://*) proto='=https' ;;
        http://127.0.0.1 | http://127.0.0.1[:/]* | http://localhost | http://localhost[:/]* | \
            'http://[::1]' | 'http://[::1]'[:/]*) proto='=http' ;;
        *) fail "public-url $url: https only (http only to a loopback address)" ;;
    esac
    mkdir -p "$work/previous"
    # The last publication's plan, cache-busted: 404 is a first publication;
    # anything else must not be taken for one (repo would lose --previous).
    # Bounded like the plans publish reads back (64 MiB) and in time.
    local release_sequence code=0 max_plan=$((64 * 1024 * 1024))
    release_sequence="$(sequence)"
    rm -f "$work/previous/publish-plan.json"
    status="$(curl --proto "$proto" --tlsv1.2 --fail --silent --show-error --retry 3 \
        --connect-timeout 30 --max-time 120 --max-filesize "$max_plan" \
        -o "$work/previous/publish-plan.json" -w '%{http_code}' \
        "$url/publish-plan.json?seaworthy-previous=$release_sequence")" || code=$?
    case "$code:$status" in
        0:200)
            # curl stops a transfer at --max-filesize only from 8.4 on.
            [ "$(wc -c <"$work/previous/publish-plan.json")" -le "$max_plan" ] ||
                fail "$url/publish-plan.json is larger than $max_plan bytes"
            previous=(--previous "$work/previous/publish-plan.json")
            ;;
        22:404) say "no publication at $url yet: the first" ;;
        22:*) fail "$url/publish-plan.json answered HTTP $status" ;;
        63:*) fail "$url/publish-plan.json is larger than $max_plan bytes" ;;
        0:*) fail "$url/publish-plan.json answered HTTP $status" ;;
        *) fail "fetching $url/publish-plan.json failed (curl exit $code)" ;;
    esac
    rm -rf "$work/repo"
    with_secrets "$tool" repo --config "$config" --packages "$packages_dir" --out "$work/repo" \
        --signing "$signing_file" "${previous[@]}"
}

publish() {
    [ -f "$work/repo/publish-plan.json" ] || fail "no $work/repo (from the repo job)"
    release || fail "publish runs on a release only (the template's rules)"
    check_release_ref
    local target="${SEAWORTHY_PUBLISH:-publish.toml}"
    need_file "$target" "publish.toml (the template's publish-toml)"
    # Held at the start (hold_credentials): the seaworthy call alone gets them.
    if [ -z "${SEAWORTHY_SECRETS:-}" ]; then
        [ -n "${held[SEAWORTHY_S3_ACCESS_KEY_ID]:-}" ] && [ -n "${held[SEAWORTHY_S3_SECRET_ACCESS_KEY]:-}" ] ||
            fail "the store's credentials (SEAWORTHY_S3_ACCESS_KEY_ID, SEAWORTHY_S3_SECRET_ACCESS_KEY) aren't set: the template's publish-secrets provides them"
    fi
    trusted_tool
    need_file "$tool" "seaworthy (from the prepare job)"
    need_tools curl:curl
    local dry_run=()
    if [ "${SEAWORTHY_PUBLISH_DRY_RUN:-0}" = 1 ]; then
        dry_run=(--dry-run)
        say "a dry run (SEAWORTHY_PUBLISH_DRY_RUN=1): everything is checked, nothing uploaded or deleted"
    fi
    with_secrets "$tool" publish --repo "$work/repo" --target "$target" "${dry_run[@]}"
}

# The third-party tools <step> runs, installed ahead of it: on GitHub by a
# step of its own that holds no secret (nothing the signing step later holds
# is in their environment, or their parent's). nFPM for package (the pinned
# release, hash-checked); osslsigncode (built from its pinned source) for a
# release's or a dev build's Authenticode: adopt-msi's, and package's when a
# Windows plan exists. Their paths go to <env file> as NFPM= and
# SEAWORTHY_OSSLSIGNCODE= lines, or are printed.
tools_step() { # <step> [<env file>]
    local for="${1:-}" file="${2:-}" lines=() line
    case "$for" in
        package | adopt-msi) ;;
        *) fail "tools: package or adopt-msi, not ${for@Q}" ;;
    esac
    require_own_checkout
    if [ "$for" = package ]; then
        NFPM="$(nfpm_path)"
        lines+=("NFPM=$NFPM")
    fi
    if { release || dev_sign; } && { [ "$for" = adopt-msi ] || [ -f "$work/plan-$windows.tsv" ]; }; then
        need_tools cmake:cmake
        local osslsigncode
        osslsigncode="$("$scripts/install-osslsigncode.sh")" || fail "building osslsigncode failed"
        [ -x "$osslsigncode" ] || fail "install-osslsigncode.sh left no osslsigncode at ${osslsigncode@Q}"
        lines+=("SEAWORTHY_OSSLSIGNCODE=$osslsigncode")
    fi
    for line in "${lines[@]}"; do
        [[ "$line" != *[[:cntrl:]]* ]] || fail "a tool's path holds a control character: ${line@Q}"
        if [ -n "$file" ]; then
            printf '%s\n' "$line" >> "$file"
        else
            printf '%s\n' "$line"
        fi
        say "tools: $line"
    done
}

step="${1:-}"
shift || true
case "$step" in
    prepare) prepare ;;
    build) build "$@" ;;
    package) package ;;
    package-macos) package_macos ;;
    adopt-msi) adopt_msi ;;
    repo) repo ;;
    publish) publish ;;
    tools) tools_step "$@" ;;
    *) echo "usage: $0 prepare|build <triple>|package|package-macos|adopt-msi|repo|publish|tools <step> [<env file>]" >&2; exit 2 ;;
esac
