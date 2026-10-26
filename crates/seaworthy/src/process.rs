//! Every external program `seaworthy` runs is made here, in one of two
//! shapes, and the signers' (a manifest signing command, osslsigncode or a
//! jsign/signtool command, rpmsign, gpg, rpmkeys) go through [`run`]: no
//! shell, a deadline, and a cap on what it may print.
//!
//! - [`tool`]: a packaging or checking program (nFPM, strip, WiX, msitools,
//!   gpg, rpmsign, rpmkeys, osslsigncode, the repository tools, the macOS
//!   tools, git, desktop-file-validate). It starts with an empty
//!   environment and gets back only the variables [`tool_environment`]
//!   allows: the system's own (the path, the home and temporary
//!   directories, the locale, proxies, Windows' folders), never a
//!   credential. On a release `seaworthy` runs where the signers'
//!   credentials are (a key handed over in the environment, a cloud
//!   signer's OIDC request token, the store's keys): none of them reaches a
//!   tool, whatever the tool or a file it reads does.
//! - [`signer`]: a signing command `signing.toml` names (a manifest signer,
//!   an Authenticode command such as `azure-sign.sh`): a custody system's
//!   client, which needs its own environment (an OIDC request token, a
//!   cloud CLI's profile). It inherits `seaworthy`'s, less the keys
//!   `signing.toml` hands over (`key-env`, `secret-key-env`, removed before
//!   anything runs), plus the credentials the command line set aside for
//!   signers alone ([`set_signer_environment`]).
//!
//! The runner is [`seaworthy_updater::process`], which the update helper uses
//! for its package-manager calls too: one implementation, reviewed once.
//! The deadline covers the whole run, draining the program's output
//! included, and on Unix the program's whole process group is killed when
//! it passes. This module maps its errors to [`DistError::Tool`].

use std::ffi::{OsStr, OsString};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

pub use seaworthy_updater::process::{Finished, MAX_OUTPUT_SHOWN, MAX_TIMEOUT};

use crate::DistError;

/// The variables a [`tool`] is given, when set: the system's own. On
/// Windows names compare without case, as Windows compares them.
pub const TOOL_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LANGUAGE",
    "TZ",
    "SOURCE_DATE_EPOCH",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
    "all_proxy",
    "XDG_RUNTIME_DIR",
    "GNUPGHOME",
    "DEVELOPER_DIR",
    // Windows: its folders and what its programs look up.
    "SystemRoot",
    "windir",
    "SystemDrive",
    "ComSpec",
    "PATHEXT",
    "USERPROFILE",
    "USERNAME",
    "APPDATA",
    "LOCALAPPDATA",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "CommonProgramFiles",
    "CommonProgramFiles(x86)",
    "CommonProgramW6432",
    "ALLUSERSPROFILE",
    "PUBLIC",
    "HOMEDRIVE",
    "HOMEPATH",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "OS",
];

/// The prefixes a [`tool`]'s variables may have beside [`TOOL_ENV`]: the
/// locale (`LC_`), git's command-scope configuration (`GIT_CONFIG_`, a
/// CI's `safe.directory`), and WiX's .NET runtime (`DOTNET_`, `NUGET_`).
pub const TOOL_PREFIXES: &[&str] = &["LC_", "GIT_CONFIG_", "DOTNET_", "NUGET_"];

/// More variable names for every [`tool`] (comma- or space-separated): an
/// environment a site's tools need that [`TOOL_ENV`] lacks. Never a
/// [denied](is_denied) one.
pub const TOOL_ENV_VARIABLE: &str = "SEAWORTHY_TOOL_ENV";

/// Names no [`tool`] is ever given, whatever allows them: seaworthy's own
/// (the store's keys among them), CI runners' (GitHub's OIDC request
/// token), cloud credentials, CI job tokens.
pub const DENIED_PREFIXES: &[&str] = &["SEAWORTHY_", "ACTIONS_", "AZURE_", "AWS_"];

/// See [`DENIED_PREFIXES`].
pub const DENIED: &[&str] = &["GITHUB_TOKEN", "CI_JOB_TOKEN"];

/// Whether `a` names the variable `b` (without case on Windows).
fn same_name(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// Whether `name` starts with `prefix` (without case on Windows).
fn has_prefix(name: &str, prefix: &str) -> bool {
    name.get(..prefix.len())
        .is_some_and(|start| same_name(start, prefix))
}

/// Whether no [`tool`] may ever be given `name`.
#[must_use]
pub fn is_denied(name: &str) -> bool {
    DENIED.iter().any(|d| same_name(name, d)) || DENIED_PREFIXES.iter().any(|p| has_prefix(name, p))
}

/// Whether `name` is a credential the command line sets aside for
/// [`signer`]s alone ([`set_signer_environment`]): a CI runner's (GitHub's
/// OIDC request token and URL), a cloud's (`AZURE_*`, `AWS_*`) or a CI job
/// token. Every one is [denied](is_denied) to tools too.
#[must_use]
pub fn is_signer_credential(name: &str) -> bool {
    DENIED.iter().any(|d| same_name(name, d))
        || ["ACTIONS_", "AZURE_", "AWS_"]
            .iter()
            .any(|p| has_prefix(name, p))
}

/// The environment a [`tool`] gets out of `vars` (the process's): the
/// variables [`TOOL_ENV`], [`TOOL_PREFIXES`] and `extra` (the value of
/// [`TOOL_ENV_VARIABLE`]) allow, never a [denied](is_denied) one. A name
/// that isn't text is left out.
#[must_use]
pub fn tool_environment(
    vars: impl IntoIterator<Item = (OsString, OsString)>,
    extra: Option<&OsStr>,
) -> Vec<(OsString, OsString)> {
    let extra = extra.map(OsStr::to_string_lossy).unwrap_or_default();
    let extra: Vec<&str> = extra
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|n| !n.is_empty())
        .collect();
    vars.into_iter()
        .filter(|(name, _)| {
            let Some(name) = name.to_str() else {
                return false;
            };
            !is_denied(name)
                && (TOOL_ENV.iter().any(|a| same_name(name, a))
                    || TOOL_PREFIXES.iter().any(|p| has_prefix(name, p))
                    || extra.iter().any(|a| same_name(name, a)))
        })
        .collect()
}

/// A packaging or checking program's command: an empty environment, then
/// what [`tool_environment`] allows of this process's.
pub fn tool(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    // allow-std-env: the tool's allowlisted environment, and the site's
    // additions to it
    let extra = std::env::var_os(TOOL_ENV_VARIABLE);
    // allow-std-env: filtered by the allowlist, credentials never pass
    command.envs(tool_environment(std::env::vars_os(), extra.as_deref()));
    command
}

/// The credentials the command line set aside for signers.
static SIGNER_ENVIRONMENT: OnceLock<Vec<(OsString, OsString)>> = OnceLock::new();

/// Sets aside `vars` for [`signer`]s alone: the command line takes the
/// [signer credentials](is_signer_credential) out of its environment
/// before anything runs (so neither a tool nor a library's own child, such
/// as the OpenPGP checks' gpg, inherits them) and hands them here. Only the
/// first call counts; returns whether it was the first.
pub fn set_signer_environment(vars: Vec<(OsString, OsString)>) -> bool {
    SIGNER_ENVIRONMENT.set(vars).is_ok()
}

/// A signing command's command (a custody system's client): this
/// process's environment, plus what [`set_signer_environment`] set aside.
pub fn signer(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    if let Some(vars) = SIGNER_ENVIRONMENT.get() {
        command.envs(vars.iter().map(|(k, v)| (k, v)));
    }
    command
}

/// Checks a configured deadline: 1 second to [`MAX_TIMEOUT`].
///
/// # Errors
/// [`DistError::Sign`] naming `what` for a value outside that range.
pub fn check_timeout(timeout: Duration, what: &str) -> Result<Duration, DistError> {
    if timeout < Duration::from_secs(1) || timeout > MAX_TIMEOUT {
        return Err(DistError::Sign(format!(
            "{what}: a timeout must be 1 to {} seconds",
            MAX_TIMEOUT.as_secs()
        )));
    }
    Ok(timeout)
}

/// Runs `command` (`what` names it in messages) with `stdin` on its
/// standard input (or none), under `timeout`, keeping at most
/// `stdout_limit` bytes of its stdout ([`seaworthy_updater::process::run`]).
///
/// # Errors
/// [`DistError::Tool`] when it can't start, or doesn't finish (its output
/// drained) within `timeout`. A non-zero exit is not an error here: the
/// caller decides, with [`Finished::shown`] for the message.
pub fn run(
    command: &mut Command,
    what: &str,
    stdin: Option<Vec<u8>>,
    timeout: Duration,
    stdout_limit: usize,
) -> Result<Finished, DistError> {
    seaworthy_updater::process::run(command, what, stdin, timeout, stdout_limit)
        .map_err(|e| DistError::Tool(e.to_string()))
}

/// [`run`], then a non-zero exit is an error; returns stdout as text.
///
/// # Errors
/// As [`run`]; [`DistError::Tool`] for a non-zero exit, with what the
/// program printed (cut short).
pub fn run_ok(command: &mut Command, what: &str, timeout: Duration) -> Result<String, DistError> {
    seaworthy_updater::process::run_ok(command, what, timeout)
        .map_err(|e| DistError::Tool(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    }

    fn names(env: &[(OsString, OsString)]) -> Vec<String> {
        env.iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn a_tool_gets_the_system_s_variables_and_never_a_credential() {
        let all = vars(&[
            ("PATH", "/usr/bin"),
            ("HOME", "/home/ci"),
            ("LC_ALL", "C"),
            ("GIT_CONFIG_COUNT", "1"),
            ("DOTNET_ROOT", "/dotnet"),
            ("SEAWORTHY_S3_SECRET_ACCESS_KEY", "s3"),
            ("SEAWORTHY_RELEASE_MANIFEST_KEY", "key"),
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "oidc"),
            ("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com"),
            ("AZURE_CLIENT_SECRET", "azure"),
            ("AWS_SECRET_ACCESS_KEY", "aws"),
            ("GITHUB_TOKEN", "gh"),
            ("CI_JOB_TOKEN", "job"),
            ("ACME_RELEASE_KEY_HEX", "custom"),
            ("RUSTC_WRAPPER", "sccache"),
        ]);
        let env = tool_environment(all.clone(), None);
        assert_eq!(
            names(&env),
            ["PATH", "HOME", "LC_ALL", "GIT_CONFIG_COUNT", "DOTNET_ROOT"]
        );
        // The site's additions, never a denied name.
        let extra = OsString::from(
            "ACME_RELEASE_KEY_HEX, SEAWORTHY_S3_SECRET_ACCESS_KEY AWS_SECRET_ACCESS_KEY,GITHUB_TOKEN",
        );
        let env = tool_environment(all, Some(&extra));
        assert!(names(&env).contains(&"ACME_RELEASE_KEY_HEX".to_owned()));
        for denied in [
            "SEAWORTHY_S3_SECRET_ACCESS_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
        ] {
            assert!(!names(&env).contains(&denied.to_owned()), "{denied}");
        }
    }

    #[test]
    fn signer_credentials_are_the_runner_s_and_the_cloud_s() {
        for name in [
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "AZURE_CLIENT_ID",
            "AWS_SESSION_TOKEN",
            "GITHUB_TOKEN",
            "CI_JOB_TOKEN",
        ] {
            assert!(is_signer_credential(name), "{name}");
            assert!(is_denied(name), "{name}");
        }
        for name in ["PATH", "SEAWORTHY_S3_ACCESS_KEY_ID", "AWSOME", "ACTIONS"] {
            assert!(!is_signer_credential(name), "{name}");
        }
        assert!(is_denied("SEAWORTHY_S3_ACCESS_KEY_ID"));
    }

    /// Every program is made by [`tool`] or [`signer`]: no other module
    /// builds a `Command` of its own, which would inherit everything.
    #[test]
    fn every_program_is_made_here() {
        fn walk(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, found);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    found.push(path);
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&src, &mut files);
        assert!(files.len() > 10, "{files:?}");
        let needle = concat!("Command", "::new(");
        for file in files {
            if file.ends_with("process.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&file).unwrap();
            assert!(
                !text.contains(needle),
                "{}: builds a Command itself: use process::tool or process::signer",
                file.display()
            );
        }
    }
}
