//! The `seaworthy-lab` command line, which bash and PowerShell lanes drive
//! alike (the crate's `README.md` documents it for lane authors):
//!
//! ```text
//! seaworthy-lab serve --root DIR (--token TOKEN | --token-file FILE) [--listen ADDR]...
//!                     [--ready FILE] [--hold FILE [--held FILE]] [--tls-cert PEM --tls-key PEM]
//! seaworthy-lab ca --out DIR --name HOST [--name HOST]... [--days N]
//! seaworthy-lab foreign-manifest --manifest FILE --out FILE
//! seaworthy-lab required-version --url URL [--timeout SECONDS]
//! ```
//!
//! Exit codes: 0 success, 1 a failure (named on stderr), 2 a usage error.
//! `serve` runs until it is killed. The conformance lane's server (the
//! e2e workspace's `conformance_server`) is [`serve_main`]: `serve`'s
//! options without the subcommand.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::LabError;
use crate::server::{Hold, Options, Server, TlsFiles, Token};

const USAGE: &str = "usage:
  seaworthy-lab serve --root DIR (--token TOKEN | --token-file FILE) [--listen ADDR]...
                      [--ready FILE] [--hold FILE [--held FILE]] [--tls-cert PEM --tls-key PEM]
  seaworthy-lab ca --out DIR --name HOST [--name HOST]... [--days N]
  seaworthy-lab foreign-manifest --manifest FILE --out FILE
  seaworthy-lab required-version --url URL [--timeout SECONDS]";

/// A failure: a usage error (exit 2) or the lab's (exit 1).
enum Failure {
    Usage(String),
    Lab(LabError),
}

impl From<LabError> for Failure {
    fn from(error: LabError) -> Self {
        Self::Lab(error)
    }
}

fn finish(result: Result<(), Failure>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(message)) => {
            eprintln!("seaworthy-lab: {message}\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Failure::Lab(error)) => {
            eprintln!("seaworthy-lab: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The whole command line (without the program name).
pub fn main(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    let mut args = args.into_iter();
    let Some(command) = args.next() else {
        return finish(Err(Failure::Usage("no command".to_owned())));
    };
    let rest: Vec<OsString> = args.collect();
    finish(match command.to_str() {
        Some("serve") => serve(rest),
        Some("ca") => ca(rest),
        Some("foreign-manifest") => foreign_manifest(rest),
        Some("required-version") => required_version(rest),
        Some("--help" | "-h" | "help") => {
            println!("{USAGE}");
            Ok(())
        }
        _ => Err(Failure::Usage(format!(
            "unknown command {:?}",
            command.to_string_lossy()
        ))),
    })
}

/// `serve`'s options alone (without the program name): the conformance
/// lane's server.
pub fn serve_main(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    finish(serve(args.into_iter().collect()))
}

/// Each flag's values, by name: every flag takes one value; `repeatable`
/// flags may appear more than once.
fn flags(
    args: Vec<OsString>,
    single: &[&str],
    repeatable: &[&str],
) -> Result<BTreeMap<String, Vec<String>>, Failure> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        let flag = flag
            .into_string()
            .map_err(|_| Failure::Usage("an argument isn't UTF-8".to_owned()))?;
        if !single.contains(&flag.as_str()) && !repeatable.contains(&flag.as_str()) {
            return Err(Failure::Usage(format!("unknown option {flag:?}")));
        }
        let value = args
            .next()
            .ok_or_else(|| Failure::Usage(format!("{flag} needs a value")))?
            .into_string()
            .map_err(|_| Failure::Usage(format!("{flag}'s value isn't UTF-8")))?;
        let values = out.entry(flag.clone()).or_default();
        if !values.is_empty() && single.contains(&flag.as_str()) {
            return Err(Failure::Usage(format!("{flag} is given twice")));
        }
        values.push(value);
    }
    Ok(out)
}

fn take(flags: &mut BTreeMap<String, Vec<String>>, flag: &str) -> Option<String> {
    flags
        .remove(flag)
        .and_then(|values| values.into_iter().next())
}

fn required(flags: &mut BTreeMap<String, Vec<String>>, flag: &str) -> Result<String, Failure> {
    take(flags, flag).ok_or_else(|| Failure::Usage(format!("{flag} is required")))
}

fn serve(args: Vec<OsString>) -> Result<(), Failure> {
    let mut flags = flags(
        args,
        &[
            "--root",
            "--token",
            "--token-file",
            "--ready",
            "--hold",
            "--held",
            "--tls-cert",
            "--tls-key",
        ],
        &["--listen"],
    )?;
    let token = match (
        take(&mut flags, "--token"),
        take(&mut flags, "--token-file"),
    ) {
        (Some(token), None) => Token::Fixed(token),
        (None, Some(file)) => Token::File(PathBuf::from(file)),
        _ => {
            return Err(Failure::Usage(
                "exactly one of --token and --token-file".to_owned(),
            ));
        }
    };
    let hold = match (take(&mut flags, "--hold"), take(&mut flags, "--held")) {
        (Some(until), held) => Some(Hold {
            until: PathBuf::from(until),
            held: held.map(PathBuf::from),
        }),
        (None, None) => None,
        (None, Some(_)) => return Err(Failure::Usage("--held needs --hold".to_owned())),
    };
    let tls = match (
        take(&mut flags, "--tls-cert"),
        take(&mut flags, "--tls-key"),
    ) {
        (Some(cert), Some(key)) => Some(TlsFiles {
            cert: PathBuf::from(cert),
            key: PathBuf::from(key),
        }),
        (None, None) => None,
        _ => {
            return Err(Failure::Usage(
                "--tls-cert and --tls-key go together".to_owned(),
            ));
        }
    };
    let options = Options {
        root: PathBuf::from(required(&mut flags, "--root")?),
        token,
        listen: flags.remove("--listen").unwrap_or_default(),
        hold,
        tls,
        ready: take(&mut flags, "--ready").map(PathBuf::from),
    };
    Server::bind(options)?.run()?;
    Ok(())
}

#[cfg(feature = "ca")]
fn ca(args: Vec<OsString>) -> Result<(), Failure> {
    let mut flags = flags(args, &["--out", "--days"], &["--name"])?;
    let out = PathBuf::from(required(&mut flags, "--out")?);
    let names = flags.remove("--name").unwrap_or_default();
    let validity = match take(&mut flags, "--days") {
        Some(days) => {
            let days: u64 = days
                .parse()
                .map_err(|_| Failure::Usage(format!("--days {days:?} isn't a number")))?;
            std::time::Duration::from_secs(days.saturating_mul(24 * 3600))
        }
        None => crate::ca::DEFAULT_VALIDITY,
    };
    let lab = crate::ca::LabCa::generate(&names, validity)?;
    lab.write(&out)?;
    println!(
        "seaworthy-lab: ca.pem, leaf.pem and leaf.key in {} for {}",
        out.display(),
        names.join(", ")
    );
    Ok(())
}

#[cfg(not(feature = "ca"))]
fn ca(_: Vec<OsString>) -> Result<(), Failure> {
    Err(Failure::Usage(
        "ca: this build has no `ca` feature".to_owned(),
    ))
}

fn foreign_manifest(args: Vec<OsString>) -> Result<(), Failure> {
    let mut flags = flags(args, &["--manifest", "--out"], &[])?;
    let input = PathBuf::from(required(&mut flags, "--manifest")?);
    let out = PathBuf::from(required(&mut flags, "--out")?);
    let signed = std::fs::read(&input).map_err(|e| LabError::io(input.display(), e))?;
    let foreign = crate::manifest::resign_with_throwaway_key(&signed)?;
    std::fs::write(&out, foreign).map_err(|e| LabError::io(out.display(), e))?;
    Ok(())
}

#[cfg(feature = "client")]
fn required_version(args: Vec<OsString>) -> Result<(), Failure> {
    let mut flags = flags(args, &["--url", "--timeout"], &[])?;
    let url = required(&mut flags, "--url")?;
    let timeout = match take(&mut flags, "--timeout") {
        Some(seconds) => std::time::Duration::from_secs(
            seconds
                .parse()
                .map_err(|_| Failure::Usage(format!("--timeout {seconds:?} isn't a number")))?,
        ),
        None => std::time::Duration::from_secs(60),
    };
    let client = crate::client::RequiredVersionClient::new(&url, timeout)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| LabError::io("the runtime", e))?;
    let token = runtime.block_on(client.fetch())?;
    println!("{token}");
    Ok(())
}

#[cfg(not(feature = "client"))]
fn required_version(_: Vec<OsString>) -> Result<(), Failure> {
    Err(Failure::Usage(
        "required-version: this build has no `client` feature".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn flags_take_one_value_each_and_repeat_only_when_allowed() {
        let parsed = flags(
            os(&["--root", "/r", "--listen", "a", "--listen", "b"]),
            &["--root"],
            &["--listen"],
        )
        .ok()
        .unwrap();
        assert_eq!(parsed["--listen"], ["a", "b"]);
        assert!(flags(os(&["--root", "a", "--root", "b"]), &["--root"], &[]).is_err());
        assert!(flags(os(&["--root"]), &["--root"], &[]).is_err());
        assert!(flags(os(&["--other", "x"]), &["--root"], &[]).is_err());
    }

    #[test]
    fn serve_refuses_inconsistent_options() {
        for args in [
            &["--root", "/tmp"][..],
            &["--root", "/tmp", "--token", "1", "--token-file", "f"],
            &["--root", "/tmp", "--token", "1", "--held", "f"],
            &["--root", "/tmp", "--token", "1", "--tls-cert", "c"],
        ] {
            assert!(
                matches!(serve(os(args)), Err(Failure::Usage(_))),
                "{args:?}"
            );
        }
    }
}
