//! The pre-pull step: pull every test image ONCE, one at a time, before
//! any container suite runs.
//!
//! `scripts/pull-test-images.sh` runs this (through the crate's
//! `pull_test_images` example) before the container suites, locally and in
//! CI. Each image goes through the launcher's own [`ensure_image`]: the
//! same digest-pin check, the same presence check (an image the daemon
//! already holds costs no registry request), the same transient-retry
//! policy. A cold daemon thus meets the registries' anonymous limits once,
//! serially, instead of as a burst of parallel test starts. The launcher
//! keeps its own retries for whatever the step did not warm.
//!
//! **One list.** The images are [`images::ALL`]: no second, hand-kept
//! list. `--only` narrows it by name; `--image` / `--images-file` add a
//! caller's own images, which must be digest pins too.
//!
//! **The skip contract.** Exactly [`crate::docker_or_skip`]'s: no daemon →
//! skip (exit 0, announced); a daemon that exists but is unusable → fail;
//! `SEAWORTHY_TEST_CONTAINERS_REQUIRED=1` fails on both, `=0` skips on both.
//! `--list` never contacts the daemon.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};

use crate::{
    docker::{self, Decision, RequiredMode},
    images,
    pull::{Ensured, ensure_image},
};

/// `--help`.
pub const USAGE: &str = "\
usage: scripts/pull-test-images.sh [--list] [--only NAME[,NAME...]]
                                   [--image REF]... [--images-file FILE]...

Pull the digest-pinned test images serially, before the container suites,
retrying transient registry failures (rate limits, 5xx, resets, timeouts,
truncated downloads) with bounded backoff. Images the daemon already holds
are skipped without contacting the registry.

  --list               print the selected references and exit (no daemon)
  --only NAMES         only these seaworthy-test-support images (comma list;
                       names below; the Linux conformance lane's systemd
                       hosts and builder are pulled only when named here)
  --image REF          also pull REF (repeatable; name:tag@sha256:<64 hex>)
  --images-file FILE   also pull every reference in FILE (one per line;
                       blank lines and # comments ignored; repeatable)
  -h, --help           this help

No daemon: skipped (exit 0). A broken daemon: exit 1.
SEAWORTHY_TEST_CONTAINERS_REQUIRED=1 fails without a usable daemon; =0 skips.
Exit codes: 0 ready or skipped, 1 a pull or the daemon failed, 2 usage.";

/// Parsed command line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Options {
    help: bool,
    list: bool,
    only: Option<Vec<String>>,
    images: Vec<String>,
    images_files: Vec<PathBuf>,
}

/// Parse the arguments (program name excluded). `--opt value` and
/// `--opt=value` are both accepted; repeated `--only` lists merge.
fn parse(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let mut options = Options::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => (flag.to_string(), Some(value)),
            _ => (arg.clone(), None),
        };
        let mut value = |name: &str| -> Result<String, String> {
            match inline {
                Some(value) => Ok(value.to_string()),
                None => args.next().ok_or_else(|| format!("{name} needs a value")),
            }
        };
        match flag.as_str() {
            "--help" | "--list" if inline.is_some() => {
                return Err(format!("{flag} takes no value"));
            }
            "-h" | "--help" => options.help = true,
            "--list" => options.list = true,
            "--only" => {
                let names = value("--only")?;
                let names: Vec<String> = names
                    .split(',')
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(str::to_string)
                    .collect();
                if names.is_empty() {
                    return Err("--only needs at least one image name".into());
                }
                options.only.get_or_insert_with(Vec::new).extend(names);
            }
            "--image" => options.images.push(value("--image")?),
            "--images-file" => options.images_files.push(value("--images-file")?.into()),
            _ => return Err(format!("unknown argument {arg:?}")),
        }
    }
    Ok(options)
}

/// The references to pull, in order, without duplicates: the selected
/// [`images::ALL`] pins first, then the extra images (each a validated
/// digest pin). `read` loads an `--images-file`.
fn select(
    options: &Options,
    read: impl Fn(&Path) -> std::io::Result<String>,
) -> Result<Vec<String>, String> {
    let mut selected: Vec<String> = Vec::new();
    let mut push = |reference: &str| {
        if !selected.iter().any(|seen| seen == reference) {
            selected.push(reference.to_string());
        }
    };
    match &options.only {
        None => images::ALL
            .iter()
            .filter(|pin| pin.group == images::Group::Suites)
            .for_each(|pin| push(pin.reference)),
        Some(names) => {
            for name in names {
                let pin = images::ALL
                    .iter()
                    .find(|pin| pin.name == name)
                    .ok_or_else(|| {
                        let known: Vec<&str> = images::ALL.iter().map(|pin| pin.name).collect();
                        format!(
                            "--only: unknown image name {name:?} (known: {})",
                            known.join(", ")
                        )
                    })?;
                push(pin.reference);
            }
        }
    }
    let mut extras: Vec<(String, String)> = options
        .images
        .iter()
        .map(|reference| ("--image".to_string(), reference.trim().to_string()))
        .collect();
    for file in &options.images_files {
        let text = read(file).map_err(|e| format!("--images-file {}: {e}", file.display()))?;
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                extras.push((
                    format!("{}:{}", file.display(), index + 1),
                    line.to_string(),
                ));
            }
        }
    }
    for (origin, reference) in extras {
        images::validate_pin(&reference).map_err(|problem| {
            format!("{origin}: refusing {reference:?}: {problem} (every image is a digest pin)")
        })?;
        push(&reference);
    }
    Ok(selected)
}

/// Run the pre-pull step with `args` (program name excluded); its exit
/// code: 0 ready or skipped, 1 a pull or the daemon failed, 2 usage.
pub async fn run(args: impl IntoIterator<Item = String>) -> ExitCode {
    const USAGE_ERROR: u8 = 2;
    let options = match parse(args) {
        Ok(options) => options,
        Err(problem) => {
            eprintln!("pull-test-images: {problem}\n\n{USAGE}");
            return ExitCode::from(USAGE_ERROR);
        }
    };
    if options.help {
        println!(
            "{USAGE}\n\nimages (--only names; the systemd hosts and builders only when named):"
        );
        for pin in images::ALL {
            let group = match pin.group {
                images::Group::Suites => "",
                images::Group::SystemdHosts => " (systemd host)",
                images::Group::Builders => " (builder)",
            };
            println!("  {:<16} {}{group}", pin.name, pin.reference);
        }
        return ExitCode::SUCCESS;
    }
    let references = match select(&options, |path| std::fs::read_to_string(path)) {
        Ok(references) => references,
        Err(problem) => {
            eprintln!("pull-test-images: {problem}");
            return ExitCode::from(USAGE_ERROR);
        }
    };
    if options.list {
        for reference in &references {
            println!("{reference}");
        }
        return ExitCode::SUCCESS;
    }

    // The container skip contract, decided exactly as `docker_or_skip`.
    let mode = match RequiredMode::parse(std::env::var(crate::REQUIRED_ENV).ok().as_deref()) {
        Ok(mode) => mode,
        Err(problem) => {
            eprintln!("pull-test-images: {problem}");
            return ExitCode::from(USAGE_ERROR);
        }
    };
    docker::ensure_crypto_provider();
    match docker::decide(&docker::probe().await, mode) {
        Decision::Run => {}
        Decision::Skip(reason) => {
            println!("pull-test-images: skipped — {reason}");
            return ExitCode::SUCCESS;
        }
        Decision::Fail(reason) => {
            eprintln!("pull-test-images: {reason}");
            return ExitCode::FAILURE;
        }
    }

    println!(
        "pull-test-images: {} image(s), one at a time",
        references.len()
    );
    let mut pulled = 0_usize;
    for (index, reference) in references.iter().enumerate() {
        let started = Instant::now();
        match ensure_image(reference).await {
            Ok(Ensured::Present) => println!("  present  {reference}"),
            Ok(Ensured::Pulled { attempts, .. }) => {
                pulled += 1;
                println!(
                    "  pulled   {reference} ({attempts} attempt(s), {:.1}s)",
                    started.elapsed().as_secs_f64()
                );
            }
            Err(error) => {
                eprintln!("  FAILED   {reference}\npull-test-images: {error}");
                let rest = &references[index + 1..];
                if !rest.is_empty() {
                    eprintln!(
                        "pull-test-images: not attempted (stopped at the first failure): {}",
                        rest.join(", ")
                    );
                }
                return ExitCode::FAILURE;
            }
        }
    }
    println!(
        "pull-test-images: {} image(s) ready ({pulled} pulled)",
        references.len()
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{Options, parse, select};
    use crate::images;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    fn no_files(path: &Path) -> std::io::Result<String> {
        panic!("unexpected read of {}", path.display())
    }

    const EXTRA: &str =
        "busybox:1.37.0@sha256:0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn parse_accepts_the_documented_options() {
        assert_eq!(parse(args(&[])), Ok(Options::default()));
        let options = parse(args(&[
            "--list",
            "--only",
            "rustfs, debian-13",
            "--only=arch",
            "--image",
            EXTRA,
            "--images-file=app-images.txt",
        ]))
        .expect("parses");
        assert_eq!(
            options,
            Options {
                help: false,
                list: true,
                only: Some(args(&["rustfs", "debian-13", "arch"])),
                images: args(&[EXTRA]),
                images_files: vec![PathBuf::from("app-images.txt")],
            }
        );
        assert!(parse(args(&["-h"])).expect("parses").help);
    }

    #[test]
    fn malformed_command_lines_are_usage_errors() {
        for bad in [
            &["--bogus"][..],
            &["rustfs"],
            &["--only"],
            &["--only", ","],
            &["--image"],
            &["--images-file"],
            &["--list=yes"],
            &["--help=me"],
            &["-h=1"],
        ] {
            assert!(parse(args(bad)).is_err(), "{bad:?} must be refused");
        }
    }

    /// The default selection IS images.rs's list (the single source of
    /// truth), in order: its suite services; the systemd hosts come only
    /// when named.
    #[test]
    fn the_default_selection_is_every_suite_pin_in_images_rs() {
        let suites: Vec<String> = images::ALL
            .iter()
            .filter(|pin| pin.group == images::Group::Suites)
            .map(|pin| pin.reference.to_string())
            .collect();
        assert_eq!(select(&Options::default(), no_files), Ok(suites));
        assert!(
            !select(&Options::default(), no_files)
                .unwrap()
                .contains(&images::DEBIAN_13.to_string())
        );
        let options = parse(args(&[
            "--only",
            "debian-13,ubuntu-24.04,ubi-9,fedora-43,arch",
        ]))
        .expect("parses");
        assert_eq!(
            select(&options, no_files),
            Ok(args(&[
                images::DEBIAN_13,
                images::UBUNTU_2404,
                images::UBI9_INIT,
                images::FEDORA_43,
                images::ARCH
            ]))
        );
    }

    #[test]
    fn only_narrows_by_name_and_refuses_unknown_names() {
        let options = parse(args(&["--only", "rustfs,rust-builder,fedora-43"])).expect("parses");
        assert_eq!(
            select(&options, no_files),
            Ok(args(&[
                images::RUSTFS,
                images::RUST_BUILDER,
                images::FEDORA_43
            ]))
        );
        let options = parse(args(&["--only", "rustfs,minio"])).expect("parses");
        let error = select(&options, no_files).expect_err("unknown name");
        assert!(
            error.contains("\"minio\"") && error.contains("rustfs, debian-13"),
            "{error}"
        );
    }

    /// A caller's extra images are held to the same pin rule, and a
    /// reference already selected is pulled once.
    #[test]
    fn extra_images_must_be_digest_pins_and_are_pulled_once() {
        let options = parse(args(&[
            "--only",
            "rustfs",
            "--image",
            EXTRA,
            "--image",
            EXTRA,
            "--image",
            images::RUSTFS,
        ]))
        .expect("parses");
        assert_eq!(
            select(&options, no_files),
            Ok(args(&[images::RUSTFS, EXTRA]))
        );
        for unpinned in ["busybox:1.37.0", "busybox:latest", "busybox"] {
            let options = parse(args(&["--image", unpinned])).expect("parses");
            let error = select(&options, no_files).expect_err("unpinned");
            assert!(error.contains("digest"), "{error}");
        }
    }

    #[test]
    fn images_files_skip_blank_lines_and_comments_and_name_bad_lines() {
        let options =
            parse(args(&["--only", "rustfs", "--images-file", "app.txt"])).expect("parses");
        let read = |_: &Path| Ok(format!("# the caller's own pins\n\n  {EXTRA}  \n"));
        assert_eq!(select(&options, read), Ok(args(&[images::RUSTFS, EXTRA])));
        let read = |_: &Path| Ok(format!("{EXTRA}\nbusybox:latest\n"));
        let error = select(&options, read).expect_err("unpinned line");
        assert!(error.starts_with("app.txt:2:"), "{error}");
        let read = |_: &Path| Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(select(&options, read).is_err());
    }
}
