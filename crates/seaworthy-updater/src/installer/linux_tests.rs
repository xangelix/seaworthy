//! Tests of the Linux installers: the pure parsers and checks, the exact
//! command lines, and each installer end to end against fake tools (the
//! real package managers run in the repository's conformance lanes).

use super::*;

fn release(version: &str, sequence: u64) -> Release {
    Release::new(version, sequence).unwrap()
}

#[test]
fn apt_plans_must_install_exactly_our_package_at_the_releases_version() {
    let ours = "Inst acme-agent [1.0.0-1] (1.1.0-2 local-deb [amd64])\nConf acme-agent (1.1.0-2 local-deb [amd64])\n";
    assert!(check_apt_plan(ours, "acme-agent", "1.1.0-2").is_ok());
    assert!(
        check_apt_plan(
            "Inst acme-agent:amd64 (1.1.0-2 local-deb [amd64])\n",
            "acme-agent",
            "1.1.0-2"
        )
        .is_ok()
    );
    // The file's own version must be the release's.
    let error = check_apt_plan(ours, "acme-agent", "1.1.0-3").unwrap_err();
    assert!(error.to_string().contains("1.1.0-3"), "{error}");
    for bad in [
        "",
        "acme-agent is already the newest version (1.1.0-2).\n",
        "Inst libfoo (2 Debian:13/stable [amd64])\nInst acme-agent (1.1.0-2 local-deb [amd64])\n",
        "Remv old-thing [1]\nInst acme-agent (1.1.0-2 local-deb [amd64])\n",
        "Purg old-thing [1]\nInst acme-agent (1.1.0-2 local-deb [amd64])\n",
        "Inst acme-agent (1.1.0-2 local-deb [amd64])\nConf libfoo (2 Debian:13/stable [amd64])\n",
        "Inst acme-agent (1.1.0-2 x)\nInst acme-agent (1.1.0-2 y)\n",
        "Remv acme-agent [1.0.0-1]\n",
        "Purg acme-agent [1.0.0-1]\nInst acme-agent (1.1.0-2 local-deb [amd64])\n",
    ] {
        assert!(
            check_apt_plan(bad, "acme-agent", "1.1.0-2").is_err(),
            "{bad:?}"
        );
    }
}

#[test]
fn installed_versions_are_read_from_each_query() {
    assert_eq!(
        parse_dpkg_query("ii |1.1.0-2\n").unwrap(),
        Some(release("1.1.0", 2))
    );
    // Triggers awaited or pending: installed.
    for status in ["iW ", "it "] {
        assert_eq!(
            parse_dpkg_query(&format!("{status}|1.1.0-2\n")).unwrap(),
            Some(release("1.1.0", 2)),
            "{status}"
        );
    }
    assert_eq!(parse_dpkg_query("rc |1.1.0-2\n").unwrap(), None);
    assert_eq!(parse_dpkg_query("un |\n").unwrap(), None);
    for bad in [
        "iU |1.1.0-2\n",
        "iF |1.1.0-2\n",
        "iH |1.1.0-2\n",
        "ii |1:1.1.0-2\n",
        "ii |1.1.0-2\nii |1.0.0-1\n",
        "",
        "ii 1.1.0-2\n",
    ] {
        assert!(parse_dpkg_query(bad).is_err(), "{bad:?}");
    }
    assert_eq!(
        parse_rpm_query("1.4.0~rc.2-812\n").unwrap(),
        release("1.4.0-rc.2", 812)
    );
    assert!(parse_rpm_query("1.4.0-812\n1.3.0-700\n").is_err());
    assert!(parse_rpm_query("1.4.0-812.el9\n").is_err());
    // The query prints an epoch when there is one: refused, not dropped.
    assert!(parse_rpm_query("1:1.4.0-812\n").is_err());
    assert!(RPM_VERSION_FORMAT.starts_with("%|EPOCH?{%{EPOCH}:}|"));
    assert_eq!(
        parse_pacman_query("acme-agent 1.4.0rc.2-812\n", "acme-agent").unwrap(),
        release("1.4.0-rc.2", 812)
    );
    assert!(parse_pacman_query("acme-agent-x 1.0.0-1\n", "acme-agent").is_err());
    assert!(parse_pacman_query("acme-agent 1:1.0.0-1\n", "acme-agent").is_err());
}

#[test]
fn transient_units_wrap_the_install_without_a_time_limit() {
    let unit = TransientUnit::default();
    let command = unit.command(
        "acme-agent-install",
        &APT_ENV,
        Path::new("/usr/bin/apt-get"),
        &[
            "install".to_owned(),
            "/var/cache/acme/agent/x.deb".to_owned(),
        ],
    );
    let args: Vec<String> = command
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert_eq!(command.get_program(), "/usr/bin/systemd-run");
    assert_eq!(
        args,
        [
            "--wait",
            "--collect",
            "--quiet",
            "--service-type=exec",
            "--unit=acme-agent-install",
            "--description=Install acme-agent-install",
            "--setenv=LC_ALL=C",
            "--setenv=DEBIAN_FRONTEND=noninteractive",
            "--setenv=NEEDRESTART_SUSPEND=1",
            "--setenv=APT_LISTCHANGES_FRONTEND=none",
            "--",
            "/usr/bin/apt-get",
            "install",
            "/var/cache/acme/agent/x.deb",
        ]
    );
    assert!(!args.iter().any(|a| a.contains("RuntimeMaxSec")));
}

#[test]
fn install_arguments_follow_the_design() {
    let (new, old) = (release("1.1.0", 2), release("1.0.0", 1));
    let file = Path::new("/var/cache/acme/agent/acme-agent.deb");
    let upgrade = Install {
        package: "acme-agent",
        file,
        signature: None,
        release: &new,
        replaces: &old,
    };
    assert_eq!(
        Apt::install_args(&upgrade, false).unwrap(),
        [
            "install",
            "-q",
            "--no-install-recommends",
            "-y",
            "-o",
            "DPkg::Lock::Timeout=300",
            "-o",
            "Dpkg::Options::=--force-confold",
            "/var/cache/acme/agent/acme-agent.deb"
        ]
    );
    assert_eq!(
        Dnf::install_args(&upgrade).unwrap(),
        [
            "upgrade",
            "-y",
            "-q",
            "--disablerepo=*",
            "--setopt=install_weak_deps=False",
            "/var/cache/acme/agent/acme-agent.deb"
        ]
    );
    let downgrade = Install {
        release: &old,
        replaces: &new,
        ..upgrade
    };
    assert!(downgrade.is_downgrade() && !upgrade.is_downgrade());
    let args = Apt::install_args(&downgrade, true).unwrap();
    assert!(args.contains(&"-s".to_owned()) && args.contains(&"--allow-downgrades".to_owned()));
    assert!(
        !Apt::install_args(&upgrade, true)
            .unwrap()
            .contains(&"--allow-downgrades".to_owned())
    );
    assert_eq!(Dnf::install_args(&downgrade).unwrap()[0], "downgrade");
    let relative = Install {
        file: Path::new("x.deb"),
        ..upgrade
    };
    assert!(Apt::install_args(&relative, false).is_err());
    assert!(Dnf::install_args(&relative).is_err());
}

/// A fake tool: a shell script running `script`, logging its arguments to
/// `<dir>/<name>.log`.
fn fake(dir: &Path, name: &str, script: &str) -> PathBuf {
    let path = dir.join(name);
    crate::tests_support::write_script(
        &path,
        &format!(
            "#!/bin/sh\necho \"$@\" >> '{}/{name}.log'\n{script}\n",
            dir.display()
        ),
    );
    path
}

fn log(dir: &Path, name: &str) -> Vec<String> {
    std::fs::read_to_string(dir.join(format!("{name}.log")))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn tools_in(dir: &Path) -> Tools {
    Tools {
        apt_get: dir.join("apt-get"),
        dpkg_query: dir.join("dpkg-query"),
        dnf: dir.join("dnf"),
        rpm: dir.join("rpm"),
        pacman: dir.join("pacman"),
        pacman_conf_tool: dir.join("pacman-conf"),
        pacman_conf: dir.join("pacman.conf"),
    }
}

#[test]
fn apt_queries_plans_and_installs_through_its_tools() {
    let dir = tempfile::tempdir().unwrap();
    let tools = tools_in(dir.path());
    fake(dir.path(), "dpkg-query", "echo 'ii |1.0.0-1'");
    fake(
        dir.path(),
        "apt-get",
        "case \"$*\" in *' -s '*) echo 'Inst acme-agent [1.0.0-1] (1.1.0-2 local-deb [amd64])';; *) [ \"$NEEDRESTART_SUSPEND\" = 1 ] || exit 9;; esac",
    );
    let apt = Apt::with(tools, TransientUnit::direct(Duration::from_secs(30)));
    assert_eq!(
        apt.installed("acme-agent").unwrap(),
        Some(release("1.0.0", 1))
    );
    let (new, old) = (release("1.1.0", 2), release("1.0.0", 1));
    let file = dir.path().join("acme-agent.deb");
    let install = Install {
        package: "acme-agent",
        file: &file,
        signature: None,
        release: &new,
        replaces: &old,
    };
    apt.install(&install).unwrap();
    assert_eq!(log(dir.path(), "apt-get").len(), 2);
    // A file whose own version isn't the release's installs nothing.
    std::fs::remove_file(dir.path().join("apt-get.log")).unwrap();
    let other = release("1.1.0", 3);
    let mismatched = Install {
        release: &other,
        ..install
    };
    assert!(matches!(
        apt.install(&mismatched),
        Err(InstallError::Plan { .. })
    ));
    assert_eq!(log(dir.path(), "apt-get").len(), 1, "only the plan ran");
    // A plan that pulls in another package installs nothing.
    fake(
        dir.path(),
        "apt-get",
        "case \"$*\" in *' -s '*) echo 'Inst libnew (1 stable [amd64])'; echo 'Inst acme-agent (1.1.0-2 local-deb [amd64])';; *) exit 0;; esac",
    );
    std::fs::remove_file(dir.path().join("apt-get.log")).unwrap();
    assert!(matches!(
        apt.install(&install),
        Err(InstallError::Plan { .. })
    ));
    assert_eq!(log(dir.path(), "apt-get").len(), 1, "only the plan ran");
    // A failing install is an install error repeating its output.
    fake(
        dir.path(),
        "apt-get",
        "case \"$*\" in *' -s '*) echo 'Inst acme-agent (1.1.0-2 local-deb [amd64])';; *) echo 'E: broken' >&2; exit 100;; esac",
    );
    let error = apt.install(&install).unwrap_err();
    assert!(
        matches!(error, InstallError::Install(ref m) if m.contains("E: broken")),
        "{error}"
    );
    // Not installed, and a failing query.
    fake(
        dir.path(),
        "dpkg-query",
        "echo 'dpkg-query: no packages found matching acme-agent' >&2; exit 1",
    );
    assert_eq!(apt.installed("acme-agent").unwrap(), None);
    fake(dir.path(), "dpkg-query", "echo broken >&2; exit 2");
    assert!(matches!(
        apt.installed("acme-agent"),
        Err(InstallError::Query(_))
    ));
}

#[test]
fn dnf_checks_the_files_own_version_then_upgrades_with_repositories_off() {
    let dir = tempfile::tempdir().unwrap();
    let tools = tools_in(dir.path());
    fake(
        dir.path(),
        "rpm",
        "case \"$1\" in -qp) echo 'acme-agent|1.1.0-2';; -q) echo '1.0.0-1';; esac",
    );
    fake(dir.path(), "dnf", "exit 0");
    let dnf = Dnf::with(tools, TransientUnit::direct(Duration::from_secs(30)));
    assert_eq!(
        dnf.installed("acme-agent").unwrap(),
        Some(release("1.0.0", 1))
    );
    let (new, old) = (release("1.1.0", 2), release("1.0.0", 1));
    let file = dir.path().join("acme-agent.rpm");
    let install = Install {
        package: "acme-agent",
        file: &file,
        signature: None,
        release: &new,
        replaces: &old,
    };
    dnf.install(&install).unwrap();
    let calls = log(dir.path(), "dnf");
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].starts_with("upgrade -y -q --disablerepo=* --setopt=install_weak_deps=False "),
        "{calls:?}"
    );
    // The file's header names another version, or another package: refused
    // before dnf runs.
    for header in [
        "acme-agent|1.0.0-1",
        "other|1.1.0-2",
        "acme-agent|1:1.1.0-2",
    ] {
        fake(
            dir.path(),
            "rpm",
            &format!("case \"$1\" in -qp) echo '{header}';; esac"),
        );
        assert!(
            matches!(dnf.install(&install), Err(InstallError::Plan { .. })),
            "{header}"
        );
    }
    assert_eq!(log(dir.path(), "dnf").len(), 1, "dnf never ran again");
    fake(
        dir.path(),
        "rpm",
        "echo 'package acme-agent is not installed'; exit 1",
    );
    assert_eq!(dnf.installed("acme-agent").unwrap(), None);
}

#[test]
fn pacman_places_the_signature_before_planning_only_when_required() {
    let dir = tempfile::tempdir().unwrap();
    let tools = tools_in(dir.path());
    // The fake pacman, like the real one, refuses even the plan without a
    // signature when the level is Required (the `required` marker), and
    // records whether a signature sat beside the file at install time.
    fake(
        dir.path(),
        "pacman",
        &format!(
            "for a; do f=\"$a\"; done\n\
             if [ -e '{dir}/required' ] && [ ! -e \"$f.sig\" ]; then echo 'error: package missing required signature' >&2; exit 1; fi\n\
             case \"$2\" in --print) echo 'acme-agent 1.1.0-2';; --noconfirm) if [ -e \"$f.sig\" ]; then echo signed >> '{dir}/result'; else echo unsigned >> '{dir}/result'; fi;; esac",
            dir = dir.path().display()
        ),
    );
    let pacman = Pacman::with(
        tools.clone(),
        TransientUnit::direct(Duration::from_secs(30)),
    );
    let (new, old) = (release("1.1.0", 2), release("1.0.0", 1));
    let file = dir.path().join("acme-agent.pkg.tar.zst");
    let signature = dir.path().join("downloaded.sig");
    std::fs::write(&signature, b"sig").unwrap();
    let install = Install {
        package: "acme-agent",
        file: &file,
        signature: Some(&signature),
        release: &new,
        replaces: &old,
    };
    // Optional (Arch's shipped LocalFileSigLevel): no signature beside it.
    fake(
        dir.path(),
        "pacman-conf",
        "printf 'SigLevel = PackageRequired\\nLocalFileSigLevel = PackageOptional\\n'",
    );
    pacman.install(&install).unwrap();
    // Required: the signature is there for the plan and the install.
    std::fs::write(dir.path().join("required"), b"").unwrap();
    fake(
        dir.path(),
        "pacman-conf",
        "printf 'SigLevel = PackageRequired\\nSigLevel = DatabaseOptional\\n'",
    );
    pacman.install(&install).unwrap();
    let result = std::fs::read_to_string(dir.path().join("result")).unwrap();
    assert_eq!(result, "unsigned\nsigned\n");
    assert!(
        !dir.path().join("acme-agent.pkg.tar.zst.sig").exists(),
        "removed afterwards"
    );
    // Required with no signature to place: the plan fails, nothing installs,
    // and nothing is left beside the file.
    let unsigned = Install {
        signature: None,
        ..install
    };
    assert!(matches!(
        pacman.install(&unsigned),
        Err(InstallError::Install(_))
    ));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("result")).unwrap(),
        "unsigned\nsigned\n"
    );
    // A plan naming anything else, or another version, installs nothing.
    std::fs::remove_file(dir.path().join("required")).unwrap();
    for plan in ["acme-agent 1.1.0-2\nlibnew 1-1", "acme-agent 1.1.0-3"] {
        fake(
            dir.path(),
            "pacman",
            &format!("printf '{}\\n'", plan.replace('\n', "\\n")),
        );
        assert!(
            matches!(pacman.install(&install), Err(InstallError::Plan { .. })),
            "{plan}"
        );
    }
    assert!(!dir.path().join("acme-agent.pkg.tar.zst.sig").exists());
    // A configuration pacman-conf refuses: nothing runs.
    fake(
        dir.path(),
        "pacman-conf",
        "echo 'error parsing' >&2; exit 1",
    );
    assert!(matches!(
        pacman.install(&install),
        Err(InstallError::Install(_))
    ));
}

#[test]
fn detection_finds_the_package_manager_that_installed_the_product() {
    let dir = tempfile::tempdir().unwrap();
    let tools = tools_in(dir.path());
    assert!(matches!(
        detect("acme-agent", &tools),
        Err(InstallError::Unsupported(_))
    ));
    fake(
        dir.path(),
        "pacman",
        "echo \"error: package '$2' was not found\" >&2; exit 1",
    );
    fake(dir.path(), "pacman-conf", "exit 0");
    fake(dir.path(), "dnf", "exit 0");
    fake(dir.path(), "rpm", "echo '1.0.0-1'");
    assert_eq!(detect("acme-agent", &tools).unwrap().name(), "dnf");
    // dpkg-query without apt-get doesn't count.
    fake(dir.path(), "dpkg-query", "echo 'ii |1.0.0-1'");
    assert_eq!(detect("acme-agent", &tools).unwrap().name(), "dnf");
    // Two package managers report it: refused.
    fake(dir.path(), "apt-get", "exit 0");
    assert!(matches!(
        detect("acme-agent", &tools),
        Err(InstallError::Unsupported(_))
    ));
    // One whose query fails is skipped: pacman's tools on a host
    // without its database.
    fake(
        dir.path(),
        "dpkg-query",
        "echo 'no packages found' >&2; exit 1",
    );
    fake(
        dir.path(),
        "pacman",
        "echo 'error: failed to initialize alpm library' >&2; exit 1",
    );
    assert_eq!(detect("acme-agent", &tools).unwrap().name(), "dnf");
    // None reports it and one failed: the failure is named.
    fake(
        dir.path(),
        "rpm",
        "echo 'package acme-agent is not installed'; exit 1",
    );
    let error = detect("acme-agent", &tools).err().unwrap();
    assert!(
        matches!(error, InstallError::Query(ref m) if m.contains("pacman")),
        "{error}"
    );
}
