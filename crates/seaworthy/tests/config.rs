//! `seaworthy.toml`: the documented example loads, and every rule refuses what
//! it should, naming the key.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use seaworthy::config::{Config, Kind, Output, UpdatePolicy, parse_duration};
use std::time::Duration;

const EXAMPLE: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v4", "x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
fips = true
maintainer = "Acme <packages@example.com>"
license = "LicenseRef-Acme-Proprietary"
homepage = "https://example.com"

[product.collector]
display-name = "Acme Forensic Collector"
description = "Collects forensic data for Acme."
launcher = "crates/acme_collector/launcher"
executable = "AcmeForensicCollector"
core = "acme_collector_core"
helper = "AcmeCollectorUpdate"
windows-directory = "Collector"
sidecars.windows = ["aws_lc_fips_*_crypto.dll", "aws_lc_fips_*_rust_wrapper.dll"]
outputs = ["msi", "zip", "deb", "rpm", "pacman", "tar"]
updates.default = "auto"

[product.collector.service]
name = "AcmeLiveResponseService"
account = "local-system"
arguments = ["service"]
restart-delays = ["15s", "60s", "300s", "900s"]
state-directory = "acme/collector"
hardening = "none"

[product.console]
display-name = "Acme Console"
description = "The Acme desktop console."
executable = "AcmeConsole"
core = "acme_console_core"
helper = "AcmeConsoleUpdate"
kind = "desktop"
windows-directory = "Console"
outputs = ["msi", "deb"]
linux.depends.deb = ["libvulkan1 | libegl1", "libxkbcommon0"]
"#;

fn edit(from: &str, to: &str) -> String {
    assert!(EXAMPLE.contains(from), "{from:?} not in the example");
    EXAMPLE.replacen(from, to, 1)
}

fn refused(text: &str, mentions: &str) {
    let err = Config::parse(text)
        .expect_err("must be refused")
        .to_string();
    assert!(err.contains(mentions), "expected {mentions:?} in: {err}");
}

/// `check` notes each msi product whose UpgradeCode is derived (an
/// existing product must pin the one its MSIs carry); a pinned code, the
/// derived one included, silences it.
#[test]
fn check_notes_msi_products_without_a_pinned_upgrade_code() {
    let config = Config::parse(EXAMPLE).unwrap();
    let notes = config.notes();
    let ids: Vec<&str> = notes.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, ["collector", "console"]);
    let derived = seaworthy::wix::upgrade_code(&config, "collector").unwrap();
    assert!(
        notes[0]
            .1
            .contains(&format!("upgrade-code = \"{derived}\"")),
        "{}",
        notes[0].1
    );
    assert!(notes[0].1.contains("Migrating an existing product"));
    let pinned = edit(
        "windows-directory = \"Collector\"",
        &format!("windows-directory = \"Collector\"\nupgrade-code = \"{derived}\""),
    );
    let notes = Config::parse(&pinned).unwrap().notes();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].0, "console");
    // No msi output, no note.
    let without = edit("outputs = [\"msi\", \"deb\"]", "outputs = [\"deb\"]");
    assert_eq!(Config::parse(&without).unwrap().notes().len(), 1);
}

#[test]
fn the_documented_example_loads() {
    let config = Config::parse(EXAMPLE).expect("valid");
    assert_eq!(
        config.defaults.targets,
        ["x86-64-v4", "x86-64-v3", "x86-64-v2"]
    );
    let collector = &config.products["collector"];
    assert_eq!(collector.kind, Kind::Service);
    assert_eq!(collector.outputs.len(), 6);
    assert!(collector.ships_helper());
    assert_eq!(collector.windows_directory(), "Collector");
    let console = &config.products["console"];
    assert_eq!(console.kind, Kind::Desktop);
    assert_eq!(console.outputs, [Output::Msi, Output::Deb]);
    assert_eq!(console.updates.default, UpdatePolicy::Auto);
    let spec = config
        .service_spec(
            "collector",
            collector,
            std::path::Path::new("/opt/acme/collector/AcmeForensicCollector"),
        )
        .expect("spec");
    assert_eq!(spec.name, "AcmeLiveResponseService");
    assert_eq!(spec.failure_policy.restart_delays.len(), 4);
    assert_eq!(spec.state_directory.as_deref(), Some("acme/collector"));
}

#[test]
fn unknown_keys_are_refused() {
    refused(
        &edit(
            "channel = \"stable\"",
            "channel = \"stable\"\nchanel = \"x\"",
        ),
        "chanel",
    );
    refused(
        &edit(
            "core = \"acme_collector_core\"",
            "core = \"acme_collector_core\"\ncores = \"x\"",
        ),
        "cores",
    );
    refused(
        &edit("state-directory", "state-dir = \"x\"\nstate-directory"),
        "state-dir",
    );
}

#[test]
fn defaults_are_validated() {
    refused(&edit("vendor = \"Acme\"", "vendor = \"Ac/me\""), "vendor");
    refused(
        &edit(
            "targets = [\"x86-64-v4\", \"x86-64-v3\", \"x86-64-v2\"]",
            "targets = []",
        ),
        "targets",
    );
    refused(
        &edit(
            "targets = [\"x86-64-v4\", \"x86-64-v3\", \"x86-64-v2\"]",
            "targets = [\"x86-64-v3\", \"x86-64-v3\"]",
        ),
        "twice",
    );
    refused(
        &edit(
            "release-signatures = [\"ml-dsa-87\"]",
            "release-signatures = []",
        ),
        "release-signatures",
    );
    refused(
        &edit(
            "release-signatures = [\"ml-dsa-87\"]",
            "release-signatures = [\"rsa\"]",
        ),
        "rsa",
    );
    refused(
        &edit("channel = \"stable\"", "channel = \"Stable!\""),
        "channel",
    );
    // every-algorithm needs at least two algorithms to mean anything.
    refused(
        &edit(
            "release-signatures = [\"ml-dsa-87\"]",
            "release-signatures = [\"ml-dsa-87\"]\nrelease-trust = \"every-algorithm\"",
        ),
        "release-trust",
    );
    refused(
        &edit(
            "release-signatures = [\"ml-dsa-87\"]",
            "release-signatures = [\"ml-dsa-87\", \"ed25519\"]\nrelease-trust = \"both\"",
        ),
        "release-trust",
    );
    refused(
        &edit(
            "maintainer = \"Acme <packages@example.com>\"",
            "maintainer = \"x\\ny\"",
        ),
        "maintainer",
    );
}

#[test]
fn products_are_validated() {
    refused(
        &EXAMPLE.replace("[product.collector", "[product.Collector"),
        "product id",
    );
    refused(
        &edit(
            "executable = \"AcmeForensicCollector\"",
            "executable = \"../evil\"",
        ),
        "executable",
    );
    refused(
        &edit(
            "core = \"acme_collector_core\"",
            "core = \"acme-collector\"",
        ),
        "core",
    );
    refused(
        &edit(
            "outputs = [\"msi\", \"zip\", \"deb\", \"rpm\", \"pacman\", \"tar\"]",
            "outputs = [\"msi\", \"msi\"]",
        ),
        "twice",
    );
    refused(
        &edit(
            "outputs = [\"msi\", \"zip\", \"deb\", \"rpm\", \"pacman\", \"tar\"]",
            "outputs = []",
        ),
        "outputs",
    );
    refused(
        &edit(
            "sidecars.windows = [\"aws_lc_fips_*_crypto.dll\"",
            "sidecars.windows = [\"../x.dll\"",
        ),
        "sidecars",
    );
    refused(
        &edit(
            "linux.depends.deb = [\"libvulkan1 | libegl1\"",
            "linux.depends.deb = [\"a, b\"",
        ),
        "depends",
    );
}

#[test]
fn the_helper_and_its_request_file_go_together() {
    refused(&edit("helper = \"AcmeCollectorUpdate\"\n", ""), "helper");
    refused(
        &edit(
            "helper = \"AcmeCollectorUpdate\"",
            "helper = \"AcmeForensicCollector\"",
        ),
        "helper",
    );
    refused(
        &edit("state-directory = \"acme/collector\"\n", ""),
        "state-directory",
    );
    // Policy off: no helper, no request file needed.
    let off = edit("helper = \"AcmeCollectorUpdate\"\n", "")
        .replacen("updates.default = \"auto\"", "updates.default = \"off\"", 1)
        .replacen("state-directory = \"acme/collector\"\n", "", 1);
    let config = Config::parse(&off).expect("valid without a helper");
    assert!(!config.products["collector"].ships_helper());
}

#[test]
fn kinds_and_services_go_together() {
    refused(
        &edit("[product.collector.service]", "[product.collector.unused]"),
        "unused",
    );
    let no_service = edit("kind = \"desktop\"", "kind = \"service\"");
    refused(&no_service, "service");
    let desktop_with_service = edit(
        "[product.collector]",
        "[product.collector]\nkind = \"tool\"",
    );
    refused(&desktop_with_service, "only kind = \"service\"");
}

#[test]
fn services_are_validated_by_the_renderers() {
    // seaworthy_service::render's own rules: systemd's unit-name alphabet…
    refused(
        &edit(
            "name = \"AcmeLiveResponseService\"",
            "name = \"Live@Response\"",
        ),
        "service",
    );
    // …MSI's bracket rule…
    refused(
        &edit(
            "arguments = [\"service\"]",
            "arguments = [\"[INSTALLDIR]\"]",
        ),
        "service",
    );
    // …and the state-directory grammar.
    refused(
        &edit(
            "state-directory = \"acme/collector\"",
            "state-directory = \"../etc\"",
        ),
        "service",
    );
    refused(
        &edit(
            "restart-delays = [\"15s\", \"60s\", \"300s\", \"900s\"]",
            "restart-delays = [\"500ms\"]",
        ),
        "service",
    );
    refused(
        &edit(
            "restart-delays = [\"15s\", \"60s\", \"300s\", \"900s\"]",
            "restart-delays = [\"soon\"]",
        ),
        "duration",
    );
}

/// A service that must read the whole host starts from `none` and turns
/// back on what it can keep, directive by directive (a forensic
/// collector); a preset name still works, a typo or a bad family is refused.
#[test]
fn hardening_is_a_preset_or_a_table_changing_one() {
    let spec = |text: &str| {
        let config = Config::parse(text).expect("valid");
        config
            .service_spec(
                "collector",
                &config.products["collector"],
                std::path::Path::new("/opt/acme/collector/AcmeForensicCollector"),
            )
            .expect("spec")
            .systemd_hardening
    };
    let none = spec(EXAMPLE);
    assert!(!none.no_new_privileges && !none.protect_home);
    let all = spec(&edit("hardening = \"none\"\n", ""));
    assert!(all.no_new_privileges && all.protect_home && all.protect_system_strict);
    let table = edit(
        "hardening = \"none\"\n",
        "[product.collector.service.hardening]\n\
         preset = \"none\"\n\
         no-new-privileges = true\n\
         protect-kernel-tunables = true\n\
         memory-deny-write-execute = true\n\
         restrict-address-families = true\n\
         extra-address-families = [\"AF_NETLINK\"]\n",
    );
    let tuned = spec(&table);
    assert!(tuned.no_new_privileges && tuned.protect_kernel_tunables);
    assert!(tuned.memory_deny_write_execute && tuned.restrict_address_families);
    assert!(!tuned.protect_home && !tuned.private_tmp && !tuned.protect_system_strict);
    assert_eq!(tuned.extra_address_families, ["AF_NETLINK"]);
    // From the default preset, a directive turned off.
    let relaxed = spec(&edit(
        "hardening = \"none\"\n",
        "hardening = { protect-home = false }\n",
    ));
    assert!(!relaxed.protect_home && relaxed.protect_system_strict);
    refused(
        &edit("hardening = \"none\"", "hardening = \"strict\""),
        "unknown variant",
    );
    refused(
        &edit(
            "hardening = \"none\"",
            "hardening = { protect-hme = false }",
        ),
        "unknown field `protect-hme`",
    );
    refused(
        &edit(
            "hardening = \"none\"",
            "hardening = { extra-address-families = [\"netlink\"] }",
        ),
        "not a valid address family",
    );
    // A setting the renderer would drop is refused, not ignored.
    refused(
        &edit(
            "hardening = \"none\"",
            "hardening = { preset = \"none\", extra-address-families = [\"AF_NETLINK\"] }",
        ),
        "extra-address-families needs restrict-address-families",
    );
    refused(
        &edit(
            "hardening = \"none\"",
            "hardening = { preset = \"none\", read-write-paths = [\"/var/log/x\"] }",
        ),
        "read-write-paths needs protect-system-strict",
    );
}

#[test]
fn durations_parse() {
    assert_eq!(parse_duration("15s").unwrap(), Duration::from_secs(15));
    assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86_400));
    assert_eq!(parse_duration("2d").unwrap(), Duration::from_secs(172_800));
    assert_eq!(
        parse_duration("1500ms").unwrap(),
        Duration::from_millis(1500)
    );
    for bad in [
        "",
        "s",
        "15",
        "15 s",
        "1.5s",
        "-1s",
        "015s",
        "15sec",
        "18446744073709551615d",
    ] {
        assert!(parse_duration(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn products_may_not_collide() {
    // The console takes the collector's Windows directory…
    refused(
        &edit(
            "windows-directory = \"Console\"",
            "windows-directory = \"collector\"",
        ),
        "share windows-directory",
    );
    // …or, as a second service, its service name (case-insensitively).
    let second = format!(
        "{EXAMPLE}\n[product.agent]\ndisplay-name = \"Acme Agent\"\ndescription = \"x\"\nexecutable = \"Agent\"\ncore = \"agent_core\"\noutputs = [\"tar\"]\nupdates.default = \"off\"\n\n[product.agent.service]\nname = \"acmeliveresponseservice\"\naccount = \"local-system\"\n"
    );
    refused(&second, "share service.name");
}

#[test]
fn windows_device_names_and_case_clashes_are_refused() {
    for name in ["CON", "nul", "Com1", "LPT9", "aux", "Tool."] {
        refused(
            &edit(
                "executable = \"AcmeForensicCollector\"",
                &format!("executable = \"{name}\""),
            ),
            "executable",
        );
    }
    refused(&edit("vendor = \"Acme\"", "vendor = \"PRN\""), "vendor");
    refused(
        &edit(
            "helper = \"AcmeCollectorUpdate\"",
            "helper = \"acmeforensiccollector\"",
        ),
        "case-insensitively",
    );
}

#[test]
fn metadata_is_validated() {
    refused(
        &edit(
            "homepage = \"https://example.com\"",
            "homepage = \"https://x\\nEvil: y\"",
        ),
        "homepage",
    );
    refused(
        &edit(
            "homepage = \"https://example.com\"",
            "homepage = \"ftp://x\"",
        ),
        "homepage",
    );
    refused(
        &edit(
            "homepage = \"https://example.com\"",
            "homepage = \"https://a b\"",
        ),
        "homepage",
    );
    refused(
        &edit(
            "release-signatures = [\"ml-dsa-87\"]",
            "release-signatures = [\"ml-dsa-87\", \"ml-dsa-87\"]",
        ),
        "twice",
    );
    // A library beyond the base system needs its package in every Linux format.
    refused(
        &edit(
            "linux.depends.deb = [\"libvulkan1 | libegl1\", \"libxkbcommon0\"]",
            "linux.needed = [\"libvulkan.so.1\"]",
        ),
        "linux.depends",
    );
    let declared = edit(
        "linux.depends.deb = [\"libvulkan1 | libegl1\", \"libxkbcommon0\"]",
        "linux.depends.deb = [\"libvulkan1\"]\nlinux.needed = [\"libvulkan.so.1\"]",
    );
    Config::parse(&declared)
        .expect("needed with the deb dependency declared (the console ships msi and deb only)");
}

#[test]
fn a_linux_unit_runs_as_root_only_by_choice() {
    // A less privileged Windows account without a sandbox would be a root unit.
    for account in ["virtual", "local-service", "network-service"] {
        refused(
            &edit(
                "account = \"local-system\"",
                &format!("account = \"{account}\""),
            ),
            "sandbox",
        );
    }
    // With a sandbox user it validates.
    let sandboxed = edit(
        "account = \"local-system\"",
        "account = \"virtual\"\nsandbox = { user = \"acme-collector\" }",
    );
    Config::parse(&sandboxed).expect("a virtual account with a sandbox user");
    // LocalSystem (root under systemd) plus a sandbox contradicts itself.
    refused(
        &edit(
            "account = \"local-system\"",
            "account = \"local-system\"\nsandbox = { user = \"acme-collector\" }",
        ),
        "contradicts",
    );
}

#[test]
fn text_that_reaches_package_metadata_has_no_dollar() {
    // nFPM expands $VAR in metadata, with no escape.
    for (from, to) in [
        (
            "description = \"Collects forensic data for Acme.\"",
            "description = \"Pay $5 now\"",
        ),
        (
            "display-name = \"Acme Forensic Collector\"",
            "display-name = \"Tensor${HOME}Guard\"",
        ),
        (
            "maintainer = \"Acme <packages@example.com>\"",
            "maintainer = \"$CI_USER <x@y.z>\"",
        ),
        (
            "license = \"LicenseRef-Acme-Proprietary\"",
            "license = \"$LICENSE\"",
        ),
        (
            "homepage = \"https://example.com\"",
            "homepage = \"https://example.com/$TOKEN\"",
        ),
        (
            "linux.depends.deb = [\"libvulkan1 | libegl1\", \"libxkbcommon0\"]",
            "linux.depends.deb = [\"lib$X\"]",
        ),
    ] {
        let err = Config::parse(&edit(from, to)).expect_err(to).to_string();
        assert!(err.contains('$'), "{to}: {err}");
    }
}

#[test]
fn names_have_length_limits() {
    let long = "x".repeat(201);
    refused(
        &edit(
            "display-name = \"Acme Forensic Collector\"",
            &format!("display-name = \"{long}\""),
        ),
        "at most 200",
    );
}

#[test]
fn names_a_release_manifest_refuses_are_refused_at_load() {
    // The manifest's product (`<vendor>-<id>`) and channel are
    // 1-64 characters with no "..": a config that loads can be signed.
    refused(
        &edit(
            "channel = \"stable\"",
            &format!("channel = \"{}\"", "c".repeat(65)),
        ),
        "at most 64",
    );
    refused(
        &edit("vendor = \"Acme\"", "vendor = \"Tensor..Guard\""),
        "\"..\"",
    );
    let long_vendor = "V".repeat(60);
    refused(
        &edit("vendor = \"Acme\"", &format!("vendor = \"{long_vendor}\"")),
        "at most 64 characters",
    );
}

/// The update helper reads its names from the same `seaworthy.toml` with
/// `seaworthy_updater::Product::from_config`, which parses only the settings
/// that name things. Both readings must agree, or the helper would look for
/// manifests, a request file or a cache directory the packages don't use.
#[test]
fn release_manifests_are_optional_only_without_an_update_helper() {
    // Products that ship no update helper (updates off) may sign no
    // release manifests; their packages keep their own signatures.
    let no_helpers = EXAMPLE
        .replacen("release-signatures = [\"ml-dsa-87\"]\n", "", 1)
        .replacen("helper = \"AcmeCollectorUpdate\"\n", "", 1)
        .replacen("updates.default = \"auto\"", "updates.default = \"off\"", 1)
        .replacen(
            "helper = \"AcmeConsoleUpdate\"\n",
            "updates.default = \"off\"\n",
            1,
        );
    let config = Config::parse(&no_helpers).unwrap();
    assert!(config.defaults.release_signatures.is_empty());
    assert!(!config.signs_manifests());
    // An explicitly empty list is the same.
    let explicit = no_helpers.replacen(
        "channel = \"stable\"\n",
        "channel = \"stable\"\nrelease-signatures = []\n",
        1,
    );
    assert!(!Config::parse(&explicit).unwrap().signs_manifests());
    assert!(Config::parse(EXAMPLE).unwrap().signs_manifests());
    // A helper installs only what a signed manifest vouches for.
    refused(
        &EXAMPLE.replacen("release-signatures = [\"ml-dsa-87\"]\n", "", 1),
        "product.collector.helper: an update helper installs only releases whose signed manifest it verifies",
    );
    // Trusted keys with nothing to sign: a leftover, refused by name.
    refused(
        &no_helpers.replacen(
            "channel = \"stable\"\n",
            "channel = \"stable\"\nrelease-keys = [{ algorithm = \"ml-dsa-87\", public-key = \"release.pub\" }]\n",
            1,
        ),
        "defaults.release-keys lists keys, but defaults.release-signatures is empty",
    );
}

const DESKTOP: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3"]
channel = "stable"
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[product.viewer]
display-name = "Acme Viewer"
description = "Views things."
executable = "AcmeViewer"
core = "viewer_core"
kind = "desktop"
windows-directory = "Viewer"
outputs = ["msi", "deb", "tar"]
updates.default = "off"
linux.command = "acme-viewer"

[product.viewer.desktop]
linux-icons = ["icons/viewer.png", "icons/viewer.svg"]
windows-icon = "icons/viewer.ico"
categories = ["Office"]
keywords = ["view"]
wm-class = "AcmeViewer"

[[product.viewer.files]]
source = "assets"
destination = "share/assets"
"#;

fn desktop_edit(from: &str, to: &str) -> String {
    assert!(
        DESKTOP.contains(from),
        "{from:?} not in the desktop example"
    );
    DESKTOP.replacen(from, to, 1)
}

#[test]
fn desktop_entries_data_files_and_commands_are_validated() {
    let config = Config::parse(DESKTOP).unwrap();
    let viewer = &config.products["viewer"];
    let desktop = viewer.desktop.as_ref().unwrap();
    assert!(desktop.start_menu && !desktop.desktop_shortcut);
    assert_eq!(desktop.app_id(&config, "viewer"), "acme-viewer");
    assert_eq!(viewer.files[0].destination(), "share/assets");
    // Every platform by default: Linux, Windows and macOS.
    assert_eq!(viewer.files[0].platforms.len(), 3);
    assert_eq!(viewer.linux.command.as_deref(), Some("acme-viewer"));
    assert!(viewer.linux.replaces.is_empty());
    let replacing = Config::parse(&desktop_edit(
        "linux.command = \"acme-viewer\"",
        "linux.command = \"acme-viewer\"\nlinux.replaces = [\"viewer-bin\", \"acme-viewer-legacy\"]",
    ))
    .unwrap();
    assert_eq!(
        replacing.products["viewer"].linux.replaces,
        ["viewer-bin", "acme-viewer-legacy"]
    );
    // Defaults: a Start-menu shortcut, Utility, the source's own name.
    let minimal = Config::parse(&desktop_edit("categories = [\"Office\"]\n", "").replacen(
        "destination = \"share/assets\"\n",
        "",
        1,
    ))
    .unwrap();
    assert_eq!(
        minimal.products["viewer"]
            .desktop
            .as_ref()
            .unwrap()
            .categories,
        ["Utility"]
    );
    assert_eq!(minimal.products["viewer"].files[0].destination(), "assets");

    for (from, to, mentions) in [
        (
            "kind = \"desktop\"",
            "kind = \"tool\"",
            "product.viewer.desktop: only a desktop app",
        ),
        (
            "wm-class = \"AcmeViewer\"",
            "app-id = \"acme..viewer\"",
            "product.viewer.desktop.app-id",
        ),
        (
            "\"icons/viewer.png\"",
            "\"icons/viewer.jpg\"",
            "product.viewer.desktop.linux-icons: icons/viewer.jpg must be a .png or .svg",
        ),
        (
            "\"icons/viewer.png\"",
            "\"../viewer.png\"",
            "must be a .png or .svg path relative to seaworthy.toml",
        ),
        (
            "\"icons/viewer.png\"",
            "\"icons/other.svg\"",
            "at most one SVG",
        ),
        (
            "windows-icon = \"icons/viewer.ico\"",
            "windows-icon = \"/etc/viewer.ico\"",
            "product.viewer.desktop.windows-icon",
        ),
        (
            "windows-icon = \"icons/viewer.ico\"",
            "windows-icon = \"icons/viewer.png\"",
            "must be a .ico path",
        ),
        (
            "display-name = \"Acme Viewer\"",
            "display-name = \"Acme: Viewer\"",
            "product.viewer.display-name: names the MSI's shortcuts",
        ),
        (
            "categories = [\"Office\"]",
            "categories = [\"Viewer\"]",
            "needs one of the freedesktop main categories",
        ),
        (
            "categories = [\"Office\"]",
            "categories = [\"Office\", \"Office\"]",
            "listed once",
        ),
        (
            "categories = [\"Office\"]",
            "categories = [\"Office;Game\"]",
            "must be a category name",
        ),
        (
            "keywords = [\"view\"]",
            "keywords = [\"view;edit\"]",
            "product.viewer.desktop.keywords",
        ),
        (
            "wm-class = \"AcmeViewer\"",
            "wm-class = \"Acme Viewer\"",
            "product.viewer.desktop.wm-class",
        ),
        (
            "linux.command = \"acme-viewer\"",
            "linux.command = \"Acme-Viewer\"",
            "product.viewer.linux.command: a command name",
        ),
        (
            "outputs = [\"msi\", \"deb\", \"tar\"]",
            "outputs = [\"msi\", \"tar\"]",
            "only a Linux package (deb, rpm, pacman) installs /usr/bin links",
        ),
        (
            "linux.command = \"acme-viewer\"",
            "linux.replaces = [\"Acme-Viewer\"]",
            "product.viewer.linux.replaces: \"Acme-Viewer\" isn't a package name",
        ),
        (
            "linux.command = \"acme-viewer\"",
            "linux.replaces = [\"viewer-bin\", \"viewer-bin\"]",
            "product.viewer.linux.replaces: \"viewer-bin\" is listed twice",
        ),
        (
            "linux.command = \"acme-viewer\"",
            "linux.replaces = [\"acme-viewer\"]",
            "product.viewer.linux.replaces: \"acme-viewer\" is a package this seaworthy.toml builds",
        ),
        (
            "outputs = [\"msi\", \"deb\", \"tar\"]\nupdates.default = \"off\"\nlinux.command = \"acme-viewer\"",
            "outputs = [\"msi\", \"tar\"]\nupdates.default = \"off\"\nlinux.replaces = [\"viewer-bin\"]",
            "product.viewer.linux.replaces: only a Linux package",
        ),
        (
            "source = \"assets\"",
            "source = \"../assets\"",
            "product.viewer.files[0].source",
        ),
        (
            "source = \"assets\"",
            "source = \"/srv/assets\"",
            "product.viewer.files[0].source",
        ),
        (
            "destination = \"share/assets\"",
            "destination = \"share/../etc\"",
            "product.viewer.files[0].destination",
        ),
        (
            "destination = \"share/assets\"",
            "destination = \"/etc/assets\"",
            "product.viewer.files[0].destination",
        ),
        (
            "destination = \"share/assets\"",
            "destination = \"share/NUL\"",
            "product.viewer.files[0].destination",
        ),
        (
            "destination = \"share/assets\"",
            "destination = \"share/$HOME\"",
            "product.viewer.files[0].destination",
        ),
        (
            "destination = \"share/assets\"",
            "destination = \"share\\\\assets\"",
            "product.viewer.files[0].destination",
        ),
        (
            "destination = \"share/assets\"",
            "destination = \"share/assets\"\nplatforms = []",
            "product.viewer.files[0].platforms",
        ),
        (
            "destination = \"share/assets\"",
            "destination = \"share/assets\"\nplatforms = [\"linux\", \"linux\"]",
            "product.viewer.files[0].platforms",
        ),
        (
            "destination = \"share/assets\"",
            "destination = \"share/assets\"\nplatforms = [\"linux\", \"windows\", \"linux\"]",
            "product.viewer.files[0].platforms",
        ),
        (
            "destination = \"share/assets\"",
            "destination = \"share/VIEWER~1.DLL\"",
            "product.viewer.files[0].destination",
        ),
        (
            "destination = \"share/assets\"",
            "destination = \"share/a!(b)\"",
            "product.viewer.files[0].destination",
        ),
        (
            "source = \"assets\"",
            "source = \"assets/.git\"",
            "no version control directory",
        ),
        (
            "categories = [\"Office\"]",
            "categories = [\"Audio\"]",
            "Audio and Video each need AudioVideo",
        ),
        (
            "display-name = \"Acme Viewer\"",
            "display-name = \"Acme Viewer With A Name So Long That No Start Menu Could Ever Show It Whole, Which Windows Then Truncates Anyway\"",
            "run past 100 characters",
        ),
    ] {
        refused(&desktop_edit(from, to), mentions);
    }
    // Without the MSI the shortcut name may hold what Windows refuses.
    Config::parse(
        &desktop_edit(
            "display-name = \"Acme Viewer\"",
            "display-name = \"Acme: Viewer\"",
        )
        .replacen(
            "outputs = [\"msi\", \"deb\", \"tar\"]",
            "outputs = [\"deb\"]",
            1,
        ),
    )
    .unwrap();
    // Two products can't share a command or a menu entry id.
    let twice = format!(
        "{DESKTOP}\n[product.other]\ndisplay-name = \"Acme Other\"\ndescription = \"x\"\nexecutable = \"AcmeOther\"\ncore = \"other_core\"\nkind = \"desktop\"\noutputs = [\"deb\"]\nupdates.default = \"off\"\nlinux.command = \"acme-viewer\"\n"
    );
    refused(&twice, "share linux.command \"acme-viewer\"");
    let twice = format!(
        "{DESKTOP}\n[product.other]\ndisplay-name = \"Acme Other\"\ndescription = \"x\"\nexecutable = \"AcmeOther\"\ncore = \"other_core\"\nkind = \"desktop\"\noutputs = [\"deb\"]\nupdates.default = \"off\"\n\n[product.other.desktop]\napp-id = \"Acme-Viewer\"\n"
    );
    refused(&twice, "share desktop.app-id \"acme-viewer\"");
    // Nor a shortcut name: one uninstall would delete the other's shortcut.
    let twice = format!(
        "{DESKTOP}\n[product.other]\ndisplay-name = \"ACME VIEWER\"\ndescription = \"x\"\nexecutable = \"AcmeOther\"\ncore = \"other_core\"\nkind = \"desktop\"\nwindows-directory = \"Other\"\noutputs = [\"msi\"]\nupdates.default = \"off\"\n\n[product.other.desktop]\napp-id = \"acme-other\"\n"
    );
    refused(
        &twice,
        "share display-name (the MSI's shortcut) \"acme viewer\"",
    );
    // Audio and Video with AudioVideo are fine.
    Config::parse(&desktop_edit(
        "categories = [\"Office\"]",
        "categories = [\"AudioVideo\", \"Video\"]",
    ))
    .unwrap();
}

#[test]
fn the_helper_reads_the_same_names_from_config() {
    let variants = [
        EXAMPLE.to_owned(),
        // The Windows directory's default: the display name's last word.
        edit("windows-directory = \"Collector\"\n", "").replace(
            "outputs = [\"msi\", \"zip\", \"deb\", \"rpm\", \"pacman\", \"tar\"]",
            "outputs = [\"deb\"]",
        ),
        edit("updates.default = \"auto\"", "updates.default = \"notify\""),
        // The hybrid policy reaches the helper's names.
        edit(
            "release-signatures = [\"ml-dsa-87\"]",
            "release-signatures = [\"ml-dsa-87\", \"ed25519\"]\nrelease-trust = \"every-algorithm\"",
        ),
        // A macOS product: its bundle id is the package's identifier.
        EXAMPLE.to_owned()
            + "\n[product.viewer]\ndisplay-name = \"Acme Viewer\"\ndescription = \"Views.\"\n\
               executable = \"AcmeViewer\"\ncore = \"acme_viewer\"\nkind = \"desktop\"\n\
               outputs = [\"dmg\"]\nupdates.default = \"off\"\n\
               sidecars.macos = [\"libaws_lc_fips_*_crypto.dylib\"]\n\n\
               [product.viewer.macos]\nbundle-id = \"com.acme.viewer\"\n",
    ];
    for text in variants {
        let config = Config::parse(&text).expect("valid");
        for (id, product) in &config.products {
            let packaged = config.update_product(id, product).expect("names");
            let helper = seaworthy_updater::Product::from_config(&text, id).expect("names");
            assert_eq!(packaged, helper, "{id}");
            assert_eq!(
                packaged.macos_package_id(),
                product.macos.as_ref().map(|m| m.bundle_id.as_str()),
                "{id}"
            );
            assert_eq!(
                packaged.package(),
                seaworthy::linux::package_name(&config, id)
            );
            assert_eq!(packaged.windows_directory(), product.windows_directory());
            assert_eq!(packaged.default_policy(), product.updates.default);
            assert_eq!(packaged.release_trust(), config.defaults.release_trust);
            // The Group Policy template writes the key the helper reads.
            let template = seaworthy::admx::template(
                &config.defaults.vendor,
                &product.windows_directory(),
                &product.display_name,
            );
            assert!(
                template
                    .admx
                    .contains(&format!("key=\"{}\"", packaged.policy_key())),
                "{id}: {}",
                template.admx
            );
            if product.service.is_some() {
                let spec = config
                    .service_spec(id, product, std::path::Path::new("/opt/x/x"))
                    .expect("spec");
                assert_eq!(
                    packaged.helper_service(),
                    Some(format!("{}-update", spec.name))
                );
                if let Some(state) = &spec.state_directory {
                    assert_eq!(
                        packaged.request_file(),
                        Some(
                            std::path::Path::new("/var/lib")
                                .join(state)
                                .join(seaworthy_service::render::systemd::UPDATE_REQUEST_FILE)
                        )
                    );
                }
            }
        }
    }
    assert_eq!(
        seaworthy_updater::UPDATE_REQUEST_FILE,
        seaworthy_service::render::systemd::UPDATE_REQUEST_FILE
    );
}

/// OpenPGP keys are read at load: the update helper compiles the same
/// files in, and only armored public key blocks are accepted.
#[test]
fn openpgp_keys_must_be_armored_public_keys_at_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let text = edit(
        "channel = \"stable\"\n",
        "channel = \"stable\"\nopenpgp-keys = [\"key.pgp\"]\n",
    );
    std::fs::write(dir.path().join("seaworthy.toml"), &text).expect("write");
    // Missing.
    assert!(Config::load(&dir.path().join("seaworthy.toml")).is_err());
    // Binary (an old-format public key packet header), then a private key.
    for key in [
        vec![0x99_u8, 0x01, 0x0d, 0x04],
        b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQ\n-----END PGP PRIVATE KEY BLOCK-----\n"
            .to_vec(),
    ] {
        std::fs::write(dir.path().join("key.pgp"), key).expect("write");
        let err = Config::load(&dir.path().join("seaworthy.toml"))
            .expect_err("refused")
            .to_string();
        assert!(err.contains("openpgp-keys"), "{err}");
    }
    std::fs::write(
        dir.path().join("key.pgp"),
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQ\n-----END PGP PUBLIC KEY BLOCK-----\n",
    )
    .expect("write");
    assert!(Config::load(&dir.path().join("seaworthy.toml")).is_ok());
}

/// The example with `[defaults.repository]` (`url`, a TOML literal
/// string), with or without a pinned OpenPGP key.
fn with_repository(url: &str, keys: bool) -> String {
    let pinned = if keys {
        "openpgp-keys = [\"repo.asc\"]\n"
    } else {
        ""
    };
    let mut text = edit(
        "homepage = \"https://example.com\"\n",
        &format!("homepage = \"https://example.com\"\n{pinned}"),
    );
    text.push_str(&format!("\n[defaults.repository]\nurl = '{url}'\n"));
    text
}

#[test]
fn the_repository_settings_are_validated() {
    // The URL the repository package points machines at.
    let url = "https://files.example.com/packages";
    let config = Config::parse(&with_repository(url, true)).unwrap();
    assert_eq!(
        config.defaults.repository.as_ref().map(|r| r.url.as_str()),
        Some(url)
    );
    assert_eq!(
        config.repository_package().as_deref(),
        Some("acme-repository")
    );
    assert_eq!(Config::parse(EXAMPLE).unwrap().repository_package(), None);
    // http only to loopback (the conformance lane's server).
    for loopback in [
        "http://127.0.0.1:8470/repo",
        "http://localhost/repo",
        "http://[::1]:8080/repo",
        "https://files.example.com",
        "https://files.example.com:8443/packages",
    ] {
        Config::parse(&with_repository(loopback, true)).unwrap();
    }
    for bad in [
        "http://files.example.com/packages",
        "http://10.0.0.1/packages",
        "https://files.example.com/packages/",
        "https://user:secret@files.example.com/packages",
        "https://user@files.example.com/packages",
        "https://files.example.com/packages?x=1",
        "https://files.example.com/packages#top",
        "https://files.example.com/$basearch",
        "https://files.example.com/a b",
        "https://files.example.com/a\"b",
        "https://files.example.com/a\\b",
        "ftp://files.example.com/packages",
        "files.example.com/packages",
        "",
        // Not as a parser writes them back: apt reads the text.
        "https:files.example.com/packages",
        "https:/files.example.com/packages",
        "https:///files.example.com/packages",
        "https://Files.Example.com/packages",
        "https://files.example.com:443/packages",
        "https://files.example.com:0/packages",
        // Characters a definition reads specially: dnf splits at commas.
        "https://files.example.com/a,b",
        "https://files.example.com/a%20b",
        "https://files.example.com/a`b",
        "https://files.example.com/a{b}",
        "https://files.example.com/a|b",
    ] {
        refused(&with_repository(bad, true), "defaults.repository.url");
    }
    // Its name is every release manifest's product: at most 64 characters.
    refused(
        &with_repository(url, true).replacen(
            "vendor = \"Acme\"",
            &format!("vendor = \"{}\"", "V".repeat(54)),
            1,
        ),
        "the repository package's name",
    );
    // The package ships the pinned keys: there must be one.
    refused(
        &with_repository(url, false),
        "defaults.repository needs defaults.openpgp-keys",
    );
    // The package's listing takes the id `repository`.
    refused(
        &with_repository(url, true).replacen("[product.console]", "[product.repository]", 1),
        "product.repository: the id is the repository package's",
    );
    // Nothing to set up without a deb or an rpm.
    refused(
        &with_repository(url, true)
            .replacen(
                "outputs = [\"msi\", \"zip\", \"deb\", \"rpm\", \"pacman\", \"tar\"]",
                "outputs = [\"msi\", \"zip\", \"pacman\", \"tar\"]",
                1,
            )
            .replacen("outputs = [\"msi\", \"deb\"]", "outputs = [\"msi\"]", 1)
            .replacen(
                "linux.depends.deb = [\"libvulkan1 | libegl1\", \"libxkbcommon0\"]\n",
                "",
                1,
            ),
        "no product builds a deb or an rpm",
    );
    // Unknown keys.
    refused(
        &with_repository(url, true).replacen(
            &format!("url = '{url}'"),
            &format!("url = '{url}'\nmirror = true"),
            1,
        ),
        "unknown field `mirror`",
    );
}
