//! Step 4 for Windows: the `.wxs`, the MSI WiX builds from it, the Group
//! Policy templates, UpgradeCodes, and the `seaworthy.toml` rules an MSI needs.
//!
//! - Golden `.wxs` files for a virtual-account service with the helper, a
//!   LocalSystem service whose display name carries every character that
//!   means something to XML, WiX or a comment, and a desktop product;
//!   `xmllint` checks each is well formed.
//! - The MSI, when `SEAWORTHY_WIX` names WiX (or a wrapper running it
//!   under Wine): built by `seaworthy package`, and its tables read back
//!   with msitools' `msiinfo`, row by row: the service tables, the recovery
//!   custom actions and their conditions, every `MsiLockPermissionsEx`
//!   descriptor and the object it's bound to, the upgrade and registry
//!   rows, the secure properties, and every file's hash against the
//!   staged file it must come from. CI builds MSIs on the Windows runner,
//!   where ICE validation and the install behaviour are tested.
//!
//! A missing tool is skipped loudly, unless
//! `SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1` turns the skip into a failure.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{artifact, build, golden, have, layout_for, layouts, nfpm, release, run};
use seaworthy::config::Config;
use seaworthy::inputs::{LINUX, WINDOWS};
use seaworthy::package::Kind;

const DEFAULTS: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
maintainer = "Acme Packaging <pkg@acme.test>"
license = "MIT"
homepage = "https://acme.test"
"#;

const AGENT: &str = r#"
[product.agent]
display-name = "Acme Agent"
description = "Collects things for Acme."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
windows-directory = "Agent"
sidecars.windows = ["extra_*.dll"]
outputs = ["msi", "zip"]

[product.agent.service]
name = "AcmeAgent"
account = "virtual"
arguments = ["service", "--mode", "full scan"]
restart-delays = ["15s", "60s"]
state-directory = "acme/agent"

[product.agent.service.sandbox]
user = "acme-agent"
"#;

/// LocalSystem, like the collector, with a display name that means
/// something to XML (`&`, `"`, `<`), to WiX (`!(bind.…)`) and to an XML
/// comment (`---`).
const COLLECTOR: &str = r#"
[product.collector]
display-name = "Acme & Co \"Field\" <Collector> !(bind.secret) --- Edition"
description = "Collects <everything> for Acme & Co."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
windows-directory = "Collector"
sidecars.windows = ["extra_*.dll"]
outputs = ["msi"]

[product.collector.service]
name = "AcmeCollector"
account = "local-system"
arguments = ["service"]
restart-delays = ["15s", "60s", "300s", "900s"]
state-directory = "acme/collector"
"#;

const CONSOLE: &str = r#"
[product.console]
display-name = "Acme Console"
description = "The Acme console."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
kind = "desktop"
windows-directory = "Console"
sidecars.windows = ["extra_*.dll"]
outputs = ["msi"]
updates.default = "notify"
upgrade-code = "{0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b}"
"#;

fn config(product: &str) -> Config {
    Config::parse(&format!("{DEFAULTS}{product}")).unwrap()
}

fn xmllint(text: &str) {
    if have("xmllint", &["--version"]) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("doc.xml");
        std::fs::write(&path, text).unwrap();
        run(Command::new("xmllint").arg("--noout").arg(&path));
    }
}

#[test]
fn the_wxs_matches_its_golden_file() {
    for (product, id) in [
        (AGENT, "agent"),
        (COLLECTOR, "collector"),
        (CONSOLE, "console"),
    ] {
        let config = config(product);
        let tmp = tempfile::tempdir().unwrap();
        let layouts = layouts(&config, id, tmp.path());
        let wxs =
            seaworthy::wix::wxs(&config, id, layout_for(&layouts, WINDOWS), &release()).unwrap();
        golden(&format!("wix/{id}.wxs"), &wxs);
        xmllint(&wxs);
    }
}

#[test]
fn only_a_desktop_products_helper_service_lets_interactive_users_start_it() {
    // The console's helper is `<package>-update`, startable and
    // queryable by interactive users, nothing more; a service
    // product's helper grants the service's account; a tool's helper ships
    // as a file only.
    let iu = "(A;;CCLCSWRPLORC;;;IU)";
    let wxs_of = |product: &str, id: &str| {
        let config = config(product);
        let tmp = tempfile::tempdir().unwrap();
        let layouts = layouts(&config, id, tmp.path());
        seaworthy::wix::wxs(&config, id, layout_for(&layouts, WINDOWS), &release()).unwrap()
    };
    let console = wxs_of(CONSOLE, "console");
    assert!(
        console.contains("<ServiceInstall Id=\"HelperService\" Name=\"acme-console-update\"")
            && console.contains("Start=\"demand\"")
            && console.contains("Account=\"LocalSystem\">"),
        "{console}"
    );
    assert_eq!(
        console.matches(iu).count(),
        2,
        "the helper's DACL, and the rollback that puts it back: {console}"
    );
    assert!(
        !console.contains("Id=\"Service\""),
        "a desktop product has no service"
    );
    let agent = wxs_of(AGENT, "agent");
    assert!(agent.contains("Name=\"AcmeAgent-update\""), "{agent}");
    assert!(
        !agent.contains(iu),
        "a service product's helper grants its account only"
    );
    let tool = wxs_of(
        &CONSOLE.replace("kind = \"desktop\"", "kind = \"tool\""),
        "console",
    );
    assert!(!tool.contains("<ServiceInstall"), "{tool}");
    assert!(!tool.contains(iu), "{tool}");
}

#[test]
fn the_programdata_folders_are_made_by_the_launchers_guard() {
    // %ProgramData%\<Vendor>\<Directory> and its folders: no CreateFolder
    // (which follows a junction a user planted), but the installed
    // launcher as SYSTEM, after InstallFiles, on a first install or an
    // upgrade, with each folder's descriptor.
    let wxs_of = |product: &str, id: &str| {
        let config = config(product);
        let tmp = tempfile::tempdir().unwrap();
        let layouts = layouts(&config, id, tmp.path());
        seaworthy::wix::wxs(&config, id, layout_for(&layouts, WINDOWS), &release()).unwrap()
    };
    let command_of = |wxs: &str| -> Vec<String> {
        let line = wxs
            .lines()
            .find(|l| l.contains("<CustomAction Id=\"ProgramDataFolders\""))
            .unwrap_or_else(|| {
                panic!(
                    "no guard in {:#?}",
                    common::wxs_lines(wxs, &["<CustomAction "])
                )
            });
        assert!(
            line.contains("Execute=\"deferred\" Impersonate=\"no\" Return=\"check\""),
            "{line}"
        );
        let start = line.find("ExeCommand=\"").unwrap() + 12;
        line[start..start + line[start..].find('"').unwrap()]
            .split(' ')
            .map(str::to_owned)
            .collect()
    };
    let sid = seaworthy_service::render::windows::virtual_account_sid("AcmeAgent").unwrap();
    let agent = wxs_of(AGENT, "agent");
    let command = command_of(&agent);
    assert_eq!(
        command,
        [
            seaworthy::wix::PROGRAMDATA_ARGUMENT,
            "Acme",
            "Agent",
            sid.as_str(),
            "state:account",
            "logs:account",
            "updates",
            "update-logs",
        ]
    );
    // Within the CustomAction target column's 255 characters.
    assert!(command.join(" ").len() <= 255, "{}", command.join(" "));
    // The descriptors the guard builds from it (seaworthy-launcher's
    // programdata tests pin the same strings) are the renderer's.
    use seaworthy_service::render::windows as win;
    let programdata = "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;RC;;;OW)";
    assert_eq!(win::data_dir_sddl(), programdata);
    assert_eq!(win::updates_dir_sddl(), programdata);
    assert_eq!(win::helper_log_dir_sddl(), programdata);
    let config = config(AGENT);
    let product = &config.products["agent"];
    let spec = config
        .service_spec("agent", product, std::path::Path::new("C:\\x\\x.exe"))
        .unwrap();
    assert_eq!(
        win::state_dir_sddl(&spec).unwrap(),
        format!("{programdata}(A;OICI;0x1301bf;;;{sid})")
    );
    // The launcher's own file, run from the install directory, right after
    // the files are installed, never in a repair or a removal.
    assert!(
        agent.contains("<CustomAction Id=\"ProgramDataFolders\" FileRef=\"f000_AcmeTool.exe\""),
        "{agent}"
    );
    assert!(
        agent.contains("<Custom Action=\"ProgramDataFolders\" After=\"InstallFiles\" Condition=\"NOT Installed AND NOT REMOVE=&quot;ALL&quot;\" />"),
        "{agent}"
    );
    for gone in [
        "CommonAppDataFolder",
        "StateDir",
        "LogsDir",
        "UpdatesDir",
        "DataDir",
    ] {
        assert!(!agent.contains(gone), "{gone}: {agent}");
    }
    // A desktop product's helper: its staging and its log, SYSTEM and
    // Administrators only; no service folders.
    let console = wxs_of(CONSOLE, "console");
    assert_eq!(
        command_of(&console)[1..],
        ["Acme", "Console", "-", "updates", "update-logs"]
    );
    // LocalSystem needs no grant: SYSTEM has full control.
    let collector = wxs_of(COLLECTOR, "collector");
    assert_eq!(
        command_of(&collector)[1..],
        [
            "Acme",
            "Collector",
            "-",
            "state",
            "logs",
            "updates",
            "update-logs"
        ]
    );
    let quiet = wxs_of(
        &CONSOLE.replace("updates.default = \"notify\"", "updates.default = \"off\""),
        "console",
    );
    assert!(
        !quiet.contains("ProgramDataFolders"),
        "no service and no helper: {quiet}"
    );
}

#[test]
fn every_file_comes_through_the_named_bind_path() {
    // WiX looks a bare relative path up in its working directory
    // first, so a same-named file there would ship instead.
    let config = config(AGENT);
    let tmp = tempfile::tempdir().unwrap();
    let layouts = layouts(&config, "agent", tmp.path());
    let wxs =
        seaworthy::wix::wxs(&config, "agent", layout_for(&layouts, WINDOWS), &release()).unwrap();
    let files: Vec<&str> = wxs.lines().filter(|l| l.contains("<File ")).collect();
    assert_eq!(files.len(), 5);
    for line in files {
        assert!(
            line.contains("Source=\"!(bindpath.tree)\\Acme\\Agent\\"),
            "{line}"
        );
    }
}

#[test]
fn wix_and_xml_syntax_in_config_text_stays_literal() {
    assert_eq!(
        seaworthy::wix::wix_text("a $(env.SECRET) !(bind.X) & \"q\" <t>"),
        "a $$(env.SECRET) !!(bind.X) &amp; &quot;q&quot; &lt;t&gt;"
    );
    let config = config(COLLECTOR);
    let tmp = tempfile::tempdir().unwrap();
    let layouts = layouts(&config, "collector", tmp.path());
    let wxs = seaworthy::wix::wxs(
        &config,
        "collector",
        layout_for(&layouts, WINDOWS),
        &release(),
    )
    .unwrap();
    assert!(
        wxs.contains(
            "Name=\"Acme &amp; Co &quot;Field&quot; &lt;Collector&gt; !!(bind.secret) --- Edition\""
        ),
        "{:#?}",
        common::wxs_lines(&wxs, &["Name=\"Acme "])
    );
    let comments: Vec<&str> = wxs
        .split("<!--")
        .skip(1)
        .map(|c| c.split("-->").next().unwrap())
        .collect();
    assert!(!comments.is_empty());
    for comment in comments {
        assert!(!comment.contains("--"), "a comment holds `--`: {comment}");
    }
}

#[test]
fn the_wxs_refuses_a_linux_layout() {
    let config = config(&AGENT.replace(
        "outputs = [\"msi\", \"zip\"]",
        "outputs = [\"msi\", \"tar\"]",
    ));
    let tmp = tempfile::tempdir().unwrap();
    let layouts = layouts(&config, "agent", tmp.path());
    assert!(
        seaworthy::wix::wxs(&config, "agent", layout_for(&layouts, LINUX), &release()).is_err()
    );
}

#[test]
fn upgrade_codes_are_stable_version_8_uuids_unless_pinned() {
    let config = config(AGENT);
    let code = seaworthy::wix::upgrade_code(&config, "agent").unwrap();
    assert_eq!(
        code,
        seaworthy::wix::upgrade_code(&config, "agent").unwrap()
    );
    assert_eq!(code.len(), 38);
    assert_eq!(&code[15..16], "8", "version 8: {code}");
    assert!(
        matches!(&code[20..21], "8" | "9" | "A" | "B"),
        "RFC 9562 variant: {code}"
    );
    assert_eq!(
        code,
        seaworthy::wix::derived_guid(&["seaworthy upgrade code", "Acme", "agent"])
    );
    assert_ne!(
        code,
        seaworthy::wix::upgrade_code(&self::config(COLLECTOR), "collector").unwrap()
    );
    assert_eq!(
        seaworthy::wix::upgrade_code(&self::config(CONSOLE), "console").unwrap(),
        "{0F1E2D3C-4B5A-4978-8A6B-5C4D3E2F1A0B}"
    );
}

#[test]
fn an_msi_product_needs_a_scoped_account_and_a_fixed_directory() {
    let refused = |product: String, mentions: &str| {
        let err = Config::parse(&format!("{DEFAULTS}{product}"))
            .unwrap_err()
            .to_string();
        assert!(err.contains(mentions), "{mentions}: {err}");
    };
    // The directory names the state, the registry key and the
    // Group Policy namespace; a display-name rename must not move them.
    refused(
        AGENT.replace("windows-directory = \"Agent\"\n", ""),
        "windows-directory",
    );
    // Shared accounts would share the MSI's grants.
    for account in ["local-service", "network-service"] {
        refused(
            AGENT.replace("account = \"virtual\"", &format!("account = \"{account}\"")),
            "service.account",
        );
    }
    // Without an msi output, neither applies.
    assert!(
        Config::parse(&format!(
            "{DEFAULTS}{}",
            AGENT
                .replace("windows-directory = \"Agent\"\n", "")
                .replace("outputs = [\"msi\", \"zip\"]", "outputs = [\"zip\"]")
        ))
        .is_ok()
    );
    // A bad pinned code.
    refused(
        CONSOLE.replace(
            "{0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b}",
            "0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b",
        ),
        "upgrade-code",
    );
}

#[test]
fn the_policy_templates_match_their_golden_files() {
    let template = seaworthy::admx::template("Acme", "Agent", "Acme Agent & Co --- Edition");
    assert_eq!(template.stem, "Acme.Agent");
    golden("admx/Acme.Agent.admx", &template.admx);
    golden("admx/Acme.Agent.adml", &template.adml);
    xmllint(&template.admx);
    xmllint(&template.adml);
    // The machine's update server, a text value beside the policy
    // under the key the helper reads first.
    let product = seaworthy_updater::Product::new("Acme", "agent", "Agent", "stable").unwrap();
    assert!(
        template.admx.contains(&format!(
            "<policy name=\"Server\" class=\"Machine\" displayName=\"$(string.Server)\" explainText=\"$(string.Server_Help)\" presentation=\"$(presentation.Server)\" key=\"{}\">",
            product.policy_key()
        )),
        "{}",
        template.admx
    );
    assert!(template.admx.contains(
        "<text id=\"Server\" valueName=\"Server\" required=\"true\" maxLength=\"2048\" />"
    ));
    assert_eq!(seaworthy_updater::MAX_SERVER_BYTES, 2048);
    assert!(template.adml.contains("<textBox refId=\"Server\">"));
}

#[test]
fn the_machines_update_server_is_an_optional_msi_property_kept_like_updates() {
    // SERVER= only where the helper ships; written only when set;
    // a repair keeps the installed value; never blocks a removal.
    let wxs_of = |product: &str, id: &str| {
        let config = config(product);
        let tmp = tempfile::tempdir().unwrap();
        let layouts = layouts(&config, id, tmp.path());
        seaworthy::wix::wxs(&config, id, layout_for(&layouts, WINDOWS), &release()).unwrap()
    };
    let agent = wxs_of(AGENT, "agent");
    for needle in [
        "<RegistrySearch Id=\"SavedServer\" Root=\"HKLM\" Key=\"SOFTWARE\\Acme\\Agent\" Name=\"Server\" Type=\"raw\" Bitness=\"always64\" />",
        "<Property Id=\"SERVER\" Secure=\"yes\" />",
        "Action=\"SetServerForMaintenance\" Value=\"[SAVEDSERVER]\" After=\"SetUpdatesDefault\" Condition=\"Installed\"",
        "Action=\"SetServerFromInstalled\" Value=\"[SAVEDSERVER]\" After=\"SetServerForMaintenance\" Condition=\"NOT Installed AND NOT SERVER AND SAVEDSERVER\"",
        "<Launch Condition=\"REMOVE = &quot;ALL&quot; OR NOT SERVER OR SERVER ~&lt;&lt; &quot;https://&quot;\"",
        "Bitness=\"always64\" Condition=\"SERVER\">",
        "<RegistryValue Root=\"HKLM\" Key=\"SOFTWARE\\Acme\\Agent\" Name=\"Server\" Type=\"string\" Value=\"[SERVER]\" KeyPath=\"yes\" />",
    ] {
        assert!(agent.contains(needle), "{needle}\n{agent}");
    }
    // The console (desktop, helper ships) has it too; a product without a
    // helper has neither the property nor the value.
    assert!(wxs_of(CONSOLE, "console").contains("<Property Id=\"SERVER\" Secure=\"yes\" />"));
    let no_helper = wxs_of(
        &CONSOLE
            .replace("helper = \"AcmeToolUpdate\"\n", "")
            .replace("updates.default = \"notify\"", "updates.default = \"off\""),
        "console",
    );
    assert!(!no_helper.contains("SERVER"), "{no_helper}");
}

#[test]
fn policy_names_never_start_with_a_digit() {
    // A name that would start with a digit gets a leading `_`.
    let digit = seaworthy::admx::template("3M", "Agent", "3M Agent");
    assert!(
        digit
            .admx
            .contains("<target prefix=\"_3MAgent\" namespace=\"3M.Policies.Agent\" />"),
        "{}",
        digit.admx
    );
    assert!(
        digit.admx.contains("<category name=\"_3MAgent\""),
        "{}",
        digit.admx
    );
}

// ---------------------------------------------------------------------------
// The MSI

/// `msiinfo export` rows of `table`, tab-split, without the three header
/// lines.
fn rows(msi: &Path, table: &str) -> Vec<Vec<String>> {
    let out = Command::new("msiinfo")
        .arg("export")
        .arg(msi)
        .arg(table)
        .output()
        .expect("msiinfo runs");
    assert!(
        out.status.success(),
        "msiinfo export {table}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .replace("\r\n", "\n")
        .lines()
        .skip(3)
        .map(|l| l.split('\t').map(str::to_owned).collect())
        .collect()
}

fn row<'a>(rows: &'a [Vec<String>], key: &str) -> &'a [String] {
    rows.iter()
        .find(|r| r[0] == key)
        .unwrap_or_else(|| panic!("no row {key} in {rows:?}"))
}

/// MSI's `MsiFileHash` columns for a file: its MD5 as four signed
/// little-endian 32-bit integers.
fn msi_hash(file: &Path) -> Vec<String> {
    let text = run(Command::new("md5sum").arg(file));
    let hex = text.split_whitespace().next().unwrap();
    let bytes: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    bytes
        .chunks(4)
        .map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]]).to_string())
        .collect()
}

fn wix() -> Option<PathBuf> {
    let wix = std::env::var_os("SEAWORTHY_WIX").map(PathBuf::from);
    if wix.is_none() {
        eprintln!(
            "SKIPPED: SEAWORTHY_WIX is unset (a wix binary, or a wrapper running it under Wine)"
        );
    }
    wix
}

#[test]
fn the_msi_carries_exactly_the_designed_tables() {
    let (Some(wix), Some(nfpm)) = (wix(), nfpm()) else {
        return;
    };
    if !have("msiinfo", &["--version"]) || !have("md5sum", &["--version"]) {
        return;
    }
    let config = config(AGENT);
    let tmp = tempfile::tempdir().unwrap();
    let artifacts = build(&config, "agent", tmp.path(), &nfpm, Some(wix));
    let msi = artifact(&artifacts, Kind::Msi);
    let code = seaworthy::wix::upgrade_code(&config, "agent").unwrap();
    let sid = seaworthy_service::render::windows::virtual_account_sid("AcmeAgent").unwrap();
    let packages = msi.parent().unwrap();
    assert!(
        std::fs::read_dir(packages).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".wixpdb")),
        "the debug database stays out of packages/"
    );

    let services = rows(&msi, "ServiceInstall");
    assert_eq!(
        row(&services, "Service"),
        [
            "Service",
            "AcmeAgent",
            "Acme Agent",
            "16",
            "2",
            "32769",
            "",
            "",
            "NT SERVICE\\AcmeAgent",
            "",
            "service --mode \"full scan\"",
            "c000_AcmeTool.exe",
            "Collects things for Acme."
        ]
    );
    assert_eq!(
        row(&services, "HelperService"),
        [
            "HelperService",
            "AcmeAgent-update",
            "Acme Agent updater",
            "16",
            "3",
            "32769",
            "",
            "",
            "LocalSystem",
            "",
            "",
            "c004_AcmeToolUpdate.exe",
            "Installs signed releases of Acme Agent."
        ]
    );
    // The service: stopped on install (an upgrade) and on removal, waiting
    // for it (2 + 32), removed on removal (128); started on install (1)
    // without waiting for it to stay running, as a service may retire at
    // once with exit 0 (Wait 0).
    let controls = rows(&msi, "ServiceControl");
    assert_eq!(
        row(&controls, "ServiceControl"),
        [
            "ServiceControl",
            "AcmeAgent",
            "162",
            "",
            "1",
            "c000_AcmeTool.exe"
        ]
    );
    assert_eq!(
        row(&controls, "ServiceStart"),
        [
            "ServiceStart",
            "AcmeAgent",
            "1",
            "",
            "0",
            "c000_AcmeTool.exe"
        ]
    );
    assert_eq!(
        row(&controls, "HelperServiceControl"),
        [
            "HelperServiceControl",
            "AcmeAgent-update",
            "162",
            "",
            "1",
            "c004_AcmeToolUpdate.exe"
        ]
    );

    // Recovery: deferred (1024) + no impersonation (2048) + an exe in a directory (34).
    let actions = rows(&msi, "CustomAction");
    assert_eq!(
        row(&actions, "ServiceRecovery"),
        [
            "ServiceRecovery",
            "3106",
            "System64Folder",
            "\"[System64Folder]sc.exe\" failure AcmeAgent reset= 86400 actions= restart/15000/restart/60000",
            ""
        ]
    );
    assert_eq!(
        row(&actions, "ServiceRecoveryOnErrorExit"),
        [
            "ServiceRecoveryOnErrorExit",
            "3106",
            "System64Folder",
            "\"[System64Folder]sc.exe\" failureflag AcmeAgent 1",
            ""
        ]
    );
    // A rolled-back removal's: rollback (256) in the script (1024) + no
    // impersonation (2048) + its exit ignored (64) + an exe in a directory (34).
    for (action, command) in [
        (
            "ServiceRecoveryRollback",
            "failure AcmeAgent reset= 86400 actions= restart/15000/restart/60000".to_owned(),
        ),
        (
            "ServiceRecoveryOnErrorExitRollback",
            "failureflag AcmeAgent 1".to_owned(),
        ),
        (
            "HelperServiceDaclRollback",
            format!(
                "sdset AcmeAgent-update D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLORC;;;{sid})"
            ),
        ),
    ] {
        assert_eq!(
            row(&actions, action),
            [
                action.to_owned(),
                "3426".to_owned(),
                "System64Folder".to_owned(),
                format!("\"[System64Folder]sc.exe\" {command}"),
                String::new()
            ]
        );
    }
    let saved_ok =
        "(SAVEDUPDATES = \"auto\" OR SAVEDUPDATES = \"notify\" OR SAVEDUPDATES = \"off\")";
    let sequence = rows(&msi, "InstallExecuteSequence");
    let at = |action: &str| -> (String, u32) {
        let r = row(&sequence, action);
        (r[1].clone(), r[2].trim().parse().unwrap())
    };
    assert_eq!(
        at("ServiceRecovery").0,
        "NOT Installed AND NOT REMOVE=\"ALL\"",
        "never in a repair"
    );
    assert_eq!(
        at("ServiceRecoveryOnErrorExit").0,
        "NOT Installed AND NOT REMOVE=\"ALL\""
    );
    assert!(at("InstallServices").1 < at("ServiceRecovery").1);
    assert!(at("ServiceRecovery").1 < at("ServiceRecoveryOnErrorExit").1);
    assert!(at("ServiceRecoveryOnErrorExit").1 < at("StartServices").1);
    // The old product is removed first, before anything writes to the
    // script (Windows Installer's rule for that placement).
    assert_eq!(
        at("RemoveExistingProducts").1,
        at("InstallInitialize").1 + 1,
        "removes the old product first"
    );
    // A removal's rollback runs them once the deleted services are back.
    for action in [
        "ServiceRecoveryRollback",
        "ServiceRecoveryOnErrorExitRollback",
        "HelperServiceDaclRollback",
    ] {
        assert_eq!(at(action).0, "Installed AND REMOVE=\"ALL\"");
        assert!(at("StopServices").1 < at(action).1);
        assert!(at(action).1 < at("DeleteServices").1);
    }
    // UPDATES: maintenance ignores the command line; a bad installed value is ignored.
    assert_eq!(
        at("SetUpdatesForMaintenance").0,
        format!("Installed AND {saved_ok}")
    );
    assert_eq!(
        at("SetUpdatesDefaultForMaintenance").0,
        format!("Installed AND NOT {saved_ok}")
    );
    assert_eq!(
        at("SetUpdatesFromInstalled").0,
        format!("NOT Installed AND NOT UPDATES AND {saved_ok}")
    );
    assert_eq!(at("SetUpdatesDefault").0, "NOT UPDATES");
    assert!(at("AppSearch").1 < at("SetUpdatesForMaintenance").1);
    assert!(at("SetUpdatesDefault").1 < at("LaunchConditions").1);
    assert_eq!(
        row(&actions, "SetUpdatesDefault")[..4],
        ["SetUpdatesDefault", "51", "UPDATES", "auto"]
    );
    assert_eq!(
        row(&actions, "SetUpdatesForMaintenance")[..4],
        [
            "SetUpdatesForMaintenance",
            "51",
            "UPDATES",
            "[SAVEDUPDATES]"
        ]
    );
    // Programs and Features' install location: a property set (51) after
    // CostFinalize resolves the directory, before the product is registered.
    assert_eq!(
        row(&actions, "SetARPINSTALLLOCATION")[..4],
        [
            "SetARPINSTALLLOCATION",
            "51",
            "ARPINSTALLLOCATION",
            "[InstallDir]"
        ]
    );
    assert!(at("CostFinalize").1 < at("SetARPINSTALLLOCATION").1);
    assert!(at("SetARPINSTALLLOCATION").1 < at("RegisterProduct").1);
    // The %ProgramData% guard: the installed launcher (18) in the script
    // (1024), as SYSTEM (2048), its exit checked; after the files, before
    // the services, never in a repair or a removal.
    assert_eq!(
        row(&actions, "ProgramDataFolders"),
        [
            "ProgramDataFolders".to_owned(),
            "3090".to_owned(),
            "f000_AcmeTool.exe".to_owned(),
            format!(
                "--seaworthy-install-programdata Acme Agent {sid} state:account logs:account updates update-logs"
            ),
            String::new()
        ]
    );
    assert_eq!(
        at("ProgramDataFolders").0,
        "NOT Installed AND NOT REMOVE=\"ALL\""
    );
    assert!(at("RemoveExistingProducts").1 < at("InstallFiles").1);
    assert!(at("InstallFiles").1 < at("ProgramDataFolders").1);
    assert!(at("ProgramDataFolders").1 < at("InstallServices").1);

    // Every descriptor, bound to its object.
    let locks: BTreeMap<(String, String), String> = rows(&msi, "MsiLockPermissionsEx")
        .into_iter()
        .map(|r| ((r[1].clone(), r[2].clone()), r[3].clone()))
        .collect();
    // SYSTEM the owner (the installer takes a squatter's directory
    // back, which windows_msi_update's squat step shows on the runner).
    // The %ProgramData% folders take theirs from the launcher's guard (the
    // ProgramDataFolders action above), never from a lock by path.
    let expected: BTreeMap<(String, String), String> = [
        (("HelperService", "ServiceInstall"), format!("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLORC;;;{sid})")),
        (("InstallDir", "CreateFolder"), format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;{sid})")),
    ]
    .into_iter()
    .map(|((object, table), sddl)| ((object.to_owned(), table.to_owned()), sddl))
    .collect();
    assert_eq!(locks, expected);

    let upgrade = rows(&msi, "Upgrade");
    assert!(
        upgrade.contains(&vec![
            code.clone(),
            String::new(),
            "1.4.0".into(),
            "1033".into(),
            "513".into(),
            String::new(),
            "WIX_UPGRADE_DETECTED".into()
        ]),
        "{upgrade:?}"
    );
    assert!(
        upgrade.contains(&vec![
            code,
            "1.4.0".into(),
            String::new(),
            "1033".into(),
            "2".into(),
            String::new(),
            "WIX_DOWNGRADE_DETECTED".into()
        ]),
        "{upgrade:?}"
    );
    // Raw (2) from the 64-bit view (16).
    assert_eq!(
        row(&rows(&msi, "RegLocator"), "SavedUpdatePolicy"),
        [
            "SavedUpdatePolicy",
            "2",
            "SOFTWARE\\Acme\\Agent",
            "UpdatePolicy",
            "18"
        ]
    );
    let registry = rows(&msi, "Registry");
    assert_eq!(registry.len(), 1);
    assert_eq!(
        registry[0][1..],
        [
            "2",
            "SOFTWARE\\Acme\\Agent",
            "UpdatePolicy",
            "[UPDATES]",
            "UpdatePolicyDefault"
        ]
    );
    let launch: Vec<String> = rows(&msi, "LaunchCondition")
        .into_iter()
        .map(|r| r[0].clone())
        .collect();
    assert!(
        launch.contains(
            &"REMOVE = \"ALL\" OR UPDATES = \"auto\" OR UPDATES = \"notify\" OR UPDATES = \"off\""
                .to_owned()
        ),
        "{launch:?}"
    );
    let properties = rows(&msi, "Property");
    let secure = &row(&properties, "SecureCustomProperties")[1];
    assert!(secure.split(';').any(|p| p == "UPDATES"), "{secure}");
    assert!(
        !secure.split(';').any(|p| p == "SAVEDUPDATES"),
        "only the server's own search may set it: {secure}"
    );
    assert_eq!(row(&properties, "ProductName")[1], "Acme Agent");

    // Every file is the staged one (never a same-named file
    // elsewhere): its size, and its version resource (stamped into
    // the launcher, the cores and the helper, so Windows Installer compares
    // versions) or, for the FIPS sidecar left as built, its hash.
    let tree = tmp
        .path()
        .join("dist/agent/x86_64-pc-windows-msvc/tree/Acme/Agent");
    let files = rows(&msi, "File");
    let hashes = rows(&msi, "MsiFileHash");
    assert_eq!(files.len(), 5);
    for file in &files {
        let name = file[2].rsplit('|').next().unwrap();
        let staged = tree.join(name);
        assert_eq!(
            file[3],
            std::fs::metadata(&staged).unwrap().len().to_string(),
            "{name}: size"
        );
        if name.starts_with("extra_") {
            assert_eq!(file[4], "", "{name}: the sidecar carries no version");
            assert_eq!(
                row(&hashes, &file[0])[2..6],
                msi_hash(&staged)[..],
                "{name}"
            );
        } else {
            assert_eq!(file[4], "1.4.0.812", "{name}: the stamped FileVersion");
            assert!(
                !hashes.iter().any(|h| h[0] == file[0]),
                "{name}: versioned files carry no hash row"
            );
        }
    }
}

#[test]
fn a_localsystem_msi_keeps_config_text_literal() {
    let (Some(wix), Some(nfpm)) = (wix(), nfpm()) else {
        return;
    };
    if !have("msiinfo", &["--version"]) {
        return;
    }
    let config = config(COLLECTOR);
    let tmp = tempfile::tempdir().unwrap();
    let artifacts = build(&config, "collector", tmp.path(), &nfpm, Some(wix));
    let msi = artifact(&artifacts, Kind::Msi);
    let properties = rows(&msi, "Property");
    assert_eq!(
        row(&properties, "ProductName")[1],
        "Acme & Co \"Field\" <Collector> !(bind.secret) --- Edition"
    );
    let services = rows(&msi, "ServiceInstall");
    assert_eq!(row(&services, "Service")[8], "LocalSystem");
    let locks: Vec<String> = rows(&msi, "MsiLockPermissionsEx")
        .into_iter()
        .map(|r| r[3].clone())
        .collect();
    // LocalSystem: SYSTEM's entry covers the account; the helper's grantee is SY.
    assert!(
        locks.contains(&"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)".to_owned()),
        "{locks:?}"
    );
    assert!(
        locks.iter().any(|l| l.ends_with("(A;;CCLCSWRPLORC;;;SY)")),
        "{locks:?}"
    );
    let actions = rows(&msi, "CustomAction");
    assert_eq!(
        row(&actions, "ServiceRecovery")[3],
        "\"[System64Folder]sc.exe\" failure AcmeCollector reset= 86400 actions= restart/15000/restart/60000/restart/300000/restart/900000"
    );
}
