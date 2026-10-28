//! `dist_msi_tables` — `adopt-msi`'s readers of an MSI from the Windows
//! runner (`seaworthy::msi_check`): `msiinfo export -s`'s SQL text of one
//! table, read strictly, and the comparison of tables with what a `.wxs`
//! declares.
//!
//! Input: `[mode][bytes]`.
//!
//! Invariants:
//! - `parse_sql_export` never panics; a table it reads, written back out
//!   (every value quoted and escaped), reads back the same (when its names
//!   are plain identifiers);
//! - `expected_from_wxs` never panics on any document;
//! - `findings` never panics on any table, under any table name (a
//!   `Directory` table whose parents loop included), and a table without
//!   rows in a table a seaworthy MSI never uses is no finding.

use std::collections::BTreeMap;

use seaworthy::msi_check::{self, Table};

/// A `.wxs` of a service with a helper and a shortcut, a setup dialog,
/// `PATH` and a file type's registry values, as `seaworthy package` writes
/// them, for the comparison.
const WXS: &str = r#"<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="Acme" Manufacturer="Acme" Version="1.0.0" UpgradeCode="{6A1F0C2E-3B4D-4E5F-9A6B-7C8D9E0F1A2B}" Scope="perMachine" Language="1033">
    <MajorUpgrade AllowSameVersionUpgrades="yes" Schedule="afterInstallInitialize" />
    <Property Id="ARPNOMODIFY" Value="1" />
    <UI>
      <TextStyle Id="SeaworthyText" FaceName="Segoe UI" Size="9" />
      <Property Id="DefaultUIFont" Value="SeaworthyText" />
      <Dialog Id="SetupDlg" Width="370" Height="270" Title="[ProductName] Setup">
        <Control Id="Accept" Type="CheckBox" X="15" Y="36" Width="340" Height="15" Property="LICENSEACCEPTED" CheckBoxValue="1" Text="I accept" />
        <Control Id="Install" Type="PushButton" X="236" Y="243" Width="56" Height="17" Default="yes" Text="Install" EnableCondition="LICENSEACCEPTED = &quot;1&quot;">
          <Publish Event="EndDialog" Value="Return" Condition="LICENSEACCEPTED = &quot;1&quot;" Order="1" />
        </Control>
      </Dialog>
      <InstallUISequence>
        <Show Dialog="SetupDlg" Before="ExecuteAction" Condition="NOT Installed" />
      </InstallUISequence>
    </UI>
    <SetProperty Id="ARPINSTALLLOCATION" Value="[InstallDir]" After="CostFinalize" Sequence="execute" />
    <StandardDirectory Id="System64Folder" />
    <CustomAction Id="ServiceRecovery" Directory="System64Folder" ExeCommand="sc.exe failure AcmeAgent" Execute="deferred" Impersonate="no" Return="check" />
    <CustomAction Id="ProgramDataFolders" FileRef="f000" ExeCommand="--seaworthy-install-programdata Acme Agent - state logs" Execute="deferred" Impersonate="no" Return="check" />
    <InstallExecuteSequence><Custom Action="ServiceRecovery" After="InstallServices" Condition="NOT Installed" /><Custom Action="ProgramDataFolders" After="InstallFiles" Condition="NOT Installed" /></InstallExecuteSequence>
    <StandardDirectory Id="ProgramFiles64Folder"><Directory Id="VendorDir" Name="Acme"><Directory Id="InstallDir" Name="Agent" /></Directory></StandardDirectory>
    <StandardDirectory Id="ProgramMenuFolder" />
    <Feature Id="Main">
      <Component Id="c000" Directory="InstallDir">
        <File Id="f000" Source="!(bindpath.tree)\Acme\Agent\AcmeTool.exe" KeyPath="yes" />
        <ServiceInstall Id="Service" Name="AcmeAgent" DisplayName="Acme" Type="ownProcess" Start="auto" ErrorControl="normal" Vital="yes" Account="LocalSystem">
          <PermissionEx Sddl="D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)" />
        </ServiceInstall>
        <ServiceControl Id="ServiceControl" Name="AcmeAgent" Stop="both" Remove="uninstall" Wait="yes" />
      </Component>
      <Component Id="PathMachine" Directory="InstallDir">
        <CreateFolder />
        <Environment Id="PathMachine" Name="PATH" Value="[InstallDir]" Action="set" Part="last" System="yes" />
      </Component>
      <Component Id="FileType000" Directory="InstallDir">
        <RegistryValue Root="HKCR" Key="Acme.Doc" Type="string" Value="Acme document" KeyPath="yes" />
        <RegistryValue Root="HKCR" Key="Acme.Doc\shell\open\command" Type="string" Value="&quot;[#f000]&quot; -- &quot;%1&quot;" />
      </Component>
      <Component Id="Shortcut" Directory="ProgramMenuFolder">
        <Shortcut Id="Shortcut" Name="Acme" Target="[#f000]" WorkingDirectory="InstallDir" />
        <RegistryValue Root="HKCU" Key="SOFTWARE\Acme" Name="Shortcut" Type="integer" Value="1" KeyPath="yes" />
      </Component>
    </Feature>
  </Package>
</Wix>"#;

const CODE: &str = "{6A1F0C2E-3B4D-4E5F-9A6B-7C8D9E0F1A2B}";

pub fn run(data: &[u8]) {
    let Some((&mode, bytes)) = data.split_first() else {
        return;
    };
    let text = crate::text(bytes);
    match mode % 3 {
        0 => round_trip(&text),
        1 => {
            let _ = msi_check::expected_from_wxs(&text);
        }
        _ => compare(&text),
    }
}

fn plain(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn quote(value: &str) -> String {
    let mut out = String::from("'");
    for c in value.chars() {
        if c == '\'' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('\'');
    out
}

fn round_trip(text: &str) {
    let Ok(table) = msi_check::parse_sql_export(text) else {
        return;
    };
    if !plain(&table.name) || !table.columns.iter().all(|c| plain(c)) {
        return;
    }
    let columns: Vec<String> = table
        .columns
        .iter()
        .map(|c| format!("`{c}` CHAR(255)"))
        .collect();
    let mut written = format!(
        "CREATE TABLE `{}` ({} PRIMARY KEY `{}`)\n",
        table.name,
        columns.join(", "),
        table.columns.first().map_or("", String::as_str)
    );
    for row in &table.rows {
        if row.is_empty() {
            return;
        }
        let names: Vec<String> = row.keys().map(|k| format!("`{k}`")).collect();
        let values: Vec<String> = row.values().map(|v| quote(v)).collect();
        written.push_str(&format!(
            "INSERT INTO `{}` ({}) VALUES ({})\n",
            table.name,
            names.join(", "),
            values.join(", ")
        ));
    }
    let again = msi_check::parse_sql_export(&written)
        .unwrap_or_else(|e| panic!("a table written back doesn't read: {e}\n{written}"));
    assert_eq!(again, table, "{written}");
}

fn compare(text: &str) {
    let expected = msi_check::expected_from_wxs(WXS).expect("the .wxs reads");
    let Ok(table) = msi_check::parse_sql_export(text) else {
        return;
    };
    for name in msi_check::COMPARED
        .iter()
        .chain(msi_check::SEQUENCES)
        .chain(msi_check::FORBIDDEN)
    {
        let tables: BTreeMap<String, Table> = [(
            (*name).to_owned(),
            Table {
                name: (*name).to_owned(),
                ..table.clone()
            },
        )]
        .into_iter()
        .collect();
        let findings = msi_check::findings(&expected, &tables, CODE);
        if msi_check::is_forbidden(name) && table.rows.is_empty() {
            assert!(
                !findings.iter().any(|f| f.contains(&format!("in {name},"))),
                "{findings:?}"
            );
        }
    }
}
