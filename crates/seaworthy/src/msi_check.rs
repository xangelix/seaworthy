//! `adopt-msi`'s check of an MSI's tables against the `.wxs` `seaworthy
//! package` wrote: the MSI comes from the Windows runner, and before it is
//! signed as the release's, everything in it that runs code, changes the
//! system or decides access must be what the `.wxs` declares.
//!
//! - **Never in a seaworthy MSI** ([`FORBIDDEN`]): tables whose rows run
//!   code or change the machine in ways the `.wxs` never asks for (a
//!   `Binary` stream, self-registration, an embedded chainer or UI, COM and
//!   advertised file-type registrations, INI files, file moves
//!   and copies and removals, ODBC, legacy ACLs, service failure actions,
//!   fonts, registry removals, dialogs). A row in any of them is refused.
//!   A `.wxs` declaring an element this check doesn't model is refused too,
//!   so a new element can't slip past it.
//! - **Exactly the `.wxs`'s** ([`expected_from_wxs`], [`findings`]): every
//!   custom action (its type, source and command line), every service
//!   (name, account, start type, type, error control, arguments, display
//!   name, description and the binary it runs), every service control,
//!   registry value, descriptor (`MsiLockPermissionsEx`: the object it's
//!   on and its SDDL), shortcut (its folder, name, target, arguments and
//!   working directory) and environment change (`PATH` alone: appended,
//!   removed on uninstall, the system's or the user's, the directory it
//!   adds and its component's condition): no row more, none less, none
//!   other. Objects are
//!   compared by what they resolve to (a directory's path, a component's
//!   key file's path), never by the ids a tool chose.
//! - **The sequences**: every action is a standard action (never a forced
//!   or scheduled reboot) or a custom action the `.wxs` schedules there,
//!   with its condition.
//! - **The upgrade rows** name the product's UpgradeCode, or are the
//!   detect-only searches the `.wxs` declares for the products it
//!   conflicts with (their UpgradeCode and property): a row that would
//!   remove another product is refused.
//!
//! The tables come from `msiinfo export -s` (SQL text: it never writes a
//! table's binary streams to disk, as the tab-separated export does), and
//! [`parse_sql_export`] reads them strictly: a line it can't read is a
//! refusal, never skipped. A table the check reads must have every column
//! it reads ([`COLUMNS`]): a column it can't find is a finding, never an
//! empty value.

#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

/// Tables a seaworthy MSI never has rows in: each one runs code or changes
/// the machine in a way the `.wxs` never declares. (Any `ODBC*` table too:
/// [`is_forbidden`].)
pub const FORBIDDEN: &[&str] = &[
    "Binary",
    "SelfReg",
    "MsiEmbeddedChainer",
    "MsiEmbeddedUI",
    "Class",
    "Extension",
    "Verb",
    "ProgId",
    "AppId",
    "TypeLib",
    "MIME",
    "IniFile",
    "RemoveIniFile",
    "MoveFile",
    "DuplicateFile",
    "RemoveFile",
    "MsiServiceConfig",
    "MsiServiceConfigFailureActions",
    "LockPermissions",
    "PublishComponent",
    "Complus",
    "Font",
    "RemoveRegistry",
    "SFPCatalog",
    "FileSFPCatalog",
    "IsolatedComponent",
    "BindImage",
    "Dialog",
    "Control",
    "ControlEvent",
];

/// Whether a seaworthy MSI never has rows in `table`.
#[must_use]
pub fn is_forbidden(table: &str) -> bool {
    FORBIDDEN.contains(&table) || table.starts_with("ODBC")
}

/// The sequence tables.
pub const SEQUENCES: &[&str] = &[
    "InstallExecuteSequence",
    "InstallUISequence",
    "AdminExecuteSequence",
    "AdminUISequence",
    "AdvtExecuteSequence",
    "AdvtUISequence",
];

/// The tables [`findings`] reads (beside [`FORBIDDEN`]'s and
/// [`SEQUENCES`]).
pub const COMPARED: &[&str] = &[
    "CustomAction",
    "ServiceInstall",
    "ServiceControl",
    "Registry",
    "MsiLockPermissionsEx",
    "Shortcut",
    "Upgrade",
    "Environment",
    "Directory",
    "Component",
    "File",
];

/// Whether [`findings`] needs `table` read.
#[must_use]
pub fn is_read(table: &str) -> bool {
    is_forbidden(table) || SEQUENCES.contains(&table) || COMPARED.contains(&table)
}

/// The columns [`findings`] reads, by table, as Windows Installer's schema
/// names them (and WiX builds them). A [`Table`] reads a column it doesn't
/// have as empty, the same as NULL, so a misnamed column here would compare
/// an MSI's value as empty: [`findings`] refuses a table that lacks one.
/// (The [`SEQUENCES`] are read by `Action` and `Condition`.)
pub const COLUMNS: &[(&str, &[&str])] = &[
    (
        "CustomAction",
        &["Action", "Type", "Source", "Target", "ExtendedType"],
    ),
    (
        "ServiceInstall",
        &[
            "ServiceInstall",
            "Name",
            "DisplayName",
            "ServiceType",
            "StartType",
            "ErrorControl",
            "LoadOrderGroup",
            "Dependencies",
            "StartName",
            "Password",
            "Arguments",
            "Component_",
            "Description",
        ],
    ),
    (
        "ServiceControl",
        &["Name", "Event", "Arguments", "Wait", "Component_"],
    ),
    ("Registry", &["Root", "Key", "Name", "Value"]),
    (
        "MsiLockPermissionsEx",
        &["LockObject", "Table", "SDDLText", "Condition"],
    ),
    (
        "Shortcut",
        &["Directory_", "Name", "Target", "Arguments", "WkDir"],
    ),
    (
        "Upgrade",
        &["UpgradeCode", "ActionProperty", "Attributes", "Remove"],
    ),
    (
        "Directory",
        &["Directory", "Directory_Parent", "DefaultDir"],
    ),
    ("Environment", &["Name", "Value", "Component_"]),
    (
        "Component",
        &["Component", "Directory_", "KeyPath", "Condition"],
    ),
    ("File", &["File", "Component_", "FileName"]),
];

/// Windows Installer's standard actions, less the two that reboot the
/// machine (`ForceReboot`, `ScheduleReboot`), which a seaworthy MSI never
/// schedules.
pub const STANDARD_ACTIONS: &[&str] = &[
    "ADMIN",
    "ADVERTISE",
    "AllocateRegistrySpace",
    "AppSearch",
    "BindImage",
    "CCPSearch",
    "CostFinalize",
    "CostInitialize",
    "CreateFolders",
    "CreateShortcuts",
    "DeleteServices",
    "DisableRollback",
    "DuplicateFiles",
    "ExecuteAction",
    "FileCost",
    "FindRelatedProducts",
    "INSTALL",
    "InstallAdminPackage",
    "InstallExecute",
    "InstallExecuteAgain",
    "InstallFiles",
    "InstallFinalize",
    "InstallInitialize",
    "InstallODBC",
    "InstallServices",
    "InstallSFPCatalogFile",
    "InstallValidate",
    "IsolateComponents",
    "LaunchConditions",
    "MigrateFeatureStates",
    "MoveFiles",
    "MsiConfigureServices",
    "MsiPublishAssemblies",
    "MsiUnpublishAssemblies",
    "PatchFiles",
    "ProcessComponents",
    "PublishComponents",
    "PublishFeatures",
    "PublishProduct",
    "RegisterClassInfo",
    "RegisterComPlus",
    "RegisterExtensionInfo",
    "RegisterFonts",
    "RegisterMIMEInfo",
    "RegisterProduct",
    "RegisterProgIdInfo",
    "RegisterTypeLibraries",
    "RegisterUser",
    "RemoveDuplicateFiles",
    "RemoveEnvironmentStrings",
    "RemoveExistingProducts",
    "RemoveFiles",
    "RemoveFolders",
    "RemoveIniValues",
    "RemoveODBC",
    "RemoveRegistryValues",
    "RemoveShortcuts",
    "ResolveSource",
    "RMCCPSearch",
    "SelfRegModules",
    "SelfUnregModules",
    "SEQUENCE",
    "SetODBCFolders",
    "StartServices",
    "StopServices",
    "UnpublishComponents",
    "UnpublishFeatures",
    "UnregisterClassInfo",
    "UnregisterComPlus",
    "UnregisterExtensionInfo",
    "UnregisterFonts",
    "UnregisterMIMEInfo",
    "UnregisterProgIdInfo",
    "UnregisterTypeLibraries",
    "ValidateProductID",
    "WriteEnvironmentStrings",
    "WriteIniValues",
    "WriteRegistryValues",
];

/// Windows Installer's standard folder properties: a directory with one
/// of these ids is that folder, wherever the `Directory` table puts it.
const STANDARD_FOLDERS: &[&str] = &[
    "TARGETDIR",
    "AdminToolsFolder",
    "AppDataFolder",
    "CommonAppDataFolder",
    "CommonFiles64Folder",
    "CommonFiles6432Folder",
    "CommonFilesFolder",
    "DesktopFolder",
    "FavoritesFolder",
    "FontsFolder",
    "LocalAppDataFolder",
    "MyPicturesFolder",
    "NetHoodFolder",
    "PersonalFolder",
    "PrintHoodFolder",
    "ProgramFiles64Folder",
    "ProgramFiles6432Folder",
    "ProgramFilesFolder",
    "ProgramMenuFolder",
    "RecentFolder",
    "SendToFolder",
    "StartMenuFolder",
    "StartupFolder",
    "System16Folder",
    "System64Folder",
    "System6432Folder",
    "SystemFolder",
    "TempFolder",
    "TemplateFolder",
    "WindowsFolder",
    "WindowsVolume",
];

/// The `.wxs` elements this check models; any other one with security
/// weight (see [`expected_from_wxs`]) is refused.
const MODELED: &[&str] = &[
    "Wix",
    "Package",
    "SummaryInformation",
    "MajorUpgrade",
    "MediaTemplate",
    "Launch",
    "Property",
    "SetProperty",
    "RegistrySearch",
    "Icon",
    "StandardDirectory",
    "Directory",
    "CustomAction",
    "InstallExecuteSequence",
    "InstallUISequence",
    "Custom",
    "Feature",
    "Component",
    "File",
    "ServiceInstall",
    "ServiceControl",
    "PermissionEx",
    "CreateFolder",
    "RegistryValue",
    "Shortcut",
    "Upgrade",
    "UpgradeVersion",
    "Environment",
];

/// One table as `msiinfo export -s` gives it: its columns, and each row by
/// column (a NULL column is the empty string).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Table {
    /// The table's name.
    pub name: String,
    /// Its columns, in order.
    pub columns: Vec<String>,
    /// Its rows.
    pub rows: Vec<BTreeMap<String, String>>,
}

impl Table {
    /// Column `name` of `row` (empty when NULL).
    fn get<'a>(row: &'a BTreeMap<String, String>, name: &str) -> &'a str {
        row.get(name).map_or("", String::as_str)
    }
}

/// A backquoted name at the start of `text`, and the rest.
fn quoted_name(text: &str) -> Option<(&str, &str)> {
    let rest = text.strip_prefix('`')?;
    let end = rest.find('`')?;
    Some((rest.get(..end)?, rest.get(end.checked_add(1)?..)?))
}

/// The comma-separated values of an `INSERT`'s `VALUES (…)`: strings in
/// single quotes (a backslash escapes the next character) and integers.
fn sql_values(text: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    let mut chars = text.chars().peekable();
    loop {
        while chars.peek() == Some(&' ') {
            chars.next();
        }
        match chars.next() {
            Some('\'') => {
                let mut value = String::new();
                loop {
                    match chars.next() {
                        Some('\\') => match chars.next() {
                            Some(c) => value.push(c),
                            None => return Err("an unterminated string".to_owned()),
                        },
                        Some('\'') => break,
                        Some(c) => value.push(c),
                        None => return Err("an unterminated string".to_owned()),
                    }
                }
                values.push(value);
            }
            Some(c) if c == '-' || c.is_ascii_digit() => {
                let mut value = String::from(c);
                while let Some(&d) = chars.peek() {
                    if !d.is_ascii_digit() {
                        break;
                    }
                    value.push(d);
                    chars.next();
                }
                if value == "-" {
                    return Err("a sign without a number".to_owned());
                }
                values.push(value);
            }
            _ => return Err("a value that is neither a string nor an integer".to_owned()),
        }
        while chars.peek() == Some(&' ') {
            chars.next();
        }
        match chars.next() {
            Some(',') => {}
            None => return Ok(values),
            Some(c) => return Err(format!("{c:?} after a value")),
        }
    }
}

/// Reads one table's `msiinfo export -s` text: a `CREATE TABLE` line, then
/// one `INSERT INTO` line per row. Anything else is refused.
///
/// # Errors
/// A line that isn't one of those, a row of another table, a column the
/// table doesn't have, or a value count that doesn't match.
pub fn parse_sql_export(text: &str) -> Result<Table, String> {
    let mut table: Option<Table> = None;
    for (number, line) in text.lines().enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.trim().is_empty() {
            continue;
        }
        let at = |why: &str| format!("line {}: {why}", number.saturating_add(1));
        if let Some(rest) = line.strip_prefix("CREATE TABLE ") {
            if table.is_some() {
                return Err(at("a second CREATE TABLE"));
            }
            let (name, rest) = quoted_name(rest).ok_or_else(|| at("no table name"))?;
            let rest = rest.trim_start();
            let rest = rest.strip_prefix('(').ok_or_else(|| at("no column list"))?;
            let columns_text = rest
                .split(" PRIMARY KEY ")
                .next()
                .ok_or_else(|| at("no column list"))?;
            let mut columns = Vec::new();
            for column in columns_text.split(", ") {
                let (column, _) =
                    quoted_name(column).ok_or_else(|| at("a column without a name"))?;
                columns.push(column.to_owned());
            }
            table = Some(Table {
                name: name.to_owned(),
                columns,
                rows: Vec::new(),
            });
        } else if let Some(rest) = line.strip_prefix("INSERT INTO ") {
            let current = table
                .as_mut()
                .ok_or_else(|| at("a row before CREATE TABLE"))?;
            let (name, rest) = quoted_name(rest).ok_or_else(|| at("no table name"))?;
            if name != current.name {
                return Err(at(&format!("a row of {name}, not {}", current.name)));
            }
            let rest = rest
                .trim_start()
                .strip_prefix('(')
                .ok_or_else(|| at("no column list"))?;
            let (names, values) = rest
                .split_once(") VALUES (")
                .ok_or_else(|| at("no VALUES"))?;
            let values = values
                .strip_suffix(')')
                .ok_or_else(|| at("an unterminated VALUES"))?;
            let mut columns = Vec::new();
            for column in names.split(", ") {
                let (column, rest) =
                    quoted_name(column).ok_or_else(|| at("a column without a name"))?;
                if !rest.is_empty() || !current.columns.iter().any(|c| c == column) {
                    return Err(at(&format!("a column {column:?} the table doesn't have")));
                }
                columns.push(column.to_owned());
            }
            let values = sql_values(values).map_err(|e| at(&e))?;
            if values.len() != columns.len() {
                return Err(at("a value count that isn't the column count"));
            }
            let mut row = BTreeMap::new();
            for (column, value) in columns.into_iter().zip(values) {
                if row.insert(column, value).is_some() {
                    return Err(at("a column given twice"));
                }
            }
            current.rows.push(row);
        } else {
            return Err(at("neither CREATE TABLE nor INSERT INTO"));
        }
    }
    table.ok_or_else(|| "no CREATE TABLE".to_owned())
}

/// A custom action the `.wxs` declares: its row, and where it's scheduled
/// (sequence table, condition).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Action {
    kind: String,
    /// Its `Source`: a directory or property id, or, for an executable
    /// in the `File` table ([`Self::source_file`]), that file's install
    /// path.
    source: String,
    target: String,
    /// The source is a file (type 18), compared by its install path.
    source_file: bool,
    scheduled: BTreeSet<(String, String)>,
}

/// A service the `.wxs` installs: its row's security-relevant columns and
/// the path of the binary it runs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Service {
    name: String,
    display_name: String,
    kind: String,
    start: String,
    error_control: String,
    account: String,
    arguments: String,
    description: String,
    binary: String,
}

/// What the `.wxs` declares, as Windows Installer's rows.
#[derive(Debug, Clone, Default)]
pub struct Expected {
    upgrade_code: String,
    actions: BTreeMap<String, Action>,
    services: BTreeSet<Service>,
    /// (name, event, wait, binary of its component).
    controls: BTreeSet<(String, String, String, String)>,
    /// (root, key, name, value).
    registry: BTreeMap<(String, String, String, String), usize>,
    /// (table, object: a directory's path or a service's name, SDDL).
    locks: BTreeMap<(String, String, String), usize>,
    /// (folder path, name, target, arguments, working directory path).
    shortcuts: BTreeSet<(String, String, String, String, String)>,
    /// Detect-only searches for other products (`conflicts`): their
    /// UpgradeCode, uppercase, and the property each sets.
    detections: BTreeSet<(String, String)>,
    /// Environment changes (`PATH`): the `Environment` row's name (its
    /// action, removal and system prefixes) and value (a directory
    /// reference resolved to the directory's path), and its component's
    /// condition.
    environment: BTreeMap<(String, String, String), usize>,
}

/// One open element while reading the `.wxs`.
#[derive(Debug, Clone)]
struct Open {
    name: String,
    /// A directory element's path; a component's directory path.
    path: Option<String>,
    /// A component's id; a service's name.
    id: Option<String>,
    /// A sequence table element's table.
    sequence: Option<String>,
}

/// A component's contents while it's open.
#[derive(Debug, Default)]
struct OpenComponent {
    directory: String,
    condition: String,
    key_file: Option<String>,
    services: Vec<Service>,
    controls: Vec<(String, String, String)>,
    shortcuts: Vec<(String, String, String, String, String)>,
}

fn join(parent: &str, name: &str) -> String {
    match (parent.is_empty(), name.is_empty() || name == ".") {
        (_, true) => parent.to_owned(),
        (true, false) => name.to_owned(),
        (false, false) => format!("{parent}/{name}"),
    }
}

/// An executable in a directory (`<CustomAction Directory= ExeCommand=>`).
const EXE_IN_DIRECTORY: u32 = 34;
/// An executable in the `File` table (`<CustomAction FileRef=
/// ExeCommand=>`).
const EXE_IN_FILE: u32 = 18;

/// The `Type` of an executable custom action of kind `base`
/// ([`EXE_IN_DIRECTORY`], [`EXE_IN_FILE`]) with its `Execute`,
/// `Impersonate` and `Return`.
fn exe_action_type(base: u32, execute: &str, impersonate: &str, ret: &str) -> Result<u32, String> {
    let execute = match execute {
        "" | "immediate" => 0,
        "deferred" => 1024,
        "rollback" => 1024 | 256,
        "commit" => 1024 | 512,
        other => {
            return Err(format!(
                "a custom action Execute={other:?}, which this check doesn't model"
            ));
        }
    };
    let impersonate = match impersonate {
        "" | "yes" => 0,
        "no" => 2048,
        other => return Err(format!("Impersonate={other:?}")),
    };
    let ret = match ret {
        "" | "check" => 0,
        "ignore" => 64,
        "asyncWait" => 128,
        "asyncNoWait" => 192,
        other => return Err(format!("Return={other:?}")),
    };
    Ok(base | execute | impersonate | ret)
}

/// A `<RegistryValue>`'s `Root` as the `Registry` table's.
fn registry_root(root: &str) -> Result<&'static str, String> {
    Ok(match root {
        "HKCR" => "0",
        "HKCU" => "1",
        "HKLM" => "2",
        "HKU" => "3",
        "HKMU" => "-1",
        other => return Err(format!("a registry root {other:?}")),
    })
}

/// A `<RegistryValue>`'s value as the `Registry` table writes it.
fn registry_value(kind: &str, value: &str) -> Result<String, String> {
    Ok(match kind {
        "string" | "" if value.starts_with('#') => format!("#{value}"),
        "string" | "" => value.to_owned(),
        "integer" => format!("#{value}"),
        "expandable" => format!("#%{value}"),
        other => {
            return Err(format!(
                "a registry value of Type={other:?}, which this check doesn't model"
            ));
        }
    })
}

/// A `<ServiceControl>`'s `Event` bits.
fn control_event(start: &str, stop: &str, remove: &str) -> Result<u32, String> {
    let bits = |value: &str, install: u32, uninstall: u32| -> Result<u32, String> {
        Ok(match value {
            "" => 0,
            "install" => install,
            "uninstall" => uninstall,
            "both" => install | uninstall,
            other => return Err(format!("a ServiceControl event {other:?}")),
        })
    };
    Ok(bits(start, 1, 16)? | bits(stop, 2, 32)? | bits(remove, 8, 128)?)
}

/// Reads what the `.wxs` `seaworthy package` wrote declares, as the rows
/// Windows Installer's tables must hold for it.
///
/// # Errors
/// XML that doesn't parse, an element with a namespace prefix (a WiX
/// extension's), an element with security weight this check doesn't model
/// (`Environment`, `RemoveFile`, `Class`, …), or an attribute value it
/// can't map.
pub fn expected_from_wxs(wxs: &str) -> Result<Expected, String> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(wxs);
    let mut stack: Vec<Open> = Vec::new();
    let mut expected = Expected::default();
    let mut component: Option<OpenComponent> = None;
    // File id -> install path; shortcut targets resolve through it.
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    // Directory id -> path.
    let mut directories: BTreeMap<String, String> = BTreeMap::new();
    let mut pending_shortcuts = Vec::new();
    let mut pending_environment: Vec<(String, String, String)> = Vec::new();
    let mut scheduled: Vec<(String, String, String)> = Vec::new();
    loop {
        let event = reader
            .read_event()
            .map_err(|e| format!("the .wxs doesn't parse: {e}"))?;
        let (element, empty) = match event {
            Event::Start(element) => (element, false),
            Event::Empty(element) => (element, true),
            Event::End(_) => {
                let closed = stack.pop();
                if closed.as_ref().is_some_and(|o| o.name == "Component") {
                    let done = component.take().unwrap_or_default();
                    finish_component(&mut expected, done, &mut pending_shortcuts);
                }
                continue;
            }
            Event::Eof => break,
            _ => continue,
        };
        let name = element.name().as_ref().to_owned();
        if name.contains(':') {
            return Err(format!(
                "the .wxs has <{name}>: a WiX extension's element this check doesn't model"
            ));
        }
        if !MODELED.contains(&name.as_str()) {
            return Err(format!(
                "the .wxs has <{name}>, which this check doesn't model"
            ));
        }
        let mut attributes = BTreeMap::new();
        for attribute in element.attributes() {
            let attribute = attribute.map_err(|e| format!("<{name}>: {e}"))?;
            let key = attribute.key.as_ref().to_owned();
            let value = attribute
                // Normalized as an XML parser (WiX's) reads it.
                .normalized_value(quick_xml::XmlVersion::Explicit1_0)
                .map_err(|e| format!("<{name} {key}>: {e}"))?
                .into_owned();
            attributes.insert(key, value);
        }
        let attr = |key: &str| attributes.get(key).cloned().unwrap_or_default();
        let parent_path = stack
            .iter()
            .rev()
            .find_map(|o| o.path.clone())
            .unwrap_or_default();
        let mut open = Open {
            name: name.clone(),
            path: None,
            id: None,
            sequence: None,
        };
        match name.as_str() {
            "Package" => expected.upgrade_code = attr("UpgradeCode"),
            "StandardDirectory" => {
                let id = attr("Id");
                directories.insert(id.clone(), id.clone());
                open.path = Some(id);
            }
            "Directory" => {
                let id = attr("Id");
                let path = if id == "TARGETDIR" {
                    String::new()
                } else if STANDARD_FOLDERS.contains(&id.as_str()) {
                    id.clone()
                } else {
                    join(&parent_path, &attr("Name"))
                };
                directories.insert(id, path.clone());
                open.path = Some(path);
            }
            "Component" => {
                let directory = match attributes.get("Directory") {
                    Some(id) => directories.get(id).cloned().ok_or_else(|| {
                        format!("component {} names an unknown directory {id}", attr("Id"))
                    })?,
                    None => parent_path.clone(),
                };
                open.path = Some(directory.clone());
                open.id = Some(attr("Id"));
                component = Some(OpenComponent {
                    directory,
                    condition: attr("Condition"),
                    ..OpenComponent::default()
                });
            }
            "File" => {
                let open_component = component
                    .as_mut()
                    .ok_or_else(|| "a <File> outside a component".to_owned())?;
                let file_name = attributes.get("Name").cloned().unwrap_or_else(|| {
                    attr("Source")
                        .rsplit(['\\', '/'])
                        .next()
                        .unwrap_or_default()
                        .to_owned()
                });
                let path = join(&open_component.directory, &file_name);
                files.insert(attr("Id"), path.clone());
                if attr("KeyPath") == "yes" || open_component.key_file.is_none() {
                    open_component.key_file = Some(path);
                }
            }
            "ServiceInstall" => {
                let open_component = component
                    .as_mut()
                    .ok_or_else(|| "a <ServiceInstall> outside a component".to_owned())?;
                let kind = match attr("Type").as_str() {
                    "ownProcess" => "16",
                    "shareProcess" => "32",
                    other => return Err(format!("a service Type={other:?}")),
                };
                if attributes.contains_key("Interactive") || attributes.contains_key("Password") {
                    return Err("an interactive service, or one with a password".to_owned());
                }
                let start = match attr("Start").as_str() {
                    "boot" => "0",
                    "system" => "1",
                    "auto" => "2",
                    "demand" => "3",
                    "disabled" => "4",
                    other => return Err(format!("a service Start={other:?}")),
                };
                let mut error_control: u32 = match attr("ErrorControl").as_str() {
                    "ignore" => 0,
                    "normal" => 1,
                    "critical" => 3,
                    other => return Err(format!("a service ErrorControl={other:?}")),
                };
                if attr("Vital") == "yes" {
                    error_control |= 32768;
                }
                open.id = Some(attr("Name"));
                open_component.services.push(Service {
                    name: attr("Name"),
                    display_name: attr("DisplayName"),
                    kind: kind.to_owned(),
                    start: start.to_owned(),
                    error_control: error_control.to_string(),
                    account: attr("Account"),
                    arguments: attr("Arguments"),
                    description: attr("Description"),
                    binary: String::new(),
                });
            }
            "ServiceControl" => {
                let open_component = component
                    .as_mut()
                    .ok_or_else(|| "a <ServiceControl> outside a component".to_owned())?;
                let event = control_event(&attr("Start"), &attr("Stop"), &attr("Remove"))?;
                let wait = match attr("Wait").as_str() {
                    "yes" => "1",
                    "no" => "0",
                    "" => "",
                    other => return Err(format!("a ServiceControl Wait={other:?}")),
                };
                open_component
                    .controls
                    .push((attr("Name"), event.to_string(), wait.to_owned()));
            }
            "CreateFolder" => {
                let directory = match attributes.get("Directory") {
                    Some(id) => directories
                        .get(id)
                        .cloned()
                        .ok_or_else(|| format!("a CreateFolder on an unknown directory {id}"))?,
                    None => component
                        .as_ref()
                        .map(|c| c.directory.clone())
                        .ok_or_else(|| "a <CreateFolder> outside a component".to_owned())?,
                };
                open.path = Some(directory);
            }
            "PermissionEx" => {
                let parent = stack
                    .last()
                    .ok_or_else(|| "a <PermissionEx> at the top".to_owned())?;
                let object = match parent.name.as_str() {
                    "ServiceInstall" => ("ServiceInstall", parent.id.clone().unwrap_or_default()),
                    "CreateFolder" => ("CreateFolder", parent.path.clone().unwrap_or_default()),
                    other => {
                        return Err(format!(
                            "a <PermissionEx> in <{other}>, which this check doesn't model"
                        ));
                    }
                };
                if attributes.keys().any(|k| k != "Sddl") {
                    return Err("a <PermissionEx> with more than its Sddl".to_owned());
                }
                let count = expected
                    .locks
                    .entry((object.0.to_owned(), object.1, attr("Sddl")))
                    .or_insert(0);
                *count = count.saturating_add(1);
            }
            "RegistryValue" => {
                if component.is_none() {
                    return Err("a <RegistryValue> outside a component".to_owned());
                }
                if attributes.contains_key("Action") {
                    return Err(
                        "a <RegistryValue Action=>, which this check doesn't model".to_owned()
                    );
                }
                let row = (
                    registry_root(&attr("Root"))?.to_owned(),
                    attr("Key"),
                    attr("Name"),
                    registry_value(&attr("Type"), &attr("Value"))?,
                );
                let count = expected.registry.entry(row).or_insert(0);
                *count = count.saturating_add(1);
            }
            "Shortcut" => {
                let open_component = component
                    .as_mut()
                    .ok_or_else(|| "a <Shortcut> outside a component".to_owned())?;
                let folder = match attributes.get("Directory") {
                    Some(id) => directories
                        .get(id)
                        .cloned()
                        .ok_or_else(|| format!("a shortcut in an unknown directory {id}"))?,
                    None => open_component.directory.clone(),
                };
                let working = match attributes.get("WorkingDirectory") {
                    Some(id) => directories.get(id).cloned().ok_or_else(|| {
                        format!("a shortcut working in an unknown directory {id}")
                    })?,
                    None => String::new(),
                };
                open_component.shortcuts.push((
                    folder,
                    attr("Name"),
                    attr("Target"),
                    attr("Arguments"),
                    working,
                ));
            }
            "CustomAction" => {
                let id = attr("Id");
                let exe = |base: u32, source: &str, source_file: bool| -> Result<Action, String> {
                    Ok(Action {
                        kind: exe_action_type(
                            base,
                            &attr("Execute"),
                            &attr("Impersonate"),
                            &attr("Return"),
                        )?
                        .to_string(),
                        source: attr(source),
                        target: attr("ExeCommand"),
                        source_file,
                        scheduled: BTreeSet::new(),
                    })
                };
                let has = |key: &str| attributes.contains_key(key);
                let action = if has("ExeCommand") && has("Directory") && !has("FileRef") {
                    exe(EXE_IN_DIRECTORY, "Directory", false)?
                } else if has("ExeCommand") && has("FileRef") && !has("Directory") {
                    // The file's id for now: its install path once every
                    // file is read (below).
                    exe(EXE_IN_FILE, "FileRef", true)?
                } else if has("Property") && has("Value") && !has("ExeCommand") {
                    Action {
                        kind: "51".to_owned(),
                        source: attr("Property"),
                        target: attr("Value"),
                        source_file: false,
                        scheduled: BTreeSet::new(),
                    }
                } else {
                    return Err(format!(
                        "custom action {id}: a kind this check doesn't model"
                    ));
                };
                if expected.actions.insert(id.clone(), action).is_some() {
                    return Err(format!("custom action {id} declared twice"));
                }
            }
            "SetProperty" => {
                let id = attr("Id");
                let action = attributes
                    .get("Action")
                    .cloned()
                    .unwrap_or_else(|| format!("Set{id}"));
                let tables: &[&str] = match attr("Sequence").as_str() {
                    "execute" => &["InstallExecuteSequence"],
                    "ui" => &["InstallUISequence"],
                    "" | "both" => &["InstallUISequence", "InstallExecuteSequence"],
                    other => return Err(format!("SetProperty {id}: Sequence={other:?}")),
                };
                let condition = attr("Condition");
                for table in tables {
                    scheduled.push((action.clone(), (*table).to_owned(), condition.clone()));
                }
                let declared = Action {
                    kind: "51".to_owned(),
                    source: id,
                    target: attr("Value"),
                    source_file: false,
                    scheduled: BTreeSet::new(),
                };
                if expected.actions.insert(action.clone(), declared).is_some() {
                    return Err(format!("custom action {action} declared twice"));
                }
            }
            "Upgrade" => {
                // WiX names the searched-for UpgradeCode `Id`.
                let code = attr("Id");
                if code.is_empty() {
                    return Err(
                        "an <Upgrade> without an Id (the UpgradeCode it searches for)".to_owned(),
                    );
                }
                open.id = Some(code.to_ascii_uppercase());
            }
            "UpgradeVersion" => {
                let code = stack
                    .last()
                    .filter(|o| o.name == "Upgrade")
                    .and_then(|o| o.id.clone())
                    .ok_or_else(|| "an <UpgradeVersion> outside an <Upgrade>".to_owned())?;
                // Only a search: a row that isn't detect-only removes the
                // product it finds.
                if attr("OnlyDetect") != "yes" {
                    return Err(format!(
                        "an <UpgradeVersion> of {code} that isn't OnlyDetect=\"yes\": it would remove that product"
                    ));
                }
                let property = attr("Property");
                if property.is_empty() {
                    return Err(format!("an <UpgradeVersion> of {code} without a Property"));
                }
                expected.detections.insert((code, property));
            }
            "Environment" => {
                let open_component = component
                    .as_ref()
                    .ok_or_else(|| "an <Environment> outside a component".to_owned())?;
                let row = environment_row(&attributes)?;
                pending_environment.push((row.0, row.1, open_component.condition.clone()));
            }
            "InstallExecuteSequence" | "InstallUISequence" => {
                open.sequence = Some(name.clone());
            }
            "Custom" => {
                let table = stack
                    .last()
                    .and_then(|o| o.sequence.clone())
                    .ok_or_else(|| "a <Custom> outside a sequence".to_owned())?;
                scheduled.push((attr("Action"), table, attr("Condition")));
            }
            _ => {}
        }
        if !empty {
            stack.push(open);
        } else if name == "Component" {
            let done = component.take().unwrap_or_default();
            finish_component(&mut expected, done, &mut pending_shortcuts);
        }
    }
    for (action, table, condition) in scheduled {
        let declared = expected
            .actions
            .get_mut(&action)
            .ok_or_else(|| format!("the .wxs schedules {action}, which it doesn't declare"))?;
        declared.scheduled.insert((table, condition));
    }
    for (id, action) in &mut expected.actions {
        if action.source_file {
            action.source = files.get(&action.source).cloned().ok_or_else(|| {
                format!(
                    "custom action {id} runs {}, a file the .wxs doesn't install",
                    action.source
                )
            })?;
        }
    }
    for (name, value, condition) in pending_environment {
        let value = resolve_directory_reference(&value, |id| directories.get(id).cloned());
        let count = expected
            .environment
            .entry((name, value, condition))
            .or_insert(0);
        *count = count.saturating_add(1);
    }
    for (folder, name, target, arguments, working) in pending_shortcuts {
        // `[#<file id>]`: the file's install path.
        let target = match target.strip_prefix("[#").and_then(|t| t.strip_suffix(']')) {
            Some(id) => files
                .get(id)
                .cloned()
                .ok_or_else(|| format!("a shortcut to an unknown file {id}"))?,
            None => target,
        };
        expected
            .shortcuts
            .insert((folder, name, target, arguments, working));
    }
    Ok(expected)
}

/// The `Environment` row WiX writes for an `<Environment>` (its binder's
/// `AddEnvironmentSymbol`): the name prefixed by the action (`=` set), `-`
/// (removed on uninstall) and `*` (the system's, not the user's), and the
/// value after `[~];` (appended to what's there). Only what seaworthy
/// writes is modeled: `PATH`, set, appended, removed on uninstall.
fn environment_row(attributes: &BTreeMap<String, String>) -> Result<(String, String), String> {
    let get = |key: &str| attributes.get(key).map(String::as_str);
    if let Some(key) = attributes.keys().find(|k| {
        !matches!(
            k.as_str(),
            "Id" | "Name" | "Value" | "Action" | "Part" | "System"
        )
    }) {
        return Err(format!(
            "an <Environment {key}=>, which this check doesn't model"
        ));
    }
    if get("Name") != Some("PATH") || get("Action") != Some("set") || get("Part") != Some("last") {
        return Err(
            "an <Environment> other than PATH, set, its value appended (Part=\"last\"), which this check doesn't model"
                .to_owned(),
        );
    }
    let system = match get("System") {
        Some("yes") => "*",
        None | Some("no") => "",
        Some(other) => return Err(format!("an <Environment System={other:?}>")),
    };
    let value = get("Value").unwrap_or_default();
    if value.is_empty() {
        return Err("an <Environment> without a value".to_owned());
    }
    Ok((format!("=-{system}PATH"), format!("[~];{value}")))
}

/// An `Environment` value `[~];[<directory id>]` with the directory's path
/// for its id (as `lookup` resolves it); any other value as it is.
fn resolve_directory_reference(value: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
    value
        .strip_prefix("[~];[")
        .and_then(|rest| rest.strip_suffix(']'))
        .filter(|id| !id.contains(['[', ']']))
        .and_then(lookup)
        .map_or_else(|| value.to_owned(), |path| format!("[~];<{path}>"))
}

/// Moves a closed component's services, controls and shortcuts into
/// `expected`, each service and control running the component's key file.
fn finish_component(
    expected: &mut Expected,
    component: OpenComponent,
    shortcuts: &mut Vec<(String, String, String, String, String)>,
) {
    let binary = component.key_file.unwrap_or_default();
    for mut service in component.services {
        service.binary.clone_from(&binary);
        expected.services.insert(service);
    }
    for (name, event, wait) in component.controls {
        expected
            .controls
            .insert((name, event, wait, binary.clone()));
    }
    shortcuts.extend(component.shortcuts);
}

/// The MSI's directories, components and files, to resolve ids to paths.
struct Resolver<'a> {
    directories: BTreeMap<&'a str, (&'a str, &'a str)>,
    components: BTreeMap<&'a str, (&'a str, &'a str)>,
    files: BTreeMap<&'a str, (&'a str, &'a str)>,
    /// Each component's condition.
    conditions: BTreeMap<&'a str, &'a str>,
}

/// A `Directory` or `File` name's long part (`short|long`, and for a
/// directory `target:source`).
fn long_name(name: &str) -> &str {
    let target = name.split(':').next().unwrap_or(name);
    target.rsplit('|').next().unwrap_or(target)
}

impl<'a> Resolver<'a> {
    fn new(tables: &'a BTreeMap<String, Table>) -> Self {
        let pairs = |table: &str, key: &str, a: &str, b: &str| {
            tables
                .get(table)
                .map(|t| {
                    t.rows
                        .iter()
                        .map(|r| (Table::get(r, key), (Table::get(r, a), Table::get(r, b))))
                        .collect()
                })
                .unwrap_or_default()
        };
        Self {
            directories: pairs("Directory", "Directory", "Directory_Parent", "DefaultDir"),
            components: pairs("Component", "Component", "Directory_", "KeyPath"),
            files: pairs("File", "File", "Component_", "FileName"),
            conditions: tables
                .get("Component")
                .map(|t| {
                    t.rows
                        .iter()
                        .map(|r| (Table::get(r, "Component"), Table::get(r, "Condition")))
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// A directory's path: its long names up to a standard folder.
    fn directory(&self, id: &str) -> Option<String> {
        let mut parts = Vec::new();
        let mut current = id;
        for _ in 0..64 {
            if STANDARD_FOLDERS.contains(&current) {
                if current != "TARGETDIR" {
                    parts.push(current.to_owned());
                }
                parts.reverse();
                return Some(
                    parts
                        .into_iter()
                        .filter(|p| !p.is_empty() && p != ".")
                        .collect::<Vec<_>>()
                        .join("/"),
                );
            }
            let (parent, name) = self.directories.get(current)?;
            parts.push(long_name(name).to_owned());
            current = parent;
        }
        None
    }

    /// A file's install path.
    fn file(&self, id: &str) -> Option<String> {
        let (component, name) = self.files.get(id)?;
        let (directory, _) = self.components.get(component)?;
        Some(join(&self.directory(directory)?, long_name(name)))
    }

    /// The install path of a component's key file.
    fn key_file(&self, component: &str) -> Option<String> {
        let (_, key) = self.components.get(component)?;
        self.file(key)
    }
}

/// Every way `tables` (each read by [`parse_sql_export`], by name) aren't
/// what `expected` declares, for the product whose UpgradeCode is
/// `upgrade_code`. Empty: the MSI's security-relevant tables are the
/// `.wxs`'s.
#[must_use]
pub fn findings(
    expected: &Expected,
    tables: &BTreeMap<String, Table>,
    upgrade_code: &str,
) -> Vec<String> {
    let mut findings = Vec::new();
    let rows = |name: &str| {
        tables
            .get(name)
            .map(|t| t.rows.as_slice())
            .unwrap_or_default()
    };
    let get = Table::get;
    for (name, table) in tables {
        if is_forbidden(name) && !table.rows.is_empty() {
            findings.push(format!(
                "{} row(s) in {name}, a table a seaworthy MSI never uses",
                table.rows.len()
            ));
        }
    }
    let read = COLUMNS.iter().copied().chain(
        SEQUENCES
            .iter()
            .map(|name| (*name, &["Action", "Condition"][..])),
    );
    for (name, columns) in read {
        let Some(table) = tables.get(name) else {
            continue;
        };
        for column in columns {
            if !table.columns.iter().any(|c| c == column) {
                findings.push(format!(
                    "its {name} table has no {column} column (the check reads it)"
                ));
            }
        }
    }
    let resolver = Resolver::new(tables);

    // Custom actions.
    let mut seen = BTreeSet::new();
    for row in rows("CustomAction") {
        let action = get(row, "Action");
        seen.insert(action.to_owned());
        match expected.actions.get(action) {
            None => findings.push(format!(
                "custom action {action}, which the .wxs doesn't declare"
            )),
            Some(declared) => {
                // An executable in the File table: by the file's install
                // path, never its key.
                let source = if declared.source_file {
                    resolver
                        .file(get(row, "Source"))
                        .unwrap_or_else(|| format!("<file {}>", get(row, "Source")))
                } else {
                    get(row, "Source").to_owned()
                };
                let found = (get(row, "Type"), source.as_str(), get(row, "Target"));
                if found
                    != (
                        declared.kind.as_str(),
                        declared.source.as_str(),
                        declared.target.as_str(),
                    )
                    || !get(row, "ExtendedType").is_empty()
                {
                    findings.push(format!(
                        "custom action {action} is {found:?}, not the .wxs's ({:?}, {:?}, {:?})",
                        declared.kind, declared.source, declared.target
                    ));
                }
            }
        }
    }
    for action in expected.actions.keys() {
        if !seen.contains(action) {
            findings.push(format!(
                "custom action {action}, which the .wxs declares, is missing"
            ));
        }
    }

    // The sequences.
    let mut scheduled: BTreeSet<(String, String)> = BTreeSet::new();
    for table in SEQUENCES {
        for row in rows(table) {
            let action = get(row, "Action");
            if STANDARD_ACTIONS.contains(&action) {
                continue;
            }
            let condition = get(row, "Condition");
            match expected.actions.get(action) {
                Some(declared)
                    if declared
                        .scheduled
                        .contains(&((*table).to_owned(), condition.to_owned())) =>
                {
                    scheduled.insert(((*table).to_owned(), action.to_owned()));
                }
                Some(_) => findings.push(format!(
                    "{table} runs {action} on {condition:?}, not where and when the .wxs schedules it"
                )),
                None => findings.push(format!(
                    "{table} runs {action}, neither a standard action nor a custom action the .wxs declares"
                )),
            }
        }
    }
    for (action, declared) in &expected.actions {
        for (table, _) in &declared.scheduled {
            if !scheduled.contains(&(table.clone(), action.clone())) {
                findings.push(format!(
                    "{table} doesn't run {action}, which the .wxs schedules there"
                ));
            }
        }
    }

    // Services.
    let mut services = BTreeSet::new();
    for row in rows("ServiceInstall") {
        let binary = resolver
            .key_file(get(row, "Component_"))
            .unwrap_or_else(|| format!("<component {}>", get(row, "Component_")));
        for column in ["LoadOrderGroup", "Dependencies", "Password"] {
            if !get(row, column).is_empty() {
                findings.push(format!("service {} has a {column}", get(row, "Name")));
            }
        }
        services.insert(Service {
            name: get(row, "Name").to_owned(),
            display_name: get(row, "DisplayName").to_owned(),
            kind: get(row, "ServiceType").to_owned(),
            start: get(row, "StartType").to_owned(),
            error_control: get(row, "ErrorControl").to_owned(),
            account: get(row, "StartName").to_owned(),
            arguments: get(row, "Arguments").to_owned(),
            description: get(row, "Description").to_owned(),
            binary,
        });
    }
    for extra in services.difference(&expected.services) {
        findings.push(format!(
            "a service the .wxs doesn't declare as such: {extra:?}"
        ));
    }
    for missing in expected.services.difference(&services) {
        findings.push(format!(
            "the .wxs's service is missing or other: {missing:?}"
        ));
    }
    let controls: BTreeSet<(String, String, String, String)> = rows("ServiceControl")
        .iter()
        .map(|row| {
            (
                get(row, "Name").to_owned(),
                get(row, "Event").to_owned(),
                get(row, "Wait").to_owned(),
                resolver
                    .key_file(get(row, "Component_"))
                    .unwrap_or_default(),
            )
        })
        .collect();
    let control_arguments = rows("ServiceControl")
        .iter()
        .any(|row| !get(row, "Arguments").is_empty());
    if control_arguments {
        findings.push("a service control with arguments".to_owned());
    }
    for extra in controls.difference(&expected.controls) {
        findings.push(format!(
            "a service control the .wxs doesn't declare: {extra:?}"
        ));
    }
    for missing in expected.controls.difference(&controls) {
        findings.push(format!(
            "the .wxs's service control is missing or other: {missing:?}"
        ));
    }

    // Registry values.
    let mut registry: BTreeMap<(String, String, String, String), usize> = BTreeMap::new();
    for row in rows("Registry") {
        let count = registry
            .entry((
                get(row, "Root").to_owned(),
                get(row, "Key").to_owned(),
                get(row, "Name").to_owned(),
                get(row, "Value").to_owned(),
            ))
            .or_insert(0);
        *count = count.saturating_add(1);
    }
    if registry != expected.registry {
        for (row, count) in &registry {
            if expected.registry.get(row) != Some(count) {
                findings.push(format!(
                    "registry value {row:?} (x{count}), which the .wxs doesn't declare so"
                ));
            }
        }
        for (row, count) in &expected.registry {
            if registry.get(row) != Some(count) {
                findings.push(format!(
                    "the .wxs's registry value {row:?} (x{count}) is missing"
                ));
            }
        }
    }

    // Descriptors.
    let service_names: BTreeMap<&str, &str> = rows("ServiceInstall")
        .iter()
        .map(|row| (get(row, "ServiceInstall"), get(row, "Name")))
        .collect();
    let mut locks: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for row in rows("MsiLockPermissionsEx") {
        let table = get(row, "Table");
        let object = get(row, "LockObject");
        let resolved = match table {
            "ServiceInstall" => service_names.get(object).map(|n| (*n).to_owned()),
            "CreateFolder" => resolver.directory(object),
            _ => None,
        }
        .unwrap_or_else(|| format!("<{table} {object}>"));
        if !get(row, "Condition").is_empty() {
            findings.push(format!("a descriptor on {resolved} with a condition"));
        }
        let count = locks
            .entry((table.to_owned(), resolved, get(row, "SDDLText").to_owned()))
            .or_insert(0);
        *count = count.saturating_add(1);
    }
    if locks != expected.locks {
        for (lock, count) in &locks {
            if expected.locks.get(lock) != Some(count) {
                findings.push(format!(
                    "descriptor {lock:?}, which the .wxs doesn't declare"
                ));
            }
        }
        for (lock, count) in &expected.locks {
            if locks.get(lock) != Some(count) {
                findings.push(format!("the .wxs's descriptor {lock:?} is missing"));
            }
        }
    }

    // Shortcuts.
    let shortcuts: BTreeSet<(String, String, String, String, String)> = rows("Shortcut")
        .iter()
        .map(|row| {
            let target = get(row, "Target");
            let target = target
                .strip_prefix("[#")
                .and_then(|t| t.strip_suffix(']'))
                .and_then(|id| resolver.file(id))
                .unwrap_or_else(|| target.to_owned());
            let working = get(row, "WkDir");
            let working = if working.is_empty() {
                String::new()
            } else {
                resolver
                    .directory(working)
                    .unwrap_or_else(|| format!("<directory {working}>"))
            };
            (
                resolver
                    .directory(get(row, "Directory_"))
                    .unwrap_or_else(|| format!("<directory {}>", get(row, "Directory_"))),
                long_name(get(row, "Name")).to_owned(),
                target,
                get(row, "Arguments").to_owned(),
                working,
            )
        })
        .collect();
    for extra in shortcuts.difference(&expected.shortcuts) {
        findings.push(format!("a shortcut the .wxs doesn't declare: {extra:?}"));
    }
    for missing in expected.shortcuts.difference(&shortcuts) {
        findings.push(format!(
            "the .wxs's shortcut is missing or other: {missing:?}"
        ));
    }

    // Environment changes: PATH, appending the directory the .wxs names,
    // the system's or the user's as it says, on its component's condition.
    let mut environment: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for row in rows("Environment") {
        let value = resolve_directory_reference(get(row, "Value"), |id| resolver.directory(id));
        let condition = resolver.conditions.get(get(row, "Component_")).map_or_else(
            || format!("<component {}>", get(row, "Component_")),
            |c| (*c).to_owned(),
        );
        let count = environment
            .entry((get(row, "Name").to_owned(), value, condition))
            .or_insert(0);
        *count = count.saturating_add(1);
    }
    if environment != expected.environment {
        for (row, count) in &environment {
            if expected.environment.get(row) != Some(count) {
                findings.push(format!(
                    "environment change {row:?} (x{count}), which the .wxs doesn't declare so"
                ));
            }
        }
        for (row, count) in &expected.environment {
            if environment.get(row) != Some(count) {
                findings.push(format!(
                    "the .wxs's environment change {row:?} (x{count}) is missing"
                ));
            }
        }
    }

    // Upgrades: the product's own, and detect-only searches for the
    // products the .wxs declares it conflicts with (never removed:
    // msidbUpgradeAttributesOnlyDetect, 2).
    let mut detected = BTreeSet::new();
    for row in rows("Upgrade") {
        let code = get(row, "UpgradeCode");
        if code.eq_ignore_ascii_case(upgrade_code)
            && code.eq_ignore_ascii_case(&expected.upgrade_code)
        {
            continue;
        }
        let property = get(row, "ActionProperty");
        let key = (code.to_ascii_uppercase(), property.to_owned());
        if !code.eq_ignore_ascii_case(upgrade_code) && expected.detections.contains(&key) {
            let detect_only = get(row, "Attributes")
                .parse::<u32>()
                .is_ok_and(|attributes| attributes & 2 == 2);
            if !detect_only || !get(row, "Remove").is_empty() {
                findings.push(format!(
                    "the upgrade row for {code} isn't detect-only (Attributes {:?}, Remove {:?}): it would remove that product",
                    get(row, "Attributes"),
                    get(row, "Remove")
                ));
            }
            detected.insert(key);
            continue;
        }
        findings.push(format!(
            "an upgrade row for {code} ({property}), neither the product's {upgrade_code} nor a product the .wxs detects"
        ));
    }
    for (code, property) in expected.detections.difference(&detected) {
        findings.push(format!(
            "the .wxs's detection of {code} ({property}) is missing"
        ));
    }
    findings
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn sql_exports_read_strictly() {
        let text = "CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` INT NOT NULL, `Source` CHAR(72), `Target` CHAR(255), `ExtendedType` LONG PRIMARY KEY `Action`)\n\
                    INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('A1', 34, 'System64Folder', 'it\\'s \"q\" \\\\ back')\n\
                    INSERT INTO `CustomAction` (`Action`, `Type`, `Source`) VALUES ('A2', -51, 'P')\n";
        let table = parse_sql_export(text).unwrap();
        assert_eq!(table.name, "CustomAction");
        assert_eq!(
            table.columns,
            ["Action", "Type", "Source", "Target", "ExtendedType"]
        );
        assert_eq!(table.rows[0]["Target"], "it's \"q\" \\ back");
        assert_eq!(table.rows[1]["Type"], "-51");
        assert_eq!(Table::get(&table.rows[1], "Target"), "");
        for bad in [
            "",
            "INSERT INTO `T` (`A`) VALUES ('x')",
            "CREATE TABLE `T` (`A` CHAR(72) PRIMARY KEY `A`)\nINSERT INTO `U` (`A`) VALUES ('x')",
            "CREATE TABLE `T` (`A` CHAR(72) PRIMARY KEY `A`)\nINSERT INTO `T` (`B`) VALUES ('x')",
            "CREATE TABLE `T` (`A` CHAR(72) PRIMARY KEY `A`)\nINSERT INTO `T` (`A`) VALUES ('x', 'y')",
            "CREATE TABLE `T` (`A` CHAR(72) PRIMARY KEY `A`)\nINSERT INTO `T` (`A`) VALUES ('x",
            "CREATE TABLE `T` (`A` CHAR(72) PRIMARY KEY `A`)\nINSERT INTO `T` (`A`, `A`) VALUES ('x', 'y')",
            "CREATE TABLE `T` (`A` CHAR(72) PRIMARY KEY `A`)\nDROP TABLE `T`",
            "CREATE TABLE `T` (`A` CHAR(72) PRIMARY KEY `A`)\nINSERT INTO `T` (`A`) VALUES (x)",
        ] {
            assert!(parse_sql_export(bad).is_err(), "{bad:?}");
        }
    }

    /// The agent's `.wxs` (tests/golden/wix/agent.wxs's shape) and the rows
    /// WiX 5 builds from it (tests/wix.rs reads them back from a real build).
    const WXS: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="Acme Agent" Manufacturer="Acme" Version="1.4.0" UpgradeCode="{B63268CD-0A50-87AF-AEB5-CE6EBFABEDF5}" Scope="perMachine" Language="1033" Codepage="65001" Compressed="yes" InstallerVersion="500">
    <SetProperty Id="ARPINSTALLLOCATION" Value="[InstallDir]" After="CostFinalize" Sequence="execute" />
    <Property Id="UPDATES" Secure="yes" />
    <SetProperty Id="UPDATES" Action="SetUpdatesDefault" Value="auto" After="AppSearch" Condition="NOT UPDATES" Sequence="both" />
    <StandardDirectory Id="System64Folder" />
    <CustomAction Id="ServiceRecovery" Directory="System64Folder" ExeCommand="&quot;[System64Folder]sc.exe&quot; failure AcmeAgent reset= 86400 actions= restart/15000" Execute="deferred" Impersonate="no" Return="check" />
    <CustomAction Id="ServiceRecoveryRollback" Directory="System64Folder" ExeCommand="&quot;[System64Folder]sc.exe&quot; failure AcmeAgent reset= 86400 actions= restart/15000" Execute="rollback" Impersonate="no" Return="ignore" />
    <CustomAction Id="ProgramDataFolders" FileRef="f000_AcmeTool.exe" ExeCommand="--seaworthy-install-programdata Acme Agent S-1-5-80-1 state:account logs:account updates update-logs" Execute="deferred" Impersonate="no" Return="check" />
    <InstallExecuteSequence>
      <Custom Action="ProgramDataFolders" After="InstallFiles" Condition="NOT Installed AND NOT REMOVE=&quot;ALL&quot;" />
      <Custom Action="ServiceRecovery" After="InstallServices" Condition="NOT Installed AND NOT REMOVE=&quot;ALL&quot;" />
      <Custom Action="ServiceRecoveryRollback" Before="DeleteServices" Condition="Installed AND REMOVE=&quot;ALL&quot;" />
    </InstallExecuteSequence>
    <StandardDirectory Id="ProgramFiles64Folder">
      <Directory Id="VendorDir" Name="Acme">
        <Directory Id="InstallDir" Name="Agent" />
      </Directory>
    </StandardDirectory>
    <StandardDirectory Id="CommonAppDataFolder">
      <Directory Id="DataVendorDir" Name="Acme">
        <Directory Id="DataDir" Name="Agent">
          <Directory Id="StateDir" Name="state" />
        </Directory>
      </Directory>
    </StandardDirectory>
    <StandardDirectory Id="ProgramMenuFolder" />
    <Feature Id="Main" Title="Acme Agent" AllowAbsent="no">
      <Component Id="c000_AcmeTool.exe" Directory="InstallDir" Bitness="always64">
        <File Id="f000_AcmeTool.exe" Source="!(bindpath.tree)\Acme\Agent\AcmeTool.exe" KeyPath="yes" />
        <ServiceInstall Id="Service" Name="AcmeAgent" DisplayName="Acme Agent" Description="Collects things for Acme." Type="ownProcess" Start="auto" ErrorControl="normal" Vital="yes" Account="NT SERVICE\AcmeAgent" Arguments="service --mode &quot;full scan&quot;" />
        <ServiceControl Id="ServiceControl" Name="AcmeAgent" Stop="both" Remove="uninstall" Wait="yes" />
        <ServiceControl Id="ServiceStart" Name="AcmeAgent" Start="install" Wait="no" />
      </Component>
      <Component Id="c004_AcmeToolUpdate.exe" Directory="InstallDir" Bitness="always64">
        <File Id="f004_AcmeToolUpdate.exe" Source="!(bindpath.tree)\Acme\Agent\AcmeToolUpdate.exe" KeyPath="yes" />
        <ServiceInstall Id="HelperService" Name="AcmeAgent-update" DisplayName="Acme Agent updater" Description="Installs signed releases of Acme Agent." Type="ownProcess" Start="demand" ErrorControl="normal" Vital="yes" Account="LocalSystem">
          <PermissionEx Sddl="D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)" />
        </ServiceInstall>
      </Component>
      <Component Id="StateDir" Directory="StateDir" Guid="{317F88CF-21D4-80AC-98DF-D6617DD9B78B}" Bitness="always64">
        <CreateFolder>
          <PermissionEx Sddl="O:SYD:P(A;OICI;FA;;;SY)" />
        </CreateFolder>
      </Component>
      <Component Id="UpdatePolicyDefault" Directory="InstallDir" Guid="{2C966902-A3C9-8F32-83F8-0358416D19D1}" Bitness="always64">
        <RegistryValue Root="HKLM" Key="SOFTWARE\Acme\Agent" Name="UpdatePolicy" Type="string" Value="[UPDATES]" KeyPath="yes" />
      </Component>
      <Component Id="StartMenuShortcut" Directory="ProgramMenuFolder" Guid="{33F95437-A9DD-8CFD-8631-7915FDB93869}" Bitness="always64">
        <Shortcut Id="StartMenuShortcut" Name="Acme Agent" Description="d" Target="[#f000_AcmeTool.exe]" WorkingDirectory="InstallDir" />
        <RegistryValue Root="HKCU" Key="SOFTWARE\Acme\Agent" Name="StartMenuShortcut" Type="integer" Value="1" KeyPath="yes" />
      </Component>
    </Feature>
  </Package>
</Wix>"#;

    const CODE: &str = "{B63268CD-0A50-87AF-AEB5-CE6EBFABEDF5}";

    /// The ProgramData folders' command line.
    const PROGRAMDATA: &str = "--seaworthy-install-programdata Acme Agent S-1-5-80-1 state:account logs:account updates update-logs";

    fn table(name: &str, columns: &[&str], rows: &[&[&str]]) -> (String, Table) {
        (
            name.to_owned(),
            Table {
                name: name.to_owned(),
                columns: columns.iter().map(|c| (*c).to_owned()).collect(),
                rows: rows
                    .iter()
                    .map(|row| {
                        columns
                            .iter()
                            .zip(row.iter())
                            .filter(|(_, v)| !v.is_empty())
                            .map(|(c, v)| ((*c).to_owned(), (*v).to_owned()))
                            .collect()
                    })
                    .collect(),
            },
        )
    }

    /// The rows WiX builds from [`WXS`], with WiX's own ids (short names,
    /// generated keys).
    fn wix_tables() -> BTreeMap<String, Table> {
        let sc = "\"[System64Folder]sc.exe\" failure AcmeAgent reset= 86400 actions= restart/15000";
        [
            table(
                "Directory",
                &["Directory", "Directory_Parent", "DefaultDir"],
                &[
                    &["TARGETDIR", "", "SourceDir"],
                    &["ProgramFiles64Folder", "TARGETDIR", "PFiles64"],
                    &["VendorDir", "ProgramFiles64Folder", "Acme"],
                    &["InstallDir", "VendorDir", "Agent"],
                    &["CommonAppDataFolder", "TARGETDIR", "CommApp"],
                    &["DataVendorDir", "CommonAppDataFolder", "Acme"],
                    &["DataDir", "DataVendorDir", "Agent"],
                    &["StateDir", "DataDir", "state"],
                    &["ProgramMenuFolder", "TARGETDIR", "."],
                    &["System64Folder", "TARGETDIR", "."],
                ],
            ),
            table(
                "Component",
                &[
                    "Component",
                    "ComponentId",
                    "Directory_",
                    "Attributes",
                    "Condition",
                    "KeyPath",
                ],
                &[
                    &[
                        "c000_AcmeTool.exe",
                        "{1}",
                        "InstallDir",
                        "256",
                        "",
                        "f000_AcmeTool.exe",
                    ],
                    &[
                        "c004_AcmeToolUpdate.exe",
                        "{2}",
                        "InstallDir",
                        "256",
                        "",
                        "f004_AcmeToolUpdate.exe",
                    ],
                    &["StateDir", "{3}", "StateDir", "260", "", ""],
                    &[
                        "UpdatePolicyDefault",
                        "{4}",
                        "InstallDir",
                        "260",
                        "",
                        "regA",
                    ],
                    &[
                        "StartMenuShortcut",
                        "{5}",
                        "ProgramMenuFolder",
                        "260",
                        "",
                        "regB",
                    ],
                ],
            ),
            table(
                "File",
                &["File", "Component_", "FileName", "FileSize"],
                &[
                    &[
                        "f000_AcmeTool.exe",
                        "c000_AcmeTool.exe",
                        "a1b2c3d4.exe|AcmeTool.exe",
                        "3",
                    ],
                    &[
                        "f004_AcmeToolUpdate.exe",
                        "c004_AcmeToolUpdate.exe",
                        "e5f6a7b8.exe|AcmeToolUpdate.exe",
                        "3",
                    ],
                ],
            ),
            table(
                "CustomAction",
                &["Action", "Type", "Source", "Target", "ExtendedType"],
                &[
                    &[
                        "SetARPINSTALLLOCATION",
                        "51",
                        "ARPINSTALLLOCATION",
                        "[InstallDir]",
                        "",
                    ],
                    &["SetUpdatesDefault", "51", "UPDATES", "auto", ""],
                    &["ServiceRecovery", "3106", "System64Folder", sc, ""],
                    &["ServiceRecoveryRollback", "3426", "System64Folder", sc, ""],
                    // An executable in the File table (18) + deferred (1024) + no
                    // impersonation (2048).
                    &[
                        "ProgramDataFolders",
                        "3090",
                        "f000_AcmeTool.exe",
                        PROGRAMDATA,
                        "",
                    ],
                ],
            ),
            table(
                "InstallExecuteSequence",
                &["Action", "Condition", "Sequence"],
                &[
                    &["CostInitialize", "", "800"],
                    &["AppSearch", "", "50"],
                    &["SetUpdatesDefault", "NOT UPDATES", "51"],
                    &["CostFinalize", "", "1000"],
                    &["SetARPINSTALLLOCATION", "", "1001"],
                    &["InstallFiles", "", "4000"],
                    &[
                        "ProgramDataFolders",
                        "NOT Installed AND NOT REMOVE=\"ALL\"",
                        "4001",
                    ],
                    &["InstallServices", "VersionNT", "5800"],
                    &[
                        "ServiceRecovery",
                        "NOT Installed AND NOT REMOVE=\"ALL\"",
                        "5801",
                    ],
                    &[
                        "ServiceRecoveryRollback",
                        "Installed AND REMOVE=\"ALL\"",
                        "1999",
                    ],
                    &["DeleteServices", "VersionNT", "2000"],
                ],
            ),
            table(
                "InstallUISequence",
                &["Action", "Condition", "Sequence"],
                &[
                    &["AppSearch", "", "50"],
                    &["SetUpdatesDefault", "NOT UPDATES", "51"],
                    &["ExecuteAction", "", "1300"],
                ],
            ),
            table(
                "AdminExecuteSequence",
                &["Action", "Condition", "Sequence"],
                &[&["InstallFiles", "", "4000"]],
            ),
            table(
                "ServiceInstall",
                &[
                    "ServiceInstall",
                    "Name",
                    "DisplayName",
                    "ServiceType",
                    "StartType",
                    "ErrorControl",
                    "LoadOrderGroup",
                    "Dependencies",
                    "StartName",
                    "Password",
                    "Arguments",
                    "Component_",
                    "Description",
                ],
                &[
                    &[
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
                        "Collects things for Acme.",
                    ],
                    &[
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
                        "Installs signed releases of Acme Agent.",
                    ],
                ],
            ),
            table(
                "ServiceControl",
                &[
                    "ServiceControl",
                    "Name",
                    "Event",
                    "Arguments",
                    "Wait",
                    "Component_",
                ],
                &[
                    &[
                        "ServiceControl",
                        "AcmeAgent",
                        "162",
                        "",
                        "1",
                        "c000_AcmeTool.exe",
                    ],
                    &[
                        "ServiceStart",
                        "AcmeAgent",
                        "1",
                        "",
                        "0",
                        "c000_AcmeTool.exe",
                    ],
                ],
            ),
            table(
                "MsiLockPermissionsEx",
                &[
                    "MsiLockPermissionsEx",
                    "LockObject",
                    "Table",
                    "SDDLText",
                    "Condition",
                ],
                &[
                    &[
                        "lockA",
                        "HelperService",
                        "ServiceInstall",
                        "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)",
                        "",
                    ],
                    &[
                        "lockB",
                        "StateDir",
                        "CreateFolder",
                        "O:SYD:P(A;OICI;FA;;;SY)",
                        "",
                    ],
                ],
            ),
            table(
                "Registry",
                &["Registry", "Root", "Key", "Name", "Value", "Component_"],
                &[
                    &[
                        "regA",
                        "2",
                        "SOFTWARE\\Acme\\Agent",
                        "UpdatePolicy",
                        "[UPDATES]",
                        "UpdatePolicyDefault",
                    ],
                    &[
                        "regB",
                        "1",
                        "SOFTWARE\\Acme\\Agent",
                        "StartMenuShortcut",
                        "#1",
                        "StartMenuShortcut",
                    ],
                ],
            ),
            table(
                "Shortcut",
                &[
                    "Shortcut",
                    "Directory_",
                    "Name",
                    "Component_",
                    "Target",
                    "Arguments",
                    "Description",
                    "Hotkey",
                    "Icon_",
                    "IconIndex",
                    "ShowCmd",
                    "WkDir",
                ],
                &[&[
                    "StartMenuShortcut",
                    "ProgramMenuFolder",
                    "ap2s5seg|Acme Agent",
                    "StartMenuShortcut",
                    "[#f000_AcmeTool.exe]",
                    "",
                    "d",
                    "",
                    "",
                    "",
                    "",
                    "InstallDir",
                ]],
            ),
            table(
                "Upgrade",
                &[
                    "UpgradeCode",
                    "VersionMin",
                    "VersionMax",
                    "Language",
                    "Attributes",
                    "Remove",
                    "ActionProperty",
                ],
                &[
                    &[CODE, "", "1.4.0", "1033", "513", "", "WIX_UPGRADE_DETECTED"],
                    &[CODE, "1.4.0", "", "1033", "2", "", "WIX_DOWNGRADE_DETECTED"],
                ],
            ),
            table("Binary", &["Name", "Data"], &[]),
            table(
                "RemoveFile",
                &[
                    "FileKey",
                    "Component_",
                    "FileName",
                    "DirProperty",
                    "InstallMode",
                ],
                &[],
            ),
        ]
        .into_iter()
        .collect()
    }

    fn set(
        tables: &mut BTreeMap<String, Table>,
        name: &str,
        row: usize,
        column: &str,
        value: &str,
    ) {
        tables.get_mut(name).unwrap().rows[row].insert(column.to_owned(), value.to_owned());
    }

    #[test]
    fn wix_s_build_of_the_wxs_passes() {
        let expected = expected_from_wxs(WXS).unwrap();
        let found = findings(&expected, &wix_tables(), CODE);
        assert!(found.is_empty(), "{found:#?}");
    }

    /// [`wix_tables`]'s descriptors as `msiinfo export -s` (msitools 0.106)
    /// prints a table of the schema WiX builds `MsiLockPermissionsEx` with:
    /// the SDDL is the `SDDLText` column, and a NULL `Condition` is left
    /// out of the row.
    const LOCK_EXPORT: &str = "CREATE TABLE `MsiLockPermissionsEx` (`MsiLockPermissionsEx` CHAR(72) NOT NULL, `LockObject` CHAR(72) NOT NULL, `Table` CHAR(32) NOT NULL, `SDDLText` CHAR(0) NOT NULL, `Condition` CHAR(255) PRIMARY KEY `MsiLockPermissionsEx`)\n\
        INSERT INTO `MsiLockPermissionsEx` (`MsiLockPermissionsEx`, `LockObject`, `Table`, `SDDLText`) VALUES ('lockA', 'HelperService', 'ServiceInstall', 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)')\n\
        INSERT INTO `MsiLockPermissionsEx` (`MsiLockPermissionsEx`, `LockObject`, `Table`, `SDDLText`) VALUES ('lockB', 'StateDir', 'CreateFolder', 'O:SYD:P(A;OICI;FA;;;SY)')\n";

    /// [`wix_tables`] with its descriptors read from `export`.
    fn with_locks(export: &str) -> BTreeMap<String, Table> {
        let mut tables = wix_tables();
        let locks = parse_sql_export(export).unwrap();
        tables.insert(locks.name.clone(), locks);
        tables
    }

    #[test]
    fn descriptors_as_msiinfo_exports_them_are_compared_by_their_sddl() {
        // A service MSI's descriptors, read as adopt-msi reads them: each
        // matches the .wxs's PermissionEx, SDDL and all.
        let expected = expected_from_wxs(WXS).unwrap();
        let found = findings(&expected, &with_locks(LOCK_EXPORT), CODE);
        assert!(found.is_empty(), "{found:#?}");
        // Another SDDL on the same directory is found, both ways.
        let other = LOCK_EXPORT.replace("O:SYD:P(A;OICI;FA;;;SY)", "O:SYD:P(A;OICI;FA;;;WD)");
        let found = findings(&expected, &with_locks(&other), CODE);
        let lock = |sddl: &str| {
            format!("(\"CreateFolder\", \"CommonAppDataFolder/Acme/Agent/state\", \"{sddl}\")")
        };
        for wanted in [
            format!(
                "descriptor {}, which the .wxs doesn't declare",
                lock("O:SYD:P(A;OICI;FA;;;WD)")
            ),
            format!(
                "the .wxs's descriptor {} is missing",
                lock("O:SYD:P(A;OICI;FA;;;SY)")
            ),
        ] {
            assert!(found.contains(&wanted), "{wanted}: {found:#?}");
        }
    }

    #[test]
    fn a_table_without_a_column_the_check_reads_is_found() {
        let expected = expected_from_wxs(WXS).unwrap();
        // The SDDL under another column name is never read as an empty
        // SDDL.
        let renamed = LOCK_EXPORT.replace("`SDDLText`", "`SDDL`");
        let found = findings(&expected, &with_locks(&renamed), CODE);
        let wanted = "its MsiLockPermissionsEx table has no SDDLText column (the check reads it)";
        assert!(found.iter().any(|f| f == wanted), "{found:#?}");
        // Every column the check reads, gone from its table.
        let sequences = SEQUENCES
            .iter()
            .map(|name| (*name, &["Action", "Condition"][..]));
        let mut checked = 0_usize;
        // With PATH, so every compared table is there.
        let expected = expected_from_wxs(&with_path(WXS)).unwrap();
        for (name, columns) in COLUMNS.iter().copied().chain(sequences) {
            let tables = path_tables();
            if !tables.contains_key(name) {
                assert!(SEQUENCES.contains(&name), "wix_tables lacks {name}");
                continue;
            }
            for column in columns {
                let mut tables = tables.clone();
                let table = tables.get_mut(name).unwrap();
                table.columns.retain(|c| c != column);
                for row in &mut table.rows {
                    row.remove(*column);
                }
                let found = findings(&expected, &tables, CODE);
                let wanted =
                    format!("its {name} table has no {column} column (the check reads it)");
                assert!(found.contains(&wanted), "{wanted}: {found:#?}");
                checked = checked.saturating_add(1);
            }
        }
        assert!(checked >= 40, "{checked}");
    }

    /// A product conflicting with another: the `.wxs` searches for the
    /// other's UpgradeCode, detect-only, and WiX's table holds that row
    /// beside the product's own; adopt-msi accepts exactly that.
    #[test]
    fn a_detect_only_search_for_a_conflicting_product_is_accepted() {
        const OTHER: &str = "{2B4E6A80-1C3D-4F5E-8A7B-9C0D1E2F3A4B}";
        let wxs = WXS.replacen(
            "<StandardDirectory Id=\"System64Folder\" />",
            &format!(
                "<Upgrade Id=\"{}\">\n      <UpgradeVersion Minimum=\"0.0.0\" IncludeMinimum=\"yes\" OnlyDetect=\"yes\" Property=\"CONFLICT_TROVE_PORTABLE\" />\n    </Upgrade>\n    <Launch Condition=\"Installed OR NOT CONFLICT_TROVE_PORTABLE\" Message=\"[ProductName] can't be installed while Trove is installed: uninstall Trove first.\" />\n    <StandardDirectory Id=\"System64Folder\" />",
                OTHER.to_ascii_lowercase()
            ),
            1,
        );
        assert_ne!(wxs, WXS);
        let expected = expected_from_wxs(&wxs).unwrap();
        let with_row = |attributes: &str, remove: &str, property: &str, code: &str| {
            let mut tables = wix_tables();
            let mut row = BTreeMap::new();
            for (column, value) in [
                ("UpgradeCode", code),
                ("VersionMin", "0.0.0"),
                ("VersionMax", ""),
                ("Language", ""),
                ("Attributes", attributes),
                ("Remove", remove),
                ("ActionProperty", property),
            ] {
                row.insert(column.to_owned(), value.to_owned());
            }
            tables.get_mut("Upgrade").unwrap().rows.push(row);
            findings(&expected, &tables, CODE)
        };
        // WiX's row: OnlyDetect (2) and VersionMinInclusive (256).
        let found = with_row("258", "", "CONFLICT_TROVE_PORTABLE", OTHER);
        assert!(found.is_empty(), "{found:#?}");
        // The search missing from the MSI.
        let found = findings(&expected, &wix_tables(), CODE);
        assert!(
            found.iter().any(|f| f.contains("detection of {2B4E6A80")),
            "{found:#?}"
        );
        // A row that would remove the other product, or another property.
        for (attributes, remove, property, code, mentions) in [
            (
                "256",
                "",
                "CONFLICT_TROVE_PORTABLE",
                OTHER,
                "isn't detect-only",
            ),
            (
                "258",
                "ALL",
                "CONFLICT_TROVE_PORTABLE",
                OTHER,
                "isn't detect-only",
            ),
            (
                "258",
                "",
                "WIX_UPGRADE_DETECTED",
                OTHER,
                "neither the product's",
            ),
            (
                "258",
                "",
                "CONFLICT_TROVE_PORTABLE",
                "{00000000-0000-0000-0000-000000000000}",
                "neither the product's",
            ),
        ] {
            let found = with_row(attributes, remove, property, code);
            assert!(
                found.iter().any(|f| f.contains(mentions)),
                "{attributes} {remove} {property} {code}: {found:#?}"
            );
        }
        // Without the .wxs declaring it, the same row is refused.
        let plain = expected_from_wxs(WXS).unwrap();
        let mut tables = wix_tables();
        let mut row = tables["Upgrade"].rows[1].clone();
        row.insert("UpgradeCode".to_owned(), OTHER.to_owned());
        row.insert(
            "ActionProperty".to_owned(),
            "CONFLICT_TROVE_PORTABLE".to_owned(),
        );
        tables.get_mut("Upgrade").unwrap().rows.push(row);
        let found = findings(&plain, &tables, CODE);
        assert!(
            found.iter().any(|f| f.contains("neither the product's")),
            "{found:#?}"
        );
        // A .wxs whose search isn't detect-only, or names no UpgradeCode
        // (`Code` is no attribute of WiX's), is refused outright.
        for bad in [
            wxs.replace("OnlyDetect=\"yes\" ", ""),
            wxs.replace(" Property=\"CONFLICT_TROVE_PORTABLE\"", ""),
            wxs.replace("<Upgrade Id", "<Upgrades Id"),
            wxs.replace("<Upgrade Id", "<Upgrade Code"),
        ] {
            assert!(expected_from_wxs(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn every_change_that_matters_is_found() {
        let expected = expected_from_wxs(WXS).unwrap();
        let check = |change: &dyn Fn(&mut BTreeMap<String, Table>), wanted: &str| {
            let mut tables = wix_tables();
            change(&mut tables);
            let found = findings(&expected, &tables, CODE);
            assert!(
                found.iter().any(|f| f.contains(wanted)),
                "{wanted}: {found:#?}"
            );
        };
        // Another command line, or an action running as the user.
        check(
            &|t| set(t, "CustomAction", 2, "Target", "cmd.exe /c evil"),
            "custom action ServiceRecovery is",
        );
        check(
            &|t| set(t, "CustomAction", 2, "Type", "34"),
            "custom action ServiceRecovery is",
        );
        // A custom action of its own, run from a stream.
        check(
            &|t| {
                t.get_mut("CustomAction").unwrap().rows.push(
                    [
                        ("Action", "Evil"),
                        ("Type", "1"),
                        ("Source", "evil"),
                        ("Target", "Run"),
                    ]
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
                );
                t.get_mut("InstallExecuteSequence").unwrap().rows.push(
                    [("Action", "Evil"), ("Sequence", "4001")]
                        .into_iter()
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .collect(),
                );
                t.get_mut("Binary").unwrap().rows.push(
                    [("Name", "evil")]
                        .into_iter()
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .collect(),
                );
            },
            "custom action Evil, which the .wxs doesn't declare",
        );
        check(
            &|t| {
                t.get_mut("Binary").unwrap().rows.push(BTreeMap::new());
            },
            "row(s) in Binary",
        );
        // A declared action dropped, or run on another condition.
        check(
            &|t| {
                t.get_mut("CustomAction").unwrap().rows.remove(2);
            },
            "ServiceRecovery, which the .wxs declares, is missing",
        );
        check(
            &|t| set(t, "InstallExecuteSequence", 8, "Condition", "1"),
            "runs ServiceRecovery on \"1\"",
        );
        check(
            &|t| set(t, "InstallExecuteSequence", 8, "Action", "ForceReboot"),
            "neither a standard action",
        );
        // The launcher's ProgramData action running another of the payload's
        // files (by key or by path), another command line, or as the user.
        check(
            &|t| set(t, "CustomAction", 4, "Source", "f004_AcmeToolUpdate.exe"),
            "custom action ProgramDataFolders is",
        );
        check(
            &|t| set(t, "File", 0, "FileName", "x|AcmeToolUpdate.exe"),
            "custom action ProgramDataFolders is",
        );
        check(
            &|t| set(t, "CustomAction", 4, "Source", "nowhere"),
            "custom action ProgramDataFolders is (\"3090\", \"<file nowhere>\"",
        );
        check(
            &|t| set(t, "CustomAction", 4, "Target", "--evil"),
            "custom action ProgramDataFolders is",
        );
        check(
            &|t| set(t, "CustomAction", 4, "Type", "1042"),
            "custom action ProgramDataFolders is",
        );
        check(
            &|t| set(t, "InstallExecuteSequence", 6, "Condition", ""),
            "runs ProgramDataFolders on \"\"",
        );
        // A service running another binary, as another account, or another start.
        check(
            &|t| {
                set(
                    t,
                    "ServiceInstall",
                    0,
                    "Component_",
                    "c004_AcmeToolUpdate.exe",
                )
            },
            "a service the .wxs doesn't declare as such",
        );
        check(
            &|t| set(t, "ServiceInstall", 0, "StartName", "LocalSystem"),
            "a service the .wxs doesn't declare as such",
        );
        check(
            &|t| set(t, "ServiceInstall", 0, "Arguments", "--evil"),
            "a service the .wxs doesn't declare as such",
        );
        check(
            &|t| set(t, "ServiceInstall", 0, "Password", "x"),
            "service AcmeAgent has a Password",
        );
        // The service's binary moved: its component's key file is another one.
        check(
            &|t| set(t, "Component", 0, "KeyPath", "f004_AcmeToolUpdate.exe"),
            "a service the .wxs doesn't declare as such",
        );
        check(
            &|t| set(t, "File", 0, "FileName", "x|AcmeToolUpdate.exe"),
            "a service the .wxs doesn't declare as such",
        );
        check(
            &|t| set(t, "ServiceControl", 0, "Event", "0"),
            "a service control the .wxs doesn't declare",
        );
        // A registry value of its own, or another value.
        check(
            &|t| set(t, "Registry", 0, "Value", "auto"),
            "registry value",
        );
        check(&|t| set(t, "Registry", 0, "Root", "1"), "registry value");
        // A descriptor on another directory (System32), or another SDDL.
        check(
            &|t| {
                set(t, "Directory", 7, "Directory_Parent", "System64Folder");
            },
            "descriptor",
        );
        check(
            &|t| {
                set(
                    t,
                    "MsiLockPermissionsEx",
                    1,
                    "SDDLText",
                    "D:(A;OICI;FA;;;WD)",
                )
            },
            "descriptor",
        );
        check(
            &|t| set(t, "MsiLockPermissionsEx", 0, "LockObject", "Service"),
            "descriptor",
        );
        // A shortcut to another file, with arguments, elsewhere.
        check(
            &|t| set(t, "Shortcut", 0, "Target", "[#f004_AcmeToolUpdate.exe]"),
            "a shortcut the .wxs doesn't declare",
        );
        check(
            &|t| set(t, "Shortcut", 0, "Arguments", "--evil"),
            "a shortcut the .wxs doesn't declare",
        );
        check(
            &|t| set(t, "Shortcut", 0, "Target", "C:\\Windows\\System32\\cmd.exe"),
            "a shortcut the .wxs doesn't declare",
        );
        // Another product's upgrade.
        check(
            &|t| {
                set(
                    t,
                    "Upgrade",
                    0,
                    "UpgradeCode",
                    "{00000000-0000-0000-0000-000000000000}",
                )
            },
            "an upgrade row for {00000000",
        );
        // A table a seaworthy MSI never uses.
        // An environment change of its own.
        check(
            &|t| {
                t.insert(
                    "Environment".to_owned(),
                    Table {
                        name: "Environment".to_owned(),
                        columns: ["Environment", "Name", "Value", "Component_"]
                            .map(str::to_owned)
                            .to_vec(),
                        rows: vec![
                            [
                                ("Environment", "e"),
                                ("Name", "=-*PATH"),
                                ("Value", "[~];C:\\evil"),
                                ("Component_", "c000_AcmeTool.exe"),
                            ]
                            .into_iter()
                            .map(|(k, v)| (k.to_owned(), v.to_owned()))
                            .collect(),
                        ],
                    },
                );
            },
            "environment change (\"=-*PATH\", \"[~];C:\\\\evil\", \"\")",
        );
        check(
            &|t| {
                t.insert(
                    "ODBCDriver".to_owned(),
                    Table {
                        name: "ODBCDriver".to_owned(),
                        columns: Vec::new(),
                        rows: vec![BTreeMap::new()],
                    },
                );
            },
            "row(s) in ODBCDriver",
        );
    }

    /// `PATH` for either scope: two components, each conditioned on the
    /// scope Windows Installer chose, appending the install directory to
    /// the system's or the user's.
    fn with_path(wxs: &str) -> String {
        wxs.replacen(
            "    </Feature>",
            "      <Component Id=\"PathMachine\" Directory=\"InstallDir\" Guid=\"{7}\" Bitness=\"always64\" Condition=\"ALLUSERS = 1\">\n        <CreateFolder />\n        <Environment Id=\"PathMachine\" Name=\"PATH\" Value=\"[InstallDir]\" Action=\"set\" Part=\"last\" System=\"yes\" />\n      </Component>\n      <Component Id=\"PathUser\" Directory=\"InstallDir\" Guid=\"{8}\" Bitness=\"always64\" Condition=\"NOT ALLUSERS\">\n        <CreateFolder />\n        <Environment Id=\"PathUser\" Name=\"PATH\" Value=\"[InstallDir]\" Action=\"set\" Part=\"last\" System=\"no\" />\n      </Component>\n    </Feature>",
            1,
        )
    }

    /// [`wix_tables`] with the rows WiX builds for [`with_path`]'s
    /// components (its binder's `AddEnvironmentSymbol`).
    fn path_tables() -> BTreeMap<String, Table> {
        let mut tables = wix_tables();
        let component = tables.get_mut("Component").unwrap();
        for (id, condition) in [
            ("PathMachine", "ALLUSERS = 1"),
            ("PathUser", "NOT ALLUSERS"),
        ] {
            component.rows.push(
                [
                    ("Component", id),
                    ("ComponentId", "{7}"),
                    ("Directory_", "InstallDir"),
                    ("Attributes", "256"),
                    ("Condition", condition),
                ]
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            );
        }
        let (name, table) = table(
            "Environment",
            &["Environment", "Name", "Value", "Component_"],
            &[
                &["PathMachine", "=-*PATH", "[~];[InstallDir]", "PathMachine"],
                &["PathUser", "=-PATH", "[~];[InstallDir]", "PathUser"],
            ],
        );
        tables.insert(name, table);
        tables
    }

    #[test]
    fn path_is_appended_as_the_wxs_says() {
        let expected = expected_from_wxs(&with_path(WXS)).unwrap();
        let found = findings(&expected, &path_tables(), CODE);
        assert!(found.is_empty(), "{found:#?}");
        let check = |change: &dyn Fn(&mut BTreeMap<String, Table>), wanted: &str| {
            let mut tables = path_tables();
            change(&mut tables);
            let found = findings(&expected, &tables, CODE);
            assert!(
                found.iter().any(|f| f.contains(wanted)),
                "{wanted}: {found:#?}"
            );
        };
        // The user's PATH made the system's, a prepend, a value kept on
        // uninstall, another directory, another condition, a row dropped.
        check(
            &|t| set(t, "Environment", 1, "Name", "=-*PATH"),
            "environment change (\"=-*PATH\", \"[~];<ProgramFiles64Folder/Acme/Agent>\", \"NOT ALLUSERS\")",
        );
        check(
            &|t| set(t, "Environment", 0, "Value", "[InstallDir];[~]"),
            "environment change (\"=-*PATH\", \"[InstallDir];[~]\"",
        );
        check(
            &|t| set(t, "Environment", 0, "Name", "=*PATH"),
            "environment change (\"=*PATH\"",
        );
        check(
            &|t| set(t, "Environment", 0, "Value", "[~];[StateDir]"),
            "[~];<CommonAppDataFolder/Acme/Agent/state>",
        );
        check(
            &|t| set(t, "Component", 5, "Condition", "1"),
            "environment change (\"=-*PATH\", \"[~];<ProgramFiles64Folder/Acme/Agent>\", \"1\")",
        );
        check(
            &|t| {
                t.get_mut("Environment").unwrap().rows.remove(1);
            },
            "the .wxs's environment change (\"=-PATH\"",
        );
        // A column the check reads, missing.
        check(
            &|t| {
                let table = t.get_mut("Environment").unwrap();
                table.columns.retain(|c| c != "Value");
                for row in &mut table.rows {
                    row.remove("Value");
                }
            },
            "its Environment table has no Value column",
        );
        // Without the .wxs's PATH, the same rows are refused.
        let plain = expected_from_wxs(WXS).unwrap();
        let found = findings(&plain, &path_tables(), CODE);
        assert_eq!(
            found
                .iter()
                .filter(|f| f.starts_with("environment change"))
                .count(),
            2,
            "{found:#?}"
        );
        // Anything but an appended, uninstalled PATH isn't modeled.
        for (from, to) in [
            ("Name=\"PATH\" Value", "Name=\"PATHEXT\" Value"),
            (
                "Part=\"last\" System=\"yes\"",
                "Part=\"first\" System=\"yes\"",
            ),
            (
                "Action=\"set\" Part=\"last\" System=\"yes\"",
                "Action=\"create\" System=\"yes\"",
            ),
            ("System=\"yes\" />", "System=\"yes\" Permanent=\"yes\" />"),
            ("System=\"yes\" />", "System=\"yes\" Separator=\",\" />"),
        ] {
            let wxs = with_path(WXS);
            assert!(wxs.contains(from), "{from}");
            assert!(
                expected_from_wxs(&wxs.replacen(from, to, 1)).is_err(),
                "{to}"
            );
        }
    }

    #[test]
    fn a_wxs_this_check_can_t_model_is_refused() {
        for (from, to, wanted) in [
            (
                "<StandardDirectory Id=\"ProgramMenuFolder\" />",
                "<StandardDirectory Id=\"ProgramMenuFolder\" /><util:CloseApplication Id=\"x\" />",
                "a WiX extension's element",
            ),
            (
                "<StandardDirectory Id=\"ProgramMenuFolder\" />",
                "<Environment Id=\"x\" Name=\"PATH\" Value=\"x\" />",
                "<Environment>",
            ),
            (
                "Execute=\"deferred\" Impersonate=\"no\" Return=\"check\"",
                "Execute=\"oncePerProcess\"",
                "Execute=\"oncePerProcess\"",
            ),
            (
                "Type=\"integer\" Value=\"1\"",
                "Type=\"multiString\" Value=\"1\"",
                "Type=\"multiString\"",
            ),
            (
                "Action=\"ServiceRecovery\" After",
                "Action=\"Undeclared\" After",
                "schedules Undeclared",
            ),
            (
                "FileRef=\"f000_AcmeTool.exe\"",
                "FileRef=\"f999\"",
                "runs f999, a file the .wxs doesn't install",
            ),
            (
                "FileRef=\"f000_AcmeTool.exe\"",
                "FileRef=\"f000_AcmeTool.exe\" Directory=\"InstallDir\"",
                "a kind this check doesn't model",
            ),
        ] {
            assert!(WXS.contains(from), "{from}");
            let err = expected_from_wxs(&WXS.replacen(from, to, 1)).unwrap_err();
            assert!(err.contains(wanted), "{wanted}: {err}");
        }
    }

    /// Every `.wxs` the packaging tests keep as golden files (what
    /// `wix.rs` writes for a service with the helper, a LocalSystem
    /// service, a desktop product): every element modeled.
    #[test]
    fn every_golden_wxs_is_modeled() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/wix");
        let mut read = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "wxs") {
                let text = std::fs::read_to_string(&path).unwrap();
                expected_from_wxs(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                read += 1;
            }
        }
        assert!(read >= 3, "{read} golden .wxs files");
        // The agent's: its ProgramData action runs the launcher.
        let agent = std::fs::read_to_string(dir.join("agent.wxs")).unwrap();
        let expected = expected_from_wxs(&agent).unwrap();
        let action = &expected.actions["ProgramDataFolders"];
        assert_eq!(action.kind, "3090");
        assert_eq!(
            action.source,
            "ProgramFiles64Folder/Acme/Agent/AcmeTool.exe"
        );
        assert!(
            action
                .target
                .starts_with("--seaworthy-install-programdata Acme Agent ")
        );
    }

    #[test]
    fn ids_resolve_to_paths() {
        let tables = wix_tables();
        let resolver = Resolver::new(&tables);
        assert_eq!(
            resolver.directory("StateDir").as_deref(),
            Some("CommonAppDataFolder/Acme/Agent/state")
        );
        assert_eq!(
            resolver.file("f000_AcmeTool.exe").as_deref(),
            Some("ProgramFiles64Folder/Acme/Agent/AcmeTool.exe")
        );
        assert_eq!(
            resolver.directory("ProgramMenuFolder").as_deref(),
            Some("ProgramMenuFolder")
        );
        assert_eq!(resolver.directory("nowhere"), None);
        assert_eq!(long_name("a1b2|Acme Agent"), "Acme Agent");
        assert_eq!(long_name("tgt|Target:src|Source"), "Target");
    }
}
