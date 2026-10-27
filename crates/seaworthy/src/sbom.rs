//! A software bill of materials per artifact (step 7 of the pipeline):
//! CycloneDX 1.6 JSON, `<artifact>.cdx.json`, beside every
//! installable artifact.
//!
//! What each SBOM says:
//!
//! - **The artifact** (`metadata.component`): the package name, the release
//!   version, its supplier (the vendor), its SHA-512, and its format,
//!   target, release sequence and build metadata (`package --build`, often
//!   the commit; left out when there is none) as properties.
//! - **Every file it installs** (`components`, type `file`): the install
//!   path and the SHA-256 of the shipped bytes, generated files (systemd
//!   units, the preset) included.
//! - **Every Rust crate compiled into its binaries**, when the binaries
//!   were built with `cargo auditable` (type `library`): `cargo auditable`
//!   embeds the resolved dependency tree in a `.dep-v0` section (zlib
//!   JSON), which `seaworthy` reads, since it never compiles and can't learn
//!   the graph otherwise. Crates from crates.io get a
//!   `pkg:cargo/<name>@<version>` purl; build-time-only crates (build
//!   scripts, proc macros) are left out, as they ship nothing. A binary
//!   without the section contributes its file entry only.
//!
//! The document is byte-reproducible: components and dependencies are
//! sorted, the serial number is a version 8 UUID derived from the
//! artifact's SHA-512, and the timestamp is `SOURCE_DATE_EPOCH`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::DistError;
use crate::config::Config;
use crate::version::Release;

/// The largest `.dep-v0` payload read, compressed and decompressed: a large
/// workspace's tree is tens of kilobytes.
const MAX_AUDIT_DATA: usize = 8 << 20;

/// One file an artifact installs.
#[derive(Debug, Clone)]
pub struct SbomFile {
    /// Where it installs.
    pub path: String,
    /// SHA-256 of its bytes, hex.
    pub sha256: String,
    /// A binary to read `cargo auditable` data from, if it is one.
    pub binary: Option<PathBuf>,
}

/// One crate in a binary's `cargo auditable` data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub struct Crate {
    /// The crate name.
    pub name: String,
    /// Its version.
    pub version: String,
    /// Where it came from: `crates.io`, `local`, `git`, `registry`, …
    #[serde(default)]
    pub source: String,
    /// `runtime` or `build`.
    #[serde(default = "runtime")]
    pub kind: String,
    /// Indices of the crates it depends on.
    #[serde(default)]
    pub dependencies: Vec<usize>,
    /// Whether it's the binary's own root crate.
    #[serde(default)]
    pub root: bool,
}

fn runtime() -> String {
    "runtime".to_owned()
}

#[derive(Deserialize)]
struct AuditData {
    packages: Vec<Crate>,
}

/// The crates `cargo auditable` recorded in `binary` (an ELF or PE image):
/// `None` when it has no `.dep-v0` section.
///
/// # Errors
/// [`DistError::Layout`] for a section that doesn't decompress or parse,
/// or exceeds the size bound.
pub fn auditable_crates(binary: &[u8]) -> Result<Option<Vec<Crate>>, DistError> {
    use object::{Object as _, ObjectSection as _};
    let Ok(file) = object::File::parse(binary) else {
        return Ok(None);
    };
    let Some(section) = file.section_by_name(".dep-v0") else {
        return Ok(None);
    };
    let bad = |why: &str| DistError::Layout(format!("cargo auditable data (.dep-v0): {why}"));
    let compressed = section.data().map_err(|_| bad("unreadable"))?;
    if compressed.len() > MAX_AUDIT_DATA {
        return Err(bad("too large"));
    }
    let json = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(compressed, MAX_AUDIT_DATA)
        .map_err(|_| bad("doesn't decompress"))?;
    let data: AuditData = serde_json::from_slice(&json).map_err(|e| bad(&e.to_string()))?;
    if data
        .packages
        .iter()
        .any(|p| p.dependencies.iter().any(|d| *d >= data.packages.len()))
    {
        return Err(bad("a dependency index is out of range"));
    }
    Ok(Some(data.packages))
}

/// `text` percent-encoded as a purl component: everything but
/// `A-Z a-z 0-9 . - _ ~` (so `2.1.1+zstd.1.5.7` becomes
/// `2.1.1%2Bzstd.1.5.7`, the canonical form tools compare).
fn purl_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn crate_ref(c: &Crate) -> String {
    if c.source == "crates.io" {
        format!(
            "pkg:cargo/{}@{}",
            purl_component(&c.name),
            purl_component(&c.version)
        )
    } else {
        format!("crate:{}@{}:{}", c.name, c.version, c.source)
    }
}

/// `value` with every object's keys sorted (as `nfpm`'s, independent of
/// `serde_json`'s `preserve_order` feature).
fn canonical(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k, canonical(v)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonical).collect()),
        other => other,
    }
}

/// Inputs describing one artifact.
#[derive(Debug, Clone)]
pub struct ArtifactInfo<'a> {
    /// The artifact file.
    pub path: &'a Path,
    /// Its format tag (`deb`, `msi`, …).
    pub format: &'a str,
    /// Its target triple.
    pub target: &'a str,
    /// The files it installs.
    pub files: &'a [SbomFile],
}

/// The SBOM of one artifact of product `id`, as JSON text. `build` is the
/// release's build metadata ([`crate::sign::BuildId`]), empty for none.
///
/// # Errors
/// [`DistError::Io`] reading the artifact or a binary;
/// [`DistError::Layout`] for unreadable `cargo auditable` data.
pub fn sbom(
    config: &Config,
    id: &str,
    release: &Release,
    build: &str,
    artifact: &ArtifactInfo<'_>,
    mtime: u64,
) -> Result<String, DistError> {
    let bytes = std::fs::read(artifact.path).map_err(|e| DistError::io(artifact.path, e))?;
    let sha512 = seaworthy_crypto::digest::sha512_hex(&bytes);
    let package = crate::linux::package_name(config, id);
    let version = release.version.to_string();
    let vendor = &config.defaults.vendor;
    let serial = crate::wix::derived_guid(&["seaworthy sbom", &sha512]);
    let serial = serial
        .trim_matches(|c| c == '{' || c == '}')
        .to_ascii_lowercase();

    let mut components: BTreeMap<String, Value> = BTreeMap::new();
    let mut dependencies: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut top: Vec<String> = Vec::new();
    for file in artifact.files {
        let file_ref = format!("file:{}", file.path);
        top.push(file_ref.clone());
        components.insert(
            file_ref.clone(),
            json!({
                "type": "file",
                "bom-ref": file_ref,
                "name": file.path,
                "hashes": [{"alg": "SHA-256", "content": file.sha256}],
            }),
        );
        let Some(binary) = &file.binary else { continue };
        let data = std::fs::read(binary).map_err(|e| DistError::io(binary, e))?;
        let Some(crates) = auditable_crates(&data)? else {
            continue;
        };
        let mut roots = Vec::new();
        for c in &crates {
            if c.kind != "runtime" {
                continue;
            }
            let reference = crate_ref(c);
            let mut component = json!({
                // The binary's own crate is the application; the rest are
                // libraries it links.
                "type": if c.root { "application" } else { "library" },
                "bom-ref": reference,
                "name": c.name,
                "version": c.version,
            });
            if c.source == "crates.io"
                && let Some(object) = component.as_object_mut()
            {
                object.insert("purl".to_owned(), Value::String(reference.clone()));
            }
            components.insert(reference.clone(), component);
            let depends: Vec<String> = c
                .dependencies
                .iter()
                .filter_map(|i| crates.get(*i))
                .filter(|d| d.kind == "runtime")
                .map(crate_ref)
                .collect();
            let entry = dependencies.entry(reference.clone()).or_default();
            entry.extend(depends);
            if c.root {
                roots.push(reference);
            }
        }
        dependencies.entry(file_ref).or_default().extend(roots);
    }
    dependencies.insert("artifact".to_owned(), top);

    let mut properties = vec![
        json!({"name": "seaworthy:format", "value": artifact.format}),
        json!({"name": "seaworthy:target", "value": artifact.target}),
        json!({"name": "seaworthy:sequence", "value": release.sequence.to_string()}),
    ];
    if !build.is_empty() {
        properties.push(json!({"name": "seaworthy:build", "value": build}));
    }
    properties.push(json!({"name": "seaworthy:file", "value": artifact.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()}));
    let doc = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": format!("urn:uuid:{serial}"),
        "version": 1,
        "metadata": {
            "timestamp": crate::archive::rfc3339(mtime),
            "tools": {"components": [{
                "type": "application",
                "name": "seaworthy",
                "version": env!("CARGO_PKG_VERSION"),
            }]},
            "supplier": {"name": vendor},
            "component": {
                "type": "application",
                "bom-ref": "artifact",
                "name": package,
                "version": version,
                "supplier": {"name": vendor},
                "hashes": [{"alg": "SHA-512", "content": sha512}],
                "properties": properties,
            },
        },
        "components": components.into_values().collect::<Vec<_>>(),
        "dependencies": dependencies
            .into_iter()
            .map(|(reference, mut depends)| {
                depends.sort();
                depends.dedup();
                json!({"ref": reference, "dependsOn": depends})
            })
            .collect::<Vec<_>>(),
    });
    let text = serde_json::to_string_pretty(&canonical(doc))
        .map_err(|e| DistError::Layout(e.to_string()))?;
    Ok(format!("{text}\n"))
}

/// The SBOM file of an artifact: `<artifact>.cdx.json`.
#[must_use]
pub fn sbom_path(artifact: &Path) -> PathBuf {
    let mut name = artifact.as_os_str().to_owned();
    name.push(".cdx.json");
    PathBuf::from(name)
}
